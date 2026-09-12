import ctypes
from ctypes import wintypes
import sys
import time
import re
import psutil
import struct

# Define Windows API types and functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Memory access permission constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
MEM_COMMIT = 0x1000
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01

# Set up Windows API calls
wintypes.LPCVOID = ctypes.c_void_p

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', wintypes.LPVOID),
        ('AllocationBase', wintypes.LPVOID),
        ('AllocationProtect', wintypes.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD),
        ('Type', wintypes.DWORD),
    ]

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t
]
VirtualQueryEx.restype = ctypes.c_size_t

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
ReadProcessMemory.restype = wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
WriteProcessMemory.restype = wintypes.BOOL

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

# ======== Fixed module base address acquisition function ========
def get_module_base_address(pid, module_name):
    """Get base address for specified process and module"""
    TH32CS_SNAPMODULE = 0x00000008
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    
    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD),
            ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", wintypes.LPVOID), 
            ("modBaseSize", wintypes.DWORD),
            ("hModule", wintypes.HMODULE),
            ("szModule", ctypes.c_char * 256),
            ("szExePath", ctypes.c_char * 260)
        ]
    
    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    
    Module32First = kernel32.Module32First
    Module32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    Module32First.restype = wintypes.BOOL
    
    Module32Next = kernel32.Module32Next
    Module32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    Module32Next.restype = wintypes.BOOL
    
    CloseHandle = kernel32.CloseHandle
    
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        error = ctypes.GetLastError()
        print(f"CreateToolhelp32Snapshot failed. Error: {error}")
        return 0
    
    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)
    
    if not Module32First(snapshot, ctypes.byref(me32)):
        error = ctypes.GetLastError()
        print(f"Module32First failed. Error: {error}")
        CloseHandle(snapshot)
        return 0
    
    base_address = 0
    found = False
    while True:
        current_module = me32.szModule.decode()
        if module_name.lower() in current_module.lower():
            base_address = me32.modBaseAddr
            found = True
            print(f"Found module '{current_module}' at base address: 0x{base_address:X}")
            break
        
        if not Module32Next(snapshot, ctypes.byref(me32)):
            break
    
    CloseHandle(snapshot)
    
    if not found:
        print(f"Module '{module_name}' not found in process {pid}")
    
    return base_address

# ======== Memory scanning function ========
def get_process_id(process_name):
    """Get process ID"""
    process_name = process_name.lower()
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == process_name:
            return proc.info['pid']
    raise RuntimeError(f"Process not found: {process_name}")

def is_readable_protection(protect):
    """Check if memory protection flags are readable"""
    return protect in [
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY
    ]

def byte_scan(process_name, pattern_str, verbose=True, addr_offset=0):
    """Reliable high-speed memory scanning, returns the first matching address
    
    Args:
        process_name: Process name to scan
        pattern_str: Byte pattern to search (hex string)
        verbose: Whether to print scan progress and results (default True)
        addr_offset: Pattern address offset, negative for backward, positive for forward (default 0)
    """
    # Parse byte pattern (supports ?? wildcards)
    tokens = pattern_str.split()
    if not tokens:
        raise ValueError("Pattern cannot be empty")
    try:
        literals = [(k, int(t, 16)) for k, t in enumerate(tokens) if t != "??"]
    except ValueError:
        raise ValueError("Invalid pattern format. Use hex bytes like 'FF 00 AA' or '??'")
    
    pattern_len = len(tokens)
    
    # Fast path: use the longest literal run as anchor, scan with C-speed
    # bytes.find, then verify wildcards. Fallback (too few literals): regex
    # with consecutive wildcards merged into .{n}
    anchor_bytes = None
    anchor_off = 0
    if len(literals) >= 6:
        best_start, best_len, run_start = 0, 0, None
        for k, t in enumerate(tokens + ["??"]):
            if t != "??":
                if run_start is None:
                    run_start = k
            elif run_start is not None:
                if k - run_start > best_len:
                    best_start, best_len = run_start, k - run_start
                run_start = None
        anchor_bytes = bytes(int(tokens[k], 16) for k in range(best_start, best_start + best_len))
        anchor_off = best_start
    
    pattern_re = None
    if anchor_bytes is None:
        regex_bytes = b""
        i = 0
        while i < pattern_len:
            if tokens[i] == "??":
                j = i
                while j < pattern_len and tokens[j] == "??":
                    j += 1
                n = j - i
                regex_bytes += b"." if n == 1 else b".{" + str(n).encode() + b"}"
                i = j
            else:
                regex_bytes += re.escape(bytes([int(tokens[i], 16)]))
                i += 1
        pattern_re = re.compile(regex_bytes, re.DOTALL)
    
    def verify_literals(buf, start):
        for k, v in literals:
            if buf[start + k] != v:
                return False
        return True
    
    # Get process ID and open process
    pid = get_process_id(process_name)
    h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        raise RuntimeError(f"Failed to open process. Error: {ctypes.get_last_error()}")
    
    try:
        # Iterate through memory regions
        base_addr = 0
        total_read = 0
        pattern_matches = 0
        region_count = 0
        readable_regions = 0
        start_time = time.time()
        last_print_time = start_time
        
        if verbose:
            print("Scanning memory...")
        
        while base_addr < 0x7FFFFFFFFFFFFFFF:  # 64-bit address space limit
            mbi = MEMORY_BASIC_INFORMATION()
            if VirtualQueryEx(h_process, base_addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                error = ctypes.GetLastError()
                # Print error but continue scanning - only print error, not progress
                base_addr += 4096  # Advance by one page size
                continue
                
            region_size = mbi.RegionSize
            region_end = base_addr + region_size
            region_count += 1
            
            # Check if memory is readable
            if mbi.State == MEM_COMMIT and is_readable_protection(mbi.Protect):
                readable_regions += 1
                
                # Scan readable memory regions - using larger chunks
                chunk_size = 10 * 1024 * 1024  # 10MB chunks (significantly reduces read calls)
                offset = 0
                carry = b""
                
                while offset < region_size:
                    read_size = min(chunk_size, region_size - offset)
                    if read_size < pattern_len:
                        offset += read_size
                        continue
                        
                    # Allocate buffer
                    buffer_type = ctypes.c_ubyte * read_size
                    buffer = buffer_type()
                    bytes_read = ctypes.c_size_t()
                    read_addr = base_addr + offset
                    
                    # Read memory
                    if ReadProcessMemory(h_process, read_addr, 
                                        ctypes.byref(buffer), 
                                        ctypes.sizeof(buffer), 
                                        ctypes.byref(bytes_read)):
                        
                        if bytes_read.value >= pattern_len:
                            # Convert to Python bytes (bulk memcpy first, then slice;
                            # slicing the ctypes array itself is a slow per-element path)
                            data = bytes(buffer)[:bytes_read.value]
                            total_read += bytes_read.value
                            blob = carry + data
                            
                            # Anchor fast scan (C-speed find + wildcard verify), regex fallback
                            match_start = -1
                            if anchor_bytes is not None:
                                pos = blob.find(anchor_bytes)
                                while pos != -1:
                                    s = pos - anchor_off
                                    if s >= 0 and s + pattern_len <= len(blob) and verify_literals(blob, s):
                                        match_start = s
                                        break
                                    pos = blob.find(anchor_bytes, pos + 1)
                            else:
                                match = pattern_re.search(blob)
                                if match:
                                    match_start = match.start()
                            if match_start >= 0:
                                pattern_matches += 1
                                match_addr = read_addr - len(carry) + match_start
                                if verbose:
                                    print(f"Found match address: 0x{match_addr+addr_offset:016X}")
                                return f"0x{match_addr+addr_offset:016X}"
                            # Keep chunk tail so patterns spanning chunk boundaries are not missed
                            carry = blob[-(pattern_len - 1):]
                    
                    # More efficient progress reporting
                    if verbose:  # Only update progress when verbose is True
                        current_time = time.time()
                        if current_time - last_print_time > 1.0:  # Update every second
                            elapsed = current_time - start_time
                            read_mb = total_read / (1024 * 1024)
                            if elapsed > 0:
                                mb_per_sec = read_mb / elapsed
                            else:
                                mb_per_sec = 0
                                
                            print(f"Scanned {read_mb:.2f} MB at {mb_per_sec:.2f} MB/sec - Regions: {region_count}")
                            last_print_time = current_time
                    
                    offset += read_size
                    
            # Move to next region
            base_addr = region_end
        
        # Final scan statistics
        if verbose:  # Only show stats when verbose is True
            elapsed_time = time.time() - start_time
            read_mb = total_read / (1024 * 1024)
            if elapsed_time > 0:
                mb_per_sec = read_mb / elapsed_time
            else:
                mb_per_sec = 0
                
            print("\nScan completed:")
            print(f"  Total regions: {region_count}")
            print(f"  Readable regions: {readable_regions}")
            print(f"  Total data scanned: {read_mb:.2f} MB")
            print(f"  Scan time: {elapsed_time:.2f} seconds ({mb_per_sec:.2f} MB/sec)")
            print(f"  Pattern matches found: {pattern_matches}")
        
        return None
    
    finally:
        CloseHandle(h_process)

# ======== Memory writing function ========
def write_qword(h_process, address, value):
    """Write 8-byte value to specified address"""
    data = value.to_bytes(8, 'little')
    buffer = (ctypes.c_ubyte * 8)(*data)
    bytes_written = ctypes.c_size_t()
    
    result = WriteProcessMemory(
        h_process,
        address,
        buffer,
        8,
        ctypes.byref(bytes_written)
    )
    
    if result and bytes_written.value == 8:
        return True
    else:
        error = ctypes.GetLastError()
        print(f"Write failed at 0x{address:X}. Error: {error}")
        return False

def is_process_running(pid):
    """Check if process with specified PID is still running"""
    try:
        # Attempt to get process info
        process = psutil.Process(pid)
        return process.is_running()
    except psutil.NoSuchProcess:
        return False

def scan_pattern(pattern, description, offset, verbose=True):
    """Scan specified memory pattern and convert to address
    
    Args:
        pattern: Memory signature to scan
        description: Scan description information
        offset: Address offset
        verbose: Whether to print detailed logs
    Returns:
        Converted memory address (integer) or None
    """

    if verbose:
        print(f"Scanning {description} signature: {pattern}")
    
    address_str = byte_scan("NMS.exe", pattern, verbose, offset)
    
    if not address_str or "0x" not in address_str:
        print(f"{description} address scan failed, please use latest exe version...")
        sys.exit(1)
    
    return int(address_str, 16)

def read_memory_value(h_process, address, size=8):
    """Read value from specified memory address"""
    buffer = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t()
    
    if not ReadProcessMemory(h_process, address, buffer, size, ctypes.byref(bytes_read)):
        return None
    
    return int.from_bytes(bytes(buffer), 'little')

def clear_memory_range(h_process, start_address, size, description):
    """Zero out bytes in specified address range"""
    try:
        # Create all-zero byte array
        zero_buffer = bytes(size)
        bytes_written = ctypes.c_size_t()
        
        # Write zeros
        success = WriteProcessMemory(
            h_process,
            start_address,
            zero_buffer,
            len(zero_buffer),
            ctypes.byref(bytes_written)
        )
        
        if success and bytes_written.value == len(zero_buffer):
            print(f"Successfully cleared {description} address range: 0x{start_address:X} - 0x{start_address+size-1:X}")
        else:
            print(f"! {description} clearance failed ({ctypes.GetLastError()})")
    except Exception as e:
        print(f"Clearance error: {e}")

if __name__ == "__main__":
    print("\n" + "="*50)
    print("Super Sentinel Hunter V1.4.7.00  @beihaixingchen")
    print("Description: Obtain sentinel & exotic ship without landing - use emote shortcuts!")
    
    print("\n" + "="*50)
    print("Starting scan...")
    start_time = time.time()
    
    try:
        # 1. Scan key byte patterns to get two target addresses
        template_sentinel_pattern = "01 00 00 00 00 00 00 00 01 00 00 00 78 00 00 00 00 00 00 00 00 00 00 00 34 00 00 00 17 00 00 00"
        template_exotic_pattern = "01 00 00 00 00 00 00 00 01 00 00 00 78 00 00 00 00 00 00 00 01 00 00 00 34 00 00 00 0E 00 00 00"
        local_sentinel_pattern = "01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 00 00 00 00 01 00 00 FF FF FF FF"
        # local_exotic_pattern = "01 00 00 00 00 00 00 00 01 00 00 00 0A 00 00 00 06"
        
        local_sentinel_address = scan_pattern(local_sentinel_pattern, "local sentinel ship seed", -0x8)
        template_sentinel_address = scan_pattern(template_sentinel_pattern, "sentinel ship template", -64)
        template_exotic_address = scan_pattern(template_exotic_pattern, "exotic ship template", -64)

        
        # 2. Open process
        pid = get_process_id("NMS.exe")
        print(f"\nFound process ID: {pid}")
        
        # Open process (add write permissions)
        h_process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | 
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            False, 
            pid
        )
        if not h_process:
            error = ctypes.GetLastError()
            raise RuntimeError(f"Failed to open process. Error: {error}")
        

        # 3. Remove "EXE NOT WORKING!" flags
        # Clear sentinel template flags
        clear_memory_range(h_process, template_sentinel_address + 24, 16, "sentinel ship template")

        # Clear exotic ship template flags
        clear_memory_range(h_process, template_exotic_address + 24, 16, "exotic   ship template")
        
    
        # 2. Main loop - runs every 5 seconds, stops when game exits
        print("\n" + "="*50)
        print("Loop detection started, press Ctrl+C to exit:")
        print("Program will check ship seed every 5s")
        print("If game exit is detected, program will automatically stop")
        
        try:
            # State tracking variables
            last_sentinel_seed = 0
            last_exotic_seed = 0
            game_running = True
            
            while game_running:
                if not is_process_running(pid):
                    print("Detected game exit, stopping program...")
                    game_running = False
                    break
                               
                # Read current sentinel seed value
                local_sentinel_value = read_memory_value(h_process, local_sentinel_address)
                if local_sentinel_value is None:
                    print("Failed to read sentinel seed, skipping round...")
                    time.sleep(5)
                    continue
                
                # Read current target address value
                target_current_value = read_memory_value(h_process, template_sentinel_address)
                if target_current_value is None:
                    print("Failed to read sentinel target value, skipping round...")
                    time.sleep(5)
                    continue
                
                # Check and update sentinel seed
                if local_sentinel_value != target_current_value:
                    print(f"\nDetected sentinel ship seed: 0x{local_sentinel_value:X}")
                    
                    # Write sentinel seed
                    if write_qword(h_process, template_sentinel_address, local_sentinel_value):
                        # Verify write result
                        new_value = read_memory_value(h_process, template_sentinel_address)
                        if new_value != local_sentinel_value:
                            print("Sentinel write verification failed!")
                        else:
                            last_sentinel_seed = local_sentinel_value
                            
                            # Scan and update exotic ship when galaxy changes
                            # exotic_seed_address = scan_pattern(local_exotic_pattern, "local exotic seed", -8, False)
                            exotic_seed_address = read_memory_value(h_process, local_sentinel_address + 0X10) + 0x520
                            
                            if exotic_seed_address:
                                exotic_seed_value = read_memory_value(h_process, exotic_seed_address)
                                if exotic_seed_value and exotic_seed_value != last_exotic_seed:
                                    # Write exotic ship seed
                                    if write_qword(h_process, template_exotic_address, exotic_seed_value):
                                        print(f"Detected exotic   ship seed: 0x{exotic_seed_value:X}")
                                        last_exotic_seed = exotic_seed_value
                            else:
                                print("Exotic ship signature scan failed, skipping update")
                
                # Wait 5 seconds
                for _ in range(5):
                    if not is_process_running(pid):
                        break
                    time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nWrite loop interrupted by user")
        
        finally:
            CloseHandle(h_process)
            print("Closed process handle")
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\nProgram exited")
    sys.exit(0)