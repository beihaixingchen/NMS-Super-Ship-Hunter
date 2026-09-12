import ctypes
from ctypes import wintypes
import sys
import time
import re
import psutil
import struct

# 定义Windows API类型和函数
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# 内存访问权限常量
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

# 设置Windows API调用
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

# ======== 固定模块基地址获取函数 ========
def get_module_base_address(pid, module_name):
    """获取指定进程和模块的基地址"""
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
            print(f"找到游戏'{current_module}'的地址: 0x{base_address:X}")
            break
        
        if not Module32Next(snapshot, ctypes.byref(me32)):
            break
    
    CloseHandle(snapshot)
    
    if not found:
        print(f"Module '{module_name}' not found in process {pid}")
    
    return base_address

# ======== 内存扫描函数 ========
def get_process_id(process_name):
    """获取进程ID"""
    process_name = process_name.lower()
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == process_name:
            return proc.info['pid']
    raise RuntimeError(f"Process not found: {process_name}")

def is_readable_protection(protect):
    """检查内存保护标志是否可读"""
    return protect in [
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY
    ]

def byte_scan(process_name, pattern_str, verbose=True, addr_offset=0):
    """可靠的高速内存扫描，返回第一个匹配地址
    
    Args:
        process_name: 要扫描的进程名
        pattern_str: 要搜索的字节模式 (十六进制字符串)
        verbose: 是否打印扫描进度和结果 (默认True)
        addr_offset: 特征码地址偏移, 向前为负向后为正 (默认0)
    """
    # 解析字节模式 (支持 ?? 通配符)
    tokens = pattern_str.split()
    if not tokens:
        raise ValueError("Pattern cannot be empty")
    try:
        literals = [(k, int(t, 16)) for k, t in enumerate(tokens) if t != "??"]
    except ValueError:
        raise ValueError("Invalid pattern format. Use hex bytes like 'FF 00 AA' or '??'")
    
    pattern_len = len(tokens)
    
    # 快速方案：取最长连续字面量段作为锚点，用 C 级 bytes.find 扫描后回验通配符
    # 退化方案（字面量太少时）：连续通配符合并为 .{n} 的正则
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
    
    # 获取进程ID并打开进程
    pid = get_process_id(process_name)
    h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        raise RuntimeError(f"Failed to open process. Error: {ctypes.get_last_error()}")
    
    try:
        # 遍历内存区域
        base_addr = 0
        total_read = 0
        pattern_matches = 0
        region_count = 0
        readable_regions = 0
        start_time = time.time()
        last_print_time = start_time
        
        if verbose:
            print("扫描内存中...")
        
        while base_addr < 0x7FFFFFFFFFFFFFFF:  # 64位地址空间上限
            mbi = MEMORY_BASIC_INFORMATION()
            if VirtualQueryEx(h_process, base_addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
                error = ctypes.GetLastError()
                # 打印错误但继续扫描 - 只打印错误不打印进度
                base_addr += 4096  # 推进一个页面大小
                continue
                
            region_size = mbi.RegionSize
            region_end = base_addr + region_size
            region_count += 1
            
            # 检查内存是否可读
            if mbi.State == MEM_COMMIT and is_readable_protection(mbi.Protect):
                readable_regions += 1
                
                # 扫描可读内存区域 - 使用更大的块
                chunk_size = 10 * 1024 * 1024  # 10MB块 (显著减少读取调用次数)
                offset = 0
                carry = b""
                
                while offset < region_size:
                    read_size = min(chunk_size, region_size - offset)
                    if read_size < pattern_len:
                        offset += read_size
                        continue
                        
                    # 分配缓冲区
                    buffer_type = ctypes.c_ubyte * read_size
                    buffer = buffer_type()
                    bytes_read = ctypes.c_size_t()
                    read_addr = base_addr + offset
                    
                    # 读取内存
                    if ReadProcessMemory(h_process, read_addr, 
                                        ctypes.byref(buffer), 
                                        ctypes.sizeof(buffer), 
                                        ctypes.byref(bytes_read)):
                        
                        if bytes_read.value >= pattern_len:
                            # 转换为Python字节（先整体memcpy再切片，切片ctypes数组是逐元素的慢路径）
                            data = bytes(buffer)[:bytes_read.value]
                            total_read += bytes_read.value
                            blob = carry + data
                            
                            # 锚点快速扫描（C级find+回验通配符），无锚点时用正则
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
                                    print(f"找到匹配地址: 0x{match_addr+addr_offset:016X}")
                                return f"0x{match_addr+addr_offset:016X}"
                            # 保留块尾部，避免特征码跨块边界漏匹配
                            carry = blob[-(pattern_len - 1):]
                    
                    # 更高效的进度报告
                    if verbose:  # 只在verbose时更新进度
                        current_time = time.time()
                        if current_time - last_print_time > 1.0:  # 每秒更新一次
                            elapsed = current_time - start_time
                            read_mb = total_read / (1024 * 1024)
                            if elapsed > 0:
                                mb_per_sec = read_mb / elapsed
                            else:
                                mb_per_sec = 0
                                
                            print(f"Scanned {read_mb:.2f} MB at {mb_per_sec:.2f} MB/sec - Regions: {region_count}")
                            last_print_time = current_time
                    
                    offset += read_size
                    
            # 移动到下一个区域
            base_addr = region_end
        
        # 最终扫描统计
        if verbose:  # 只在verbose时显示统计
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

# ======== 内存写入函数 ========
def write_qword(h_process, address, value):
    """向指定地址写入8字节值"""
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
    """检查指定PID的进程是否仍在运行"""
    try:
        # 尝试获取进程信息
        process = psutil.Process(pid)
        return process.is_running()
    except psutil.NoSuchProcess:
        return False

def scan_pattern(pattern, description, offset, verbose=True):
    """扫描指定的内存模式并转换为地址
    
    Args:
        pattern: 要扫描的特征码字符串
        description: 扫描描述信息
        offset: 地址偏移量
        verbose: 是否打印详细日志
    Returns:
        转换后的内存地址(整数)或None
    """

    if verbose:
        print(f"扫描{description}特征码: {pattern}")
    
    address_str = byte_scan("NMS.exe", pattern, verbose, offset)
    
    if not address_str or "0x" not in address_str:
        print(f"{description}地址扫描失败，请使用最新版本exe...")
        sys.exit(1)
    
    return int(address_str, 16)

def read_memory_value(h_process, address, size=8):
    """从指定内存地址读取值"""
    buffer = (ctypes.c_ubyte * size)()
    bytes_read = ctypes.c_size_t()
    
    if not ReadProcessMemory(h_process, address, buffer, size, ctypes.byref(bytes_read)):
        return None
    
    return int.from_bytes(bytes(buffer), 'little')

def clear_memory_range(h_process, start_address, size, description):
    """将指定地址范围的字节清零"""
    try:
        # 创建全零字节数组
        zero_buffer = bytes(size)
        bytes_written = ctypes.c_size_t()
        
        # 写入全零
        success = WriteProcessMemory(
            h_process,
            start_address,
            zero_buffer,
            len(zero_buffer),
            ctypes.byref(bytes_written)
        )
        
        if success and bytes_written.value == len(zero_buffer):
            print(f"已成功清零 {description} 地址范围: 0x{start_address:X} - 0x{start_address+size-1:X}")
        else:
            print(f"! {description} 清零失败 ({ctypes.GetLastError()})")
    except Exception as e:
        print(f"清零错误: {e}")


if __name__ == "__main__":
    print("\n" + "="*50)
    print("MOD: 超级飞船猎人")
    print("版本: 1.4.7.00")
    print("时间: 2026.09.13")
    print("作者: 北海星辰")
    print("QQ群: 1群:884609884(如满请加2群) 2群:618088968")
    print("简介: 使用表情立刻获取本星系护卫飞船和异星飞船!")
    
    print("\n" + "="*50)
    print("开始扫描...")
    start_time = time.time()
    
    try:
        # 1. 扫描关键字节模式获取两个目标地址
        template_sentinel_pattern = "01 00 00 00 00 00 00 00 01 00 00 00 78 00 00 00 00 00 00 00 00 00 00 00 34 00 00 00 17 00 00 00"
        template_exotic_pattern = "01 00 00 00 00 00 00 00 01 00 00 00 78 00 00 00 00 00 00 00 01 00 00 00 34 00 00 00 0E 00 00 00"
        local_sentinel_pattern = "01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 00 00 00 00 01 00 00 FF FF FF FF"
        # local_exotic_pattern = "01 00 00 00 00 00 00 00 01 00 00 00 0A 00 00 00 06"
        
        local_sentinel_address = scan_pattern(local_sentinel_pattern, "本地护卫飞船种子", -0x8)
        template_sentinel_address = scan_pattern(template_sentinel_pattern, "护卫飞船模板", -64)
        template_exotic_address = scan_pattern(template_exotic_pattern, "异星飞船模板", -64)

        
        # 2. 打开进程
        pid = get_process_id("NMS.exe")
        print(f"\n寻找进程ID: {pid}")
        
        # 打开进程（添加写入权限）
        h_process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | 
            PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            False, 
            pid
        )
        if not h_process:
            error = ctypes.GetLastError()
            raise RuntimeError(f"打开进程失败. 错误: {error}")
        

        # 3.删掉EXE NOT WORKING!标志
        # 为护卫飞船模板标志清零
        clear_memory_range(h_process, template_sentinel_address + 24, 16, "护卫飞船模板")

        # 为异星飞船模板标志清零
        clear_memory_range(h_process, template_exotic_address + 24, 16, "异星飞船模板")
        
    
        # 2. 进入主循环，每5秒操作一次，并在游戏退出时停止
        print("\n" + "="*50)
        print("循环检测启动, 按下 Ctrl+C 将退出:")
        print("程序将每5s检测一次飞船种子")
        print("如果检测到游戏已退出, 程序将自动停止")
        
        try:
            # 状态跟踪变量
            last_sentinel_seed = 0
            last_exotic_seed = 0
            game_running = True
            
            while game_running:
                if not is_process_running(pid):
                    print("检测到游戏已退出，停止程序...")
                    game_running = False
                    break
                               
                # 读取当前护卫飞船种子值
                local_sentinel_value = read_memory_value(h_process, local_sentinel_address)
                if local_sentinel_value is None:
                    print("读取护卫飞船种子失败，跳过本轮...")
                    time.sleep(5)
                    continue
                
                # 读取模板地址当前值
                target_current_value = read_memory_value(h_process, template_sentinel_address)
                if target_current_value is None:
                    print("读取护卫飞船目标值失败，跳过本轮...")
                    time.sleep(5)
                    continue
                
                # 检查并更新护卫飞船种子
                if local_sentinel_value != target_current_value:
                    print(f"\n检测到护卫飞船种子: 0x{local_sentinel_value:X}")
                    
                    # 写入护卫飞船种子
                    if write_qword(h_process, template_sentinel_address, local_sentinel_value):
                        # 验证写入结果
                        new_value = read_memory_value(h_process, template_sentinel_address)
                        if new_value != local_sentinel_value:
                            print("护卫飞船写入验证失败!")
                        else:
                            last_sentinel_seed = local_sentinel_value
                            
                            # 星系变化时扫描并更新异星飞船
                            # exotic_seed_address = scan_pattern(local_exotic_pattern, "本地异星种子", -8, False)
                            exotic_seed_address = read_memory_value(h_process, local_sentinel_address + 0X10) + 0x520
                            
                            if exotic_seed_address:
                                exotic_seed_value = read_memory_value(h_process, exotic_seed_address)
                                if exotic_seed_value and exotic_seed_value != last_exotic_seed:
                                    # 写入异星飞船种子
                                    if write_qword(h_process, template_exotic_address, exotic_seed_value):
                                        print(f"检测到异星飞船种子: 0x{exotic_seed_value:X}")
                                        last_exotic_seed = exotic_seed_value
                            else:
                                print("异星飞船特征码扫描失败，跳过异星飞船更新")
                
                # 等待5秒
                for _ in range(5):
                    if not is_process_running(pid):
                        break
                    time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n写入循环被用户中断")
        
        finally:
            CloseHandle(h_process)
            print("已关闭进程句柄")
    
    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n程序已退出")
    sys.exit(0)