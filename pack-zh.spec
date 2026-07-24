# -*- mode: python -*-
# pyinstaller pack-zh.spec
import sys

block_cipher = None

a = Analysis(
    ['hook1.4-zh.py'],
    binaries=[],
    datas=[], 
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='超级飞船猎人 V1.4.6.42.1',
    onefile=True,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True, 
    icon='POLICEMESSAGEICON.png'
)