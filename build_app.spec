# Build from the project root with PyInstaller 6.22.3 on Windows x64.
from pathlib import Path
import sys
from PyInstaller.utils.hooks import collect_delvewheel_libs_directory, copy_metadata
root = Path(SPECPATH)
gmp_datas, gmp_binaries = collect_delvewheel_libs_directory('gmpy2')
# Pin OpenSSL to the libraries shipped with this Python, avoiding System32 conflicts.
ssl_binaries = [(str(Path(sys.base_prefix) / 'DLLs' / name), '.')
                for name in ('libssl-3-x64.dll', 'libcrypto-3-x64.dll')]
# Some managed Python runtimes load an adjacent CA policy file from ssl.py.
ssl_policy = Path(sys.base_prefix) / 'Lib' / 'codex-rejected-cas.pem'
ssl_datas = [(str(ssl_policy), '.')] if ssl_policy.exists() else []
metadata = [entry for package in ('phe', 'gmpy2', 'cryptography', 'PySide6-Essentials')
            for entry in copy_metadata(package)]
a = Analysis([str(root/'src/main.py')], pathex=[str(root/'src')],
    binaries=gmp_binaries+ssl_binaries, datas=gmp_datas+metadata+ssl_datas, hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['matplotlib','scipy','pandas','IPython','tkinter','PySide6.QtWebEngineCore','PySide6.QtWebEngineWidgets'],
    noarchive=False, optimize=0)
# Windows supplies UCRT/API sets and the unversioned ICU API used by Qt.
# A third-party icuuc.dll found on PATH can have incompatible versioned exports.
a.binaries = [entry for entry in a.binaries if not (
    Path(entry[0]).name.lower().startswith('api-ms-win-') or
    Path(entry[0]).name.lower() in {'ucrtbase.dll', 'icuuc.dll', 'icuin.dll', 'icu.dll'})]
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,a.binaries,a.datas,[],name='MiPiaoLab',debug=False,
    bootloader_ignore_signals=False,strip=False,upx=False,console=True,
    disable_windowed_traceback=False)
