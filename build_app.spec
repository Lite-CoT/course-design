# Build from the project root with PyInstaller 6.22.3 on Windows x64.
from pathlib import Path
from PyInstaller.utils.hooks import collect_delvewheel_libs_directory, copy_metadata
root = Path(SPECPATH)
gmp_datas, gmp_binaries = collect_delvewheel_libs_directory('gmpy2')
metadata = [entry for package in ('phe', 'gmpy2', 'cryptography', 'PySide6-Essentials')
            for entry in copy_metadata(package)]
a = Analysis([str(root/'src/main.py')], pathex=[str(root/'src')],
    binaries=gmp_binaries, datas=gmp_datas+metadata, hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[],
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
    disable_windowed_traceback=False,hide_console='hide-early')
