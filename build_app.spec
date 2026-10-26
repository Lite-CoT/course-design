# Build from the project root with PyInstaller 6.22.3 on Windows x64.
from pathlib import Path
root = Path(SPECPATH)
a = Analysis([str(root/'src/main.py')], pathex=[str(root/'src'),str(root/'work/deps')],
    binaries=[], datas=[], hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[],
    excludes=['matplotlib','scipy','pandas','IPython','tkinter','PySide6.QtWebEngineCore','PySide6.QtWebEngineWidgets'],
    noarchive=False, optimize=0)
# Windows 10/11 supplies UCRT/API sets. Do not ship unrelated PATH copies.
a.binaries = [entry for entry in a.binaries if not (
    Path(entry[0]).name.lower().startswith('api-ms-win-') or
    Path(entry[0]).name.lower()=='ucrtbase.dll')]
pyz=PYZ(a.pure)
exe=EXE(pyz,a.scripts,a.binaries,a.datas,[],name='MiPiaoLab',debug=False,
    bootloader_ignore_signals=False,strip=False,upx=False,console=True,
    disable_windowed_traceback=False,hide_console='hide-early')
