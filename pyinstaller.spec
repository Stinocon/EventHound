# PyInstaller spec for win-evtx-analyzer

block_cipher = None

hiddenimports = [
    'Evtx',
    'xmltodict',
    'orjson',
    'click',
    'fastapi',
    'uvicorn'
]

from PyInstaller.utils.hooks import collect_submodules
hiddenimports += collect_submodules('Evtx')


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='win-evtx-analyzer',
    debug=False,
    strip=False,
    upx=True,
    console=True,
)
