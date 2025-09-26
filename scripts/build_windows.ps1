$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RootDir = Split-Path -Parent $ScriptDir
Set-Location $RootDir

python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pyinstaller --clean --onefile --name win-evtx-analyzer pyinstaller.spec | Out-Host
New-Item -ItemType Directory -Force -Path dist_windows | Out-Null
Copy-Item dist\win-evtx-analyzer.exe dist_windows\
Write-Host "Built dist_windows/win-evtx-analyzer.exe"
