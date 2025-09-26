#!/bin/zsh
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P)
ROOT_DIR=$(dirname "$SCRIPT_DIR")
cd "$ROOT_DIR"

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pyinstaller --clean --onefile --name win-evtx-analyzer pyinstaller.spec | cat
mkdir -p dist_macos
cp dist/win-evtx-analyzer dist_macos/
echo "Built dist_macos/win-evtx-analyzer"
