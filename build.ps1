$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    py -3 -m venv .venv
}

$python = ".venv\Scripts\python.exe"
& $python -m pip install --upgrade pip
& $python -m pip install -r requirements.txt
& $python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name "Net-Tracker" `
    --add-data "Network.png;." `
    main.py

Write-Host "Portable EXE: dist\Net-Tracker.exe"