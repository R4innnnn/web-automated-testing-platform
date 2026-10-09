$ErrorActionPreference = "Stop"
$backend = (Resolve-Path (Join-Path $PSScriptRoot "..\backend")).Path
$python = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "未找到 Python 虚拟环境，请先运行 code\scripts\setup.ps1"
}
& $python -m uvicorn app.main:app --app-dir $backend --host 127.0.0.1 --port 8000
