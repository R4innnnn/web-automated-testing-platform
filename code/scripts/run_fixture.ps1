$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$python = Join-Path $root "backend\.venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "请先运行 code\scripts\setup.ps1"
}
& $python (Join-Path $root "fixtures\mini_target.py") --port 8777
