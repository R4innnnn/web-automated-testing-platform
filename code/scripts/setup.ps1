$ErrorActionPreference = "Stop"
$backend = Join-Path $PSScriptRoot "..\backend"
$frontend = Join-Path $PSScriptRoot "..\frontend"
$python = Join-Path $backend ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $python)) {
    python -m venv (Join-Path $backend ".venv")
}
& $python -m pip install -r (Join-Path $backend "requirements.txt")
& $python -m playwright install chromium

Push-Location $frontend
try {
    npm ci
    npm run build
} finally {
    Pop-Location
}
Write-Host "安装完成。运行 code\scripts\start.ps1 启动平台。"
