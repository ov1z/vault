# Build Vault into a single Windows .exe.
#   PS> .\build.ps1
# Output: dist\Vault.exe

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Cleaning previous build..." -ForegroundColor Cyan
Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue

Write-Host "Running PyInstaller (via 'python -m' so it uses the interpreter that has the deps)..." -ForegroundColor Cyan
python -m PyInstaller --noconfirm --clean `
  --name Vault `
  --onefile `
  --windowed `
  --icon vault.ico `
  --add-data "vaultpm/web;web" `
  --collect-all webview `
  --collect-all clr_loader `
  --collect-all pythonnet `
  --hidden-import clr `
  run.py

if (Test-Path "dist\Vault.exe") {
  Write-Host "`nDone -> dist\Vault.exe" -ForegroundColor Green
} else {
  Write-Host "`nBuild failed: dist\Vault.exe not found" -ForegroundColor Red
  exit 1
}
