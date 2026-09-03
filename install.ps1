# ==============================================================================
#  CTF DevTools — Fast One-Line Installer (Windows PowerShell)
# ==============================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║          🛡️   CTF DevTools v1.0.0 — Automated Installer   🛡️          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
Write-Host "[*] Checking Python installation..." -ForegroundColor Blue
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py"
} else {
    Write-Host "[!] Error: Python 3 is not installed or not in PATH." -ForegroundColor Red
    Write-Host "    Please install Python 3.10+ from https://www.python.org/downloads/ or via 'winget install Python.Python.3.12'"
    Exit 1
}

$pyVer = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "[+] Detected Python $pyVer ($pythonCmd)" -ForegroundColor Green

# 2. Check Directory & Source Setup
$installDir = Join-Path $env:USERPROFILE ".ctf-devtools"
if (Test-Path "pyproject.toml") {
    Write-Host "[*] Installing from local repository directory..." -ForegroundColor Blue
    & $pythonCmd -m pip install -e .
} else {
    Write-Host "[*] Downloading CTF DevTools from GitHub to $installDir ..." -ForegroundColor Blue
    if (Get-Command git -ErrorAction SilentlyContinue) {
        if (Test-Path "$installDir\.git") {
            git -C $installDir pull --quiet
        } else {
            git clone --quiet https://github.com/BrianC0des/ctf-devtools.git $installDir
        }
        Set-Location $installDir
        & $pythonCmd -m pip install -e .
    } else {
        Write-Host "[*] Git not found, installing directly via pip..." -ForegroundColor Blue
        & $pythonCmd -m pip install "git+https://github.com/BrianC0des/ctf-devtools.git"
    }
}

# 3. Check Optional Tools
Write-Host ""
Write-Host "[*] Checking Recommended Companion Tools on Windows:" -ForegroundColor Cyan
$tools = @("curl", "php", "node")
foreach ($t in $tools) {
    $found = Get-Command $t -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "  • [✓] $t : $($found.Source)" -ForegroundColor Green
    } else {
        Write-Host "  • [○] $t : Not found in PATH (optional, used for local sandboxes)" -ForegroundColor Yellow
    }
}

# 4. Create Downloads Directory
$dlDir = Join-Path $env:USERPROFILE "CTF\ctf-dev-downloads"
if (-not (Test-Path $dlDir)) {
    New-Item -ItemType Directory -Path $dlDir -Force | Out-Null
}
Write-Host "  • [✓] Downloads Dir : $dlDir" -ForegroundColor Green

Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  🎉 CTF DevTools is Ready to Launch on Windows!" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Launch with:" -ForegroundColor White
Write-Host "  ctf-dev <TARGET_URL>   or   ctf-devtools <TARGET_URL>" -ForegroundColor Cyan
Write-Host ""
Write-Host "Example:" -ForegroundColor White
Write-Host "  ctf-dev http://challenge.picoctf.net:12345" -ForegroundColor Yellow
Write-Host ""
