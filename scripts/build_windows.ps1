$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

python -m pip install -e '.[packaging]'

$distRoot = Join-Path (Get-Location) 'dist'
$buildRoot = Join-Path (Get-Location) 'build'

python -m PyInstaller --noconfirm --clean --onefile --windowed --name MCP-Security-Guard-Desktop --paths src --collect-all PySide6 --distpath (Join-Path $distRoot 'desktop') --workpath (Join-Path $buildRoot 'desktop') src/mcp_security_guard/gui.py
if ($LASTEXITCODE -ne 0) { throw 'Desktop executable build failed.' }

python -m PyInstaller --noconfirm --clean --onefile --console --name mcp-security-guard-proxy --paths src --collect-all mcp --distpath (Join-Path $distRoot 'proxy') --workpath (Join-Path $buildRoot 'proxy') scripts/mcp_security_guard_proxy.py
if ($LASTEXITCODE -ne 0) { throw 'Proxy executable build failed.' }

Write-Host "Desktop app: $(Join-Path $distRoot 'desktop\MCP-Security-Guard-Desktop.exe')"
Write-Host "MCP proxy:   $(Join-Path $distRoot 'proxy\mcp-security-guard-proxy.exe')"
