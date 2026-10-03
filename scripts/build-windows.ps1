param([switch]$Test)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not $IsWindows) { throw 'Run this script in PowerShell 7 on Windows.' }
$sqlite = $env:TRIPWIRE_SQLITE_ROOT
if (-not $sqlite -or -not (Test-Path (Join-Path $sqlite 'include/sqlite3.h'))) {
    throw 'Set TRIPWIRE_SQLITE_ROOT to your vcpkg installed/x64-windows directory. See docs/PLATFORM_SUPPORT.md.'
}
$env:PATH = (Join-Path $sqlite 'bin') + ';' + $env:PATH
$flags = @('-Xcc', ('-I' + (Join-Path $sqlite 'include')), '-Xlinker', ('/LIBPATH:' + (Join-Path $sqlite 'lib')))
if ($Test) {
    & swift test @flags
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
& swift build -c release --product tripwire @flags
if ($LASTEXITCODE) { exit $LASTEXITCODE }
New-Item -ItemType Directory -Force dist/windows/desktop, dist/windows/resources | Out-Null
Copy-Item .build/release/tripwire.exe dist/windows/
Copy-Item (Join-Path $sqlite 'bin/sqlite3.dll') dist/windows/
Copy-Item desktop/tripwire_desktop.py, desktop/requirements.txt dist/windows/desktop/
Copy-Item Sources/TripWireApp/Resources/OverlayFrame*.png, assets/branding/AppIcon.png dist/windows/resources/
@'
param([string]$Database)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$options = @('desktop/tripwire_desktop.py', '--cli', './tripwire.exe')
if ($Database) { $options += @('--db', $Database) }
& python @options
exit $LASTEXITCODE
'@ | Set-Content dist/windows/start-desktop.ps1
Write-Output 'Built dist/windows. Swift runtime and Python/Qt are required; this is a developer bundle, not a signed installer.'
