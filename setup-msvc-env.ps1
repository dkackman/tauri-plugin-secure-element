# Setup Visual Studio Build Tools environment for ARM64
# Run this script before building: . .\setup-msvc-env.ps1

$vsPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\18\BuildTools"
$vcPath = "$vsPath\VC"

# Find MSVC version
$msvcVersion = Get-ChildItem "$vcPath\Tools\MSVC" -Directory | Select-Object -First 1 -ExpandProperty Name

if (-not $msvcVersion) {
    Write-Error "MSVC tools not found. Please install Visual Studio Build Tools with C++ support."
    exit 1
}

$msvcPath = "$vcPath\Tools\MSVC\$msvcVersion"

# Check for ARM64 linker
$arm64Linker = Get-ChildItem "$msvcPath\bin\Hostarm64\ARM64" -Filter "link.exe" -ErrorAction SilentlyContinue

if (-not $arm64Linker) {
    Write-Warning "ARM64 linker not found at: $msvcPath\bin\Hostarm64\ARM64\link.exe"
    Write-Warning "Please install 'MSVC v143 - VS 2026 C++ ARM64 build tools' component"
    Write-Warning "Opening Visual Studio Installer..."
    Start-Process "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe"
    exit 1
}

# Set up environment variables
$env:PATH = "$msvcPath\bin\Hostarm64\ARM64;$env:PATH"
$env:VCINSTALLDIR = "$vcPath\"
$env:INCLUDE = "$msvcPath\include;$env:INCLUDE"
$env:LIB = "$msvcPath\lib\ARM64;$env:LIB"

# Add Windows SDK paths if available
$sdkPath = "${env:ProgramFiles(x86)}\Windows Kits\10"
if (Test-Path $sdkPath) {
    $sdkVersion = Get-ChildItem "$sdkPath\Include" -Directory | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty Name
    if ($sdkVersion) {
        $env:INCLUDE = "$sdkPath\Include\$sdkVersion\ucrt;$sdkPath\Include\$sdkVersion\um;$sdkPath\Include\$sdkVersion\shared;$env:INCLUDE"
        $env:LIB = "$sdkPath\Lib\$sdkVersion\ucrt\arm64;$sdkPath\Lib\$sdkVersion\um\arm64;$env:LIB"
    }
}

Write-Host "Visual Studio Build Tools environment configured for ARM64" -ForegroundColor Green
Write-Host "MSVC Version: $msvcVersion" -ForegroundColor Green
Write-Host "Linker found at: $($arm64Linker.FullName)" -ForegroundColor Green

