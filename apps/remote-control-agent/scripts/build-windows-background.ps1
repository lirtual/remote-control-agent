# Build a GUI-subsystem, windowless, job-supervised launcher using Windows SDK.
# Build only on pinned GitHub Windows runners; never compile on end-user devices.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Output)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitOperatingSystem -or
    [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw 'Native Windows x64 builder required'
}
$source = Join-Path $PSScriptRoot 'windows-background-launcher.c'
$vswhere = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Trusted Visual Studio toolchain absent' }
$installation = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $installation) { throw 'MSVC x64 compiler unavailable' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $vcvars)) { throw 'MSVC environment unavailable' }
$target = [IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($target)) | Out-Null
$cmd = 'call "' + $vcvars + '" >nul && cl.exe /nologo /W4 /WX /O2 /MT /DUNICODE /D_UNICODE /Fo"' +
  (Join-Path ([IO.Path]::GetDirectoryName($target)) 'rca-background.obj') +
  '" /Fe"' + $target + '" "' + $source + '" /link /SUBSYSTEM:WINDOWS shell32.lib'
& cmd.exe /d /s /c $cmd
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $target)) {
  throw 'Native windowless Agent launcher build failed'
}
Write-Output ('Built job-supervised GUI-subsystem launcher: ' + $target)
