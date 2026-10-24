# Build and run a tiny, disposable Windows AppContainer networking experiment.
# It does not alter Windows firewall, WFP, the user's browser or the Agent.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP -or
    -not [Environment]::Is64BitOperatingSystem -or
    [Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
  throw 'Isolated GitHub Windows x64 CI only'
}
$vswhere = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Trusted MSVC tooling absent' }
$installation = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $installation) { throw 'MSVC native x64 compiler missing' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $vcvars)) { throw 'MSVC environment unavailable' }
$source = Join-Path $PSScriptRoot 'windows-appcontainer-loopback-probe.cpp'
# The AppContainer must traverse ancestor directories to load its image.
# GitHub RUNNER_TEMP lives under private D:\a\_temp ACLs. Put only this
# disposable fixture beneath ProgramData's traversable parent instead.
$folder = Join-Path $env:ProgramData ('rca-appcontainer-' + [guid]::NewGuid().ToString('N'))
$exe = Join-Path $folder 'rca-ci-loopback-probe.exe'
New-Item -ItemType Directory -Path $folder | Out-Null
try {
  $cmd = 'call "' + $vcvars + '" >nul && cl.exe /nologo /W4 /WX /O2 /MT /EHsc /std:c++17 /DUNICODE /D_UNICODE /Fo"' +
    (Join-Path $folder 'probe.obj') + '" /Fe"' + $exe + '" "' + $source +
    '" /link /SUBSYSTEM:CONSOLE userenv.lib ws2_32.lib advapi32.lib'
  & cmd.exe /d /s /c $cmd
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe)) {
    throw 'Windows AppContainer probe build failed'
  }
  # A disposable AppContainer may need read/execute ACL to start this
  # temporary fixture. Grant only its own directory and binary, never a
  # source repository, user profile, firewall, proxy or system directory.
  & icacls.exe $folder /grant '*S-1-15-2-1:(OI)(CI)RX' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot grant package read access to CI fixture' }
  & icacls.exe $exe /grant '*S-1-15-2-1:(RX)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Cannot grant package executable access' }
  & $exe
  if ($LASTEXITCODE -ne 0) { throw 'Native AppContainer loopback feasibility probe failed' }
} finally {
  Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
}
