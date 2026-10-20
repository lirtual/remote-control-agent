# Uninstall one verified, inactive Windows Agent runtime version only.
# Does NOT delete device identity, pairing grant, diagnostics or receipts.
# The caller must stop/disable a task using that version beforehand.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$')]
  [string]$Version
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    -not [Environment]::Is64BitOperatingSystem -or
    $env:LOCALAPPDATA -notmatch '^[A-Za-z]:[\\/]') {
  throw 'Native 64-bit Windows with a local user profile required'
}
$owner = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($owner.IsSystem) { throw 'SYSTEM is not an Agent owner' }
$sid = $owner.User.Value
$allowed = @($sid, 'S-1-5-18')
$programs = [IO.Path]::Combine($env:LOCALAPPDATA, 'mcp-workers', 'remote-control', 'programs')
$target = [IO.Path]::Combine($programs, "$Version-windows-x64")

function Assert-Private([string]$dir) {
  $entry = Get-Item -LiteralPath $dir -Force -ErrorAction Stop
  if (-not $entry.PSIsContainer -or
      ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Untrusted Agent directory'
  }
  $acl = [IO.Directory]::GetAccessControl($dir)
  if (-not $acl.AreAccessRulesProtected -or
      $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) {
    throw 'Untrusted Agent directory owner or inheritance'
  }
  $ownerFull = $false
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $allowed -notcontains $rule.IdentityReference.Value) {
      throw 'Unexpected Agent ACL grant'
    }
    if ($rule.IdentityReference.Value -eq $sid -and
        (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
        [Security.AccessControl.FileSystemRights]::FullControl)) { $ownerFull = $true }
  }
  if (-not $ownerFull) { throw 'Insufficient Agent directory permission' }
}

foreach ($dir in @(
  [IO.Path]::Combine($env:LOCALAPPDATA, 'mcp-workers'),
  [IO.Path]::Combine($env:LOCALAPPDATA, 'mcp-workers', 'remote-control'),
  $programs
)) { Assert-Private $dir }

if (-not (Test-Path -LiteralPath $target)) {
  Write-Output ('Version not installed; identity preserved: ' + $Version)
  exit 0
}
Assert-Private $target
# Do not allow removing an installed runtime out from under the Task Scheduler.
$name = 'RCA-Remote-Control-v2-' + $sid.Replace('-', '_')
$task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($task) {
  foreach ($action in $task.Actions) {
    $execute = [string]$action.Execute
    if ($execute.StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase)) {
      throw 'Disable the owned Windows task before uninstalling its runtime'
    }
  }
}
# Avoid unlinking a still-running runtime. A Get-Cim failure is uncertain, not safe.
$node = [IO.Path]::Combine($target, 'bin', 'node.exe')
foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction Stop)) {
  $executable = [string]$process.ExecutablePath
  if ($executable -and $executable.Equals($node, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Version still running; stop it before uninstall'
  }
}
# An unexpected link/alias or extra file must not turn recursive removal into
# an arbitrary deletion. Keep the explicit file inventory intact and verified.
foreach ($file in @(Get-ChildItem -LiteralPath $target -Recurse -Force -ErrorAction Stop)) {
  if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Untrusted installed Windows Agent link'
  }
}
$nodeSha = (Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash.ToLowerInvariant()
if ($nodeSha -cne 'ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32') {
  throw 'Untrusted native runtime executable'
}
$manifest = Get-Content -LiteralPath ([IO.Path]::Combine($target, 'bundle.json')) -Raw | ConvertFrom-Json
if ($manifest.version -cne $Version) { throw 'Installed version manifest mismatch' }
$verifier = [IO.Path]::Combine($target, 'apps', 'remote-control-agent',
  'scripts', 'verify-windows-preview.mjs')
& $node $verifier $target
if ($LASTEXITCODE -ne 0) { throw 'Untrusted native runtime files; no deletion attempted' }

# Only this verified, explicit version path is removed. Never remove the
# programs parent, identity PEM, device ID, diagnostics, SQLite or cloud grant.
[IO.Directory]::Delete($target, $true)
Write-Output ('Uninstalled native runtime version; identity preserved: ' + $Version)
