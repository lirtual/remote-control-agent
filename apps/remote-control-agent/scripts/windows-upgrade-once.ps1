# Short-lived, same-owner Windows Task switch watchdog. This script must be
# launched only by the already-approved Agent receipt's independent WMI child.
# It does not create a service, scheduled task or new device identity.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$')][string]$OperationId,
  [Parameter(Mandatory=$true)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$')][string]$OriginalVersion,
  [Parameter(Mandatory=$true)][ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$')][string]$TargetVersion
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    -not [Environment]::Is64BitOperatingSystem -or -not $env:LOCALAPPDATA) {
  throw 'Native same-user Windows upgrade required'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.IsSystem) { throw 'SYSTEM cannot upgrade a paired user Task' }
$taskName = 'RCA-Remote-Control-v2-' + $identity.User.Value.Replace('-', '_')
$root = [IO.Path]::Combine($env:LOCALAPPDATA,'mcp-workers','remote-control')
$programs = [IO.Path]::Combine($root,'programs')
$old = [IO.Path]::Combine($programs,$OriginalVersion + '-windows-x64')
$target = [IO.Path]::Combine($programs,$TargetVersion + '-windows-x64')
$taskScript = [IO.Path]::Combine($old,'apps','remote-control-agent','scripts','windows-user-task.ps1')
$receiptDir = [IO.Path]::Combine($root,'receipts')
# This watchdog only runs against already staged immutable programs. StageOnly
# must have returned success in the original Agent BEFORE WMI launch.
$node = [IO.Path]::Combine($target,'bin','node.exe')
$verify = [IO.Path]::Combine($target,'apps','remote-control-agent','scripts','verify-windows-preview.mjs')
$entry = [IO.Path]::Combine($target,'apps','remote-control-agent','src','windows-v2.js')
foreach ($file in @($taskScript,$node,$verify,$entry)) {
  $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Linked or invalid verified native upgrade file'
  }
}
# Task validator checks immutable SID, user-only LogonType, trigger, action path,
# version ACL, all via the existing code. No owner-controlled arbitrary path.
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $taskScript -Action Status | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Original Task identity could not be verified' }
& $node $verify $target | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Target release inventory is not verified' }
$manifest = Get-Content -LiteralPath ([IO.Path]::Combine($target,'bundle.json')) -Raw | ConvertFrom-Json
if ($manifest.version -cne $TargetVersion -or $manifest.upgrade_protocol -cne 'owner-one-shot-v1') {
  throw 'Target does not provide reviewed remote-upgrade reconciliation'
}
# A proof file can only be produced by a NEW signed Agent WSS authentication
# after Task restart. The watchdog never trusts its own local Switch output
# as proof of success. The same-user Shell boundary is not an OS sandbox.
$proof = [IO.Path]::Combine($receiptDir,'upgrade-auth-' + $OperationId + '.json')
$outcome = [IO.Path]::Combine($receiptDir,'upgrade-outcome-' + $OperationId + '.json')
$switched = $false
$result = 'needs_attention'
function Write-Outcome([string]$status) {
  if ($status -notin @('completed','rolled_back','needs_attention')) { throw 'Unknown upgrade state' }
  $json = @{ operation_id = $OperationId; original_version = $OriginalVersion;
    target_version = $TargetVersion; status = $status } | ConvertTo-Json -Compress
  # Atomic create: never overwrite evidence from a previous invocation.
  $stream = [IO.File]::Open($outcome,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $stream.Write($bytes,0,$bytes.Length)
    $stream.Flush($true)
  } finally { $stream.Dispose() }
}
try {
  if (Test-Path -LiteralPath $outcome) { throw 'One-shot operation already has a terminal outcome' }
  if (Test-Path -LiteralPath $proof) { throw 'Unexpected preexisting reconnect proof' }
  & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $taskScript -Action Switch -Direction Upgrade -Version $TargetVersion | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Task switch did not succeed' }
  $switched = $true
  for ($index=0; $index -lt 90; $index++) {
    if (Test-Path -LiteralPath $proof -PathType Leaf) {
      try {
        $claim = Get-Content -LiteralPath $proof -Raw | ConvertFrom-Json
        if ($claim.operation_id -ceq $OperationId -and
            $claim.target_version -ceq $TargetVersion -and
            $claim.status -ceq 'authenticated_wss') {
          & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $taskScript -Action Status | Out-Null
          if ($LASTEXITCODE -eq 0) {
            $result = 'completed'
            break
          }
        }
      } catch { # Invalid proof cannot authorize success; remain bounded. }
    }
    Start-Sleep -Seconds 1
  }
  if ($result -cne 'completed') { throw 'New Agent authenticated reconnect not verified' }
} catch {
  if ($switched) {
    try {
      & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $taskScript -Action Switch -Direction Rollback -Version $OriginalVersion | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'Rollback rejected' }
      $result = 'rolled_back'
    } catch { $result = 'needs_attention' }
  } else {
    # The native Switch handles its own failure rollback. Do not claim a clean
    # rollback without observing the original task identity and action.
    $result = 'needs_attention'
  }
} finally {
  try { Write-Outcome $result } catch { throw 'Cannot persist upgrade outcome; manual reconciliation required' }
}
if ($result -cne 'completed') { throw 'Remote Agent upgrade unconfirmed; inspect guarded receipt' }
