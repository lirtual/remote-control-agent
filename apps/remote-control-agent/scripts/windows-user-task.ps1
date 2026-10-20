# Windows native Remote Control user task; only interactive user logon.
# Does not create an elevated service, use a password or touch cloud grants.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Enable','Start','Stop','Disable','Status','Switch')][string]$Action,
  [string]$Endpoint, [string]$Entry, [string]$Node,
  [string]$Version, [ValidateSet('Upgrade','Rollback')][string]$Direction,
  [switch]$CIInjectFailure
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not $env:LOCALAPPDATA) {
  throw 'Native Windows user session required'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.IsSystem) { throw 'System identity rejected' }
$sid = $identity.User.Value
$name = 'RCA-Remote-Control-v2-' + $sid.Replace('-', '_')
$root = [IO.Path]::GetFullPath([IO.Path]::Combine(
  $env:LOCALAPPDATA,'mcp-workers','remote-control','programs'))
$task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
function Check-Program([string]$nodePath, [string]$entryPath) {
  if ($nodePath -match '[";]' -or $entryPath -match '[";]') { throw 'Invalid program path' }
  $n = [IO.Path]::GetFullPath($nodePath)
  $e = [IO.Path]::GetFullPath($entryPath)
  if (-not $n.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase) -or
      -not $e.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Only private versioned program directories are allowed'
  }
  $relNode = $n.Substring($root.Length + 1)
  $relEntry = $e.Substring($root.Length + 1)
  $version = ($relNode -split '\\')[0]
  if ($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?-windows-x64$' -or
      $relNode -notin @(($version + '\bin\node.exe'), ($version + '\bin\rca-background.exe')) -or
      $relEntry -ne ($version + '\apps\remote-control-agent\src\windows-v2.js')) {
    throw 'Untrusted Agent version or entrypoint'
  }
  foreach ($file in @($n,$e)) {
    $item = Get-Item -LiteralPath $file -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'Linked or missing program entry'
    }
  }
}
function Check-Existing {
  if (-not $task) { throw 'Agent task not installed' }
  # Task Scheduler may return the principal as a local account name,
  # DOMAIN\user, or SID. Resolve to the same immutable Windows SID rather
  # than weakening the owner boundary with string/name comparisons.
  try {
    $principalId = [string]$task.Principal.UserId
    if ($principalId -match '^S-1-[0-9]+(?:-[0-9]+)+$') {
      $taskUserSid = ([Security.Principal.SecurityIdentifier]::new($principalId)).Value
    } else {
      $account = [Security.Principal.NTAccount]::new($principalId)
      $taskUserSid = $account.Translate([Security.Principal.SecurityIdentifier]).Value
    }
  } catch {
    throw 'Task principal identity cannot be verified'
  }
  if ($taskUserSid -cne $sid -or
      [string]$task.Principal.RunLevel -ne 'Limited' -or
      [string]$task.Principal.LogonType -notin @('Interactive','InteractiveToken') -or
      $task.Actions.Count -ne 1 -or $task.Triggers.Count -ne 1) {
    throw 'Task identity, permissions or trigger changed'
  }
  $actionInfo = $task.Actions[0]
  $arguments = [string]$actionInfo.Arguments
  # Extract the one approved entry path and HTTPS endpoint; compare verbatim.
  if ($arguments -cnotmatch '^"([^"]+)" run --endpoint "(https://[A-Za-z0-9.-]+(?::[0-9]+)?/)"$') {
    throw 'Untrusted scheduled task arguments'
  }
  Check-Program ([string]$actionInfo.Execute) $Matches[1]
  if ([string]$task.Triggers[0].CimClass.CimClassName -notlike '*LogonTrigger') {
    throw 'Unexpected task trigger'
  }
}
if ($Action -eq 'Status') {
  if (-not $task) {
    '{"installed":false,"running":false,"autostart":"at-user-logon"}'
    exit 0
  }
  Check-Existing
  $running = ($task.State -eq 'Running')
  '{"installed":true,"running":' + $running.ToString().ToLowerInvariant() + ',"autostart":"at-user-logon"}'
  exit 0
}
if ($Action -eq 'Enable') {
  if ($task) { throw 'Cannot overwrite an existing scheduled task' }
  if (-not $Node -or -not $Entry -or -not $Endpoint) {
    throw 'Explicit native entrypoint and endpoint required'
  }
  if ($Endpoint -cnotmatch '^https://[A-Za-z0-9.-]+(?::[0-9]+)?/$') {
    throw 'Untrusted HTTPS endpoint'
  }
  Check-Program $Node $Entry
  # Use a reviewed no-window launcher; Windows Job Object owns child Node.
  $background = [IO.Path]::Combine([IO.Path]::GetDirectoryName($Node),'rca-background.exe')
  Check-Program $background $Entry
  $arguments = '"' + $Entry + '" run --endpoint "' + $Endpoint + '"'
  $scheduledAction = New-ScheduledTaskAction -Execute $background -Argument $arguments -WorkingDirectory ([IO.Path]::GetDirectoryName($Entry))
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
  $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $scheduledAction -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
  'enabled'
  exit 0
}

if ($Action -eq 'Switch') {
  # Transactional local program switch. Both versions are installed and
  # verified before touching the sole same-owner logon task.
  Check-Existing
  if ($Endpoint -or $Node -or $Entry -or
      $Version -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$' -or
      $Direction -notin @('Upgrade','Rollback')) { throw 'Untrusted switch arguments' }
  $oldAction = $task.Actions[0]
  $oldArguments = [string]$oldAction.Arguments
  if ($oldArguments -cnotmatch '^"([^"]+)" run --endpoint "(https://[A-Za-z0-9.-]+(?::[0-9]+)?/)"$') {
    throw 'Cannot preserve previous Worker origin'
  }
  $oldEntry = $Matches[1]
  $originalEndpoint = $Matches[2]
  $oldNode = [IO.Path]::GetFullPath([string]$oldAction.Execute)
  Check-Program $oldNode $oldEntry
  $oldRelative = $oldNode.Substring($root.Length + 1)
  $oldDir = ($oldRelative -split '\\')[0]
  $oldVersion = $oldDir.Substring(0, $oldDir.Length - '-windows-x64'.Length)
  $oldNumber = [version](($oldVersion.Substring(1) -split '-')[0])
  $newNumber = [version](($Version.Substring(1) -split '-')[0])
  if (($Direction -eq 'Upgrade' -and $newNumber -le $oldNumber) -or
      ($Direction -eq 'Rollback' -and $newNumber -ge $oldNumber)) {
    throw 'Invalid version upgrade/rollback direction'
  }
  $candidate = [IO.Path]::Combine($root,($Version + '-windows-x64'))
  $nextNode = [IO.Path]::Combine($candidate,'bin','node.exe')
  $nextBackground = [IO.Path]::Combine($candidate,'bin','rca-background.exe')
  # Legacy RC1/RC2 remains available for explicit rollback only.
  $nextActionExe = if (Test-Path -LiteralPath $nextBackground -PathType Leaf) { $nextBackground } else { $nextNode }
  if ($Direction -eq 'Upgrade' -and $nextActionExe -ne $nextBackground) { throw 'Background launcher required for new version' }
  $nextEntry = [IO.Path]::Combine($candidate,'apps','remote-control-agent','src','windows-v2.js')
  Check-Program $nextNode $nextEntry
  Check-Program $nextActionExe $nextEntry
  foreach ($folder in @($root, $candidate)) {
    $item = Get-Item -LiteralPath $folder -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'Untrusted version directory'
    }
    $acl = [IO.Directory]::GetAccessControl($folder)
    if (-not $acl.AreAccessRulesProtected -or
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) {
      throw 'Untrusted version owner'
    }
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
          @($sid,'S-1-5-18') -notcontains $rule.IdentityReference.Value) {
        throw 'Unexpected version ACL'
      }
    }
  }
  # No global PATH dependency; verify the exact newly installed package.
  $manifestPath = [IO.Path]::Combine($candidate,'bundle.json')
  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
  if ($manifest.version -cne $Version -or
      $manifest.upgrade_profile -cnotin @('read-only-no-shell-v1', 'paired-full-v1') -or
      ($Direction -eq 'Upgrade' -and $manifest.upgrade_profile -cne 'paired-full-v1')) {
    throw 'Unreviewed Windows package version or capability profile'
  }
  $validator = [IO.Path]::Combine($candidate,'apps','remote-control-agent','scripts','verify-windows-preview.mjs')
  & $nextNode $validator $candidate | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Candidate package manifest verification failed' }
  # New runtime status must pass using the original identity. No remote calls.
  & $nextNode $nextEntry status | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Candidate local identity validation failed' }
  $newArgs = '"' + $nextEntry + '" run --endpoint "' + $originalEndpoint + '"'
  $newAction = New-ScheduledTaskAction -Execute $nextActionExe -Argument $newArgs -WorkingDirectory ([IO.Path]::GetDirectoryName($nextEntry))
  $wasRunning = ($task.State -eq 'Running')
  $changed = $false
  try {
    if ($wasRunning) { Stop-ScheduledTask -TaskName $name -ErrorAction Stop }
    Set-ScheduledTask -TaskName $name -Action $newAction -ErrorAction Stop | Out-Null
    $changed = $true
    if ($CIInjectFailure) {
      if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Failure injection unavailable outside CI' }
      throw 'Isolated CI switch failure injection'
    }
    $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
    Check-Existing
    if (-not [string]::Equals([string]$task.Actions[0].Execute,$nextActionExe,[StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([string]$task.Actions[0].Arguments,$newArgs,[StringComparison]::Ordinal)) {
      throw 'Task switch was not persisted'
    }
    if ($wasRunning) {
      Start-ScheduledTask -TaskName $name -ErrorAction Stop
      Start-Sleep -Seconds 2
      $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
      if ($task.State -ne 'Running') { throw 'Updated Agent exited immediately' }
    }
    # This proves only local version switching, NOT signed WSS liveness.
    Write-Output ('switched-local-' + $Direction.ToLowerInvariant())
    exit 0
  } catch {
    $rollbackOkay = $false
    try {
      # Restore the saved original action without changing principal,
      # trigger, Worker endpoint, cloud grant or identity material.
      if ($changed) { Set-ScheduledTask -TaskName $name -Action $oldAction -ErrorAction Stop | Out-Null }
      $task = Get-ScheduledTask -TaskName $name -ErrorAction Stop
      Check-Existing
      if (-not [string]::Equals([string]$task.Actions[0].Execute,$oldNode,[StringComparison]::OrdinalIgnoreCase) -or
          -not [string]::Equals([string]$task.Actions[0].Arguments,$oldArguments,[StringComparison]::Ordinal)) {
        throw 'Previous task action not restored'
      }
      if ($wasRunning) { Start-ScheduledTask -TaskName $name -ErrorAction Stop }
      $rollbackOkay = $true
    } catch { $rollbackOkay = $false }
    if ($rollbackOkay) { throw 'Local version switch refused; previous task restored' }
    throw 'Local version switch failed and task restore is uncertain; manual check required'
  }
}

Check-Existing
switch ($Action) {
  Start   { Start-ScheduledTask -TaskName $name -ErrorAction Stop; 'start-requested' }
  Stop    { Stop-ScheduledTask -TaskName $name -ErrorAction Stop; 'stop-requested' }
  Disable {
    if ($task.State -eq 'Running') { Stop-ScheduledTask -TaskName $name -ErrorAction Stop }
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
    # Preserve protected private key, device ID and cloud grant.
    'disabled'
  }
}
