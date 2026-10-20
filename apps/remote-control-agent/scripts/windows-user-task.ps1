# Windows native Remote Control user task; only interactive user logon.
# Does not create an elevated service, use a password or touch cloud grants.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Enable','Start','Stop','Disable','Status')][string]$Action,
  [string]$Endpoint, [string]$Entry, [string]$Node
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
      $relNode -ne ($version + '\bin\node.exe') -or
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
  if ($task.Principal.UserId -notin @($sid,$identity.Name) -or
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
  $arguments = '"' + $Entry + '" run --endpoint "' + $Endpoint + '"'
  $scheduledAction = New-ScheduledTaskAction -Execute $Node -Argument $arguments -WorkingDirectory ([IO.Path]::GetDirectoryName($Entry))
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
  $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
  $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $name -Action $scheduledAction -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
  'enabled'
  exit 0
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
