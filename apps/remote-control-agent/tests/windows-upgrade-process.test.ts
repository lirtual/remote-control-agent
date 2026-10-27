import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { test } from "node:test";

/** #39: exercise a bounded, harmless WMI-launched child. Never change the
 * Agent Task or install a package on a GitHub Actions runner. */
test("native Windows same-owner WMI child outlives its launching shell and is outside inherited jobs",{
  skip: process.platform !== "win32",
  timeout: 25_000,
},()=>{
  const system = process.env.SystemRoot;
  assert.ok(system && /^[a-z]:[\\/]/i.test(system),"system Windows location required");
  const powershell=path.win32.join(system,"System32","WindowsPowerShell","v1.0","powershell.exe");
  const run = (script:string) => {
    const r = spawnSync(powershell,["-NoLogo","-NoProfile","-NonInteractive","-Command",script],{
      encoding:"utf8",timeout:12_000,windowsHide:true,
      maxBuffer:32*1024,
    });
    assert.equal(r.error,undefined,r.error?.message);
    assert.equal(r.status,0,"Windows PowerShell probe failed: "+r.stderr.slice(-800));
    return r.stdout.trim();
  };
  const start = Date.now();
  // Win32_Process.Create is a built-in Windows API, not a new service/task.
  // It does not inherit the caller's Job, unlike ordinary nested spawn().
  const launched=JSON.parse(run([
    "$p="+JSON.stringify(powershell),
    "$cmd='"'+$p+'" -NoLogo -NoProfile -NonInteractive -Command "Start-Sleep -Seconds 24"'",
    "$created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$cmd} -ErrorAction Stop",
    "if($created.ReturnValue -ne 0){throw 'Native one-shot launcher rejected'}",
    "@{pid=[int]$created.ProcessId} | ConvertTo-Json -Compress",
  ].join("; "))) as {pid:number};
  assert.ok(Number.isSafeInteger(launched.pid)&&launched.pid>0);
  try {
    // The launcher's PowerShell process has exited. Observe from another
    // process and independently verify SID + Job membership of its child.
    const observed=JSON.parse(run([
      "$pidToCheck="+launched.pid,
      "$proc=Get-CimInstance Win32_Process -Filter ('ProcessId='+$pidToCheck) -ErrorAction Stop",
      "if(-not $proc -or $proc.Name -ne 'powershell.exe'){throw 'WMI child absent after parent exit'}",
      "$localSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
      "$childSid=(Invoke-CimMethod -InputObject $proc -MethodName GetOwnerSid).Sid",
      "$source='using System;using System.Runtime.InteropServices; public static class RcaUpgradeJobCheck{[DllImport("kernel32.dll",SetLastError=true)]public static extern bool IsProcessInJob(IntPtr p,IntPtr job,out bool b);}'",
      "Add-Type -TypeDefinition $source -ErrorAction Stop",
      "$h=[Diagnostics.Process]::GetProcessById($pidToCheck)",
      "$inJob=$true",
      "$checked=[RcaUpgradeJobCheck]::IsProcessInJob($h.Handle,[IntPtr]::Zero,[ref]$inJob)",
      "@{sameOwner=($childSid -eq $localSid);inJob=$inJob;checked=$checked} | ConvertTo-Json -Compress",
    ].join("; "))) as {sameOwner:boolean;inJob:boolean;checked:boolean};
    assert.deepEqual(observed,{sameOwner:true,inJob:false,checked:true});
  } finally {
    // Kill only the exact fresh child, not a reused PID/unrelated process.
    run([
      "$target=Get-CimInstance Win32_Process -Filter ('ProcessId="+launched.pid+"') -ErrorAction SilentlyContinue",
      "if($target -and $target.Name -eq 'powershell.exe' -and "+
        "$target.CreationDate -ge (Get-Date '1970-01-01T00:00:00Z').AddMilliseconds("+start+").ToLocalTime() -and "+
        "(Invoke-CimMethod -InputObject $target -MethodName GetOwnerSid).Sid -eq "+
        "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value){Stop-Process -Id "+
        launched.pid+" -Force -ErrorAction Stop}",
      "'clean'",
    ].join("; "));
  }
});
