# API contract: https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
# Ephemeral child supervisor only; never installed as a service or scheduled task.
param([ValidateSet('Run','Recover','Stop')][string]$Action = 'Run')
$ErrorActionPreference = 'Stop'
try {
  $x = [Console]::In.ReadToEnd() | ConvertFrom-Json
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class HandoffJob {
  [StructLayout(LayoutKind.Sequential)] struct IO { public ulong a,b,c,d,e,f; }
  [StructLayout(LayoutKind.Sequential)] struct Basic { public long a,b; public uint flags; public UIntPtr min,max; public uint count; public UIntPtr affinity; public uint priority,scheduling; }
  [StructLayout(LayoutKind.Sequential)] struct Extended { public Basic basic; public IO io; public UIntPtr a,b,c,d; }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup { public int size; public string reserved,desktop,title; public uint x,y,w,h,xc,yc,fill,flags; public short show,cb; public IntPtr extra,input,output,error; }
  [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup startup; public IntPtr attributes; }
  [StructLayout(LayoutKind.Sequential)] struct Info { public IntPtr process,thread; public uint pid,tid; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr a,string n);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j,int c,ref Extended e,uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string exe,StringBuilder cmd,IntPtr a,IntPtr b,bool inherit,uint flags,IntPtr env,string cwd,ref StartupEx s,out Info p);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,int flags,ref IntPtr size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr attribute,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
  [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
  [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr h);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h,uint ms);
  [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int n);
  static void Require(bool ok) { if(!ok) throw new InvalidOperationException("handoff_native_failure"); }
  public static void Run(string exe,string arguments,string cwd,Process owner,long expiresAt,Action<int,string> record) {
    IntPtr job=CreateJobObject(IntPtr.Zero,null); Require(job!=IntPtr.Zero);
    Info p=new Info(); IntPtr attributes=IntPtr.Zero, jobValue=IntPtr.Zero; bool initialized=false;
    try {
      Extended e=new Extended(); e.basic.flags=0x2000; // KILL_ON_JOB_CLOSE
      Require(SetInformationJobObject(job,9,ref e,(uint)Marshal.SizeOf(typeof(Extended))));
      IntPtr size=IntPtr.Zero;
      InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
      attributes=Marshal.AllocHGlobal(size); jobValue=Marshal.AllocHGlobal(IntPtr.Size);
      Require(InitializeProcThreadAttributeList(attributes,1,0,ref size)); initialized=true;
      Marshal.WriteIntPtr(jobValue,job);
      // Windows 10+ assigns the job atomically at process creation. There is no
      // orphan window between CreateProcess and AssignProcessToJobObject.
      Require(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x2000D),jobValue,new IntPtr(IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
      StartupEx s=new StartupEx(); s.startup.size=Marshal.SizeOf(typeof(StartupEx)); s.startup.flags=0x100;
      s.startup.input=GetStdHandle(-10); s.startup.output=GetStdHandle(-11); s.startup.error=GetStdHandle(-12); s.attributes=attributes;
      Require(CreateProcess(exe,new StringBuilder("\""+exe+"\" "+arguments),IntPtr.Zero,IntPtr.Zero,true,0x08080004,IntPtr.Zero,cwd,ref s,out p));
      var child=Process.GetProcessById((int)p.pid);
      record((int)p.pid,child.StartTime.ToUniversalTime().Ticks.ToString());
      Require(WaitForSingleObject(owner.Handle,0)==258);
      long remaining=expiresAt-DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
      Require(remaining>0 && remaining<=900000);
      var clock=Stopwatch.StartNew();
      Require(ResumeThread(p.thread)!=0xffffffff);
      while(clock.ElapsedMilliseconds<remaining && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()<expiresAt && WaitForSingleObject(owner.Handle,200)==258 && WaitForSingleObject(p.process,0)==258) {}
    } finally {
      if(initialized) DeleteProcThreadAttributeList(attributes);
      if(attributes!=IntPtr.Zero) Marshal.FreeHGlobal(attributes);
      if(jobValue!=IntPtr.Zero) Marshal.FreeHGlobal(jobValue);
      CloseHandle(job);
      if(p.process!=IntPtr.Zero) { Require(WaitForSingleObject(p.process,5000)==0); CloseHandle(p.process); }
      if(p.thread!=IntPtr.Zero) CloseHandle(p.thread);
    }
  }
}
'@
  function Find-Exact($id) {
    if (-not $id -or $id.pid -isnot [int] -or $id.pid -le 0 -or $id.started -notmatch '^\d{12,20}$' -or
        $id.executable -notmatch '^[A-Za-z]:\\') { throw 'Invalid process marker' }
    $p = Get-Process -Id ([int]$id.pid) -ErrorAction SilentlyContinue
    if ($null -eq $p) { return $null }
    $null = $p.Handle # Pin this kernel process before examining identity.
    if ($p.StartTime.ToUniversalTime().Ticks.ToString() -cne $id.started) { return $null } # PID reused: original process has exited
    if ($p.MainModule.FileName -ine $id.executable) { throw 'Process identity ambiguous' }
    return $p
  }
  if ($Action -ne 'Run') {
    if (-not [IO.File]::Exists($x.marker)) { 'confirmed'; exit 0 }
    $m = [IO.File]::ReadAllText($x.marker) | ConvertFrom-Json
    if ($m.version -ne 1 -or -not $m.owner -or -not $m.supervisor) { throw 'Invalid ownership marker' }
    $owner = Find-Exact $m.owner
    if ($owner -and ($Action -ne 'Stop' -or $owner.Id -ne $x.owner_pid -or $m.owner.started -cne $x.owner_started)) { throw 'Owner is still running' }
    $supervisor = Find-Exact $m.supervisor
    if ($supervisor) { $supervisor.Kill(); if (-not $supervisor.WaitForExit(5000)) { throw 'Supervisor still running' } }
    if (-not $m.child) { throw 'Child creation outcome unknown' }
    if ($m.child) {
      $child = Find-Exact $m.child
      if ($child -and -not $child.WaitForExit(5000)) { throw 'Owned job child still running' }
    }
    [IO.File]::Delete($x.marker)
    'confirmed'; exit 0
  }
  $owner = Get-Process -Id ([int]$x.owner_pid)
  $null = $owner.Handle # Retain the original kernel object; never follow a reused PID.
  if ($owner.HasExited -or $owner.StartTime.ToUniversalTime().Ticks.ToString() -cne $x.owner_started) { throw 'Owner exited or changed' }
  $self = Get-Process -Id $PID
  $m = @{version=1; owner=@{pid=$owner.Id; started=$owner.StartTime.ToUniversalTime().Ticks.ToString(); executable=$owner.MainModule.FileName};
    supervisor=@{pid=$PID; started=$self.StartTime.ToUniversalTime().Ticks.ToString(); executable=$self.MainModule.FileName}}
  function Save-Marker([bool]$exclusive) {
    $mode = if ($exclusive) { [IO.FileMode]::CreateNew } else { [IO.FileMode]::Create }
    $f = [IO.File]::Open($x.marker,$mode,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=[Text.Encoding]::UTF8.GetBytes(($m | ConvertTo-Json -Depth 4 -Compress)); $f.Write($bytes,0,$bytes.Length); $f.Flush($true) } finally { $f.Dispose() }
  }
  $intent = [IO.File]::ReadAllText($x.marker) | ConvertFrom-Json
  if ($intent.version -ne 1 -or $intent.owner.pid -ne $owner.Id -or $intent.owner.started -cne $x.owner_started -or $intent.supervisor) { throw 'Intent mismatch' }
  Save-Marker $false
  # Re-read the single protected deployment configuration, never arbitrary argv.
  $config = [IO.File]::ReadAllText([IO.Path]::Combine($x.config_directory,'browser-handoff-config.json')) | ConvertFrom-Json
  if ((($config.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'cloudflared_path,cloudflared_sha256,email' -or
      $config.email -cnotmatch '^[A-Za-z0-9.!#$%&''+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' -or $config.email.Length -gt 254 -or
      $config.cloudflared_path -notmatch '^[A-Za-z]:\\' -or $config.cloudflared_path.Contains('"') -or
      $config.cloudflared_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
      $x.port -lt 1 -or $x.port -gt 65535 -or $x.directory.Contains('"')) { throw 'Invalid deployment configuration' }
  if ($config.cloudflared_path -cne $x.config.cloudflared_path -or $config.email -cne $x.config.email -or
      $config.cloudflared_sha256 -cne $x.config.cloudflared_sha256) { throw 'Deployment configuration changed' }
  $x | Add-Member executable $config.cloudflared_path
  $x | Add-Member sha256 $config.cloudflared_sha256
  $empty = [IO.Path]::Combine($x.directory,'browser-handoff-tunnel.yml')
  if ([IO.File]::ReadAllText($empty) -cne "{}`n") { throw 'Invalid tunnel configuration' }
  $arguments = 'tunnel --config "'+$empty+'" --no-autoupdate --output json --url http://127.0.0.1:'+$x.port+' --allowed-mail '+$config.email
  $remaining = [long]$x.expires_at - [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  if ($remaining -le 0 -or $remaining -gt 900000) { throw 'Invalid deadline' }
  # SHA rechecked immediately before CreateProcess; deployment config is read-only.
  $binaryLock = [IO.File]::Open($x.executable,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  if ((Get-FileHash -LiteralPath $x.executable -Algorithm SHA256).Hash.ToLowerInvariant() -cne $x.sha256) { throw 'Executable changed' }
  [HandoffJob]::Run($x.executable,$arguments,$x.directory,$owner,[long]$x.expires_at,{
    param($childPid,$started)
    $m.child=@{pid=$childPid; started=$started; executable=$x.executable}
    Save-Marker $false
  })
  $binaryLock.Dispose()
  # Keep durable child identity until Node independently confirms cleanup.
  exit 0
} catch {
  # Never echo exception data (which can contain deployment secrets or command lines).
  [Console]::Error.WriteLine('{"level":"error","message":"handoff_supervisor_failed"}')
  exit 1
}
