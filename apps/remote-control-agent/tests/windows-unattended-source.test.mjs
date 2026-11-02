import assert from "node:assert/strict";
import {test} from "node:test";
import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";

const text=readFileSync(fileURLToPath(new URL("../../../install.ps1",import.meta.url)),"utf8");
test("unattended Windows opt-in is limited to a running, already-paired owner task",()=>{
  for(const part of [
    "RCA_UNATTENDED_UPGRADE -ceq 'owner-approved-task-v1'",
    "RCA_UNATTENDED_UPGRADE -ceq 'launch-approved-task-v1'",
    "New-ScheduledTaskPrincipal -UserId $me.Name -LogonType Interactive -RunLevel Limited",
    "New-ScheduledTask -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings",
    "Start-ScheduledTask -TaskName $name -ErrorAction Stop",
    "upgrade-result-",
    "upgrade-claim-",
    "[IO.FileMode]::CreateNew",
    "-not $alreadyPaired -or -not $task",
    "$task.State -ne 'Running'",
    ".owner-stopped",
    "-not $detachedUpgrade -and -not (Confirm-Upgrade",
    "Local switch returned; independent signed-WSS verification required.",
    "if ($detachedUpgrade -and $StageOnly)",
  ]) assert(text.includes(part),part);
});
