# RCA: owner-approved upgrades via Remote Control Shell

Status: source candidate, not yet officially released. This changes only
existing Windows/Linux upgrade entrypoints. Production release, existing
paired-device upgrades, and Mac support have independent gates.

## Contract

Remote Control run_command may initiate upgrades explicitly approved by the
owner, but a launched command is not an upgrade-completed receipt. Never
restart the Agent *inside its own managed Shell*. Run the switch from an
independent same-user operating-system task, then verify the new signed WSS
session after the old connection drops.

Only already-approved, permanent, owner-ON devices are eligible. Do not
re-pair, renew expired grants, bypass intentional STOP, clear receipts,
perform unreviewed downgrades, or add a persistent updater. Old Unknown
operations must not be replayed. Use the Worker-pinned immutable GitHub
Release and the existing installer freeze and rollback. Ordinary local
one-click installation and interactive upgrade remain unchanged.

## Linux x64/ARM64 (including WSL2)

After this path has been distributed by an official Release, use the installed
RCA CLI from Remote Control:

    rca upgrade --unattended

From an Agent Shell whose working directory is the verified installed
apps/remote-control-agent folder, use its packaged scripts/rca.sh entry if
rca is not on PATH. Never guess an unrelated binary or run a checkout.

The launcher checks the existing permanent full-tools service and owned
program files. It dispatches a bounded temporary systemd-run --user unit
in its own cgroup; the inner worker can bypass the normal TTY requirement
only with this explicit invocation and a verified invocation context.
It uses existing pin discovery, archive checks, local installer lock, active
operation freeze, service switch and rollback. No separate service remains.
Output status=launched is only an acknowledgement.

Inspect the observed unit through systemctl --user and journalctl --user,
then independently verify Agent version, unchanged device_id, authenticated
WSS and historical receipts via MCP. If the installed CLI is older than this
feature, do not remove its TTY restriction: bootstrap the new immutable
installer in a separate reviewed OS-owned process first.

## Windows x64

The official Worker-served PowerShell installer recognizes one deliberate
same-user environment flag:

    RCA_UNATTENDED_UPGRADE=owner-approved-task-v1

Only an existing paired, running, owner-ON Windows user-logon Task can use
this flag. Stage-only, initial install, owner-stopped, downgrade, foreign
Task and missing identity must fail closed. The regular public one-liner
without the flag continues to ask for explicit confirmation.

A Remote Control Shell intentionally sets the *launch* flag
RCA_UNATTENDED_UPGRADE=launch-approved-task-v1, and runs the official
Worker PowerShell bootstrap from https://rca.lirtual.dpdns.org/install.ps1
after checking HTTPS 200 and rejecting redirects. The Worker wrapper
verifies the source SHA. The reviewed installer then creates an isolated
one-time same-user Scheduled Task (Interactive logon, limited privileges,
no automatic trigger) in the existing protected program directory.

The separate Task runs the *same reviewed installer code* with the
execution-only flag owner-approved-task-v1, checks the immutable Release,
current Task and version, and uses the existing task switch/rollback.
Do not execute the installer switch inside the Agent's own Shell.

The detached Task writes a sanitized, owner-private, operation-specific
outcome (local-switch-returned or needs-attention). The remote initiator must
record the operation/task identifier, not infer completion from scheduling
success. After the new signed connection returns, independently compare
version, exact device ID, WSS availability and retained receipts, and
remove only the already-verified one-shot Task. A blocked Task Scheduler
or unknown local state is a hard stop, not grounds for SYSTEM execution.

## Boundaries

No MCP upgrade_agent tool, background auto-updater, new Worker, server,
database, credential flow or replacement for the existing one-click
scripts. Source and CI success are not production or physical-device E2E.
macOS remains gated by Spec #657.

## Windows first-hop boundary

A currently installed Agent that predates the private upgrade pipe cannot
be promoted by pretending its operations are quiescent. One independently
approved interactive local upgrade to a Release that includes this feature
is needed before future Remote Control-only upgrades can rely on the new
in-process freeze. Do not bypass the missing pipe, disable the safety guard,
or infer an idle state from task status or an operation listing.

The existing signed WSS/receipt and controlled local rollback are mandatory
postconditions, not established by the detached Task's created/succeeded status.
