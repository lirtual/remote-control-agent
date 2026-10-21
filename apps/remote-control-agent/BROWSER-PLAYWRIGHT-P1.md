# Browser P1: direct Playwright inside existing Remote Control Agent

Status: **Draft source-only candidate; neither installed nor enabled.**

## P9 Windows owner-trusted Goal A scope (2026-10-21)

**Owner-approved risk scope, documentation only:** Native Windows, one owner-paired Agent, existing locally installed Chrome, and a *separate Agent-private Automation Profile*. The owner explicitly accepts residual access by untrusted web pages, redirects, DNS and WebSockets to host loopback/LAN resources. The actual native Windows 302-to-loopback hit (`attempted=1, blocked=0, localHits=1`; [CI #39520350950](https://github.com/lirtual/remote-control-agent/actions/runs/39520350950)) is **NOT SSRF ISOLATED**, but strict zero-egress containment is no longer the prerequisite for this accepted personal-device Goal A. The route/first-hop checks remain best-effort hygiene, not a security guarantee. Strict isolation remains Goal B, unpassed.

**Still not approved:** Network-risk acceptance is not an instruction to browse internal admin/metadata endpoints, access the owner's existing Chrome Profile, navigate arbitrary consequential URLs without per-action confirmed intent, expose click/fill/submit/JS/CDP, merge/release/upgrade an installed Agent, or turn on browser MCP tools. Preserve native release provenance/rollback, Portal + signed WSS, single-owner lifecycle, stable Operation IDs and unknown/no-replay SQLite semantics. Browser `start/status/snapshot/close` and controlled disposable test-page navigation are candidates for isolated acceptance only; unrestricted browser navigation and high-impact/ambiguous effects remain gated by a real, exact-operation, single-use user approval proof not currently implemented.

**P9 evidence reuse:** P3 demonstrated a real packaged Windows BrowserManager local launch + semantic snapshot and a *separate* real signed local Worker/DO/WSS `read_file`, not one browser tool traversing that entire chain. P5 proved direct local subresource blocking on Windows but real 302 isolation failure. Reuse without overstating either; no extra browser process, proxy, network firewall, DNS resolver, new approval service or second database is selected. First remaining proof is actual supported ChatGPT client confirmation with execution-boundary verification; then a separately authorized disposable signed browser MCP E2E. No production binary or device mutation in this documentation-only update.

Source of truth: [P9 architecture](https://github.com/lirtual/mcp-workers/blob/docs/browser-automation-grilling-20261020/docs/remote-control/BROWSER-ARCHITECTURE-REVIEW-20261020.md#p9-acceptance-reconciliation--trusted-windows-goal-a-2026-10-21) and [ADR-0030 amendment](https://github.com/lirtual/mcp-workers/blob/docs/browser-automation-grilling-20261020/docs/remote-control/adr/0030-browser-conservative-gating-consent-evidence-acceptance.md#p9--owner-approved-goal-a-risk-boundary-2026-10-21).

---


### Latest P3 release acceptance correction (2026-10-21)

**Windows-first P3 remains the selected scope.** The native Windows packaged nine-file Playwright candidate passed its independent CI/installer/upgrade/rollback tests in run #39459661346. Its production Agent entrypoint still does not instantiate BrowserManager and browser MCP tools remain disabled.

**Linux full installer acceptance is NOT complete.** Although the Node.js Release verifier accepted the optional Linux nine-file library archive, the independent Python bootstrap validator (bootstrap-v2.py, also used by validate-local-archive.py) still has its own strict directory/file allowlist. The actual optional Linux archive failed safely with ValueError: Unexpected archive directory. Therefore earlier claims that the optional Linux browser library archive was fully installer-verifiable or deployable are superseded; only the Node.js verification/extraction path passed. Neither the Python whitelist nor hashes were relaxed, and no Linux browser package was released.

The **standard browser-free Linux** Agent package again passed the real Python archive verifier after updating the Release builder static source contract for optional locally injected BrowserBackend. The revised guard still requires full paired capability, durable receipts, and explicit rejection of browser injection on read-only connections. Local v2-install/Release tests: 43/43 PASS. Windows-browser P3 can proceed independently; Linux/WSL Chromium provisioning and Python-validated vendor archive support are deferred. Do not introduce a third pinned dependency inventory merely to unblock Windows-first functionality.



The latest architectural decision is documented at https://github.com/lirtual/mcp-workers/blob/docs/browser-automation-grilling-20261020/docs/remote-control/BROWSER-ARCHITECTURE-REVIEW-20261020.md

## Single backend and code reuse

- candidates/browser-playwright.ts: the only actual candidate BrowserManager using official playwright-core@1.64.1. Independent Agent-private Profile; start/status, checked HTTP(S) navigation, bounded AI ARIA snapshot with snapshot_version, and close. Browser Ref interaction APIs have been independently validated on Windows/WSL but click/fill are **not** yet exposed by the five staged MCP tools.
- src/browser-backend.ts: small type-only contract. It is not a second runtime, selector, backend implementation or registry.
- src/browser-operations.ts, src/execution.ts, src/operations.ts, src/v2-connection-lifecycle.ts: selectively reuse existing authenticated WSS transport, SQLite receipts, non-replay and 150ms running acknowledgment.
- Previous agent-browser CLI and its per-platform EXE packaging are **not** part of this branch. No new Worker, session store, authorization server or CLI dispatcher.

## Existing release safety remains authoritative

The current reviewed Agent release builder rejects new external runtime imports by design. Therefore this Playwright candidate stays outside the production src import graph, while playwright-core is devDependency-only for typecheck/tests. The normal Agent startup still injects **no** browser backend and Worker Draft PR #143 still disables browser tools. Moving Playwright into the shipped Agent requires separate dependency, browser binary, provenance, licensing, Linux/Windows compatibility and upgrade/rollback acceptance. Do not relax the builder or silently enable tools.

## Proven versus pending

- P0: real paired Windows and WSL Playwright API acceptance, including AI snapshots, getByRef, iframe, stale Ref rejection and controlled TodoMVC (separate from this exact candidate class).
- P1: typecheck, mocked BrowserManager, actual existing Agent SQLite receipts and authenticated WSS tests, normal package dependency guard tests.
- Not yet proven: **this exact manager in an installed Agent**, real ChatGPT-to-Worker-to-Agent browser round trip, OS/process crash recovery, browser binary packaging, production enablement, macOS or verifiable exact one-use high-impact approval.
- Public URL shape checks do **not** ensure redirect, DNS or subresource safety. Navigation may have external effects; never equate browser action success with website business transaction completion.
- Any future Ref effect must bind device/session/tab and current snapshot_version, and reject stale/mismatched Ref. No arbitrary JavaScript/CDP or personal browser Profile.
- Historical hostile-execution network containment remains DEFERRED/UNPASSED; high-impact and ambiguous effects remain disabled.

Next: isolated real Chromium + signed WSS/receipts acceptance, then separate release packaging review and owner deployment approval. No merge or deployment authorized by this Draft.

## P2 isolated real-Chromium acceptance (2026-10-20)

Real paired WSL Agent device, pinned Node 24.21.0, `playwright-core@1.64.1`, disposable Chromium Headless Shell revision 1248 and private Profile/SQLite. No deployed browser tools, installed Agent upgrade, new Cloudflare namespace, external account or production state was used.

- **PASS — local post-auth WSS fixture:** Worker Draft #143's actual `parseBrowserCall` builds strict browser frames; existing Agent `monitorDeviceSocket` receives them on a *fixture representing the already authenticated socket*. Actual `PlaywrightBrowserManager` launches Chrome, SQLite admits browser_start and prevents duplicate start, browser_navigate first reports `running` then `completed`, disconnects and reconnects without replay, reads bounded AI Snapshot with `snapshot_version`, rejects arbitrary OS Shell arguments, and handles `revoke_cleanup` with `confirmed` and zero live browser session. This **does not verify cryptographic WSS pairing, a real deployed Worker DO or ChatGPT MCP tools/call**.
- **PASS — abrupt child termination:** a disposable, independently started Node test parent was sent `SIGKILL`. The single Chromium process tagged with the exact test Profile was absent afterward (0 survivors); this is evidence for this scenario only, not a general crash-recovery guarantee.
- **FAIL discovered, then fixed — concurrent revocation/navigation:** originally `stopOwnedForRevocation()` called `close()` while `navigate()` held the normal operation mutex, so revocation returned `uncertain` and the browser stayed active after navigation completed. The source-only fix adds an internal revocation latch and force-close of the *owned* Playwright `BrowserContext`, even while navigation is in progress. Startup and snapshot also reject a concurrent revoke, and no new browser can launch after revoke. No second scheduler, daemon or storage added.
- **PASS — fixed real-Chromium race:** during a deliberately blocked navigation, revocation interrupted page.goto and left zero active sessions. With the existing receipt engine used for the effect, the revocation status and durable navigation receipt are both `unknown`/`uncertain` rather than falsely claiming that an external website effect did not happen; the same Operation ID is not replayed. Two new automatic tests cover revoke-during-navigation and revoke-during-startup; all **10 browser-specific tests pass** locally.

**Still gated:** the test socket starts *after* authentication and the Worker tools remain disabled. Real signed WSS exchange + actual Worker/DO MCP routing, installed Agent package with audited Playwright and compatible browser binary, physical Windows Agent E2E, crash/restart/profile handling across all modes, hostile-network isolation and exact verified high-impact approval remain **UNPASSED**. Neither successful test fixtures nor Source Draft constitutes merge or deployment permission.

## P3 feasibility checkpoint — existing release format, not yet a candidate Release (2026-10-20)

**Status: compiled runtime smoke PASS, signed Release packaging/installation NOT PASSED.** This is a bounded selection gate, not permission to weaken production safeguards.

### Measured Linux x64 components and validated import layout

On the already-authorized disposable WSL Ubuntu test device with bundled Agent Node 24.21.0 and pinned `playwright-core@1.64.1`:

| Input | Observed footprint | Packaging implications |
| --- | --- | --- |
| Bundled Node 24 ELF | 126,595,440 bytes (~121 MiB); gzip level 1 ~49.7 MB | Existing, unchanged |
| Playwright core installed package | ~14 MiB; 115 regular files | Must be reviewed as actual runtime dependency, not a devDependency |
| Version-matched Chromium Headless Shell 156.0.8078.4 (revision 1248) | ~273 MiB; 289 regular files; main binary gzip level 1 ~95.1 MB | Includes license, ICU data, locales, resources and shared libraries; **do not silently strip** |
| Playwright FFmpeg cache | ~5.1 MiB | Separately identify whether any enabled feature actually needs it |
| Combined Node + core + headless shell (no tar overhead) | ~408 MiB | **Exceeds the existing 240 MiB Linux decompression bound** |

Actual package files have no symlinks; each provenance/license obligation still requires review. The Playwright package LICENSE and Chromium `LICENSE.headless_shell` are present in upstream artifacts. **Main executable gzip measurements do not establish complete archive size.**

**Full staging attempt / hard negative evidence:** A disposable directory containing compiled BrowserManager JS, all `playwright-core` files, the matching Chromium shell and actual bundled Agent Node totalled **425,166,669 bytes** in the test's `bin/` + `apps/` trees (408 regular files, before adding the production Agent's scripts). An attempted deterministic `tar --format=ustar` reported **two Playwright static asset paths as unrepresentable** and exited nonzero, even though their total paths were only ~101 and 110 bytes; the ustar prefix/name split matters, not just aggregate length. The resulting `gzip -1` file was 179,362,545 bytes but is **incomplete and NOT a valid package or acceptable compressed-size measurement**. Never treat this output as an accepted archive or merely switch to an unaudited tar format. The original Linux verifier's 80-entry whitelist and 240 MiB decompression limit remain independently blocking even if path layout is fixed.

**Candidate JS load proof:** The staged layout itself (not a tar) ran successfully under the existing Agent-bundled Node 24.21.0, loading `playwright-core@1.64.1` from an Agent-local `node_modules` directory and Chromium from Agent-owned `vendor`. Real TodoMVC navigation, AI Snapshot/version and context close all passed. Browser runtime selection and complete packaged-file authentication remain unverified.

The Playwright candidate was transpiled to ordinary `.js` and placed into a **disposable preview directory with the Agent's normal Node-compatible layout** (package under `apps/remote-control-agent/node_modules/playwright-core`, headless shell under an Agent-owned `vendor` directory). The compiled JS loaded the exact `playwright-core` version, started a real matching Chromium, navigated the controlled Playwright TodoMVC, returned a versioned AI ARIA Snapshot, and closed the context successfully. **PASS**. This did not install, update or replace the paired Agent.

### Verified release security constraints (NOT relaxed)

- The current Linux `verify-v2-release.mjs` limits **downloaded archive to 180 MiB**, **uncompressed tar to 240 MiB**, **archive entries to 80** and file/directory names to an explicit fixed whitelist. The runtime package plus browser alone contains **404 files**, before accounting for Node, Agent or directory entries.
- A synthetic tar with one unapproved `apps/remote-control-agent/vendor/` entry was correctly rejected by the **unchanged real `inspectTarGzip` validator**. PASS, fail-closed.
- Windows `verify-windows-preview.mjs` permits at most **41** hashed runtime files and its own strict path allowlist; the existing PR #15 Windows-only optional staging experiment does not override or prove production acceptance for the new BrowserManager.
- The current `build-v2-release.mjs` forbids new external `src` imports, and the reviewed `paired-full-v1` runtime constructor injects **no browser**. Those rules remain in place. Never simply increase the tar/file-count limits or bypass the external-import check.

### Minimal next design and acceptance gate

**Do not create a new browser Worker, installer, service, download proxy, package repository, second CLI or cache database.** Before editing the existing signed archive format, compare only two viable options against the owner's install simplicity requirements:

1. **Use an existing compatible local Chrome/Chromium** and distribute the audited Playwright library with the existing Agent. This is smaller and already works on the Windows PoC device, but a fresh Linux device may not have a compatible browser; no cross-platform seamless install claim is allowed.
2. **Ship a version-matched Chromium alongside Playwright in the existing signed Agent archive**. This better serves a one-command Linux setup, but requires an intentional new vetted manifest/file inventory, archive limits with a realistic memory-budget assessment, licensing/provenance, and install/rollback acceptance. Evaluate whether safely retaining the existing in-memory gzip/tar parser is appropriate; do not create a streaming archive parser without evidence it is required.

**Stop/go:** Choose only after (a) complete distribution bytes, file counts and memory impact are measured; (b) the verifier is reviewed for new allowlisted paths with exact content hashes; (c) no unreviewed runtime import is admitted; and (d) isolated Windows x64 / Linux x64 upgrade, rollback and real launch/cleanup tests pass. Only then consider Linux ARM64 and macOS evidence separately. Worker CI still intentionally uses a separate pinned public Agent fixture and must not be silently retargeted.

This checkpoint does **not** establish deployable browser-enabled Agent assets, installer/upgrade acceptance, real installed-device rollback, macOS parity, public browser tool activation, or a safe high-impact web automation policy.

## P3 installed-Chrome option: cross-platform selection experiment (2026-10-20)

**Status:** native Windows **PASS**, WSL/Linux **NO INSTALLED CHROME**; no release/archive format changes or production enablement.

To avoid custom executable scans, the one source-only `PlaywrightBrowserManager` now asks Playwright itself to launch `channel: "chrome"` **only when no trusted installer-owned `browserExecutable` was supplied**. The explicit absolute installer-controlled matching Chromium path still takes precedence. The Agent's established temporary private Profile, no arbitrary MCP binary input, no downloads, single runtime and no automatic fallback service remain unchanged.

| Device / executable | Observed result |
| --- | --- |
| Paired native Windows, Node 24.12.0, system Chrome 155.0.8059.85 | Actual BrowserManager (compiled from this candidate) started the system Chrome via official Playwright `channel:"chrome"`, navigated public TodoMVC, returned AI Snapshot/version and closed normally. **PASS**. |
| Same native Windows with Playwright-core v1.64.1, exact channel-only API | **PASS**, no custom browser path resolver, no additional EXE from us. |
| Paired Ubuntu WSL2, Agent-bundled Node 24.21.0, same Playwright-core 1.64.1 | **NO INSTALLED CHROME**: Playwright itself rejects `channel:"chrome"` (looks for `/opt/google/chrome/chrome`); no auto-install or alternate executable was requested. This **blocks library-only seamless WSL installation**. |
| Playwright library payload on Linux | 13,477,952 bytes, 115 regular files; by itself it still exceeds the signed Agent's current 80-entry archive maximum when combined with existing files. This is *not* a validated installable package. |

**Outcome:** Direct Playwright + existing Chrome is the simplest runtime on a device that already has a supported compatible Chrome. It is **not** an acceptable promise of zero-configuration browser support for Linux/WSL, macOS or systems with only Edge/other browsers. Chrome channel uses the host's installed version and may break compatibility after auto-updates; re-test before enabling. The existing signed Agent package/installer still needs a **separately reviewed dependency and manifest strategy**. Do not automatically add a second installer or download path. Consider whether a version-matched Chromium variant is truly necessary on platforms lacking a supported browser, and only then adjust the existing vetted release/install path under a distinct explicit approval gate.

**Checked:** TypeScript typecheck PASS, 12 browser-focused tests PASS; Windows actual manager/channel runtime PASS and clean close. The browser remains **source-only and inactive**, Worker `BROWSER_TOOLS_ACCEPTED = false`, production Node/browser installation unchanged, and no merge, release or deployment.

## P3 signed Linux library-only candidate — 9 pinned upstream files (2026-10-20)

**Latest result: unpublished Linux x64 Release candidate VALIDATED for library carriage and real Chromium launch, NOT a production/browser-enabled Agent.** This refines the earlier *full npm package* (~14 MiB/115 files) and *Chromium-in-archive* (~273 MiB/289 files) estimates. The broad upstream copy is **not** the selected library-only distribution.

### Reuse official prebuilt Playwright bundles without a new bundler

The pinned \`playwright-core@1.64.1\` npm package already ships \`lib/coreBundle.js\` and \`lib/utilsBundle.js\`. For the verified phase-one API scope, an isolated Windows Chrome 155 PoC ran with **eight official upstream files** (package.json, browsers.json, index.js, index.mjs, LICENSE, lib/bootstrap.js, lib/coreBundle.js, lib/utilsBundle.js). The Release candidate includes a ninth, \`lib/utilsBundle.js.LICENSE\`, preserving embedded dependency notices. **Every one** has a fixed SHA-256 pinned from the verified local 1.64.1 npm package; independent supply-chain review is still required in the existing Linux verifier; no standalone esbuild/ncc tool, full npm tree, native CLI or separate installer.

The **existing** Linux Release builder now accepts an explicit opt-in \`--browser-core-dir /absolute/verified/playwright-core\` and copies only those nine files. It checks source and intermediate path file *types* (rejects symlinks), exact per-file SHA-256 and package version before staging. Ordinary builds with no option retain the existing browser-free file inventory and behavior; the verifier source has changed, so byte-identical archives from old commits are **not** asserted. The existing \`verify-v2-release.mjs\` accepts those exact names **only with a complete \`bundle.json.browser_runtime\` manifest**, requires the nine files and three precise directories, and verifies fixed SHA-256 for every file *before* installation. The existing 180 MiB compressed, 240 MiB decompressed and 80-entry limits, tar path whitelist, immutable Release digest check and no-overwrite installer remain intact.

### Actual offline builds and verified installation staging

Using pinned Agent Node **24.21.0** and the original native session-supervisor built locally on paired WSL/Linux x64:

| Unpublished artifact | Compressed bytes | Checked tar entries | Real original verifier and isolated extraction |
| --- | ---: | ---: | --- |
| Standard browser-free Agent | **44,422,981** | 33 | PASS |
| Optional nine-file Playwright Agent | **45,713,662** | 45 | PASS |

Optional Playwright costs only **1,290,681 bytes** compressed and **12 entries** (9 pinned files plus 3 required directories); archive SHA-256, architecture, entry inventory, per-file digests and no-overwrite installation semantics passed. The **real Node binary extracted from that exact candidate archive**, together with the nine extracted Playwright files and an *externally staged, version-matched* Chromium Headless Shell revision 1248, completed controlled TodoMVC navigation, AI ARIA Snapshot, \`getByRef\` text input, iframe inspection and context close. This does **not** bundle Chromium and does not test a full browser-enabled production Agent.

**Negative tests:** existing old-format archives pass unchanged; extra vendor files without an opt-in are rejected; missing files, altered bytes and version mismatches are rejected before extraction; symlinked upstream inputs refused; an intentionally corrupted upstream bundle cannot create partial staging. A disposable HOME/no-TTY attempt using the candidate package's real installer was refused before device identity or systemd unit creation.

**Regression:** typecheck PASS; Release suite **8/8 PASS** (2 added vendor security tests); upgrade/rollback *mocked/local* suites **25 pass, 1 skip, 0 fail**. Full Agent suite: **261 tests, 257 pass, 3 skipped, 1 failed** — the already-known \`v2-connection-lifecycle.test.ts:744\` Shell/WSS \`unavailable\` vs \`completed\`, not a new Playwright failure. Do not describe full regression as green.

### Boundaries and next gates

- **Library packaging Linux x64:** verified only as an unpublished candidate; not merged or published. Agent startup still injects no browser. Worker browser tools remain **disabled**.
- **Actual Chrome on Windows:** source BrowserManager with \`channel:"chrome"\` passed real Windows tests, but these Linux-only builder changes do **not** make an installed Windows browser-enabled release. Windows file allowlist and signing remain separate acceptance gates.
- **Linux without Chrome:** the candidate contains **only** the Playwright library; compatible Chromium and its platform dependencies must still be supplied or otherwise approved within the existing install flow. No silent browser download, auto-install, new hosted service or external CLI is implied.
- **Support surface:** selected official bundle files passed phase-one start/navigate/semantic snapshot/ref/iframe scenarios on real browsers. Full Playwright (downloads, trace, browser inspection, future APIs) is **not** asserted supported by this small fixed-file inventory. Every upstream version change needs a fresh digest audit and real cross-platform tests.
- **Upgrade and rollback:** isolated staging and existing simulated rollback tests passed, but a real installed permanent Agent's promotion/upgrade/rollback with this candidate is **not accepted**; current \`paired-full-v1\` upgrade-profile restrictions must be reviewed, not bypassed.
- **No extra systems:** one Agent, one Playwright backend, existing signed archive and verifier, zero runtime configuration switches added. Preserve existing auth, receipts and explicitly confirmed high-impact behavior gates.

## P3 native Windows x64 preview: reuse the same nine-file Playwright payload (2026-10-21)

**Status: Windows x64 native CI acceptance PASS — [run #39459201600](https://github.com/lirtual/remote-control-agent/actions/runs/39459201600), with Ubuntu x64/ARM64 also PASS.** The existing Windows x64 preview builder now accepts an optional absolute Playwright core directory. It reuses Linux's SHA-256-verified nine-file staging routine; an ordinary five-argument Windows build is unchanged. On opt-in, the builder includes exactly nine Playwright 1.64.1 upstream files and records their hashes and an explicit browser_runtime inventory in the existing manifest. It never runs npm, downloads Chrome or adds another Agent.

The standalone Windows preview verifier still enforces the existing 41-file maximum, path constraints and file hash validation. In addition, it refuses Playwright contents without an explicit, complete browser_runtime manifest and verifies each vendored file against nine separately pinned SHA-256 values. A shared Linux test confirms that both independent Windows and Linux pinned file maps remain identical (release suite now 9/9 PASS locally). Empty/default preview files remain acceptable with no browser changes.

The native Windows CI now builds a second, unpublished v0.0.1-ci preview containing the nine files, compresses and re-extracts it, verifies the archive, and checks actual installed Chrome through the extracted Playwright API (semantic snapshot, Ref input, iframe). It tests corrupted vendor file and altered manifest rejection. Then it reuses the **existing offline ZIP installer and synthetic user-logon task tests** to upgrade from the original browser-free v0.0.0-ci preview to the browser-library v0.0.1-ci preview, verify the installed package hashes, inject a failed switch, roll back to v0.0.0-ci, and verify preserved identity. This is not a new installer or service.

**Observed CI result:** the reviewed Windows ZIP installer initially rejected the newly introduced core directories. The original installer ZIP allowlist now accepts precisely those three directories and the nine approved file paths; it still enforces its 70-entry, 100 MB downloaded ZIP, 150 MB expanded ZIP, symlink refusal, SHA-256 and no-overwrite limits. A second native Windows run completed actual offline base-to-Playwright upgrade and rollback with synthetic identity, forced post-switch failure recovery, preservation of the identity and library hashes, and uninstall cleanup. All CI jobs PASS. Earlier Linux job failures were a Windows-only smoke script accidentally discovered by Linux wildcard tests; the script was scoped explicitly to the Windows workflow instead of weakening platform assertions.

**Boundaries:** GitHub Actions Windows synthetic acceptance is not an actual upgrade on the owner's paired device. A verified file payload does not enable browsers in the production Agent: the BrowserManager is still candidate-only, existing startup injects no browser and Worker browser tools remain disabled. There is still no accepted one-command Chrome/Chromium install for WSL devices lacking browsers; Linux ARM64, real user-service promotion and public immutable Windows release publication remain separate gates. Keep all PRs Draft and do not deploy or merge without a later decision.

## P3 Phase-one host: native Windows Chrome, WSL development (2026-10-21)

**Decision:** Scope the first browser-enabled target to an approved native Windows Agent with compatible installed Chrome. The existing Worker already routes tools by an explicit device_id. WSL remains the independently paired Shell/filesystem development device; no automatic host selection, cross-OS browser bridge, extra Worker, new downloader, or separate Agent is required. Never include real device IDs or hostnames in public documents.

**Deferred, not a Windows-first blocker:** A WSL/Linux Agent with no Linux Chrome cannot use the Windows chrome.exe as a native Linux Playwright executable. Its Chromium provisioning, Linux installed browser Agent and macOS support require later platform-specific evidence. Do not enlarge the signed artifact or add a proxy solely to force WSL-first browser parity.

### Minimal locally trusted browser injection — still off in production

The existing maintainAuthenticatedDeviceSession() now accepts an optional locally constructed BrowserBackend and gives it to the existing long-lived Agent execution engine/SQLite receipt manager across authenticated WebSocket reconnects. Without the argument, browser operations remain unavailable; an explicit read-only Agent cannot accept browser injection. Neither real Agent startup entrypoint constructs a BrowserManager; there are no new user settings, network routes, authorization systems, databases or implicit browser launches.

An isolated synthetic device identity test verified real lifecycle behavior: default-denied browser_status, explicit injected browser_status, and rejection of injected browser capability on read-only connections. On ordinary Agent shutdown the engine now reuses its owned browser-context cancellation (the existing revocation cleanup path), so a pending navigation cannot strand an owned Chrome solely because normal close() is busy. This never kills an arbitrary Chrome instance or modifies a personal browser Profile.

**Evidence:** typecheck PASS; browser-specialized tests 13/13 PASS; scoped lifecycle injection 1/1 PASS; Release safety tests 9/9 PASS. A broader local lifecycle run had 27 passes and two Shell-related failures in existing non-browser test cases; do not label the full suite green or ascribe these failures to the new browser gate without isolating the baseline.

**Remaining before enabling:** separately reviewed source inclusion/injection in native Windows Agent startup, installed artifact + existing Chrome + signed WSS end-to-end with an isolated synthetic device, rollback/crash cleanup on installed binaries, and explicit high-impact one-use authorization. Current Windows and Linux production entrypoints, Worker Draft browser tool advertisement, production device identities and installed Agents remain unchanged. No merge, release or deployment.

## P3 Windows packaged startup injection — exact reviewed manager (2026-10-21)

**Scope:** An optional **unpublished Windows preview** can contain the actual PlaywrightBrowserManager compiled from the already-reviewed candidate alongside the existing nine pinned Playwright runtime files. A standard Windows Agent still has neither BrowserManager nor a browser-runtime manifest, and browser tools remain disabled in the Worker. No separate installer, browser download, configuration variable, device bridge, or external executable selector was introduced.

The existing Windows builder now includes exactly one extra compiled BrowserManager at the fixed Agent-local candidates/browser-playwright.js path **only with** the nine-file browser core payload, with an independently pinned SHA-256 digest. Both the existing Windows standalone manifest verifier and the existing Windows ZIP installer explicitly permit that single file/directory; the verifier requires the fixed Manager digest on optional browser bundles and refuses a manager without the browser manifest. All original Windows archive entry limits, path validation, signed ZIP digest requirements, local private identity checks and no-overwrite installer behavior remain.

The existing native Windows run entrypoint calls createPackagedBrowserForWindows() **only after** local identity/ACL verification. This helper returns no backend when an original/default Agent has no browser runtime in its local manifest. For an optional packaged browser preview, it reruns the existing complete local Windows artifact verifier before dynamically importing the one fixed Manager module and constructs it with the Agent-private store path. The same signed WSS lifecycle and SQLite receipts then receive this local BrowserBackend, with existing revocation and owned-context cleanup. A failed local verification refuses startup; it never falls back to a personal Chrome Profile or unpinned browser.

The existing Windows CI now tests the real Agent startup helper from both the standard and candidate extracted archives and starts Chrome through **the actual packaged BrowserManager**, checks AI Snapshot and clean context close, and confirms altered compiled Manager source is refused **before import**. Existing generic Playwright Ref and iframe tests and synthetic offline ZIP upgrade/rollback remain in the same workflow.

**Acceptance still required:** current native Windows CI result for this commit, real production-signed Worker-to-Agent browser operation, actual owner-approved paired-device installation and rollback, safe one-use high-impact authorization, and explicit enabling of Worker browser MCP tools. This Draft alone does not merge, publish, deploy, upgrade or activate a currently paired device.

## P3 Native Windows paired-host isolated browser/WSS dispatch validation (2026-10-21)

**PASS — actual authorized native Windows test host, without replacing its running paired Agent.** Source is the Draft `fd3b88e` snapshot, staged outside `LOCALAPPDATA/mcp-workers/remote-control` in a disposable Windows TEMP directory. `playwright-core@1.64.1` came from the exact nine upstream files verified by the existing SHA-256-pinned Linux staging helper. The test used native Windows Node **24.12.0**, an already-installed Chrome and a fresh isolated browser Profile/SQLite receipt directory.

The existing Agent `monitorDeviceSocket`, `executeV2SessionRead`, `executeV2FileOperation`, `createAgentExecutionEngine` and actual `PlaywrightBrowserManager` completed the following **native Windows** tests:

1. Reject remote-supplied browser executable overrides; start a real Chrome Profile through the existing WSS frame dispatcher.
2. Deduplicate `browser_start` by durable Operation ID; use the same Agent SQLite receipt state.
3. Navigate the controlled public Playwright TodoMVC URL and retrieve its real bounded AI Snapshot.
4. Reject a loopback navigation target (`127.0.0.1`) before its browser side effect and prevent repeat execution. The existing conservative effect receipt is **`unknown`**, not `bad_request`; that is intentional non-replay behavior rather than a successful navigation.
5. Simulate a WSS disconnect/reconnect with a **new local socket but the same execution engine**. Preserve the browser session and Operation ID receipt.
6. Complete ordinary browser close, then restart using a new Operation ID and stop the **Agent-owned** Chrome via the existing revocation cleanup path.
7. Verify that after revocation no Chrome session is opened by a new start attempt; its effect receipt is again conservatively `unknown`.
8. Compare the current installed Agent's identity file SHA-256 before/after: **unchanged**. Post-test host inspection: **zero test-tagged Chrome survivors**, and the existing Agent process/scheduled task still present.

**Crucial test boundary:** This used a **local synthetic authorized WSS socket**, not a real cryptographically authenticated `DeviceCoordinator` Durable Object WebSocket connection on Windows. Earlier isolated WSL P2 covered a real local Worker/DO + signed Ed25519 WSS + Chromium chain; that proof is separate and must not be merged into a claim of one fully deployed Windows end-to-end test. The current native Windows test ran TS source from a temporary directory, **not the installed candidate executable**. The ongoing production Agent was neither installed/updated nor given browser capabilities. No Worker browser tools were advertised, no production credential was copied, and no GitHub Release or Cloudflare Worker was deployed.

**Next acceptance gates:** actual verified candidate install into a disposable Windows Agent identity, real signed WSS/DO dispatch on that native candidate, process crash/restart and immutable artifact rollback, and user confirmation for consequential web actions. Preserve the Windows-first/no-WSL-Chromium-dependency scope. No extra services or browser proxy required.

## P3 Native Windows → real local Worker / SQLite DO / Ed25519 WSS (2026-10-21)

**PASS for the existing approved read-only MCP route and signed device transport.** A native Windows Node 24.12.0 test process imported unmodified Draft Agent TypeScript sources from a disposable Windows TEMP directory. The target was the actual lirtual/mcp-workers Remote Control Worker (Draft at 37254b9), running in local Wrangler 4.151.0 on WSL, using **real local SQLite Durable Object state** rather than an in-memory fake. Windows reached WSL directly at IPv4 loopback without a proxy, Tunnel or new component.

**Real protocol evidence:** Windows generated a fresh Ed25519 private key and a temporary-grant enrollment; the local test owner Portal approved this exact pending public key through pairing_lookup / pairing_approve. Windows recovered the new device ID through an actual Ed25519-signed challenge and opened a genuine network WSS using the rc-v2 protocol. An owner MCP read_file call passed through the Worker, its local Durable Object, signed WSS and the Windows Agent source to read only a disposable TEMP marker. A bad Portal bearer returned HTTP 401. After a clean disconnect, Windows **reconnected using the same temporary key and a new signed challenge**, repeated the MCP read successfully, revoked that device in the local DO and verified subsequent reads could no longer access the marker. All PASS.

**Safety and cleanup:** Production Worker source was not changed; browser tool advertisement remains disabled (BROWSER_TOOLS_ACCEPTED = false). The installed Windows Remote Control Agent process, scheduled task and private identity were not replaced; identity SHA-256 before/after matched. The local Portal bearer was a disposable test value, and the locally enrolled private key and temporary receipt files were cleaned after the test. The approved test device was revoked, and the local Wrangler session was stopped through the existing owned-session stop tool. No production credential, device identity, Cloudflare deployment, release or merge was involved.

**Limitations — do not claim browser signed E2E yet:** The real Worker did not advertise browser MCP operations. An attempt to alter even the disposable Worker source to enable browser tools was blocked by the tool safety check and was not circumvented. Earlier native Windows real-Chrome tests used a synthetic socket, and an earlier WSL isolated proof used a real local DO; neither constitutes a completed browser tool call over this signed Windows connection. The current Windows test executed disposable Agent TypeScript source under Node 24.12.0, **not an installed pinned Windows preview binary**. Actual candidate-package startup with synthetic local identity, signed browser route, crash/restart, rollback and high-impact one-use authorization remain separate unpassed gates.

**Architecture remains simple:** first browser target is approved native Windows with installed Chrome; use existing device_id routing, Portal authentication, real DO/WSS and Agent SQLite receipts; defer WSL Chromium provisioning and Python bootstrap work. All PRs remain Draft.

## P3 CI-built Windows x64 candidate — native Chrome, real signed DO/WSS and crash recovery (2026-10-21)

**PASS, unpublished portable candidate on actual paired Windows host; no modification to the installed Agent.** A manual-only Agent CI extension (`da17ad8`) exports the **one-day** `p3-windows-isolated-candidate` artifact only after the existing native Windows full-tools/offline install/upgrade/post-switch rollback/identity-preservation suite has passed. [Workflow #39516563886](https://github.com/lirtual/remote-control-agent/actions/runs/39516563886) passed Ubuntu x64, Ubuntu ARM64 and Windows x64. The CI fixture candidate was `v0.0.1-ci` and was **not** an immutable published Release. The downloaded CI artifact and transferred Windows ZIP had the same SHA-256 (`ade1894aa20cacdd6e0a5f3b56931f8d85615fb91544acc6583f531d642b9a34`). The separately extracted native Windows verifier validated the **32-file manifest**, the pinned `node.exe` 24.21.0 digest, all bundled Playwright 1.64.1 files and the fixed BrowserManager digest. It was executed exclusively from a fresh Windows TEMP directory, not from the installed `LOCALAPPDATA/mcp-workers/remote-control/programs` tree.

### Actual Windows host acceptance

The **extracted CI-bundled Node 24.21.0** and compiled Agent (not system Node/TypeScript) first loaded the independently verified BrowserManager and started the machine's existing compatible Chrome with a private test Profile. Public TodoMVC navigation, bounded AI Snapshot and normal browser close all passed. A separate, temporary LOCALAPPDATA value was then used for the same packaged Agent, and the existing Windows private-store PowerShell ACL helper sealed a freshly created **temporary-grant Ed25519 identity**. No existing production identity, file or scheduled task was opened for writing.

The unchanged Remote Control Worker was started in a separate WSL **local** Wrangler process backed by **real local SQLite Durable Object state**, with a test-only owner Portal bearer and browser MCP tool advertisement still set to **false**. Using the existing MCP pairing tools, the disposable key was owner-approved; the **actual packaged** Windows Agent established the real signed `rc-v2` WebSocket. MCP `read_file` was delivered through the real local Worker/DO/WSS to the packaged Windows Agent and returned only the isolated marker file. The owner tool list contained **no browser tools**, confirmed in the live test.

For a real recovery check, the test forcibly terminated **only the child process ID it had spawned for this disposable packaged Agent**; the device became unavailable over the signed route. The *same* Node binary and preserved temporary identity were then used to start a replacement process, obtain a fresh Ed25519 challenge/signature, reconnect and successfully repeat the marker-file MCP read. Finally the local test owner **revoked the temporary grant** and the packaged Agent exited normally. All checks PASS. The real owner's installed identity SHA-256 was unchanged and the existing Remote Control task count before/after remained unchanged.

**What this proves:** the same unpublished CI-built Windows candidate, on the real Windows host, separately passed real Chrome startup and real signed Worker/DO/WSS device execution, plus an abrupt test-owned Agent process stop/restart with identity-preserving recovery. This materially improves on previous source-only or CI-runner-only proofs.

**What is still not claimed:** The Worker browser MCP flag is unchanged and disabled; **no browser MCP mutation traversed the real Worker/DO/WSS**. The browser was invoked locally by the packaged BrowserManager before launching the signed Agent session. No signed release, production Agent installation/upgrade, real-task rollback, cross-origin browser authorization or explicit one-use high-impact confirmation was performed on the owner device. CI's separate synthetic user-task upgrade/rollback remains the verified rollback evidence. Linux/WSL Chromium provisioning and the optional Linux Python-bootstrap browser package remain deferred under Windows-first scope.

**Cleanup:** revoke the temporary device, stop and delete the temporary local Worker/SQLite DO, delete candidate ZIP and private test profiles/identity/receipts after acceptance, preserve the original installed Agent and task. All PRs remain Draft, and no publishing, merging or production tool enablement is approved.

## P5 Playwright Context request filter — no new proxy (2026-10-21)

**Source-only hardening; still disabled in Worker.** In the single existing Agent-local PlaywrightBrowserManager, a `browserContext.route("**/*", ...)` hook now installs **before new page creation** and rejects directly addressed IPs, localhost, local/intranet hostnames and non-HTTP(S) routes at the point Playwright sees an intercepted network request. Unlike the previous `navigate`-only check, this applies to directly intercepted **iframe and HTML subresource requests**, but **not browser-followed HTTP redirect hops**. Legitimate public HTTP(S) assets with long query strings remain eligible; the 2,048-character tool-input limit is unchanged.

**Tests:** Agent browser manager unit cases now 9/9 PASS, including blocked local and numeric-address request objects, redirected-hop equivalent cases, subresource examples, allowed public assets and route installation before a page is created; Agent TypeScript typecheck PASS. The native Windows CI binds a test-only HTTP server to **127.0.0.1**, verifies an HTML image subresource is blocked, and records the **real blocking limitation** discovered by an independently mocked HTTP 302. In CI #39520350950, the actual browser DID fetch the redirected localhost URL (`attempted=1, blocked=0, localHits=1`). Do **not** claim redirect isolation; further native CI tests only the directly intercepted subresource and explicitly labels redirect egress **NOT ACCEPTED**. The audited compiled Windows Manager digest changes to `fa332b50b9823a17fcc96f1c4f6673a86eb32ecf956076bc4522c2acaecccc52`; the builder still refuses unpinned compiled code and the independent Windows verifier requires the same exact digest.

**Official API basis:** Playwright's published [Network documentation](https://playwright.dev/docs/network) explicitly treats a request and its redirects as one routed unit, with the browser following 3xx redirects without invoking the route handler again. This overrides the initial stub-only redirect test assumption. Native CI #39519984152 and #39520350950 exposed that assumption, rather than an independent security success.

**Deliberate threat-model boundaries:** this is **defense in depth, not proof of SSRF isolation**. URL hostname syntax cannot fix public DNS names resolving to private IP addresses or DNS rebinding; the Chromium resolver may not match any Node lookup. Playwright `context.route` is not a firewall for browser WebSocket traffic, every non-HTTP channel, or network requests made before interception is installed during a persistent Profile's process startup. Likewise, browser navigation to an otherwise public URL may change website state. Do not claim internet/host network isolation or automatic user authorization from these tests.

**No overdesign:** no firewall rules, proxy, arbitrary remote browser selector, second Agent/service or additional Worker/DO schema. The first-stage browser target remains a personally approved Windows device with an existing Chrome and a private Agent-owned Profile. Only five typed operations are staged. No click/input/JS/download actions are part of this stage. Explicit user approval for consequential browsing, credible DNS/private-network egress scope, and a separate browser-MCP signed tool acceptance remain prerequisites for turning on `BROWSER_TOOLS_ACCEPTED`. The live Worker and installed Agents remain unchanged; all PRs stay Draft.

## P13 first-hop trailing-dot hostname guard (2026-10-21)

Source-only Draft correction: `localhost.`, `localhost..`, `printer.local.` and `service.internal..` previously avoided the URL hostname suffix filter. Both the Worker input parser and Agent-local browser initial/request-route checker now ignore trailing DNS root dots **when validating** the effective hostname, while leaving an ordinary public FQDN such as `example.com.` eligible. Native Windows BrowserManager compiled artifact SHA-256 after independent TypeScript transpilation: `cf7a7545378383d741a68a32bedc213af0ead4f79159bac747d3020f6236e1ec`. The independent Windows package verifier and builder must enforce the updated hash; the prior digest above remains historical evidence for its exact previous source. This is initial-target hygiene only, **NOT** DNS/redirect/subresource SSRF isolation. Browser MCP production gate remains disabled. No install, merge or production deployment.

## P13 isolated Windows 24-hour grant request (2026-10-21)

The native Windows CLI previously hard-coded permanent pairing. The new optional `pair --endpoint https://.../ --name P13-disposable --grant temporary` reuses the existing Ed25519 `newEnrollment` and Worker 24-hour temporary-device grant contract. Without the flag, normal permanent behavior is unchanged; no other command accepts the flag. Pairing still creates only a **pending** request, never approves a device, and neither this CLI option nor an MCP bearer token can prove owner consent. Approval must occur through a supported owner-authorized workflow, not through a synthetic test fixture or bypassed tool safety check. No production browser activation or real device pairing was performed during development.
