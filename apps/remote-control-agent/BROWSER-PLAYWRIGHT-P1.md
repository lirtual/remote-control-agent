# Browser P1: direct Playwright inside existing Remote Control Agent

Status: **Draft source-only candidate; neither installed nor enabled.**

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
