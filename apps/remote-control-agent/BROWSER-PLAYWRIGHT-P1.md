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
