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
