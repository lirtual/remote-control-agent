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
