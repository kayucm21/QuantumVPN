# Quantum Control 2.1.2-network.1

Server-only update, 5 October 2026. No APK rebuild, version bump, GitHub
publication, release-date change or VPN-engine restart is included.

## Routing confirmation and target scanner

The prior confirmation page inherited `Referrer-Policy: no-referrer`, which
makes a browser's navigational POST send `Origin: null`. The main panel and
confirmation preview now explicitly use `same-origin` referrer policy.
Exact public HTTPS Origin, fetch metadata and session-bound CSRF remain checked;
missing/foreign Origin, wrong token and another session still fail closed.

Scanning opens a visible dialog with progress, target/domain/subdomain/IP,
public DNS addresses, measured TCP/443 delay, availability, the current policy's
recommendation, and qualified guidance about the existing Reserve TLS profile.
The editable input supports up to **24** targets, not Internet-wide discovery.
Three default targets are an editable example, not the complete Internet.

The operator can select multiple successful targets and choose their direction.
Confirmation merges only those validated targets into a draft. Live signed
routing changes require a separate preview and publication. Evidence expires
after ten minutes and is bound to actor/session, active revision, draft and
scan contents; replay, forged selections and changed bases are rejected.
Resolution and TCP work have time, response, thread and target bounds; mixed
private/public DNS fails closed and literal checked IPs prevent rebinding.

The actual browser smoke test used disposable local fixture data. It caught and
fixed a JavaScript form-property collision (`name=action` shadowed `form.action`).
Scan, checkbox selection and draft confirmation then passed. Production routes
were not changed merely to test the confirmation UI.

## Node stability and network alerts

Balancing uses only registered VPN nodes, never public DNS diagnostic probes.
It ranks a recent series using median TCP delay, spread and failed checks,
rejects stale evidence, and keeps a healthy current recommendation when the
score difference is small. Existing quarantine and drain policies remain
deterministic; this ranking does not rewrite subscriptions or reset tunnels.

The network guard detects repeated failures/timeouts and regressions against
a measured healthy baseline, deduplicates alerts, waits for repeated recovery,
and persists state outside release/routing settings. Explicit public diagnostic
targets are capped at three per four-minute worker pass; the interactive scanner
has its own independent 24-target limit. The worker never overwrites the UI scan.
Telegram alerts record the actual send result; no alerts are fabricated to test
production delivery. Missing DNS/TLS evidence remains missing.

The cause of degradation is **unconfirmed**. A generic failure cannot prove
TSPU interference; no unconditional blocking protection or guaranteed client
latency/throughput is claimed. VDS-local TCP checks are not Android VPN tests.
The current server already uses BBR with fq. Read-only inventory found successful
checks of its own endpoint, which cannot establish real YouTube client speed.

## Gemini and model tasks

Official Google Gemini **3.8 Flash** REST support is prepared, not downloaded
model weights. The independent open-weight Google family is Gemma, not Gemini.
Qwen3 0.6B remains active because this VDS has no Gemini API key configured.
Selecting Gemini without a key leaves the previous model unchanged.

The server reads `QV_GEMINI_API_KEY` (or standard Gemini environment variables).
The key is never stored in HTML, APK, model input or Git. Requests use a fixed
Google HTTPS endpoint, a header key, no redirects/tools, bounded input/output
and timeout, strict JSON validation, and a maximum of 120 attempts per UTC day.
This is a quota bound, not a guarantee of free usage or provider availability.

The model sees numeric aggregates and one-way node IDs, not raw endpoint
addresses, subscription links, logs or personal data. Instructions require
evidence-based availability/stability/load/backup analysis, explicitly unknown
causes, and a safe next step. Invented nodes or execution actions are rejected;
reserve recommendations must refer to algorithm-confirmed healthy nodes.
It cannot execute shell, change DNS, rotate ports or restart VPN. Configuration
changes continue through the existing human-reviewed CAS preview workflow.

## Verification

- **324** Python unit and real loopback HTTP tests passed, including control
  confirmation/security, scanner evidence/SSRF/deadlines, model privacy/errors,
  repeated network evidence/recovery and guarded deployment.
- Scanner JavaScript syntax passed; real local browser interaction passed.
- Independent code reviews found and fixed unknown-model reporting, unsafe
  malformed projection handling, and false reminders across monitoring gaps.
- Deployment uses pinned SSH trust, exact old/new source hashes, private source
  and SQLite backups and source-only rollback. It restarts only the operator.
- The scheduled APK release remains 5.11.3 at 6 October 2026 00:00 Moscow
  (`2026-10-05T21:00:00Z`). Both existing APKs and signatures remain unchanged.
- Live guarded deployment returned `applied`, build `2.1.2-network.1`, with
  configuration, public signed APIs and signing identity unchanged. Backup:
  `/var/lib/quantumvpn-operator/aurora-source-backups/aurora-9bb757531b15436daee61e0affc44aa5`.
- The worker's first live report had DNS coverage 3, TCP coverage 4, TLS coverage
  0, and correctly showed `insufficient_data` rather than inventing a diagnosis.
  The explicit registered node remained the recommendation. Bot polling was
  fresh, the existing menu authenticated, SQLite integrity was `ok`, and
  operator/RosPanel/nginx/Reserve TLS services stayed active. Routing revision
  remained 7, with the current game and both virtual wallets retained.
- Both production ABI APIs returned `5.11.2 / 501102099` with VDS URLs;
  current download HEADs were 200 and scheduled 5.11.3 HEADs 404. HTTPS login
  returned 200. No early APK publication occurred.

Live Gemini inference is **not verified** without the owner's valid API key.
Physical Android/network throughput and TSPU attribution are **not verified**.

Official references:
[Gemini models](https://ai.google.dev/gemini-api/docs/models),
[key security](https://ai.google.dev/gemini-api/docs/api-key),
[REST generation](https://ai.google.dev/api/generate-content),
[structured output](https://ai.google.dev/gemini-api/docs/structured-output),
[Fetch Origin](https://fetch.spec.whatwg.org/#append-a-request-origin-header).
