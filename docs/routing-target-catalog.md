# Routing target catalogue

The operator panel's **Маршруты → Сканировать цели · открыть каталог** opens a
searchable, paginated list, not a probe of the entire Internet. Opening or
searching the catalogue does not initiate DNS lookups or TCP connections.

The initial seed contains 2,883 unique concrete domains/subdomains, pinned to
`hydraponique/roscomvpn-geosite` revision
`6b4fe3a4013eae99fea11caaddba160a8b0c0577`. Provenance and per-source checksums are
in `tools/assets/routing-catalog-seed.json`; the MIT licence is included beside
it. Regex, wildcard and include directives are not probe targets.

The panel merges the seed with concrete public targets from active rules,
draft rules, manually entered targets, accumulated scan findings and TXT imports.
Duplicate targets have one catalogue entry with multiple source labels. Private
addresses are excluded from the catalogue; existing routing policies are not
altered. Resolved public IPs appear after a real scan, not by scanning the seed.

## Operator workflow

1. Search by domain, subdomain or public IP; filter by type and page through 50
   targets at a time. An IP search also matches stored DNS addresses.
2. Select up to 24 concrete targets across pages. CIDR networks remain visible
   but cannot be scanned as if they were individual hosts.
3. Choose **Проверить выбранные**. The existing bounded scanner checks DNS and
   TCP/443 from the VDS. These measurements are not phone latency, VPN throughput
   or evidence of filtering. Unchecked targets show **Не измерено**.
4. Review reachable targets, choose their directions and explicitly confirm
   adding them to the draft. Publishing that draft is a separate guarded action.

Probe concurrency adapts to measured VDS load/RAM (1–8 workers, two concurrent
scan sessions, the existing time budget). Under excessive pressure, probes are
deferred while browsing/search remains available. Catalogue size is not reduced
when the server is busy.

TXT imports are additive, require an operator role, same-origin and session
CSRF, and do not create routing rules. Limits: 1 MiB text, 20,000 entries per
import and 100,000 stored targets. Failed imports are atomic. At capacity, optional
policy/scan catalogue synchronization returns a warning without losing scan
results or making existing catalogue pages unavailable.

## Data and deployment

The three `routing_target_catalog*` SQLite tables hold catalogue data only.
Catalogue imports/searches do not change signed routing revision, release state,
subscriptions or signing keys. Seed installation changes only seed membership;
imports and accumulated scan history survive updates.

`tools/deploy-aurora-panel.py --with-catalog` includes an exact allowlist of the
catalogue module, seed and licence. The source-only deployment uses pinned SSH
trust, expected previous hashes, a database/source backup and unchanged public
API/settings/signing checks. It restarts only the operator service, not VPN cores.

After deployment, `tools/verify-routing-catalog-vds.py --host <VDS>` checks
authenticated catalogue pages/search, access rejection, no-cache responses and
unchanged settings, both ABI APIs and Ed25519 identity. It uses the existing
administrator from the running service over pinned SSH, emits aggregate counts
only, and makes no POST requests or probe scans.

Deployment verification on 2026-10-07: panel `2.2.1-routing.1`, 2,894 known
unique targets (seed plus existing rules/history), 169 YouTube search matches,
50 targets per page with no overlap, public IP lookup successful, unauthenticated
access 401 and invalid filters 400. Public APIs, configuration and signing
identity were unchanged. A source/database backup was retained at
`/var/lib/quantumvpn-operator/aurora-source-backups/aurora-69ccfc95c20f4be6ace8054b188ec3e8`.

Local verification:

```powershell
python -m unittest tools.test_target_catalog tools.test_catalog_ui tools.test_routing_scan_dialog tools.test_deploy_aurora_panel
python -m unittest discover -s tools -p 'test_*.py'
```

For disposable browser QA, run `tools/preview-routing-catalog.py` with the existing
panel dependencies on `PYTHONPATH`. It binds only `127.0.0.1:8767`, uses temporary
storage and synthetic measurements; never interpret fixture latency as a real
network test. Stop the fixture after verification.
