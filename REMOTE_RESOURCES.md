# Signed presentation resources

APK 5.11.1 introduces a **data-only** resource format. It is not a hot-code loader.
Native Kotlin, permissions, dependencies, VPN protocols and engine fixes still
require a signed APK and Android's installation confirmation.

The operator's `resources` tab saves immutable drafts, previews their fields and
images, publishes to a stable device-hash test cohort (1–100%), promotes, and rolls
back. Resource publication never changes the APK version. An older revision is
rolled back with a *new publication sequence*. Stop-test also advances sequence.

Supported keys:

- `texts`: `brand_name` (32), `tagline` (100), `welcome` (120), `games_title` (40),
  `games_subtitle` (100 characters). Unknown/control-character values are rejected.
- `theme`: `accent` (`#RRGGBB`), `compact_home` (boolean; does not shrink navigation).
- `assets`: `logo` and `background`, each SHA-256, size, MIME, width, height. No URL.

Images: static JPEG/PNG, ≤2 MiB input, ≤16M input pixels. The server decodes,
clears metadata and re-encodes, reducing background to 1440px and logo to 256px.
SVG, ZIP, animation and executables are not accepted. Upload request ≤5 MiB;
JSON import ≤16 KiB. Importing referenced assets requires matching uploaded bytes.

`GET /api/client/resources?version_code=501101099` returns 204 when no compatible
publication exists, or an Ed25519 envelope. `kind=quantumvpn-resources-v1` is inside
the signed canonical payload for domain separation from routing. The APK pins the
existing panel public key, never a key advertised by the response. Signature,
SHA-256, schema, app compatibility, sequence and asset limits are checked before
application. Assets use same-origin hash paths, HTTPS, no redirects, bounded reads
and decode-bound verification. No server private key is copied into source/APK.

The client keeps current and previous verified envelopes in one AtomicFile journal,
with the highest accepted publication sequence. It publishes state only after all
assets and the journal are committed. Offline/failure keeps the last good version;
corrupt current cache can fall back to previous verified bytes. All network, file
hashing and image decoding run off the UI thread. Refresh is on foreground entry,
at most once per five minutes, or explicit Settings → Resources refresh. Cache
cleanup is restricted to the app's own hashed asset files and `.part` files.
Personal backgrounds, Android accessibility choice and dynamic colors take priority.

Source archives belong outside the web root, accessible only to the server owner.
They are for maintenance; they are never served or executed by the resource client.

Verification: Python module/HTTP/CSRF tests and Android JVM verifier tests. Device
cache/visual tests must be run separately; a local build is not a physical-device
pass. Deploy tool creates source + SQLite backups before applying changes; it does
not reset clients, subscriptions, keys, VPN settings or previous releases.
