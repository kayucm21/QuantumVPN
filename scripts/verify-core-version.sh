#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1090,SC1091
source "$PROJECT_ROOT/core.properties"
: "${CORE_TAG:?Missing CORE_TAG}"
: "${CORE_COMMIT:?Missing CORE_COMMIT}"
SING_BOX_CLI="${1:-$PROJECT_ROOT/core-build/output/sing-box}"

if [[ ! -x "$SING_BOX_CLI" ]]; then
    echo "sing-box CLI is not executable: $SING_BOX_CLI" >&2
    exit 1
fi

VERSION_OUTPUT="$("$SING_BOX_CLI" version)"
printf '%s\n' "$VERSION_OUTPUT"

VERSION_LINE="$(sed -n 's/^sing-box version //p' <<<"$VERSION_OUTPUT")"
REVISION_LINE="$(sed -n 's/^Revision: //p' <<<"$VERSION_OUTPUT")"
if [[ "$VERSION_LINE" != "${CORE_TAG#v}" ]]; then
    echo "Embedded core version mismatch: $VERSION_LINE" >&2
    exit 1
fi
if [[ "$REVISION_LINE" != "$CORE_COMMIT" ]]; then
    echo "Embedded core revision mismatch: $REVISION_LINE" >&2
    exit 1
fi

echo "Pinned core identity verified."
