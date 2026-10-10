#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SING_BOX_CLI="${1:-$PROJECT_ROOT/core-build/output/sing-box}"

if [[ ! -x "$SING_BOX_CLI" ]]; then
    echo "sing-box CLI is not executable: $SING_BOX_CLI" >&2
    exit 1
fi

mapfile -t FIXTURES < <(find "$PROJECT_ROOT/testdata" -type f -name '*.json' | sort)
if [[ "${#FIXTURES[@]}" -ne 7 ]]; then
    echo "Expected exactly 7 fixtures, found ${#FIXTURES[@]}" >&2
    exit 1
fi

mapfile -t MANIFEST_FIXTURES < <(
    awk -v root="$PROJECT_ROOT/testdata/" '{print root $2}' "$PROJECT_ROOT/testdata/SHA256SUMS" | sort
)
if [[ "${FIXTURES[*]}" != "${MANIFEST_FIXTURES[*]}" ]]; then
    echo "Fixture set differs from testdata/SHA256SUMS" >&2
    exit 1
fi

(
    cd "$PROJECT_ROOT/testdata"
    sha256sum -c SHA256SUMS
)

for fixture in "${FIXTURES[@]}"; do
    "$SING_BOX_CLI" check -c "$fixture"
    echo "OK ${fixture#"$PROJECT_ROOT/"}"
done

echo "Accepted fixtures: ${#FIXTURES[@]}/7"
