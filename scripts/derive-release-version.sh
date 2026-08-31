#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ ! "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-beta\.([0-9]+))?$ ]]; then
    echo "Release tag must be vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-beta.N" >&2
    exit 1
fi

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"
beta="${BASH_REMATCH[5]:-}"
if (( major > 20 || minor > 999 || patch > 999 )); then
    echo "Release version is outside the deterministic versionCode range" >&2
    exit 1
fi

if [[ -n "$beta" ]]; then
    if (( beta < 1 || beta > 98 )); then
        echo "Beta number must be between 1 and 98" >&2
        exit 1
    fi
    slot="$beta"
    prerelease=true
    channel=beta
else
    slot=99
    prerelease=false
    channel=stable
fi

version_code=$((10#$major * 100000000 + 10#$minor * 100000 + 10#$patch * 100 + 10#$slot))
if (( version_code <= 0 || version_code > 2100000000 )); then
    echo "Derived Android versionCode is invalid: $version_code" >&2
    exit 1
fi

echo "ZAPRET_VERSION_NAME=${tag#v}"
echo "ZAPRET_VERSION_CODE=$version_code"
echo "ZAPRET_PRERELEASE=$prerelease"
echo "ZAPRET_RELEASE_CHANNEL=$channel"
