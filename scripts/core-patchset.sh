#!/usr/bin/env bash

# Sourced by core build scripts after core.properties. The upstream checkout stays
# pinned to CORE_COMMIT; the small application patch is verified, applied only for
# compilation, recorded in artifacts, and reversed on every exit path.

: "${CORE_PATCH_FILE:?Missing CORE_PATCH_FILE}"
: "${CORE_PATCH_SHA256:?Missing CORE_PATCH_SHA256}"

verify_core_patchset() {
    local project_root="$1"
    local patch_path="$project_root/$CORE_PATCH_FILE"
    [[ -f "$patch_path" ]] || {
        echo "Missing core patch: $patch_path" >&2
        return 1
    }
    printf '%s  %s\n' "$CORE_PATCH_SHA256" "$patch_path" | sha256sum -c - >/dev/null
}

apply_core_patchset() {
    local project_root="$1"
    local source_dir="$2"
    local patch_path="$project_root/$CORE_PATCH_FILE"
    verify_core_patchset "$project_root"
    git -C "$source_dir" apply --check "$patch_path"
    git -C "$source_dir" apply "$patch_path"
}

reverse_core_patchset() {
    local project_root="$1"
    local source_dir="$2"
    local patch_path="$project_root/$CORE_PATCH_FILE"
    git -C "$source_dir" apply --reverse --check "$patch_path"
    git -C "$source_dir" apply --reverse "$patch_path"
}
