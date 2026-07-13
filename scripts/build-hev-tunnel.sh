#!/bin/bash
set -euo pipefail

HEV_VERSION="${HEV_VERSION:-2.15.0}"
NDK_HOME="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
JNI_BASE="${1:-app/src/main/jniLibs}"

if [[ -z "$NDK_HOME" || ! -d "$NDK_HOME" ]]; then
  echo "Android NDK not found. Set ANDROID_NDK_HOME or NDK_HOME."
  exit 1
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

git clone --depth 1 --branch "$HEV_VERSION" --recursive \
  https://github.com/heiher/hev-socks5-tunnel.git "$TMPDIR/hev-socks5-tunnel"

mkdir -p "$TMPDIR/jni"
ln -s "$TMPDIR/hev-socks5-tunnel" "$TMPDIR/jni/hev-socks5-tunnel"
echo 'include $(call all-subdir-makefiles)' > "$TMPDIR/jni/Android.mk"

"$NDK_HOME/ndk-build" \
  NDK_PROJECT_PATH="$TMPDIR" \
  APP_BUILD_SCRIPT="$TMPDIR/jni/Android.mk" \
  APP_ABI="armeabi-v7a arm64-v8a x86_64" \
  APP_PLATFORM=android-26 \
  NDK_LIBS_OUT="$TMPDIR/libs" \
  NDK_OUT="$TMPDIR/obj" \
  "APP_CFLAGS=-O3 -DPKGNAME=com/v2ray/ang/service" \
  -j"$(nproc)"

mkdir -p "$JNI_BASE/arm64-v8a" "$JNI_BASE/armeabi-v7a" "$JNI_BASE/x86_64"
cp "$TMPDIR/libs/arm64-v8a/libhev-socks5-tunnel.so" "$JNI_BASE/arm64-v8a/"
cp "$TMPDIR/libs/armeabi-v7a/libhev-socks5-tunnel.so" "$JNI_BASE/armeabi-v7a/"
cp "$TMPDIR/libs/x86_64/libhev-socks5-tunnel.so" "$JNI_BASE/x86_64/"
ls -la "$JNI_BASE"/*/
