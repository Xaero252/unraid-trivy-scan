#!/bin/bash
# unraid-os.sh - prepare a local copy of an official Unraid OS root filesystem for tests/e2e.sh (OS scan), on the
# build host only. Downloads the release zip from Lime Tech's public release server (pinned version, URL and
# SHA-256 below), checks it, extracts bzroot (the root filesystem) and bzmodules (a squashfs that Unraid 7.x mounts
# on /usr, see rc.S: 'bzcheck "$BRANCH" "bzmodules" # /usr') into tests/.work/unraid-os/root, owned by the
# current user. Nothing is run from the extracted tree; it is only read by Trivy, read-only.
# Prints the root path on the last line. Needs about 4 GB free disk while extracting (zip removed afterwards).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
VER=7.3.4
URL=https://releases.unraid.net/dl/stable/7.3.4/ae8169459e2277e8d450b9a590c18f747dd8eaa50ebc54743a36cadd093cbfb8/unRAIDServer-7.3.4-x86_64.zip
SHA=ba608638e743b323f4581e911fd07093158344010dab14bb19607b46999530e9   # from https://releases.unraid.net/json
W=$HERE/tests/.work/unraid-os
ROOT=$W/root
if [ -f "$ROOT/.ready" ] && [ "$(cat "$ROOT/.ready")" = "$VER" ]; then echo "$ROOT"; exit 0; fi
mkdir -p "$W/dl"; cd "$W/dl"
ZIP=unRAIDServer-$VER-x86_64.zip
if ! [ -f bzroot ] || ! [ -f bzroot.sha256 ] || ! [ -f bzmodules ] || ! [ -f bzmodules.sha256 ] || ! [ -f bzimage ] || ! [ -f bzimage.sha256 ]; then
  [ -f "$ZIP" ] || curl -fsSL --retry 2 -o "$ZIP" "$URL"
  echo "$SHA  $ZIP" | sha256sum -c --quiet
  unzip -o -q "$ZIP" bzroot bzroot.sha256 bzmodules bzmodules.sha256 bzimage bzimage.sha256
fi
for f in bzroot bzmodules bzimage; do
  [ "$(sha256sum <"$f" | cut -d' ' -f1)" = "$(tr -d ' \n' <"$f.sha256")" ] || { echo "FATAL: $f does not match $f.sha256"; exit 1; }
done
# bzroot = an uncompressed early-microcode cpio, then the zstd- (older releases: xz-) compressed root cpio.
OFF=$(python3 -I -c '
import sys
b = open(sys.argv[1], "rb").read()
t = b.find(b"TRAILER!!!")
c = [i for i in (b.find(b"\x28\xb5\x2f\xfd", t), b.find(b"\xfd7zXZ\x00", t)) if i >= 0]
print(min(c) if t >= 0 and c else -1)' bzroot)
[ "$OFF" -gt 0 ] || { echo "FATAL: compressed root not found in bzroot"; exit 1; }
rm -rf "${ROOT:?}"; mkdir -p "$ROOT"
tail -c +"$((OFF + 1))" bzroot | { zstd -dcq 2>/dev/null || xz -dc; } \
  | (cd "$ROOT" && cpio -idm --no-absolute-filenames --quiet 2>/dev/null) || true   # device nodes fail as non-root
[ -f "$ROOT/etc/unraid-version" ] && [ -d "$ROOT/var/lib/pkgtools/packages" ] || { echo "FATAL: bzroot extraction incomplete"; exit 1; }
rm -rf "${ROOT:?}/usr"
unsquashfs -q -n -no-xattrs -d "$ROOT/usr" bzmodules >/dev/null
[ -d "$ROOT/usr/local/emhttp" ] || { echo "FATAL: bzmodules is not the /usr tree"; exit 1; }
# the kernel version as the running server would report it (uname -r), from the bzimage header
file -b bzimage | sed -n 's/.*version \([^ ]*\) .*/\1/p' >"$W/kernel"
rm -f "$ZIP"
echo "$VER" >"$ROOT/.ready"
echo "$ROOT"
