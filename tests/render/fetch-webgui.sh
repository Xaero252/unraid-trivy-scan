#!/bin/bash
# fetch-webgui.sh - download Unraid's webGui stylesheets and fonts (github.com/unraid/webgui, pinned commit) into
# tests/.work/webgui for the render harness. They are not part of this repository.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/../.." && pwd)
COMMIT=a91a4618a9de3284f6e057b21006f2cfd8468f4e   # unraid/webgui master on 2026-10-25
SRC=https://raw.githubusercontent.com/unraid/webgui/$COMMIT/emhttp/plugins/dynamix/styles
D=$HERE/tests/.work/webgui/webGui/styles
[ -f "$D/.commit" ] && [ "$(cat "$D/.commit")" = "$COMMIT" ] && exit 0
rm -rf "$D"; mkdir -p "$D/themes"
for f in default-fonts.css default-cases.css font-awesome.css default-color-palette.css default-base.css default-dynamix.css \
         themes/black.css themes/white.css themes/gray.css themes/azure.css \
         clear-sans.woff clear-sans-bold.woff clear-sans-italic.woff clear-sans-bold-italic.woff \
         bitstream.woff bitstream-bold.woff font-awesome.woff font-cases.woff font-unraid.woff; do
  curl -fsS --retry 2 -o "$D/$f" "$SRC/$f"
done
echo "$COMMIT" >"$D/.commit"
echo "webGui styles at $D"
