#!/bin/bash
# action-test.sh - include/action.php behind a request prologue that behaves like Unraid's local_prepend.php
# (php auto_prepend_file): it validates csrf_token from $_POST, else from the X-CSRF-Token header, and then
# unset()s $_POST['csrf_token']. The 2026.10.27-2026.11.01 releases failed every button with "invalid csrf_token"
# because action.php re-checked only $_POST. Served by php -S on 127.0.0.1; the trivy-scan script is a stub.
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-trivy-scan
W=$HERE/tests/.work/action; rm -rf "$W"; mkdir -p "$W/root/plugins"
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }
TOKEN=0123456789ABCDEF
printf 'csrf_token="%s"\n' "$TOKEN" >"$W/var.ini"
printf '#!/bin/sh\necho "stub $1"\n' >"$W/script"; chmod 755 "$W/script"
ln -s "$P" "$W/root/plugins/unraid-trivy-scan"
cat >"$W/prepend.php" <<PHP
<?php
// Mirrors Unraid 7.3.4 /usr/local/emhttp/plugins/dynamix/include/local_prepend.php lines 17-51 (read on a server).
function csrf_terminate(\$reason) { echo "prologue: \$reason csrf_token"; exit; }
if ((\$_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
  \$var = parse_ini_file('$W/var.ini');
  \$t = \$_POST['csrf_token'] ?? (\$_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
  if (\$t === null) csrf_terminate("missing");
  if (!hash_equals(\$var['csrf_token'], \$t)) csrf_terminate("wrong");
  unset(\$_POST['csrf_token']);
  unset(\$_SERVER['HTTP_X_CSRF_TOKEN']);
}
PHP
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
UTS_VARINI=$W/var.ini UTS_SCRIPT=$W/script php -d auto_prepend_file="$W/prepend.php" -S 127.0.0.1:"$PORT" -t "$W/root" >"$W/server.log" 2>&1 &
SRV=$!; trap 'kill $SRV 2>/dev/null' EXIT
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
U=http://127.0.0.1:$PORT/plugins/unraid-trivy-scan/include/action.php
req() { curl -s -w ' %{http_code}' "$@" "$U"; }
for a in start stop update-db; do
  R=$(req -H "X-CSRF-Token: $TOKEN" --data "action=$a&csrf_token=$TOKEN")
  [ "$R" = "{\"ok\":true,\"message\":\"stub $a\"} 200" ] && ok "button '$a' (body + header token, as report.js sends): $R" || bad "button '$a': $R"
done
R=$(req -H "X-CSRF-Token: $TOKEN" --data "action=start")
[ "${R##* }" = 200 ] && ok "header-only token accepted" || bad "header-only token: $R"
R=$(req --data "action=start&csrf_token=$TOKEN")
[ "${R##* }" = 200 ] && ok "body-only token accepted (prologue checked it)" || bad "body-only token: $R"
R=$(req --data "action=start&csrf_token=WRONGWRONGWRONG0")
case "$R" in "prologue: wrong csrf_token"*) ok "wrong token stopped by the prologue";; *) bad "wrong token: $R";; esac
R=$(req --data "action=start")
case "$R" in "prologue: missing csrf_token"*) ok "missing token stopped by the prologue";; *) bad "missing token: $R";; esac
R=$(req -H "X-CSRF-Token: $TOKEN" --data "action=rm-rf")
[ "${R##* }" = 400 ] && ok "unknown action: 400" || bad "unknown action: $R"
grep -q "X-CSRF-Token" "$P/assets/report.js" && ok "report.js sends the X-CSRF-Token header" || bad "report.js does not send X-CSRF-Token"
# Browsers must fetch the new report.js after an update. build.sh pins every file mtime to the release day, so a
# filemtime() cache key stayed the same between two releases of one day and kept the old (broken) script cached.
if grep -n 'filemtime' "$P"/*.page; then bad "a page still derives its asset cache key from filemtime"; else ok "asset cache keys are content hashes, not mtimes"; fi
exit $fail
