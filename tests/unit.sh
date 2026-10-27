#!/bin/bash
# shellcheck disable=SC2015,SC2016  # "check && ok || bad" is intended (ok never fails); PHP snippets are single-quoted on purpose
# unit.sh - offline unit tests. A fake `docker` on PATH records calls, so no real container or image is touched.
# Covers: cron validation (bash and PHP agree on every case), the settings reader (bash and PHP) against hostile
# files, include/validate.php in update.php's scope, `apply` (cron only for a valid schedule), `uninstall` guards,
# the .plg lifecycle rules, and include/aggregate.php on fixture Trivy JSON (tests/aggregate-test.php).
set -uo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
P=$HERE/src/usr/local/emhttp/plugins/unraid-trivy-scan
S=$P/scripts/trivy-scan
W=$HERE/tests/.work/unit; rm -rf "$W"; mkdir -p "$W/bin"
fail=0; ok() { echo "ok   $*"; }; bad() { echo "FAIL $*"; fail=1; }

cat >"$W/bin/docker" <<EOF
#!/bin/sh
echo "docker \$*" >>"$W/docker.log"
case "\$1" in ps) exit 0 ;; info) exit 0 ;; esac
exit 0
EOF
chmod 755 "$W/bin/docker"
export PATH="$W/bin:$PATH"
cd "$W" || exit 1                       # globbing check: a "*" must never expand to file names here
touch "$W/aaa-glob-trap" "$W/zzz-glob-trap"

# ---------------------------------------------------------------- cron: bash and PHP must agree
php_valid() { php -r 'require $argv[1]; echo uts_valid($argv[2], $argv[3]) ? "1" : "0";' "$P/include/lib.php" "$1" "$2"; }
sh_valid()  { printf 'SCHEDULE="%s"\n' "$1" >"$W/c.cfg"; UTS_CFG=$W/c.cfg bash "$S" config | grep -q '^INVALID=' && echo 0 || echo 1; }
while IFS='|' read -r want expr; do
  [ -z "$expr$want" ] && continue
  a=$(sh_valid "$expr"); b=$(php_valid SCHEDULE "$expr")
  if [ "$a" = "$want" ] && [ "$b" = "$want" ]; then ok "cron '$expr' -> $want (bash and PHP)"; else bad "cron '$expr': want $want, bash $a, php $b"; fi
done <<'EOF'
1|
1|30 3 * * *
1|*/15 * * * *
1|0 0-23/2 1,15 1-12 0-7
1|59 23 31 12 7
1|00 03 * * 0
0|* * * *
0|* * * * * *
0|60 * * * *
0|* 24 * * *
0|* * 0 * *
0|* * * 13 *
0|* * * * 8
0|5-1 * * * *
0|*/0 * * * *
0|1,,2 * * * *
0|1, * * * *
0|@daily
0|30 3 * * mon
0|30  3 * * *
0|$(touch PWN) * * * *
0|* * * * *; touch PWN
0|`id` * * * *
EOF
[ ! -e "$W/PWN" ] && ok "no command substitution ran while reading schedules" || bad "a schedule executed a command"

# ---------------------------------------------------------------- settings reader against a hostile file
printf '%s\r\n' 'SCHEDULE="$(touch PWN2)"' 'SCOPE=all; touch PWN3' 'TIMEOUT="060"' 'NOTIFY="no"' 'PATH="/evil"' \
  'REGISTRY_CHECK=yes' 'JAVA_DB="maybe"' 'DASH_TILE="no" ' 'garbage line' '=x' 'SHOW_TAB="yes"' >"$W/h.cfg"
printf '%s\n' '* * * * * touch /PWN4' >>"$W/h.cfg"
OUT=$(UTS_CFG=$W/h.cfg bash "$S" config)
want='DASH_TILE=yes
JAVA_DB=yes
NOTIFY=no
REGISTRY_AUTH=no
REGISTRY_CHECK=yes
REMOVE_DATA=no
SCHEDULE=
SCOPE=running
SHOW_TAB=yes
TIMEOUT=60'
[ "$(grep -v '^INVALID=' <<<"$OUT")" = "$want" ] && ok "bash reader: valid keys taken, invalid -> defaults, unknown keys ignored, CRLF ok" \
  || bad "bash reader output: $(tr '\n' ' ' <<<"$OUT")"
inv_sh=$(sed -n 's/^INVALID=//p' <<<"$OUT" | tr ' ' '\n' | sort | tr '\n' ' ')
PHPOUT=$(php -r 'require $argv[1]; $c = uts_config($p, $argv[2]); ksort($c); foreach ($c as $k=>$v) echo "$k=$v\n"; $k = array_keys($p); sort($k); echo "INVALID=", implode(" ", $k), "\n";' "$P/include/lib.php" "$W/h.cfg")
[ "$(grep -v '^INVALID=' <<<"$PHPOUT")" = "$want" ] && ok "PHP reader gives the same settings" || bad "PHP reader: $(tr '\n' ' ' <<<"$PHPOUT")"
inv_php=$(sed -n 's/^INVALID=//p' <<<"$PHPOUT" | tr ' ' '\n' | sort | tr '\n' ' ')
[ "$inv_sh" = "$inv_php" ] && [ -n "$inv_sh" ] && ok "bash and PHP flag the same invalid keys: $inv_sh" || bad "invalid keys differ: bash '$inv_sh' php '$inv_php'"
[ ! -e "$W/PWN2" ] && [ ! -e "$W/PWN3" ] && [ ! -e /PWN4 ] && ok "hostile settings file executed nothing" || bad "hostile settings executed a command"
DEF_SH=$(sed -n 's/^declare -A DEF=(\(.*\)/\1/p;/^ *\[NOTIFY\]/p' "$S" | tr -d '()' | tr ' ' '\n' | grep '^\[' | sed 's/^\[\([A-Z_]*\)\]=/\1=/; s/"//g' | sort)
DEF_PHP=$(php -r 'require $argv[1]; $d = UTS_DEFAULTS; ksort($d); foreach ($d as $k=>$v) echo "$k=$v\n";' "$P/include/lib.php")
[ "$DEF_SH" = "$DEF_PHP" ] && ok "defaults identical in scripts/trivy-scan and include/lib.php" || bad "defaults differ: $(tr '\n' ' ' <<<"$DEF_SH") vs $(tr '\n' ' ' <<<"$DEF_PHP")"
[ "$(UTS_CFG=$W/none.cfg bash "$S" config)" = "$DEF_PHP" ] && [ "$(UTS_CFG=$W/none.cfg php -r 'require $argv[1]; $c=uts_config(); ksort($c); foreach ($c as $k=>$v) echo "$k=$v\n";' "$P/include/lib.php")" = "$DEF_PHP" ] \
  && ok "missing settings file -> defaults" || bad "missing settings file"

# ---------------------------------------------------------------- validate.php in update.php's scope
# vphp evaluates PHP array literals written in this file (test input only, never external data).
vphp() {   # vphp '<php array literal for $_POST>' '<php array literal for $keys>' -> save=<0|1> post=<json> keys=<json>
  php -r '$docroot="/nonexistent"; $_POST = eval("return ".$argv[2].";"); $keys = eval("return ".$argv[3].";"); $save = true;
          ob_start(); include $argv[1]; $msg = ob_get_clean();
          echo "save=", (int)$save, " post=", json_encode($_POST), " keys=", json_encode($keys), " msg=", trim($msg), "\n";' \
    "$P/include/validate.php" "$1" "$2"
}
R=$(vphp "['#file'=>'/x','SCHEDULE'=>' 30  3 * * 0 ','SCOPE'=>'all','TIMEOUT'=>'060','csrf_token'=>'t','EVIL'=>'1']" "['NOTIFY'=>'no','OLD'=>'x','SCOPE'=>'bad']")
grep -q 'save=1' <<<"$R" && grep -q '"SCHEDULE":"30 3 \* \* 0"' <<<"$R" && grep -q '"TIMEOUT":"60"' <<<"$R" \
  && ! grep -q 'csrf_token\|EVIL' <<<"$R" && grep -q 'keys={"NOTIFY":"no"}' <<<"$R" \
  && ok "validate.php: normalises, drops unknown keys and csrf_token, cleans the merged file keys" || bad "validate.php valid case: $R"
R=$(vphp "['SCHEDULE'=>'\$(reboot) * * * *','SCOPE'=>'all']" "[]")
grep -q 'save=0' <<<"$R" && grep -q 'NOT saved.*SCHEDULE' <<<"$R" && ok "validate.php: invalid schedule refuses the save" || bad "validate.php invalid: $R"
R=$(vphp "['SCHEDULE'=>\"30 3 * * *\n* * * * * touch /x\"]" "[]")
grep -q 'save=0' <<<"$R" && ok "validate.php: newline injection refused" || bad "validate.php newline: $R"
R=$(vphp "['SCOPE'=>['all'],'NOTIFY'=>'yes']" "[]")
grep -q 'save=0' <<<"$R" && ok "validate.php: array value refused" || bad "validate.php array: $R"
R=$(vphp "['SHOW_TAB'=>'yes\"','TIMEOUT'=>'4']" "[]")
grep -q 'save=0' <<<"$R" && grep -q 'SHOW_TAB, TIMEOUT' <<<"$R" && ok "validate.php: quote in value and out-of-range timeout refused" || bad "validate.php misc: $R"

# ---------------------------------------------------------------- apply: cron only for a valid schedule
export UTS_CRON_FILE=$W/cron/uts.cron UTS_UPDATE_CRON=$W/bin/update_cron
printf '#!/bin/sh\necho x >>%s/update_cron.log\n' "$W" >"$W/bin/update_cron"; chmod 755 "$W/bin/update_cron"
printf 'SCHEDULE="15 4 * * 1"\n' >"$W/a.cfg"
UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ "$(grep -v '^#' "$UTS_CRON_FILE")" = "15 4 * * 1 /usr/local/emhttp/plugins/unraid-trivy-scan/scripts/trivy-scan cron >/dev/null 2>&1" ] \
  && [ -s "$W/update_cron.log" ] && ok "apply: valid schedule -> cron file + update_cron" || bad "apply valid: $(cat "$UTS_CRON_FILE" 2>&1)"
printf 'SCHEDULE="15 4 * * 1\n* * * * * touch %s/PWN5"\n' "$W" >"$W/a.cfg"
UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ ! -e "$UTS_CRON_FILE" ] && ok "apply: invalid (multi-line) schedule -> no cron file" || bad "apply invalid wrote: $(cat "$UTS_CRON_FILE")"
printf 'SCHEDULE=""\n' >"$W/a.cfg"; UTS_CFG=$W/a.cfg bash "$S" apply >/dev/null
[ ! -e "$UTS_CRON_FILE" ] && ok "apply: empty schedule -> no cron file" || bad "apply empty"
grep -q 'docker run\|docker pull' "$W/docker.log" 2>/dev/null && bad "apply/config touched docker run/pull" || ok "apply and config never run or pull an image"

# ---------------------------------------------------------------- uninstall guards
: >"$W/docker.log"
mkdir -p "$W/d1/unraid-trivy-scan/cache" "$W/run"
printf 'REMOVE_DATA="yes"\n' >"$W/u.cfg"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d1/unraid-trivy-scan UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ ! -e "$W/d1/unraid-trivy-scan" ] && grep -q '^docker rmi aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c$' "$W/docker.log" \
  && ok "uninstall REMOVE_DATA=yes: data dir removed, docker rmi of the pinned reference only" || bad "uninstall yes: $(cat "$W/docker.log")"
mkdir -p "$W/d2/other"; UTS_CFG=$W/u.cfg UTS_DATA=$W/d2/other UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -d "$W/d2/other" ] && ok "uninstall: refuses a data path not ending in /unraid-trivy-scan" || bad "uninstall removed an unexpected path"
mkdir -p "$W/victim"; touch "$W/victim/keep"; mkdir -p "$W/d3"; ln -s "$W/victim" "$W/d3/unraid-trivy-scan"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d3/unraid-trivy-scan UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -e "$W/victim/keep" ] && ok "uninstall: a symlinked data dir is not followed" || bad "uninstall followed a symlink"
mkdir -p "$W/d4/unraid-trivy-scan"; : >"$W/docker.log"; printf 'REMOVE_DATA="no"\n' >"$W/u.cfg"
UTS_CFG=$W/u.cfg UTS_DATA=$W/d4/unraid-trivy-scan UTS_RUN=$W/run bash "$S" uninstall >/dev/null
[ -d "$W/d4/unraid-trivy-scan" ] && ! grep -q rmi "$W/docker.log" && ok "uninstall REMOVE_DATA=no keeps data and image" || bad "uninstall no"
grep -q 'docker rm -f\|docker ps -aq --filter label=unraid-trivy-scan=1' "$W/docker.log" && ok "uninstall stops only containers labelled unraid-trivy-scan=1" || bad "uninstall label filter: $(cat "$W/docker.log")"

# ---------------------------------------------------------------- .plg lifecycle
PLG=$HERE/unraid-trivy-scan.plg
INST=$(php -r '$d=new DOMDocument(); $d->substituteEntities=true; $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) { if ($f->getAttribute("Method")==="remove") continue; foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent, "\n"; }' "$PLG")
REM=$(php -r '$d=new DOMDocument(); $d->load($argv[1], LIBXML_NOENT); foreach ($d->getElementsByTagName("FILE") as $f) if ($f->getAttribute("Method")==="remove") foreach ($f->getElementsByTagName("INLINE") as $i) echo $i->textContent;' "$PLG")
grep -Eq 'trivy-scan (start|run|cron|update-db)|docker (pull|run)' <<<"$INST" && bad "install/boot block starts a scan or a download" || ok "install/boot blocks never scan or download"
grep -q 'trivy-scan stop' <<<"$INST" && grep -q 'trivy-scan apply' <<<"$INST" && ok "pre-install stops a running scan, post-install only applies cron" || bad "install block stop/apply"
grep -q 'trivy-scan uninstall' <<<"$REM" && ok "remove block runs uninstall (stop, cron, optional cleanup)" || bad "remove block"
grep -q 'case $f in \*/unraid-trivy-scan-2026[^)]*-x86_64-1.txz) ;;' <<<"$INST" && ok "old-package cleanup keeps the version being installed" || bad "package cleanup not version-preserving"
grep -q 'pluginURL="&pluginURL;"' "$PLG" && grep -q '<!ENTITY gitURL    "https://raw.githubusercontent.com/luuvasara/unraid-trivy-scan/main">' "$PLG" \
  && grep -q '<!ENTITY pluginURL "&gitURL;/&name;.plg">' "$PLG" && ok "pluginURL = .../luuvasara/unraid-trivy-scan/main/unraid-trivy-scan.plg" || bad "pluginURL"
VER=$(sed -n 's/^ *<!ENTITY version *"\([^"]*\)">.*/\1/p' "$PLG")
[[ $VER =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}[a-z]?$ ]] && ok "version $VER is YYYY.MM.DD[a-z]" || bad "version $VER"
MD5=$(sed -n 's/^ *<!ENTITY md5 *"\([^"]*\)">.*/\1/p' "$PLG"); PKG=$HERE/packages/unraid-trivy-scan-$VER-x86_64-1.txz
[ -f "$PKG" ] && [ "$(md5sum <"$PKG" | cut -d' ' -f1)" = "$MD5" ] && [ "$(cut -d' ' -f1 "$PKG.md5")" = "$MD5" ] \
  && ok "package and .md5 match the .plg &md5;" || bad "package md5 (run ./build.sh)"
cmp -s <(tar -xJOf "$PKG" ./usr/local/emhttp/plugins/unraid-trivy-scan/scripts/trivy-scan) "$S" && ok "package contains the current scripts/trivy-scan" || bad "package is stale (run ./build.sh)"
grep -c 'TRIVY_IMAGE=' "$S" | grep -qx 1 && ! grep -rq 'aquasec/trivy:' "$P" --include=*.php --include=*.page && ok "the Trivy image is named in exactly one place" || bad "Trivy image named in more than one place"

# ---------------------------------------------------------------- aggregate on fixture Trivy JSON
php "$HERE/tests/aggregate-test.php" "$HERE" || fail=1

exit $fail
