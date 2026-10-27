#!/bin/bash
# run-tests.sh [--e2e] - all offline checks: lint, unit tests, render tests (local php -S + headless Chrome).
# --e2e also runs tests/e2e.sh against the local Docker (pulls small public images, removes what it added).
# The render screenshots in docs/screenshots/ are rewritten; with --e2e they are made from the e2e registry report.
set -uo pipefail
T=$(cd "$(dirname "$0")" && pwd)
rc=0
section() { echo; echo "== $*"; }
section lint;   "$T/lint.sh" || rc=1
section unit;   "$T/unit.sh" || rc=1
if [ "${1:-}" = --e2e ]; then
  section e2e;  E2E_KEEP=${E2E_KEEP:-0} "$T/e2e.sh" || rc=1
  section render; DEMO_REPORT=$T/.work/e2e/report-registry.json "$T/render/render-test.sh" || rc=1
else
  section render; "$T/render/render-test.sh" || rc=1
fi
echo; [ $rc -eq 0 ] && echo "ALL PASSED" || echo "FAILURES (see FAIL lines above)"
exit $rc
