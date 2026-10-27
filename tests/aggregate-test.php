<?php
/* tests/aggregate-test.php <repo>: include/aggregate.php against tests/fixtures/basic (hand-written Trivy JSON,
 * schema 2). Prints "ok"/"FAIL" lines; exit 1 on any failure. Work files go to tests/.work/agg. */
$repo = $argv[1];
$agg = "$repo/src/usr/local/emhttp/plugins/unraid-trivy-scan/include/aggregate.php";
$w = "$repo/tests/.work/agg"; @mkdir($w, 0755, true);
$out = "$w/report.json"; @unlink($out);
$fail = 0;
function t(bool $c, string $m) { global $fail; echo ($c ? "ok   " : "FAIL ") . "aggregate: $m\n"; if (!$c) $fail = 1; }
function run(string $agg, string $work, string $out): string {
  return (string)shell_exec('php ' . escapeshellarg($agg) . ' ' . escapeshellarg($work) . ' ' . escapeshellarg($out)
    . ' scope=all registry=yes trivy=0.76.1@sha256:x 2>&1');
}
$o1 = run($agg, "$repo/tests/fixtures/basic", $out);
$r = json_decode((string)@file_get_contents($out), true);
t(is_array($r), "report.json written and valid JSON");
$c = []; foreach ($r['cves'] ?? [] as $x) $c[$x['id']] = $x;
t(count($c) === 5, "5 distinct CVEs (malformed entries dropped): " . implode(',', array_keys($c)));
t(($r['summary']['invalid_entries'] ?? -1) === 2, "2 malformed vulnerability entries counted");
t(($c['CVE-2024-0001']['severity'] ?? '') === 'CRITICAL', "CVE rated CRITICAL and HIGH by two images takes the highest");
t(($r['summary']['by_severity']['CRITICAL']['total'] ?? 0) === 1 && ($r['summary']['by_severity']['HIGH']['total'] ?? 0) === 1,
  "each CVE counted once, at its highest severity (CRITICAL=1, HIGH=1)");
t(count($c['CVE-2024-0001']['affected'] ?? []) === 2 && ($c['CVE-2024-0001']['image_count'] ?? 0) === 2, "duplicate row removed, 2 images affected");
t(($c['CVE-2024-0001']['fix'] ?? '') === 'package', "fixed version present -> fix=package (newer image still has it)");
t(($c['CVE-2024-0002']['fix'] ?? '') === 'update', "no package fix but gone from the newer image -> fix=update");
t(($c['CVE-2024-0004']['severity'] ?? '') === 'UNKNOWN', "odd severity -> UNKNOWN");
t(($c['CVE-2024-0004']['fix'] ?? '') === 'update' && ($c['CVE-2024-0003']['fix'] ?? '') === 'both', "will_not_fix but absent from newer image -> update; package fix + absent -> both");
t(($c['GHSA-abcd-efgh-ijkl']['url'] ?? '') === 'https://github.com/advisories/GHSA-abcd-efgh-ijkl', "https advisory URL kept");
$ups = []; foreach ($c['CVE-2024-0001']['affected'] as $a) $ups[] = $a['update'];
t($ups === ['present', 'same'], "per-image registry state: present in newer image / image current (" . implode(',', $ups) . ")");
$im = $r['images'] ?? [];
t(($im[0]['update'] ?? '') === 'newer' && ($im[1]['update'] ?? '') === 'current' && ($im[2]['update'] ?? '') === 'skipped', "image registry states newer/current/skipped");
t(($im[2]['scan'] ?? '') === 'failed' && strpos($im[2]['error'] ?? '', 'timed out') === 0, "failed image listed with its reason");
t(($im[1]['stale'] ?? false) === true && ($im[0]['containers'] ?? []) === ['web', 'web-worker'], "stale flag and container list");
t(!isset($im[0]['digests']), "digests are not published in the report");
t(($r['summary']['images'] ?? 0) === 2 && ($r['summary']['failed'] ?? 0) === 1, "summary: 2 scanned, 1 failed");
t(($r['warnings'] ?? []) === ['Java DB update failed: example'], "warnings carried into the report");
t(strpos($o1, 'new_fixable_critical=1') !== false, "first report: 1 new fixable critical");
$ids = array_column($r['cves'], 'id');
t($ids[0] === 'CVE-2024-0001' && end($ids) === 'CVE-2024-0004', "sorted by severity: " . implode(',', $ids));
$o2 = run($agg, "$repo/tests/fixtures/basic", $out);
t(strpos($o2, 'new_fixable_critical=0') !== false, "second run with the same findings: 0 new fixable critical");
// broken local JSON -> image becomes failed, nothing else breaks
$b = "$w/broken"; @mkdir("$b/local", 0755, true);
file_put_contents("$b/images.tsv", "1\tsha256:" . str_repeat('d', 64) . "\tx:1\tx:1\t0\t\tc\t\n");
file_put_contents("$b/results.tsv", "1\tlocal\tok\t\n");
file_put_contents("$b/local/1.json", "{not json");
run($agg, $b, "$w/broken.json");
$rb = json_decode((string)file_get_contents("$w/broken.json"), true);
t(($rb['images'][0]['scan'] ?? '') === 'failed' && ($rb['images'][0]['error'] ?? '') === 'Trivy output is not valid JSON', "invalid Trivy JSON -> image failed with reason");
exit($fail);
