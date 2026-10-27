<?php
/* unraid-trivy-scan: settings check, included by Unraid's /update.php through the form's #include field, before
 * the settings file is written. In that scope $_POST holds the form, $keys the current file and $save decides
 * whether anything is written. Unknown keys (and update.php's csrf_token, should it still be there) are dropped,
 * every value must pass the same rules scripts/trivy-scan applies when it reads the file; any invalid value
 * refuses the whole save. */
require_once __DIR__ . '/lib.php';

$uts_errors = [];
foreach (array_keys($_POST) as $k) {
  if (is_string($k) && $k !== '' && $k[0] === '#') continue;
  if (!array_key_exists($k, UTS_DEFAULTS)) { unset($_POST[$k]); continue; }
  $v = $_POST[$k];
  if (!is_string($v)) { $uts_errors[] = $k; unset($_POST[$k]); continue; }
  $v = uts_normalize($k, $v);
  if (!uts_valid($k, $v)) { $uts_errors[] = $k; continue; }
  $_POST[$k] = $k === 'TIMEOUT' ? (string)(int)$v : $v;
}
// the file that is merged with the form keeps only known, valid keys
$keys = is_array($keys ?? null) ? $keys : [];
foreach (array_keys($keys) as $k) {
  if (!array_key_exists($k, UTS_DEFAULTS) || !uts_valid($k, (string)$keys[$k])) unset($keys[$k]);
}
if ($uts_errors) {
  $save = false;
  echo 'Settings NOT saved, invalid value for: ' . uts_h(implode(', ', $uts_errors)) . "\n";
}
