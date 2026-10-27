# Changelog

Copied by build.sh from the <CHANGES> block of unraid-trivy-scan.plg; edit the .plg, not this file.

## 2026.10.27
- First release.
- Scans the images of running containers (optionally also stopped ones) by image ID with Trivy 0.76.1, pinned by version and digest.
- Three container roles: the database download has network but no Docker socket; the local scan has the socket but runs with --network none and a read-only database; the optional registry check has network but no socket and is the only one that can receive registry logins.
- Report: one row per CVE with the affected images and packages, severity and fix-status filters (CVEs without a fix hidden by default), search, sorting, paging, failed images with the reason, warnings.
- Dashboard tile, optional header tab, notification on new fixable critical CVEs.
- Settings are read as data and validated on save and on read; an invalid cron schedule never reaches cron.
- No scan or download on install or at boot; a running scan is stopped on upgrade and removal; optional cleanup of the data directory and the Trivy image on removal.
