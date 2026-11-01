# Changelog

Copied by build.sh from the <CHANGES> block of unraid-trivy-scan.plg; edit the .plg, not this file.

## 2026.11.02
- New: a running scan is now stopped when you stop the array (Unraid's "stopping Docker" event), so it no longer holds the shares open or leaves scan containers behind.
- Change: the data folder now follows the "Default appdata location" of Settings, Docker (default /mnt/user/appdata, so nothing changes unless you moved it). If you did, the first scan downloads the databases again into the new place; the old folder can be deleted by hand. If the location is not available (array stopped), the scan says so and creates nothing.
- Fix: when the settings form refused a value, the page still printed a "Scheduled scan" line as if the change had been applied. It now says "Settings NOT saved" in the same log style as Unraid's own pages and does not touch the schedule. Also logged to the system log.
- Fix: a rejected security token (session expired, page left open) showed "HTTP 200" on the buttons; it now says to reload the page.
- Fix: the header tab was labelled "TRIVYSCANTAB"; it is now labelled "Vulnerabilities" (Unraid takes the label of a header tab from the page's Name, not its Title).
- The header tab is now only shown while the array is started, like other plugins' tabs. The settings form no longer carries a duplicate token field and stores its file by the relative name Unraid's own forms use.
- Tests now run the settings save through copies of Unraid 7.3.4's real update.php and request prologue.
## 2026.11.01c
- Fix: the Scan now, Stop and Update database buttons still failed with "invalid csrf_token". Unraid's request prologue removes the token from both the form data and the X-CSRF-Token header after checking it, so the plugin's own second check could never pass. The plugin now relies on Unraid's check and only checks the token itself where that prologue is absent. Verified against the real prologue of Unraid 7.3.4.
## 2026.11.01b
- Fix: after updating to 2026.11.01a the buttons could still fail with "invalid csrf_token", because the browser kept the old script: the pages keyed their script and style URLs on the file time, which the package sets to the release day. They now use a hash of the file contents, so every change reaches the browser.
## 2026.11.01a
- Fix: the Scan now, Stop and Update database buttons failed with "Could not start: invalid csrf_token". Unraid's request prologue removes csrf_token from the form data after checking it, so the plugin's own second check never saw it; the page now also sends the token in the X-CSRF-Token header. A new test runs the buttons behind a prologue that behaves like Unraid's.
## 2026.11.01
- Fix: a first install failed with "run failed: '/bin/bash' returned 1". The pre-install step returned the exit status of its last file test when no plugin package was on the flash yet; it now always ends with success.
## 2026.10.31
- New: scan the Unraid OS itself (setting "Scan the Unraid OS", on by default). trivy rootfs runs in its own container with --network none, no Docker socket and a read-only database; only /usr, /lib, /lib64, /bin, /sbin and /opt are mounted, read-only and without the mounts below them. /mnt, /boot, /etc, /proc, /sys and /var/lib/docker are never mounted.
- The OS findings (Go binaries such as Docker, containerd, runc and rclone; Node.js packages including the Unraid API; other language packages) appear in the report as the target "Unraid OS" plus its version (for example "Unraid OS 7.3.4"), with the file path of each affected package.
- Trivy has no Slackware support, so the OS packages and the kernel are not CVE-matched. The report lists them (package, version, build, kernel version) in a collapsible section, with a link to the release notes.
- Per-target timeout and failure reason also for the OS scan. Notification subject no longer says "Container images" only.
## 2026.10.27
- First release.
- Scans the images of running containers (optionally also stopped ones) by image ID with Trivy 0.76.1, pinned by version and digest.
- Three container roles: the database download has network but no Docker socket; the local scan has the socket but runs with --network none and a read-only database; the optional registry check has network but no socket and is the only one that can receive registry logins.
- Report: one row per CVE with the affected images and packages, severity and fix-status filters (CVEs without a fix hidden by default), search, sorting, paging, failed images with the reason, warnings.
- Dashboard tile, optional header tab, notification on new fixable critical CVEs.
- Settings are read as data and validated on save and on read; an invalid cron schedule never reaches cron.
- No scan or download on install or at boot; a running scan is stopped on upgrade and removal; optional cleanup of the data directory and the Trivy image on removal.
