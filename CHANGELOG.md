# Changelog

Notable changes to the Security Scan plugin and its scan suite. Versions follow
[semantic versioning](https://semver.org), and the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] - 2026-10-21

### Changed

- The bar no longer stays red for a week after harmless changes. The file
  integrity section reports findings, not log lines: a path several checks
  logged is one finding, and findings are grouped into items by folder (and,
  for reds, by the day first seen), so one kernel update is one item rather
  than 26,000 lines. The bar and the summary count items.
- An unexplained file in a system code path that no package owns is amber,
  not red, when it was last changed while pacman was running. Red is kept
  for evidence: a package's file that fails pacman's check, a boot file
  changed with no package update, and an unowned system file written while
  pacman was not running.
- A red stays in the report until it is acknowledged or a rule explains it,
  rather than leaving after the window; the scan keeps the AIDE logs that
  hold an open red. Ambers still leave with the window.

### Added

- `sudo security-report --ack ID --reason TEXT` records an item as checked,
  and `--ack amber` records every amber item. The acknowledgement holds each
  file's state, so a file that changes again is a new finding. `--acks`
  lists them and `--unack ID` removes one. They are kept in
  `/etc/security-scan/acknowledged.json`, which AIDE does not watch, are
  noted in the journal, and are listed in the report as green items.

## [0.2.13] - 2026-10-21

### Fixed

- Kernel modules that DKMS builds, such as the NVIDIA driver from
  `nvidia-open-dkms`, read as red "unpackaged file in a system code path"
  after every NVIDIA or kernel update. dkms installs them into
  `/usr/lib/modules/<kernel>/updates/dkms/`, which no package owns. Such a
  module is now a package change when all of these hold: it is a regular
  file, for a kernel whose module folder an installed package owns; it is
  byte for byte the copy dkms keeps of its build in
  `/var/lib/dkms/<name>/<version>/<kernel>/<arch>/module/`, which must be a
  regular file owned by root that no one else may write, in folders that are
  root's alone and not links; the source it was built from,
  `/usr/src/<name>-<version>/`, is reached without a link, its `dkms.conf`
  belongs to an installed package, and pacman finds nothing wrong with any
  of that package's files there; and the module was last
  changed while pacman ran the dkms package's `70-dkms-install.hook`, from
  when pacman.log records the hook starting until the next line pacman
  logs. A module copied in by hand, or changed later, stays red.
- The report applies the same rule to red lines logged before this version.
  Each AIDE log now records that it was graded with security-scan rules 3,
  so the red lines of logs from 0.2.12 are re-checked against all the
  current rules, as long as the file has not changed since that run.

## [0.2.12] - 2026-10-21

### Security

- Text taken from scanned files could be read as markup by the bar panel.
  The panel drew each finding with Qt's `Text` in its default format, which
  guesses at rich text, so a pickle file whose import names held an
  `<img src=...>` tag could make the desktop fetch an address of the
  attacker's choosing when the panel showed that finding. The same holds for
  file names, repository names and package output. Every `Text` in the
  panel now shows its string as plain text, and the bar tooltip drops the
  characters markup is made of. The HTML report already escaped every
  string; a test now holds it to that.
- The same text could forge lines of the scan log. picklescan prints a
  pickle's import names, which may hold new lines, and the scan copied its
  output into the log as it was, so a crafted name could add a `summary:`
  line the report then took as the scan's own, or a `Dangerous globals:`
  line that broke the scan's arithmetic and stopped it before the folders
  after it were scanned. Everything a scanning tool prints now goes into the
  log with `| ` in front of each line and control characters shown as `?`;
  picklescan's counts are read only from its own summary block, the last
  one it prints, and a count that is not a plain number makes the scan an
  error. The report reads `summary:` and `!!` only from lines the scan
  wrote, and the rootkit and lynis sections read their counts from the
  scan's summary line rather than from the first match anywhere in the log.
- Finding text in the terminal report could carry terminal control codes,
  new lines, or Unicode marks that are invisible or reverse the order text
  is shown in. The report now shows each such character as `?`, in the
  terminal, the HTML page and the JSON the panel reads.
- Notification titles and bodies are now written with `&`, `<` and `>` as
  entities, since many notification daemons read the body as markup. They
  hold counts and log paths only, so nothing visible changes.
- The AIDE check skipped every changed path that the file system called a
  folder. That test followed symlinks and used AIDE's escaped form of a
  name, so a package folder swapped for a symlink to elsewhere was never
  red, a folder whose mode or owner changed (`chmod 777 /etc/sudoers.d`) was
  never reported, and a file whose name holds a new line could hide behind a
  folder named like AIDE's escape for it. AIDE's own type letter now decides
  what is a folder; a folder a package lists must still be one; a folder's
  mode, owner and type are checked with `pacman -Qkk` like a file's; and
  AIDE's `\ooo` escapes are decoded, with a name that holds a control
  character graded red as AIDE wrote it.
- A package file replaced by a symlink, or a symlink by a file, shows in
  `pacman -Qkk` only as a "File type mismatch", which no check looked for,
  so AIDE and rkhunter both accepted it as verified. Both now treat it as a
  failed check, as they do a package whose file list (mtree) is missing.
- A package configuration file edited on this machine, such as `/etc/hosts`,
  was graded green as "verified by pacman". pacman 7 marks these
  "backup file:" in `pacman -Qkk` and words `pacman -Qii` differently from
  what the check read, so the amber "edited locally" verdict never fired.
  It is now amber.
- A file that pacman still lists for an installed package but that is no
  longer on disk was graded as a package change. No package change removed
  it, so it is now amber, to confirm.

### Fixed

- The AIDE check no longer runs out of time after a kernel update. It asked
  pacman about each changed file in turn, twice, and a kernel update
  changes tens of thousands of files, so on 2026-10-21 the run reached the
  unit's 45 minute limit and was stopped. The baseline only moves on once
  every change is graded, so each later run met the same pile. The check
  now makes one `pacman -Ql` for the whole system, one `pacman -Qkk` over
  the packages that own a changed file, and one call of `security-report`
  for the rarer explanations. The same 46,000 changes now take about ten
  to fifteen seconds. The lists stay in the scan's private temporary folder
  and never reach a command line.
- A check that a package update overlapped is set aside instead of graded.
  On 2026-10-20 the check graded files while glibc was being replaced;
  pacman crashed for a moment and fourteen icon files of `yaru-icon-theme`
  read as unpackaged reds. The check now waits up to ten minutes for a
  running pacman before it starts, and a check during which pacman starts a
  transaction logs `summary: skipped`, which the report does not grade, and
  keeps the baseline, so the next check reports every change in full. A
  pacman counts as running only while a process holds its lock file open; a
  lock file left by a pacman that crashed is noted and the check goes ahead.
  Checks set aside since the last graded one are amber in "Scans ran on
  schedule" once the first is a day old and red after three, with the
  reason. If pacman cannot list or check its packages at all, the run is an
  error and the baseline is again kept. A new database left by a failed
  run is removed before AIDE runs, and a failure of the `security-report`
  call is logged.
- "Scans ran on schedule" read a run that was stopped before it finished as
  a run on schedule, because its log held no error line. A run with no
  summary line is now amber, and red when it ran past its time limit (the
  unit says so, or its log was written to for the whole limit) or the run
  before it did not finish either. A run that is still going (its unit is
  active, or its log was written in the last ten minutes) is not graded;
  the run before it is.
- The modules of a kernel that is no longer installed read as thousands of
  "unpackaged file removed" lines after each kernel update, because
  `kernel-modules-hook` keeps the running kernel's modules until the next
  boot and deletes them then, outside any pacman run. When the folder is
  gone, no package owns it and it is not the running kernel's, they are now
  one package-change line that counts them. The report applies the same
  rule to such lines logged earlier.
- Files removed by a package upgrade or removal read as amber, because the
  package no longer listed them. The check now keeps each installed
  package's file list beside the AIDE baseline, in
  `/var/lib/security-scan/owners.gz`, readable by root only, and a removed
  file that belonged to a package pacman has since upgraded, removed,
  reinstalled or downgraded is a package change. The first check after
  upgrading has no saved list yet and grades removals as before.
- The module index that `depmod` writes into `/usr/lib/modules/<version>`
  (`modules.dep`, `modules.alias`, their `.bin` forms and the rest) after a
  kernel update read as unpackaged reds. It is now a package change when
  the folder belongs to an installed kernel package and the file is byte for
  byte what depmod builds now, run into a temporary folder that links to
  the real module tree.
- Files a package's own install script writes read as unpackaged reds or
  checksum failures: a voice typing tool links `/usr/bin/<name>` to the
  build for this CPU, and 1password rewrites its polkit policy with `sed -i`
  on every upgrade. Such a file is now a package change when it was last
  changed while pacman.log shows that package being installed or upgraded to
  the version installed now, and that version's install script has a
  command that writes the file's exact path (a redirection, `cp`, `mv`,
  `install`, `ln`, `touch`, `tee`, `truncate`, `sed -i` or `dd of=`), with
  the path written out or held in a variable the script gives one value. A
  file the script only names is amber: graphviz removes its plugin list and
  has `dot -c` write it again, which no rule can read. A package file must
  otherwise pass pacman's check apart from its content; a symlink must
  point at a file of the same package that pacman verifies. The check uses
  the file's change time (ctime), which `touch` cannot set back, so a file
  edited at any other moment stays red. The README's Limits section says
  what this cannot tell.
- The report re-checks red lines logged before this version against these
  rules, and also clears a red "unpackaged" line when the file is a
  package's file that pacman verifies now and that has not changed since
  before the run that logged it, which was the mark of the lookups that
  failed during the 2026-10-20 update. A line is re-checked only while the
  file has not changed since that run started, so a later rewrite inside a
  package's window, or a write while the check ran, cannot clear an earlier
  red. Removed files under the module folder of a kernel that is no longer
  installed, which an earlier version listed one by one (a run on
  2026-10-21 listed 29,551 of them), are folded into the count of package
  changes. Each AIDE log now records
  the version of the rules it was graded with, and lines graded with these
  rules are re-checked only against `SCRIPTLET_LINKS` and `HOOK_PATCHED`.
- The report keeps pacman's answers for the length of one run and asks who
  owns every re-checked file in one call. Re-checking the logs of the week
  of this release made it take about ten seconds; it now takes about two on
  the machine it was written on, faster than 0.2.11.

- Every package file on a FAT `/boot` failed pacman's permission check,
  because the mount gives all files one mode (`fmask=0077`), so
  `/boot/amd-ucode.img` was red after every amd-ucode upgrade. On a file
  system without Unix modes (FAT, exFAT, NTFS), a package file whose only
  faults are a mode, owner and group exactly matching the mount options,
  and whose content pacman verifies, is now a package change, as long as
  that mode and owner are safe: root's, in group root or the packaged
  group, writable by no group or other, and with no permission the package
  does not give apart from FAT's execute bits. A mount that hands the files
  to a user (`uid=1000`) or to everyone (`umask=0000`) stays red. Of mounts
  stacked on one mount point, the one in use counts.
- glibc's `/usr/lib/gconv/gconv-modules.cache`, which its pacman hook
  rebuilds, read as an unpackaged red, and so did lib32-glibc's
  `/usr/lib32/gconv/gconv-modules.cache` and systemd's hardware database
  `/usr/lib/udev/hwdb.bin`. The caches pacman hooks rebuild (gconv and
  lib32 gconv, the hardware database, GTK 3 input methods, desktop MIME
  types, GIO and GTK 4 GIO modules) are
  now explained only when they are byte for byte what their tool builds
  now, run into a temporary folder. 0.2.11 accepted the GTK and MIME caches
  when their modification time fell just after the hook ran, which `touch`
  can set. The report applies the rule to older lines.
- cupsd rewrites `/etc/cups/printers.conf` and `classes.conf` 0600
  `root:cups`, which read as a red ownership or permission failure. A
  configuration file a package keeps across upgrades, by the backup list in
  pacman's database, whose only change is a tighter mode, and perhaps
  another group, while root still owns it, is now amber, like an edited
  configuration file. A permission the package does not give, or another
  owner, stays red. pacman 7 reports such a mode change as a plain warning,
  not a "backup file:" line, so the backup list is read from its database.
- The desktop user's home folder is amber wherever it is; one outside
  `/home` was graded as a system code path. The watched home folders get
  the lighter folder rule (`~/.config/autostart`, `~/.config/systemd/user`,
  `~/.config/environment.d`, `~/.ssh`, `~/.local/bin`), so a new file there
  is not also reported as a change to the folder.
- Model findings in the panel and report no longer show the `| ` the log
  puts in front of tool output.

### Added

- `HOOK_PATCHED` in `scan.conf`: package files that a pacman hook of this
  machine's own patches after each upgrade, as `file=hook:sha256` entries,
  with the SHA-256 of the file as patched (several may be given, separated
  by commas). A listed file is a package change only while its content has
  one of those sums, the hook file is in `/etc/pacman.d/hooks`, owned by
  root and writable by no one else, pacman finds nothing wrong with the
  file but its content, and the file was last changed within a minute of
  pacman.log recording that hook running. Empty by default. It is read the
  way `SCRIPTLET_LINKS` is: only from the file, only when written out
  literally.

### Changed

- `pacman` runs in the C locale wherever its messages are read, since they
  are matched as English text.
- The report starts every program by its full path in `/usr/bin` with a
  fixed environment (a system PATH and the C locale), and the scan runs its
  Python checks with nothing from the environment but PATH, so a folder
  early in a session's PATH, or a variable such as `GCONV_PATH` or
  `GIO_EXTRA_MODULES`, cannot steer a pacman call or a rebuilt cache.
- AIDE now watches GIO's own module cache,
  `/usr/lib/gio/modules/giomodule.cache`, which was excluded as churn; it is
  explained when `gio-querymodules` builds the same file.
- rkhunter's check of changed binaries asks `pacman -Qkk` once per package
  rather than once per file.
- The README's Limits section now says that AIDE skips a file whose name is
  not valid UTF-8.

## [0.2.11] - 2026-10-15

### Security

- When the desktop user had no group of their own, 0.2.10 left `scan.conf`
  and `risk-register.toml` readable by every local user, so that the report
  could still read them. They hold the user's name, home folder and
  repository paths. The installer now refuses to install in that case,
  before it changes anything, and says how to give the user a private
  primary group. Uninstalling works as before. If an earlier version left
  files in `/etc/security-scan`, the refusal says so and suggests
  `chmod o-rwx` on them until the group exists.
- The test for a group of the user's own is stricter. The group must have
  the user's name and be their primary group, both found in the local
  files; it must be the only group with its GID, with no other member in
  `/etc/group` or `/etc/gshadow`; and no other account may have it as its
  primary group. A primary group shared by several accounts, such as
  `users`, does not count. Only the local files list every account, so a
  machine whose `/etc/nsswitch.conf` also looks up accounts or groups
  elsewhere, such as in LDAP or SSSD, does not qualify either. 0.2.10 did
  not look at `/etc/gshadow`, at other groups with the same GID, or at where
  accounts and groups were looked up.
- A file in `/etc/security-scan` that an administrator had given to another
  group, such as `users`, kept that group, so all of its members could
  still read it after 0.2.10 tightened its mode. Installing now moves
  `scan.conf` and `risk-register.toml` to the desktop user's own group and
  prints `take ... from group` for each. Files only root reads already lost
  their group permissions.
- Each scan shared its log folder in `/var/log/security-scan` (0750) and
  its copy of the lynis report (0640) with the group named after the
  desktop user, even when that group was no longer private, for example
  because another account had been added to it after installing. The logs
  name repositories, files and findings. Each scan run as root now makes
  the same test as the installer and, without a private group, keeps the
  folder 0700 for root alone, writes the lynis copy 0600, and says so on
  stderr. An existing folder is closed on the next run.

## [0.2.10] - 2026-10-14

A review of 0.2.9 looked for every other place where private names or paths
could reach other local users, through the process list or a readable file.

### Security

- AIDE findings in the home folder, such as a changed file in `~/.ssh` or
  `~/.local/bin`, were passed to `pacman`, `readlink` and `python3` as
  arguments, so a private file name was visible in the process list. Paths in
  the home folder are now handled only inside the shell. No package owns
  them, so the verdicts and their wording are unchanged, except that a link
  in the home folder can no longer be explained by a package's install
  script or a `SCRIPTLET_LINKS` entry. A system link that points into the
  home folder is handled the same way, and so is a home folder file in
  rkhunter's results.
- The model scan started `picklescan` and `find` with each model folder's
  path as an argument, visible for the whole scan. Both now run from inside
  the folder. A folder that cannot be entered is reported as not scanned.
- `security-report` passed file paths to `pacman -Qqo` as arguments. It now
  passes them on standard input.
- The files in `/etc/security-scan` were readable by every local user,
  though they hold the desktop user's name and home folder, the folders
  scanned, gitleaks rules written to find a private name, and the paths of
  repositories with findings. `gitleaks.toml` and `aide.conf`, read only by
  the scans, are now 0600. `scan.conf` and `risk-register.toml`, which the
  report reads as the desktop user, are 0640 and shared with that user's own
  group. Installing over an earlier version tightens existing files once and
  prints `make ... private` for each. It only ever removes permissions, and
  leaves a symlink, a file root does not own or anything that is not a
  regular file as it is, with a note. If the user has no group of their own,
  those two files stay readable by everyone and the installer says so. AIDE
  watches `/etc`, so the first scan after upgrading reports these mode
  changes once, in amber.
- The HTML report and the folder that holds it were written with the user's
  umask, usually readable by everyone, though they name repositories, rules
  and changed files. Pages are now 0600 and `~/.local/share/security-report`
  is 0700, and pages already there are made private. A page is written to a
  new file and renamed into place, so a symlink at its path is replaced, not
  written through.

### Fixed

- gitleaks exits 1 both when it finds a secret and when it fails, for
  example on a missing config, so a failed run read as clean. Secrets now
  give exit 3, and any other non-zero exit is logged as an error, which the
  report shows. A missing or unreadable `gitleaks.toml` is logged as well.
- The report dropped a repository whose path holds a space, so its findings
  were missing and the section could show green. Such paths are now read in
  full. If the scan counted more findings than the report could match to a
  repository, the section shows the difference in red.
- A failed write of the HTML report prints a message and exits 2, rather
  than a traceback.

## [0.2.9] - 2026-10-14

### Security

- The gitleaks scan put the path of each repository with findings in its
  desktop notification. `notify-send` takes the notification text as a
  command-line argument, which any local user can read in the process list,
  so repository names and their finding counts were visible outside the
  protected scan logs. The notification now gives only the counts and the log
  path, and the log alone names the repositories.
- gitleaks itself was started with each repository's path on its command
  line, which exposed the same names while it ran. It now runs from inside
  the repository and is given `.`, so no repository path appears in any
  command line the scan starts.

### Changed

- Because gitleaks now scans `.`, an allowlist `paths` pattern in
  `/etc/security-scan/gitleaks.toml` is matched against the path relative to
  the repository root. A pattern that names the repository folder no longer
  matches; drop the folder from it. See INSTALL.md.
- For the same reason, a `.gitleaksignore` fingerprint now names the file
  relative to the repository root, as one committed in a repository usually
  does. An entry written with the full path no longer matches.

## [0.2.8] - 2026-10-12

### Added

- `tests/sandbox-install.sh` runs the installer against a temporary folder
  standing in for `/`, with the system commands replaced by stand-ins, and
  checks fresh installs, upgrades from every release from 0.2.1 to 0.2.7,
  uninstalls, and the refusals below. It needs no root.

### Security

- The installer replaced any existing file at the paths of its units in
  `/etc/systemd/system` and `/etc/systemd/user`, and the uninstaller removed
  every `security-scan-*.timer`, including timers this plugin never
  installed. Both could overwrite or delete units an administrator manages.
  A unit is now replaced or removed only when it is a regular file, not a
  symlink, owned by root, whose content is exactly a unit this plugin has
  shipped, either in the checkout or in an earlier release. The uninstaller
  works from the exact list of names the plugin installs, not a glob, and
  lists anything it leaves in place. Reported in
  omacom/omarchy-plugin-marketplace#8732.
- The same rule now covers the installer's other paths. Before it changes
  anything, the installer checks `security-scan` and `security-report` in
  `/usr/local/bin`, `/opt/security-scan`, the picklescan environment and
  `/etc/security-scan`. If one holds something that is not this plugin's, it
  lists every such path with the reason and stops, leaving the machine as it
  was. The uninstaller removes only the picklescan environment from
  `/opt/security-scan`, not the whole folder, and removes the folder itself
  only once it is empty.
- Files are written to a temporary name in the same folder and renamed into
  place, so a symlink at the destination is replaced rather than written
  through. Existing folders are no longer given new permissions, a
  regenerated `aide.conf` is never more open than the file it replaces, its
  backup keeps the original's permissions up to 0644, and an earlier backup
  from the same day is no longer overwritten.
- The picklescan environment in `/opt/security-scan` is replaced or removed
  only when this installer made it: it carries a marker file the installer
  now writes, or has picklescan installed in it. Any other virtual
  environment at that path is refused. Of the uv tool folder from 0.2.1,
  only picklescan is removed, and the folder only once nothing else is in
  it.
- `/opt/security-scan` and `/etc/security-scan` are refused when group or
  others can write to them, and `aide.conf` is never read through a
  symlink. `--user 0`, or another name for UID 0, is
  refused like `root`. A temporary file is removed if the run is
  interrupted before it is renamed into place.

## [0.2.7] - 2026-10-04

### Fixed

- A package file whose own install script gives it a group and the setgid
  bit no longer turns the integrity check red after every update of that
  package. 1password does this to its browser helper and 1password-cli to
  `op`, so pacman reports a GID and permissions mismatch on files whose
  content is untouched. Such a file is now a package change only when pacman
  finds nothing else wrong with it, the install script plainly runs `chgrp`
  and `chmod g+s` on that exact path, and the file's group, owner and mode
  match what the script and the package say. The script's `chgrp` and
  `chmod` must be certain to run: text in a heredoc, a function nothing
  calls, or a command inside an `if` or after `&&` does not count. The
  rootkit check accepts the same files. Red lines logged before this
  version are not re-graded and age out of the window as usual.
- The report no longer accepts a linked file as verified when it runs as a
  user who cannot read the file. pacman then prints "failed to calculate"
  instead of a checksum mismatch, which the check had not looked for.
- A mismatch line early in a very long pacman listing could be missed,
  because `printf | grep -q` under pipefail reads an early match as no
  match. The scan now matches against the text directly.

### Changed

- A package file that fails only pacman's ownership or permission check is
  now reported as that, instead of as failing pacman's checksum.

## [0.2.6] - 2026-10-03

### Added

- A `reportDays` setting, from 1 to 7 and 7 by default, sets how many days of
  scan results the bar and panel grade. A finding drops out of the bar once it
  is older than that, instead of always waiting a full week. The Monday report
  still covers seven days.

### Changed

- Each scan's latest run now always counts, even when it is older than the
  window, so a short window does not turn a weekly scan such as rkhunter
  amber for having no result. Whether a scan is overdue is still graded in
  the scan health section. `--days` must be at least 1.

### Fixed

- A boot file changed by a package reinstall or downgrade was graded red as
  "boot file changed with no package update", because the scan counted only
  installs, upgrades and removals. A `reinstalled` or `downgraded` line in
  `pacman.log` now counts too. The report applies the same rule to red lines
  already logged: it reads that line as a package change when `pacman.log`
  records a transaction between the end of the check before it and the start
  of the check that logged it, comparing times with their zones so a change of
  clocks cannot reorder them. A transaction made while or after that check
  ran, or a later check's verdict, never clears it. Each check now logs the
  window its own count used, and the report uses that when it is there. Run
  the installer again so the scheduled scan uses the new rule.

## [0.2.5] - 2026-09-30

### Added

- A `SCRIPTLET_LINKS` setting in `scan.conf` lists symlinks, each with the
  package whose files it may point to, that the package's install script
  points at a file it picks when it runs, such as voxtype-bin's
  `/usr/bin/voxtype`. The general rule rightly leaves such a link red, since
  the target cannot be read from the script. A listed link is a package change
  only while it is a symlink, not a file, and resolves to a file owned by the
  listed package alone, pacman finds that file unaltered, and the package's
  install script has an `ln -s` command for the link's exact path. The list is
  empty by default, so nothing changes unless you add to it, and links not on
  it are treated exactly as before. The value is read from the file only,
  must be written out in full, and is ignored if the file is not root's
  alone. The scan runs the report's own check through a hidden option, and
  the report applies it to red lines logged before the link was listed. Add
  the setting to an installed `scan.conf` by hand, since the installer never
  overwrites it, and run the installer again so the scheduled scan uses it.

### Fixed

- AIDE no longer reports limine-snapper-sync's snapshot bookkeeping as red.
  A change to `/boot/limine.conf`, `/boot/limine.conf.old` or
  `limine_history/snapshots.json` with no package update is a package change
  only when limine-snapper-sync's own program logged writing the file since
  the last check, and the file differs from a trusted copy of `limine.conf`
  only inside the Snapshots sub-menu, whose entries may boot only command
  lines and kernel images the trusted copy already boots. A changed kernel
  command line, kernel or initramfs path, or any other entry stays red. The
  scan keeps the trusted copy in `/var/lib/security-scan`, readable by root
  only, and refreshes it after each check that finds nothing red under
  `/boot`; until the first check has made it, these changes stay red. The
  check lives in security-report, and security-scan runs it through a hidden
  `--limine-snapshot-change` option. The weekly report leaves red lines
  logged earlier as they are, because it cannot read `/boot` or the trusted
  copy. Run the installer again after upgrading, so the scheduled scan uses
  the new rule.

## [0.2.4] - 2026-09-29


### Fixed

- The rootkit section grades only the latest rkhunter run. It used to add up
  the warnings of every run in the report's window, so a warning that a later
  clean run had cleared, such as the missing passwd and group copies on the
  first run, stayed red for up to seven days. When an earlier run had warnings
  the latest one no longer shows, the headline now says so.

## [0.2.3] - 2026-09-27


### Fixed

- AIDE no longer reports a symlink as red when a package's own install
  script made it and it points where that script points it. It is explained
  only while it resolves to a file the package owns, pacman finds that file
  unaltered, and the package's install script has an `ln -s` command for the
  link's exact path whose target is written out in full and resolves to that
  same file. The report applies the same check to a red line logged before
  the scanner knew about it, against the system as it is now. Run the
  installer again after upgrading, so the scheduled scan uses the new rule.

### Security

- The first version of that check, on the main branch but never released,
  accepted a link to any verified file of the package whose install script
  named the link's path. A system command link repointed to a different file
  from the same package was therefore reported as a package change instead
  of red, in both the scan and the weekly report. The link's current target
  must now be exactly the target the install script gives. A target held in
  a variable, two different targets for the same link, an `ln` without `-s`,
  or an `ln` option the parser does not understand leaves the link red.
  Reported in omacom/omarchy-plugin-marketplace#8732.
- The scan and the report now read install scripts with one parser, in
  `security-report`, which `security-scan` runs through a hidden
  `--scriptlet-link-target` option, so the two cannot disagree.

## [0.2.2] - 2026-09-26

### Security

- The installer no longer runs `uv tool install --upgrade picklescan --with
  numpy` as root, which fetched whatever versions PyPI served on the day.
  picklescan and numpy are now pinned to exact versions and SHA-256 hashes in
  `system/picklescan-requirements.txt`, and installed as root with
  `--require-hashes` and `--only-binary :all:` into a virtual environment in
  `/opt/security-scan/picklescan`. Any file whose hash is not listed is
  refused, and nothing is built from source. Upgrades now happen only by
  changing that file in a new commit. The old uv tool folder,
  `/opt/security-scan/tools`, is removed.

## [0.2.1] - 2026-09-25

### Changed

- The bar lock is now tinted green, amber or red to match the report, in
  place of the small dot on its corner. A report that could not be read shows
  amber rather than a grey dot.


### Fixed

- AIDE no longer reports a browser's `policies.json` as red when a local
  pacman hook rewrites it after every update to switch off telemetry and
  studies, so that it always fails pacman's checksum. It is explained only
  while the hook is installed and the file holds nothing but the browser's own
  policies and those two switches; any other policy leaves it red.
- The report applies the same check to a RED line for that file logged
  before the scanner knew about the hook, against the file as it is now. The
  log itself is left as written.

## [0.2.0] - 2026-09-24

### Added

- A Privacy (Black Ops) section in the report. It reads the counts in
  `~/.local/state/black-ops/summary.json`, written by Black Ops 0.3.0 and
  later, and nothing else. It is red only when listen mode saw a program
  contact a telemetry host that nobody has reviewed, amber for unreviewed
  software watch findings, protections that slipped, a summary that cannot be
  read, or one more than eight days old, and green when Black Ops is on and
  every count is clean. Each item says what to do.
- A grey rating for things that are off or not installed. Grey is shown but is
  never a problem and never changes the overall rating. The section is grey
  when Black Ops is not installed or is switched off, and listen mode and the
  software watch are grey items while they are off. Grey sections start
  folded in the panel.
- Privacy entries in the risk register, which can lower the rating of one
  privacy item, limited by `count` to the findings that were looked at. A leak
  cannot be accepted this way.
- Tests for the privacy section, run with
  `python3 -m unittest discover -s tests`.

## [0.1.0] - 2026-09-23

First release.

### Added

- Six scheduled scans, run as root by `bin/security-scan` from one templated
  systemd service and six persistent timers: `arch-audit`, `aide` and `models`
  daily, `gitleaks` and `rkhunter` weekly on Monday, and `lynis` monthly. They
  run at idle CPU and disk priority, keep the last 12 logs of each scan in
  `/var/log/security-scan`, and send a desktop notification when they find
  something.
- A report, `bin/security-report`, that reads those logs and grades every
  finding green, amber or red, in the terminal, as a self-contained HTML page,
  or as JSON. It exits 1 when the overall rating is red.
- A risk register, `/etc/security-scan/risk-register.toml`, that records by
  hand what each known package CVE or gitleaks finding means on this machine
  and what is being done about it. A finding with no entry is reported as not
  yet assessed rather than passed, and a CVE entry whose assessed version is
  newer than the installed one is flagged for re-assessment.
- Standing risks, such as the firewall and disk encryption, checked live each
  time the report runs, so a protection that stops being in place is reported red.
- Scan health graded as a finding. A scan that has gone quiet turns amber and
  then red according to its cadence, and one that failed, or never ran, is red.
  A missing result is never read as a clean one.
- AIDE changes explained before they are reported. A file that `pacman -Qkk`
  still verifies counts as a package change, a boot file that changed with no
  package update is red, and unpackaged changes are amber where your own work
  normally lands and red in system code paths. AIDE re-baselines after every
  check, so each run reports only what is new.
- rkhunter's "file properties have changed" warnings accepted only when pacman
  verifies every file they name, after which rkhunter's record is updated.
- A model scan with `picklescan` over the folders in `MODEL_ROOTS`, which
  skips Python environments and reports a scan that crashed as failed.
- A weekly report on Monday at 13:00, written as a dated HTML page with a
  `latest.html` link and announced by a notification that can open it.
- A bar widget: a lock in the bar's own colour with a corner dot that is amber
  or red to match the report, grey when the report cannot be read, and absent
  when it is green. Its panel lists every section, its findings, and what is
  being done about each one, and can open the full report.
- An installer, `bin/security-scan-install`, that installs the packages,
  `picklescan`, the programs, the configuration and the units, creates the
  first baselines, and can be run again safely. `--dry-run` shows every action
  without root, and `--uninstall` removes what it installed while keeping the
  configuration, logs and baselines.

[0.2.0]: https://github.com/brightwalker25/omarchy-security-scan/releases/tag/v0.2.0
[0.1.0]: https://github.com/brightwalker25/omarchy-security-scan/releases/tag/v0.1.0
