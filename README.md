# Spycatcher

Spycatcher catches signs that someone has been in the machine or has tampered
with it: changed system files, rootkits, leaked secrets, poisoned model files
and exposed packages. Catching those signs is what the name refers to.

It is a scheduled scan suite for Arch and Omarchy, and a bar widget that
shows its verdict. Six scans run in the background on systemd timers, a report
grades what they found green, amber or red, and a lock in the bar takes the
same colour. Click the lock and the panel lists
every section of the report, what each finding is, and what is being done
about it.

It exists because a scan whose output nobody reads protects nothing. Each of
these tools is useful, but run by itself each one either writes to a log that
is never opened or reports the same known and harmless findings
every week until you stop reading it. The report reads the logs for you,
explains what can be explained (a file changed because a package was upgraded,
a CVE the Arch tracker still lists after the fix shipped), and grades what is
left.

```bash
git clone https://github.com/brightwalker25/spycatcher.git ~/Work/spycatcher
sudo ~/Work/spycatcher/bin/spycatcher-install
ln -s ~/Work/spycatcher ~/.config/omarchy/plugins/brightwalker25.spycatcher
omarchy plugin enable brightwalker25.spycatcher --section right
```

The scans need root, so they are installed by a privileged installer rather
than by `omarchy plugin add`. The widget needs nothing beyond the plugin
itself. [INSTALL.md](INSTALL.md) covers the requirements, what the installer
changes, the first-run baselines, the configuration files, running scans by
hand, and uninstalling.

## Moving from Security Scan

Before 0.4.0 this project was called Security Scan, with the plugin id
`brightwalker25.security-scan`, the programs `security-scan` and
`security-report`, and folders named `security-scan`. Running the new
installer over such an install moves it to the new names: it renames the
configuration, logs, state and weekly pages, replaces the programs and units,
re-baselines AIDE so that the move is not reported, renames the plugin link
and changes the plugin id in `~/.config/omarchy/shell.json`, keeping the
widget's settings. Check it first with `--dry-run`, then restart the shell.
[INSTALL.md](INSTALL.md#moving-from-security-scan) describes each step.

## Removing

```bash
sudo ~/Work/spycatcher/bin/spycatcher-install --uninstall
omarchy plugin disable brightwalker25.spycatcher
rm ~/.config/omarchy/plugins/brightwalker25.spycatcher
```

The uninstaller removes only the units and programs this plugin installed,
and keeps your configuration, logs and baselines.
[INSTALL.md](INSTALL.md#uninstalling) lists what stays and how to delete it.

## What it scans

| Scan | Cadence | What it catches |
|---|---|---|
| `arch-audit` | daily | installed packages with a known CVE in the Arch security tracker, and how many a `pacman -Syu` would fix |
| `aide` | daily | files added, removed or changed under `/boot`, `/usr`, `/etc`, `/opt` and `/root`, and in the places in your home folder where malware settles to survive a reboot |
| `models` | daily | pickle-format AI model files that would run code when loaded, found with `picklescan` |
| `gitleaks` | weekly, Monday | keys, tokens, passwords and private names in the working trees of your git repositories |
| `rkhunter` | weekly, Monday | known rootkits, hidden files, and changes to the properties of system binaries |
| `lynis` | monthly | a hardening audit of the whole system, with a score out of 100 |

The daily scans start shortly after midnight, the Monday scans after 10:00 and
the monthly audit after 11:00 on the first of the month, each with a random
delay of up to two hours (six for lynis) so they do not all start at once. The
timers are persistent: a scan missed because the laptop was off or asleep runs
at the next opportunity. The scans run at idle CPU and disk priority, so they
do not compete with the desktop.

The home folder paths AIDE watches are `~/.config/autostart`,
`~/.config/systemd/user`, `~/.config/environment.d`,
`~/.config/fish/config.fish`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`,
`~/.ssh` and `~/.local/bin`. A program that cannot get root can still arrange
to start again from one of these, and they change rarely, so a change there is
worth a look.

gitleaks scans the working tree of each repository, not its history. History
that has already been published would be reported again every week, and a
report that repeats the same old finding every week teaches you to ignore it.

## Design

A shell script, `spycatcher-scan`, runs one scan and writes a log with a
`summary:` line and, where it can, a verdict on each line it found. A Python
script, `spycatcher-report`, reads those logs and a hand-written risk register
and grades the result. The bar widget and panel render the report's JSON and
decide nothing. All of the judgement is in the two scripts, and both run from a
terminal:

```bash
spycatcher-report                # the report in colour
spycatcher-report --all          # with the green items listed too
spycatcher-report --json         # what the widget reads
```

### How findings are graded

Every item in the report is green, amber or red, every section takes the worst
rating of its items, and the overall rating is the worst of the sections.

Green means there is no real exposure: the issue is fixed, not reachable, not
installed, or unfixed but negligible on this machine, so that a sensible habit
is all it needs. Amber means the exposure is real and is contained only while
the action the report gives is kept up; it also covers changes that are
probably yours but that only you can confirm. An item that stays amber for
good keeps the bar amber for good, so amber is kept for things that still need
watching. Red means something needs doing now, and in the file integrity
section it is kept for evidence: a package's file that fails pacman's check,
a boot file that changed with no package update, or a file in a system code
path that no package owns and that was written while pacman was not running.

### Findings, items and acknowledgements

A bar that is always red is soon ignored, so the file integrity section
reports findings rather than log lines, and lets you clear a finding once you
have checked it.

- A path that several checks logged is one finding, dated by the first check
  that logged it.
- Findings are grouped into items by the folder they are in, cut to its first
  three levels. A red item also takes the day it was first seen, which tells
  one event from another; an amber item is one folder. Files removed that no
  package listed are one item a day, since an upgrade removes them from
  hundreds of folders at once. One kernel update is therefore one item, not
  thousands, and the bar counts items.
- Each item has an eight-character ID, and the report prints the command
  that clears it:

  ```bash
  sudo spycatcher-report --ack 3f9a1c2b --reason "kernel-modules-hook backup"
  sudo spycatcher-report --ack amber --reason "my edits this week"   # every amber item
  spycatcher-report --acks            # what has been acknowledged
  sudo spycatcher-report --unack 3f9a1c2b
  ```

  An acknowledgement needs root, so nothing running as you can silence a red.
  `--ack` lists how many files it covers in each folder before it records
  them. It records each file of the item in the state it is in now (for a
  file, its inode, size and change time; for a link, its target; for a
  folder, its mode and owner) in `/etc/spycatcher/acknowledged.json`,
  readable by you and root, and notes it in the journal. It covers only what
  was logged before it, and only while the file is in that state: a file
  that changes again, or that a later check logs again, is a new finding.
  A file in a folder you may not look into, such as `/etc/sudoers.d`, is
  judged by the logs alone. The ID is made from the files in the item, so a
  file that joins an item after you read the report gives it a new ID and
  the old one no longer works. `--ack amber` leaves out any item with a file
  where a change could give someone root or code that runs at boot or login
  (sudoers, PAM, systemd, pacman's hooks, polkit, `/usr/local/bin` and the
  like); those need their own IDs. Every acknowledgement is listed in the
  report as a green item, and the headline says how many there are, so one
  you did not make shows.
- A red stays until it is acknowledged or a rule explains it; it does not
  leave the report when it is a week old. The scan keeps every AIDE log that
  still holds an open red when it prunes old logs. An amber leaves the report
  with the window (`--days`, seven by default).

The report covers nine sections: whether the scans ran on schedule, known
package vulnerabilities, file integrity, rootkits, AI model files, secrets in
your code, system hardening, standing risks, and privacy. The standing risks
section is not a scan. It holds protections you rely on, and each one is
tested live when the report runs, so that a protection you are relying on (the
firewall being active, the disk being encrypted) is reported red if it stops
being in place.

A fourth rating, grey, means off or not installed. A grey item or section is
shown so that you know it was not checked, but it never counts as a problem
and never changes the overall rating. Only the privacy section uses it.

### The privacy section

The Privacy (Black Ops) section reports on
Black Ops, the privacy
plugin, if you use it. It reads one file, `~/.local/state/black-ops/summary.json`,
which Black Ops 0.3.0 and later writes. That file holds counts and states
only, and the report shows only counts. It never reads another Black Ops
file, never runs Black Ops, and names no host, program or package.

| Rating | When |
|---|---|
| grey | Black Ops is not installed or is switched off; listen mode or the software watch is off |
| green | Black Ops is on and every count is clean |
| amber | watch findings not yet reviewed, protections that slipped or were never put in place, a summary that cannot be read, or a summary more than eight days old |
| red | listen mode saw a program on this machine contact a telemetry, analytics or crash-report host, and nobody has reviewed it |

Red has the same meaning as in Black Ops itself, so the report is never red
for anything Black Ops would show as amber. A summary more than eight days old
means the Black Ops watchdog has stopped, so its counts are shown but graded
amber. Risk register entries can lower the rating of individual items, but
not of a leak, which is cleared by reviewing it in Black Ops.

The weekly report runs as your own user, so the summary is found in your home
folder, or under `$XDG_STATE_HOME` when that is set. Run through `sudo`, the
report reads the summary of the user who ran `sudo`. Run as root with no such
user, it reads nothing and says so. `BLACK_OPS_SUMMARY` names another file,
which is what the tests use.

### The risk register

A package CVE or a gitleaks finding is only as serious as its circumstances on
this machine. A vulnerability in a library that nothing reachable uses is not
the same as one in the SSH server. The report cannot know the difference, so
the difference is written down by hand in a risk register,
`/etc/spycatcher/risk-register.toml`. Each entry records what the finding
is, what it means here, how confident the assessment is, the rating it
deserves, and what is being done about it. The report shows that text in place
of the raw finding.

A finding with no entry is not passed. A package CVE with no entry is shown as
"not yet assessed", red when the tracker rates it high or critical and amber
otherwise. A gitleaks finding with no entry is red. As a result, the
register can only make the report quieter for findings someone has actually
looked at.

Each CVE entry records the package version it was assessed against. If the
installed version is ever older than that, which happens after a downgrade,
the entry is flagged for re-assessment. Many entries in the Arch tracker stay
open long after the fix has shipped, so a common entry is one marked `stale`:
listed by the tracker, but already fixed in the installed version.

### A scan that stops running is a finding

A scan that has not run leaves no findings, and no findings looks the same as
a clean result. So the report grades each scan's age. A daily scan is amber
after two days without a log and red after seven. A weekly scan is amber after
nine days and red after 21, and the monthly audit after 35 and 62. A scan that
has never run is red. A scan whose last log records an error, or contains
a line marked `!!`, is red as well, because a scan that fails every night is
not protecting anything.

A run that was stopped before it wrote its summary line, by a shutdown or by
the unit's time limit, graded nothing. It is amber, and red when the unit
says it ran past its time limit or the run before it did not finish either,
since the next run meets the same work. A run that is still going, because
its unit is active or its log was written in the last ten minutes, is not
graded yet; the run before it is. A run counts as timed out when the unit
says so or when its log kept being written for the whole 45 minute limit,
since the unit's own record is reset when the next run starts.

An AIDE check set aside because pacman was updating packages (`summary:
skipped`) is not a result either. One is normal. When every check since the
last graded one was set aside, the first of them a day ago, that is amber,
and after three days red, with the reason the check logged.

The report reads a scan's result only from the lines the scan wrote itself.
Everything a scanning tool prints goes into the log with `| ` in front of
each line and control characters shown as `?`, because it can quote text an
attacker chose, such as a pickle file's import names, and a forged
`summary:` or `!!` line must not pass for the scan's own.

This is also what makes the bar widget safe to leave on a timer. The report
reads stored results and probes nothing live, so a colour that is a few minutes
old cannot hide a scan that went quiet: the report itself turns amber and then
red when that happens.

### AIDE explains changes before it reports them

A plain AIDE report on a rolling-release system is mostly package upgrades,
and after a large upgrade it runs to thousands of lines. `spycatcher-scan aide`
explains each change before it is reported:

- A file owned by a package that `pacman -Qkk` still verifies (content, size,
  file type, link target, permissions and ownership all match the package) is
  counted as a package change. A bare modification-time mismatch is ignored,
  because it is common and harmless.
- A file owned by a package that fails that check is red, and so is every
  file of a package whose file list (mtree) is missing.
- A file in a system code path that no package owns, and that no rule below
  explains, is amber when it was last changed while pacman was running: from
  the hooks pacman runs before a transaction until the last line it logs for
  that run. It reads "appeared during the package update of DATE, which no
  rule explains". The same file written while pacman was not running is
  red. `/boot`, `/etc`, `/usr/local`, `/opt`, `/root` and the home folders
  keep their own grading.
- A package's configuration file that you have edited is amber.
- A removed file is a package change when it belonged to a package, at the
  last check, that pacman has since upgraded, removed, reinstalled or
  downgraded. Each check keeps the package file lists beside the AIDE
  baseline for this, in `/var/lib/spycatcher/owners.gz`, readable by root
  only. Any other removed file is amber, including one that pacman still
  lists for an installed package.
- The modules of a kernel that is no longer installed are one package-change
  line that counts them, once the folder `/usr/lib/modules/<version>` is
  gone, no package owns it, and it is not the running kernel's.
  `kernel-modules-hook` keeps the running kernel's modules through an
  upgrade and deletes them after the next boot, outside any pacman run.
- The module index `depmod` writes into `/usr/lib/modules/<version>`
  (`modules.dep`, `modules.alias`, their `.bin` forms and the rest) is a
  package change when that folder belongs to an installed kernel package and
  the file is byte for byte what depmod builds now. The check runs depmod
  into a temporary folder that links to the real module tree, so nothing on
  the system is written, once per kernel version and run, which takes about
  a second. The modules themselves are checked as package files.
- A kernel module that DKMS builds, such as the NVIDIA driver from
  `nvidia-open-dkms`, is installed into
  `/usr/lib/modules/<kernel>/updates/dkms/`, which no package owns. It is a
  package change when it is a regular file for a kernel whose module folder
  an installed package owns; it is byte for byte the copy dkms keeps of its
  build in `/var/lib/dkms/<name>/<version>/<kernel>/<arch>/module/`, which
  must be a regular file owned by root that no one else may write; the
  source it was built from, `/usr/src/<name>-<version>/`, is reached
  without a link, its `dkms.conf` belongs to an installed package, and
  pacman finds nothing wrong with any of that package's files there; and the
  module was last changed while pacman ran the dkms package's
  `70-dkms-install.hook`, from when pacman.log records the hook starting
  until the next line pacman logs. A module copied in by hand, or changed
  later, stays red.
- A file a package's own install script writes, such as a link to the build
  that suits this CPU, or its own file it edits with `sed -i`, is a package
  change when the file was last changed while pacman.log shows that package
  being installed or upgraded to the version installed now, and that
  version's install script has a command that writes the file's exact path:
  a redirection, the last operand of `cp`, `mv`, `install` or `ln`, an
  operand of `touch`, `tee` or `truncate`, a file `sed -i` edits, or `dd`'s
  `of=`, written out or held in a variable the script gives one literal
  value. When the script only names the path, for example removing it before
  another program writes it again, the file is amber, to confirm. A package's own file must otherwise pass pacman's check
  apart from its content, and a link must point at a file of the same
  package that pacman verifies. The time used is the file's change time
  (ctime), which the kernel sets on every write and `touch` cannot set back,
  so a file edited at any other moment, even by the same package's commands
  run by hand, stays red. See Limits for what this rule cannot tell.
- A package file that a pacman hook of your own patches after each upgrade
  can be listed in `HOOK_PATCHED` in `scan.conf`, as
  `file=hook:sha256`, with the SHA-256 of the file as patched (several sums
  may be given, separated by commas). Nothing is listed by default. A listed
  file is a package change only while its content has one of the listed
  sums, the hook file is in `/etc/pacman.d/hooks`, owned by root and
  writable by no one else, pacman finds nothing wrong with the file but its
  content, and the file was last changed within a minute of pacman.log
  recording that hook running. A patch applied by hand, other content, or a
  later edit stays red. When the package changes the file upstream, the
  patched file changes too, and stays red until its new sum is listed.
- A changed file under `/boot` is a package change if pacman installed,
  upgraded or removed anything since the last check, because that is when the
  boot image is rebuilt. With no package change it is red, with one
  exception below.
- limine-snapper-sync rewrites `/boot/limine.conf`, its `.old` copy and its
  own `limine_history/snapshots.json` whenever snapper creates or removes a
  snapshot, which happens on timers and around pacman runs that change no
  package. Such a change is a package change only when limine-snapper-sync's
  own program logged writing that file since the last check, at the time the
  file was written, and the file differs from a trusted copy of
  `limine.conf` only inside the Snapshots sub-menu. Every entry in that
  sub-menu must boot a command line the trusted copy already boots, with
  only the snapshot's own subvolume swapped in, and a kernel image the
  trusted copy already boots. Any other difference, such as a changed kernel
  command line, kernel or initramfs path, or a new entry, stays red. The
  trusted copy is kept in `/var/lib/spycatcher`, readable by root only,
  and is refreshed after each check that finds nothing red under `/boot`.
  Until the first check has made it, every such change stays red. The
  weekly report cannot repeat this check for a red line logged earlier,
  because it cannot read `/boot` or the trusted copy, so those stay red.
- A file that no package owns is amber under `/usr/local`, `/opt`, `/etc`,
  `/root`, `/home` and the desktop user's home folder wherever it is, where
  your own changes normally land, and red anywhere else, such as `/usr/bin`
  or `/usr/lib`. Watched folders in the home folder get the same lighter
  folder rule as the system ones, so a new file in `~/.ssh` is one line,
  not also a line for the folder's times.
- A package file on a file system without Unix modes, such as a FAT `/boot`
  mounted with `fmask=0077`, gets its mode and owner from the mount, so
  pacman reports a permissions mismatch for it after every upgrade. It is a
  package change when pacman finds nothing else wrong with it, its content
  included, its mode, owner and group are exactly what the mount options
  give, and those are safe: owned by root, in group root or the packaged
  group, writable by no group or other, and with no permission the package
  does not give apart from the execute bits FAT gives every file. A mount
  that hands the files to a user, or lets others write them, stays red. The
  weekly report runs as the desktop user, who cannot look into such a
  `/boot`. For a red line of this kind logged earlier, where the scan's
  pacman check found nothing but the mode, the report judges a file it
  cannot look at from the mount options alone, since the mount gives every
  file there its mode.
- A cache that a pacman hook rebuilds (glibc's and lib32-glibc's
  `gconv-modules.cache`, systemd's `hwdb.bin`, the GTK 3 input method
  cache, the desktop file MIME cache, GIO's and GTK 4's GIO module caches,
  graphviz's plugin list `config8`) is a package change when it is byte for
  byte what its tool (`iconvconfig`, `systemd-hwdb`,
  `gtk-query-immodules-3.0`, `update-desktop-database`, `gio-querymodules`,
  `dot -c`) builds now, run by its full path with a fixed environment into
  a temporary folder. When it was
  written does not count, since `touch` can set that.
- A configuration file a package keeps across upgrades (pacman's backup
  list) whose only change is
  a tighter mode, and perhaps another group, while root still owns it, is
  amber, like an edited configuration file: cupsd rewrites `printers.conf`
  0600 `root:cups`. A permission the package does not give, or another
  owner, stays red. The scan applies this as root. A red line of this kind
  logged before 0.2.12, where the scan's pacman check found nothing but the
  mode, is re-checked by the report too, for a file unchanged since; as the
  desktop user, pacman cannot read the file, which is then allowed.
- A browser's `policies.json` that a local pacman hook rewrites after every
  update, to switch telemetry and studies off, always fails pacman's checksum.
  It is not red while that hook is installed and the file holds only the
  browser's own policies and those two switches. Any other policy
  leaves it red. The weekly report applies the same check to a red line
  logged before this rule existed.
- Some packages link `/usr/bin/<name>` to the build that suits this CPU or
  graphics card, from their install script, on every upgrade. No package owns
  such a link, so it would read as an unpackaged file in `/usr/bin`. It is a
  package change only while it resolves to a file a package owns, pacman finds
  that file unaltered, and that same package's install script has an `ln -s`
  command for the link's exact path whose target is written out in full and
  resolves to that same file. A link repointed to any other file, even
  another file of the same package, stays red. So does a link whose target
  the install script only works out when it runs (held in a variable), or
  for which it names two different targets. The weekly report applies the
  same check to a red line logged before this rule existed.
- Such a link whose target is held in a variable can be accepted on one
  machine by listing it in `SCRIPTLET_LINKS` in `scan.conf`, with the package
  whose files it may point to. Nothing is listed by default. A listed link is
  a package change only while it is a symlink, not a file, and resolves to a
  file owned by that package alone, pacman finds that file unaltered, and the
  package's install script has an `ln -s` command for the link's exact path.
  The weekly report applies the same check, through the same code, to a red
  line logged before the link was listed.

AIDE's own type letter decides whether an entry is a folder, never a look at
the path, which would follow a symlink put where a folder was. A folder a
package lists must still be a folder, and a file must not have become one; a
folder whose mode or owner changed is graded like a file. AIDE writes a
backslash or a control character in a name as `\ooo`; names are decoded
before they are checked, and a name that holds a control character, such as
a new line, is red as AIDE wrote it.

The changes are graded from one `pacman -Ql` of every installed package's
files, taken just before AIDE reads the system, one `pacman -Qkk` over the
packages that own a changed file, and one call of `spycatcher-report` for the
rules above that need it, never from one pacman call per file. A kernel
update changes tens of thousands of files, which takes seconds this way. The
lists are kept in the scan's private temporary folder and no path reaches a
command line.

A package update in the middle of a check gives a picture that is neither
the old system nor the new one, and pacman itself can fail while its
libraries are replaced. So the check waits up to ten minutes for a running
pacman, one that holds its lock file open, before it starts. A lock file no
process holds is left over from a pacman that crashed; the check notes it
and goes ahead, since listing and checking packages only reads. A check during which pacman starts a transaction is
set aside: it logs `summary: skipped`, which the report does not grade, and
keeps the baseline, so the next check reports every change in full. If
pacman cannot list or check its packages at all, the run is an error and the
baseline is kept too.

After each check it re-baselines, so the next run reports only what is new. The
previous baseline is kept as `/var/lib/aide/aide.db.prev.gz`, and the logs keep
every finding for the weekly report. Each log records the version of the
rules it was graded with. The weekly report re-checks red lines logged by
earlier versions against the rules above, and red lines of any version
against `SCRIPTLET_LINKS` and `HOOK_PATCHED`, which may have been added to
since, but only while the file has not changed since that check started: a
file written later, or while the check ran, may not be what the check saw. It also clears a red
"unpackaged" line whose file is a package's file that pacman verifies now
and that has not changed since the run that logged it. In the report, amber changes are grouped
by folder, so a week of ordinary work reads as a few lines rather than
hundreds.

### rkhunter changes are accepted only when pacman verifies them

rkhunter records the properties of system binaries and warns when they change.
It has no pacman support, so after every upgrade it warns about every binary
the upgrade replaced. `spycatcher-scan rkhunter` checks each file named in that
warning with `pacman -Qkk`. If every one of them is owned by a package and
matches it byte for byte, the warning is accepted and rkhunter's record is
updated. If any one of them cannot be verified, nothing is accepted, the record
is left alone, and the report shows each unverified file as red. Files that
pacman did verify are not reported. Every other rkhunter warning is red.

### What the model scan covers

Model files in the older pickle format (`.ckpt`, `.pt`, `.pth`, `.bin`, `.pkl`,
`.pickle`) can run arbitrary code when they are loaded. `picklescan` looks
inside them for the imports that would do that: a dangerous import is red and
a suspicious one is amber. `.safetensors` and GGUF files are data only and
cannot run code, so there is nothing for it to find in them.

The scan covers only that. Python environments (`.venv`, `venv`,
`site-packages`) are skipped, along with `node_modules` and `.git`, because
they hold library test fixtures rather than models and flood the scan with
parse warnings. That means a malicious pip package is not covered: supply-chain
risk in Python packages is a different problem, and this scan does not claim
to address it. If `picklescan` crashes partway through a folder, the run is
recorded as failed, not as clean.

## The bar widget

The widget is a lock glyph tinted to match the report. It is a lock rather
than a shield so that it cannot be confused with VPN Check, which usually sits
next to it.

| Lock | Meaning |
|---|---|
| green | the report is green |
| amber | the report is amber, or could not be read |
| red | the report is red |

A report that fails to run would otherwise look the same as a green one, so a
failure always shows amber, and the panel says why. The green, amber and red are fixed colours rather
than theme colours, because a theme is free to make its urgent colour a soft
pink, and a warning that reads as decoration does not work as a warning.

The widget re-reads the report every five minutes whether or not the panel is
open. That is cheap: the report reads stored logs and asks pacman a few
read-only questions, touches no network, and takes about two seconds on the
machine it was written on. It uses the copy installed in `/usr/local/bin`,
and falls back to the copy in the plugin if the installed one is too old to
support `--json`.

Clicking the lock opens the panel. Middle-clicking re-reads the report. The
panel shows:

- the overall rating, the report's one-line summary, and the period it covers;
- a Refresh button, and an Open full report button that writes a fresh HTML
  report and opens it in the browser;
- one block per section, with its rating and a one-line verdict. Sections with
  something to say start unfolded and green ones start folded. A finding shows
  what it is, the detail behind it, and a line headed "What is being done".
  Green items inside a section that is not green are hidden behind a link, so
  the findings that need attention come first;
- any error, or anything the report printed on stderr, such as a risk register
  that could not be parsed.

Findings quote file names, repository names, package output and the names a
model file imports, any of which someone else can choose. The panel shows
every string as plain text, never as rich text, so a name that holds HTML,
such as an image tag, is shown as the characters it is and loads nothing.
The HTML report escapes every string, the terminal report shows control
characters and text-reordering marks as `?`, and desktop notifications write
`&`, `<` and `>` as entities.

The panel can also be driven over IPC, for example from a key binding:

```bash
omarchy-shell brightwalker25.spycatcher toggle
omarchy-shell brightwalker25.spycatcher refresh
```

## The weekly report

On Monday at 13:00, after the Monday scans, a user timer writes the report as a
self-contained HTML page in `~/.local/share/spycatcher/`, named by date so
that past weeks stay comparable, and points `latest.html` at it. The folder
and its pages are readable by you alone. It then sends
a desktop notification with the overall rating and the summary line. The
notification is marked critical when the report is red, and has an Open action
that shows the page. If the laptop is off at 13:00, the report runs at the next
login.

Each scan also sends its own notification as it finishes when it finds
something: vulnerable packages, secrets in a repository, unexplained file
changes, rootkit warnings, a dangerous or suspicious model
file, or a failed AIDE or model scan. Packages with a fix waiting, secrets,
unexplained changes, rootkit warnings and dangerous model files are sent as
critical. The
logs are written either way; a notification is skipped only when there is no
graphical session to send it to.

## Limits

A rootkit loaded at boot runs beneath the scans and can hide from anything that
runs on the same machine, including all six of these. AIDE watches `/boot` and
reports a boot file that changes with no package update as red, which catches a
tampered image on disk, but it cannot see anything that has hidden itself from
the running kernel. The report does not track Secure Boot.

rkhunter is dated. Its rootkit signatures have seen little maintenance for
years, so it mainly finds old, well-known rootkits. It is kept for its checks
of file properties, hidden files and startup configuration, which are still
useful, rather than for its signature list.

AIDE comes from the AUR, not the official repositories, so `pacman -Syu` does
not update it. Update it with your AUR helper, for example `yay -Syu`.

A program already running as root that writes a file in a system code path
while a real package update runs gets amber, not red, if no rule explains the
file. A file's change time cannot be moved into a past update without
changing the clock. An acknowledgement is only as good as the check behind
it, and root can write `acknowledged.json`; the report lists every
acknowledgement so that one you did not make is visible.

The risk register is judgment written by hand. An entry is only as good as the
assessment behind it, and a wrong entry makes a real finding look managed.
Check the fix version against the upstream project before marking an entry
`stale`, and re-assess when a package changes. The register is keyed by package
name, so once a package has an entry, a new CVE for that same package is shown
with the existing entry's text rather than as not yet assessed. The ratings in
the example register describe the machine it was written on and are not a
judgment about yours.

When `arch-audit` cannot reach the Arch security tracker, it records the run as
skipped. The report ignores skipped runs, so the package section keeps showing
the last real result, and a long offline stretch appears as a stale scan in
the schedule section.

The gitleaks scan looks only at working trees, and only for repositories whose
`.git` folder is at most three levels below the scan root, which means the
repository itself is at most two levels below it.

Several AIDE rules accept a file whose content cannot be compared with
anything: a file a package's install script writes or edits, and an amber
file it only names. They rest on when the file last changed, which only the
kernel sets, so a file changed at any other moment stays red. A program that
already runs as root could still wait for the package's step and write the
file inside it, and that write would be accepted whatever it holds. The
module index and `HOOK_PATCHED` files are compared by content and do not
have this gap. A module DKMS built has it too: AIDE does not watch
`/var/lib/dkms`, so a program running as root could write the module, the
copy dkms keeps of it and a hook line in pacman.log.

AIDE does not record a file whose name is not valid UTF-8; it skips such a
name without a word, so a file planted under one is not seen by this check.
rkhunter's check of hidden and odd files is the only cover for that here.

lynis is written with servers in mind. A score in the high 60s is typical for a
desktop, and most of its suggestions are server hardening. Its warnings are
advice on how the machine could be set up, not signs that anyone has been in
it, so the report lists them in green for information and never grades on
them. The one it raises whenever arch-audit reports anything is marked as
covered by the package section. An audit that is missing or overdue is
graded in the scan schedule section, like every other scan.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover the privacy section against the fixtures in
`tests/fixtures/black-ops`. They run in a temporary folder and do not read
your home folder, `/etc` or the scan logs.

```bash
bash tests/sandbox-install.sh
```

This runs the installer, and the installers of earlier releases, as your own
user against a temporary folder that stands in for `/` and for your home
folder, with `pacman`, `systemctl`, `aide`, `uv` and the other system commands
replaced by stand-ins. It checks fresh installs, the move from each Security
Scan release to the new names (run twice, and as a dry run), uninstalls, and
that files the plugin did not write are refused and left unchanged. It needs
no root and changes nothing outside the temporary folder.

## Settings

| Key | Default | Effect |
|---|---|---|
| `refreshIntervalMs` | 300000 | How often the bar re-reads the report, between 30 seconds and an hour |
| `reportDays` | 7 | How many days of scan results the bar and panel grade, from 1 to 7. Each scan's latest run always counts, even when it is older; the Monday report always covers seven days |
| `hideWhenGreen` | false | Hide the lock when the report is green, so it shows only when it is amber or red |

These affect only the widget. The scans run on their own timers whatever the
widget is set to. The scan settings live in `/etc/spycatcher`; see
[INSTALL.md](INSTALL.md#configuration).

## Requirements

Arch Linux or Omarchy with systemd, the Omarchy shell for the widget, `uv` for
installing `picklescan`, and an AUR helper for AIDE. `picklescan` and `numpy`
come from PyPI, pinned to the exact versions and SHA-256 hashes in
`system/picklescan-requirements.txt`, so what runs as root is fixed by the
commit you install from. The installer adds the
rest from the official repositories; see
[INSTALL.md](INSTALL.md#requirements). Your account needs a primary group of
its own in the local account files, or the installer refuses to install; see
[INSTALL.md](INSTALL.md#configuration).

## Changelog

[CHANGELOG.md](CHANGELOG.md).

## Written with AI help

Yes, an AI helped write this. No, it is not Skynet (or is it? 😉). Either
way, I have checked the code to make sure it is not plotting Judgment Day. If
that still puts you off, no hard feelings. The whole point of Linux is that
you decide what runs on your computer.

## Licence

MIT. The bar widget and panel scaffolding derive from Omarchy's own shell
plugins; see `LICENSE`.
