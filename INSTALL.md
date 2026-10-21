# Installing Security Scan

There are two parts to install. The scans, their timers and the weekly report
are installed system-wide by a privileged installer, because the scans run as
root. The bar widget is an ordinary Omarchy shell plugin. Either works without
the other: the scans and the weekly report need no widget, and the widget only
reads what the scans have stored.

For what each scan catches and how the report grades it, see the
[README](README.md).

## Requirements

| Needed | Used for |
|---|---|
| Arch Linux or Omarchy, with systemd | the timers, and `pacman` for installing and verifying packages |
| `sudo` | running the installer |
| `uv` | installing `picklescan`, which is not packaged for Arch |
| an AUR helper such as `yay` | installing AIDE, which is only in the AUR |
| Omarchy shell with plugin support | the bar widget and panel |
| a primary group of your own, named after your account, in the local account files | sharing `scan.conf` and the risk register with the weekly report and no one else; see [Configuration](#configuration) |

The installer adds `arch-audit`, `lynis`, `gitleaks`, `rkhunter` and `python`
from the official repositories itself. It does not install `uv` or AIDE.

AIDE has to be built by your own account, because AUR helpers refuse to build
as root. Install it before running the installer:

```bash
yay -S aide
sudo pacman -S uv
```

Neither is strictly required for the rest to install. Without AIDE, the
installer carries on, and every AIDE run logs "aide not installed", which the
report shows as a failed scan. Without `uv`, `picklescan` is skipped and the
model scan fails the same way. In both cases the installer ends with a note
saying what is left to do, and re-running it after installing the missing
piece completes the setup.

## Installing the scans

```bash
git clone https://github.com/brightwalker25/omarchy-security-scan.git ~/Work/omarchy-security-scan
cd ~/Work/omarchy-security-scan
bin/security-scan-install --dry-run
sudo bin/security-scan-install
```

The dry run needs no root. It prints every command the installer would run
and changes nothing, so you can check what will run as root before running
it. Without root it cannot see inside `/var/lib/aide` or
`/var/lib/rkhunter`, and says so rather than guessing whether the baselines
exist.

The installer treats the account that ran `sudo` as the desktop user: the one
that receives notifications, may read the logs, and whose home folder is
scanned. From a root shell, or to choose another account, pass
`--user NAME`.

It installs, in order:

1. The packages above, with `pacman -S --needed`.
2. `picklescan` and `numpy`, with `uv`, into a virtual environment in
   `/opt/security-scan/picklescan`, with the command linked as
   `/usr/local/bin/picklescan`. It goes in a root-owned folder rather than your
   `~/.local` because it runs as root. Both come from PyPI, so they are pinned
   to the exact versions and SHA-256 hashes in
   `system/picklescan-requirements.txt`. The installer runs
   `uv pip sync --require-hashes --only-binary :all:` with that file: any
   download whose hash is not listed is refused, and nothing is built from
   source. It never upgrades them on its own; a new version arrives only as a
   change to that file in a new commit of this repository, which you can read
   before re-running the installer. `uv pip sync` makes the environment match the
   file exactly, and it is rebuilt when Arch moves to a new Python version. numpy is there
   because picklescan needs it to read `.npy` files.
3. `security-scan` and `security-report`, copied into `/usr/local/bin`.
4. The configuration in `/etc/security-scan`, described under
   [Configuration](#configuration).
5. The system units: `security-scan@.service` and one timer per scan, all
   enabled and started.
6. The weekly report's units, `security-report.service` and
   `security-report.timer`, as user units in `/etc/systemd/user`, enabled for
   every user and started for the desktop user.
7. The first baselines for AIDE and rkhunter, described under
   [First run](#first-run).

It is safe to run again. Files that hold your own settings are kept, and
everything else is brought up to date with the checkout. After pulling a new
version of the repository, run it again: until you do, the installed programs
and units stay as they were.

### Files that are not this plugin's

Before it changes anything, packages included, the installer checks every path
it would write over. A unit in `/etc/systemd/system` or `/etc/systemd/user` is
replaced only when it is a regular file, not a symlink, owned by root, whose
content is exactly a unit this plugin has shipped, in this checkout or in an
earlier release. `security-scan` and `security-report` in `/usr/local/bin` are
replaced only when they are this plugin's programs. `/opt/security-scan` and
`/etc/security-scan` must be real folders owned by root that only root can
write to. `/opt/security-scan/picklescan` must be a Python virtual environment
that this installer made: it carries the marker file
`.security-scan-installer`, or has picklescan installed in it, as earlier
releases left it. If any path holds something else, the installer lists each
one with the reason and stops without changing the machine. The desktop user
can never be root, under any name or as `--user 0`.

A unit you have edited counts as yours, so it is not overwritten. To change one
of this plugin's units, use a drop-in instead (`sudo systemctl edit
security-scan-lynis.timer`, for example), which the installer never touches.
To go back to the shipped unit, delete the edited file and run the installer
again.

New files are written to a temporary name in the same folder and then renamed
into place, so a symlink at the destination is replaced rather than followed,
and an interrupted run never leaves a half-written file. A file that is
already up to date is left as it is, so re-running the installer does not show
up in AIDE. Existing folders keep their permissions, and a regenerated
`aide.conf` is never made more open than the file it replaces.

If you once installed the report's units by hand in `~/.config/systemd/user`,
those copies take precedence over the ones in `/etc/systemd/user` and would
hide every future update. The installer does not delete files in your home
folder, so it lists them and prints the commands to remove them.

### Why the programs are copied rather than linked

`security-scan` runs as root on a timer, and `security-report` is run by the
weekly report. If `/usr/local/bin/security-scan` were a symlink into the
checkout, anyone who can write to the checkout, which includes your own
account and anything running as it, could change what root runs next. So both
are copied, owned by root, and a change to the checkout does nothing until the
installer is run again. The same reasoning is why `scan.conf` is ignored if it
is not owned by root or is writable by anyone else: it is sourced by a script
running as root.

## Installing the widget

The plugin is installed from a checkout by linking it into the plugins folder.
If you cloned the repository to install the scans, use that same checkout:

```bash
ln -s ~/Work/omarchy-security-scan ~/.config/omarchy/plugins/brightwalker25.security-scan
omarchy plugin enable brightwalker25.security-scan --section right
```

The plugin id is the link name, so the link has to be named exactly
`brightwalker25.security-scan` whatever the checkout is called. If `enable`
reports that it cannot find the plugin, ask the shell to look again and then
enable it:

```bash
omarchy-shell shell rescanPlugins
omarchy plugin enable brightwalker25.security-scan --section right
```

`--before <id>`, `--after <id>` and `--index <n>` place the lock next to a
particular widget rather than at the end of the row, for example next to VPN
Check:

```bash
omarchy plugin enable brightwalker25.security-scan --section right --after brightwalker25.vpn-check
```

After editing the QML, restart the shell to see the change:

```bash
omarchy-restart-shell
```

Validate the manifest after editing it:

```bash
omarchy plugin validate ~/Work/omarchy-security-scan
```

The widget runs `/usr/local/bin/security-report --json`, and falls back to
the copy inside the plugin if the installed one is missing or too old to
support `--json`. Either way it needs the logs in `/var/log/security-scan`,
which only exist once the scans have been installed and have run.

## First run

Two scans compare against a baseline, and both baselines are made during the
first install.

AIDE records the state of every watched file. If there is no baseline yet, the
installer starts the AIDE scan in the background, and that first run creates
the baseline and compares nothing. On a typical system it takes several
minutes. Its log records "baseline created", and the next daily run is the
first real check.

rkhunter needs a record of file properties before its first check, or it
reports every binary as changed. The installer runs `rkhunter --propupd` to
create it if there is none.

The other scans have no baseline and start on their normal schedule. Until
each has run once, the report shows it as never having run, in red, and the
lock in the bar is red. To get a complete report straight away, run each scan
by hand as shown under
[Running scans and reports by hand](#running-scans-and-reports-by-hand). The
gitleaks and models scans take a few minutes, and lynis takes longer.

The first package and gitleaks results are likely to include findings with no
risk register entry. A package finding is shown as not yet assessed, and a
gitleaks finding as a possible secret in red. That is expected: see [Writing a risk register entry](#writing-a-risk-register-entry).

## Configuration

Everything lives in `/etc/security-scan`, owned by root. These files hold
private names and paths, so no other local user can read them. The report
runs as the desktop user, so the two it reads are shared with that user's own
group; the rest are root's alone.

| File | Installed | Readable by | Holds |
|---|---|---|---|
| `scan.conf` | once, never overwritten | root and your group (0640) | the desktop user, the folder of repositories for gitleaks, the folders of model files, links to accept from install scripts, files your own pacman hooks patch |
| `aide.conf` | generated on every install | root (0600) | what AIDE watches and ignores |
| `gitleaks.toml` | once, never overwritten | root (0600) | extra gitleaks rules and allowlists |
| `risk-register.toml` | once, never overwritten | root and your group (0640) | your assessment of each known finding |

"Your group" is the group with your user name, when it is your primary group
in `/etc/passwd` and `/etc/group`, is the only group with its GID, has no other
members in `/etc/group` or `/etc/gshadow`, and is no other account's primary
group. Only the local files list every account, so the `passwd` and `group`
lines in `/etc/nsswitch.conf` may name only `files` and `systemd`, not a
directory such as LDAP or SSSD. If there is no such group, for example when
every account has `users` as its primary group, the installer refuses to
install and changes nothing, because sharing `scan.conf` and the risk register
with the report would let other local users read them too. Give your account a
private primary group and log in again before installing:

```bash
sudo groupadd "$USER" && sudo usermod -g "$USER" "$USER"
```

If a group with your user name already exists, `groupadd` fails. Then make
that group your primary group with `usermod -g` instead, once it has no other
members and no other account has it as its primary group. Installing over a
version before 0.2.10 tightens existing files once and prints
`make ... private` for each; it never loosens a mode, and leaves a symlink or
a file root does not own as it is, with a note. If the report reads a file
that was given to another group, such as `users`, it moves to your group, with
`take ... from group`; a file only root reads loses its group permissions.
Use `sudo` to read `gitleaks.toml` and `aide.conf`.

`/etc/rkhunter.conf.local` is also installed once and never overwritten. It
holds rkhunter exceptions for files that are known to be harmless on a stock
Arch install.

`scan.conf` sets five values:

| Key | Default | Effect |
|---|---|---|
| `DESKTOP_USER` | the account that ran `sudo` | who is notified and may read the logs; the scans refuse to run without it rather than guess |
| `SCAN_ROOT` | `~/Work` | gitleaks scans every repository whose `.git` folder is at most three levels below this |
| `MODEL_ROOTS` | `~/AI ~/.cache/huggingface` | folders searched for model files, separated by spaces; folders that do not exist are skipped |
| `SCRIPTLET_LINKS` | empty | `link=package` pairs, separated by spaces: symlinks a package's install script points at a file it picks at run time, which AIDE then treats as package changes while they pass the checks described in the README; read only from the file, never the environment |
| `HOOK_PATCHED` | empty | `file=hook:sha256` entries, separated by spaces: package files that a pacman hook of your own in `/etc/pacman.d/hooks` patches after each upgrade, given by the hook's file name and the SHA-256 of the file as patched (several sums may be separated by commas), which AIDE then treats as package changes while they pass the checks described in the README; read only from the file, never the environment |

The installer writes the home folder out in full, since the scans run as root
and `~` would mean root's home. A variable set in the environment overrides
the file for that run, except `SCRIPTLET_LINKS` and `HOOK_PATCHED`, which the
weekly report also reads and so are taken from the file alone. A
`scan.conf` installed before 0.2.12 has no `HOOK_PATCHED` line; add one by
hand if you need it, since the installer never rewrites the file.

`aide.conf` is generated from `system/aide.conf.in` in the checkout, with your
home folder filled in, and is replaced every time the installer runs. If the
installed copy differs from what would be generated, it is saved first as
`aide.conf.bak-YYYYMMDD`, with the same permissions. A backup from earlier the
same day is not overwritten; the new one gets a `.1`, `.2` and so on after the
date. To change what AIDE watches, edit the template and
run the installer again, not the installed file.

`gitleaks.toml` extends the upstream rules. The example shows how to add a
rule for a private name that should never appear in a published repository,
and how to scope an allowlist entry to one rule, one file and the text on the
matching line, so that a real secret in the same place is still reported.
Replace the placeholder name in the installed copy only, never in a file you
commit.

An allowlist `paths` pattern is matched against the file's path relative to
the root of the repository being scanned, such as `data/signatures.toml`, not
against its full path. Before 0.2.9 the full path was used, so a pattern that
names the repository folder, such as `my-repo/data/signatures\.toml$`, no
longer matches. Drop the folder name from it, and keep the rule and line
conditions so the entry stays narrow.

### Writing a risk register entry

The register has four kinds of entry. The installed copy contains one example
of each; replace them with your own assessments, since their ratings describe
another machine.

A package CVE is keyed by package name, as `arch-audit` prints it:

```toml
[cve.wget]
assessed = 2026-09-23
assessed_version = "1.25.0-6"
status = "open"
rating = "amber"
confidence = "medium"
risk = "wget sends your login to a second site if the first one redirects it (CVE-2021-31879)."
finding = "Upstream never fixed this in wget 1.x. It only matters when wget is given a username and password."
action = "Do not use wget with --user or --password; use curl for anything that needs credentials."
```

- `assessed_version` is the version you checked, from `pacman -Q wget`. If the
  installed version is ever older, the entry is flagged for re-assessment.
- `status` is `stale` when the tracker still lists a CVE that the installed
  version already fixes, `open` when there is no fix and the risk is managed,
  or `accepted` for a deliberate choice.
- `rating` is `green` for no real exposure, `amber` for a real but contained
  one, and `red` for something that needs doing now. The report uses this
  rating in place of the tracker's severity.
- `risk` replaces the tracker's line in the report, `finding` explains the
  rating, and `action` says what is being done. Write them as plain sentences;
  they are shown as they are.

Before marking an entry `stale`, check the upstream fix version against the
installed version rather than trusting the tracker or a summary of it. The
entry covers the package, not one CVE, so when the tracker adds a new CVE for
a package that already has an entry, update the entry.

A gitleaks finding is keyed by any short name, and matched by the repository
path and the rule id, both as the log prints them:

```toml
[secrets.example-handover]
assessed = 2026-09-23
repo = "/home/your-user/Work/example"
rule = "private-local-identity"
file = "NOTES.md"
rating = "amber"
risk = "NOTES.md contains a private account name in home-directory paths."
finding = "Committed and pushed, but the repo is private. Not a password or key."
action = "Replace the paths with ~ before the repo is made public, and clean the history then too."
```

`repo` must be the absolute path, with the home folder written out. A real key
or password does not belong in the register: rotate it and remove it from the
repository. An allowlist entry in `gitleaks.toml` is the right place for a
match that is not a secret at all.

A standing risk records a design choice and names a live check:

```toml
[standing.firewall]
assessed = 2026-09-23
check = "ufw_active"
rating = "green"
status = "accepted"
risk = "Inbound connections."
finding = "ufw denies all inbound connections except the ones you have allowed."
action = "None needed while ufw stays active."
```

The checks available are `ufw_active` and `root_luks`. The rating applies
while the check holds. If it stops holding, the entry turns red. `root_luks` holds when the device mounted at `/` is itself a LUKS
mapping.

A privacy entry lowers the rating of one item in the Privacy (Black Ops)
section. It is keyed by the item's name, and `count` limits it to the number
of findings that were looked at:

```toml
[privacy.watch-unreviewed]
assessed = 2026-09-24
count = 1
rating = "green"
status = "accepted"
risk = "Installed software contains the address of a tracking service."
finding = "The one finding is a crash reporter that is switched off in the program's settings."
action = "Review it in Black Ops when there is time; a second finding is reported again."
```

The names are `unreadable`, `stale`, `watch-unreviewed`, `watch-noscan`,
`slipped`, `unapplied`, `attention`, `registered` and `warn`. An entry can
only lower a rating. A leak seen by listen mode cannot be accepted in the
register; review it in Black Ops instead. The register is installed once, so
an existing copy does not gain this example; add an entry by hand if you need
one.

If the register cannot be parsed, the report still runs as though it were
empty, so every finding shows as not yet assessed, and the parse error appears
at the foot of the panel.

## Running scans and reports by hand

Start a scan through its unit, so that it runs exactly as the timer runs it:

```bash
sudo systemctl start security-scan@aide.service
```

The instances are `arch-audit`, `aide`, `models`, `gitleaks`, `rkhunter` and
`lynis`. The command returns when the scan finishes. Each run writes a log in
`/var/log/security-scan`, named by scan and time, and the last 12 logs of each
scan are kept. The folder belongs to root and your group (0750), and the copy
of the lynis report in it is 0640, so reading the logs and running the report
need no `sudo`. "Your group" means the same here as in
[Configuration](#configuration), and each scan checks it again when it runs,
because groups can change after installing. If the group is no longer yours
alone, for example because another account was added to it, the scan makes
the folder root's alone (0700), writes the lynis copy 0600, and says so in
the journal. The report then cannot read the logs until the group is private
again.

To point one run somewhere else without editing `scan.conf`, run the script
directly with the variable set:

```bash
sudo env SCAN_ROOT=/home/your-user/Projects /usr/local/bin/security-scan gitleaks
```

The report reads the logs from the last seven days:

```bash
security-report
```

| Flag | Effect |
|---|---|
| `--plain` | no colour |
| `--all` | also list the green items inside sections that need attention |
| `--html FILE` | write a self-contained HTML page to `FILE` |
| `--json` | machine-readable output, as the widget reads it |
| `--status` | print only the overall rating and the one-line summary |
| `--days N` | look back `N` days instead of 7 |

The report exits 1 when the overall rating is red and 0 otherwise, so it can
be used in a script. `--days` changes which AIDE, rkhunter and model scan logs
are read. The package, gitleaks and lynis sections always read the latest log,
and the scan ages are measured from now whatever `--days` is set to.

To produce this week's page and notification now rather than on Monday:

```bash
systemctl --user start security-report.service
```

## Settings

Configured through the widget's settings in the Omarchy shell, or by hand in
the widget's entry in `~/.config/omarchy/shell.json`.

| Key | Default | Effect |
|---|---|---|
| `refreshIntervalMs` | 300000 | how often the bar re-reads the report, from 30000 to 3600000 |
| `hideWhenGreen` | false | hide the lock when the report is green |

The widget only reads stored results, so the interval costs almost nothing
and changes nothing about when the scans run.

## Troubleshooting

The lock is amber and the panel shows an error in red at the bottom. The
widget could not read the report: `security-report` did
not run, exited with an error, or printed something that was not the expected
JSON. The panel says which. Run the same command the
widget runs:

```bash
security-report --json
```

If the command is not found, the scans have not been installed and the copy
inside the plugin could not be run either. A Python traceback is a bug in the
report. A logs folder that is missing or unreadable does not cause this:
the report still runs and shows every scan as never having run, in red.
If that happens while the scans are running, check that the desktop user in
`scan.conf` is your account, since only that account can read the logs.

A scan is amber or red for running late. Check that its timer is enabled and
when it last fired, and read the journal of its last run:

```bash
systemctl list-timers 'security-scan-*'
journalctl -u security-scan@gitleaks.service -n 50
```

Amber a day or two after a scan was due usually means the laptop was off or
asleep through the scheduled time. The timers are persistent, so the scan runs
at the next opportunity and the rating clears on its own. A scan that is red
for having failed has an error in its log: open the newest file for that scan
in `/var/log/security-scan`. A log that says `DESKTOP_USER is not set` means
`scan.conf` is missing or was ignored for not being owned by root.

AIDE reports many changes after installing software. Packages installed with
pacman or an AUR helper are verified by pacman and counted as package changes,
so they do not appear as findings. What does appear is software installed
outside the package manager: an installer script that writes into `/opt` or
`/usr/local`, `npm install -g`, or `pip` with `--break-system-packages`. Under
`/opt`, `/usr/local` and `/etc` these are amber and grouped by folder in the
report, so check that they are what you installed. Under `/usr/bin` or
`/usr/lib` they are red, because nothing but pacman should write there. Either
way, AIDE re-baselines after every check, so the same files are not reported
again. If a folder changes constantly and is not worth watching, add an
exclusion to `system/aide.conf.in` and run the installer again.

rkhunter warns about a file that you believe is harmless. Find the package
that owns it and check that the package still verifies:

```bash
pacman -Qo /usr/bin/example
pacman -Qkk example
```

If the file is owned by a package and `pacman -Qkk` reports no checksum or
size mismatch for it, add an exception to `/etc/rkhunter.conf.local`, using
the same kind of entry as the examples there (`SCRIPTWHITELIST` for a command
shipped as a script, `ALLOWHIDDENFILE` for a hidden file, and so on). Then run
the check again with `sudo systemctl start security-scan@rkhunter.service`. Do
not add an exception for a file that pacman cannot verify.

The weekly report did not appear. It runs as your user, so check the user
timer rather than the system ones:

```bash
systemctl --user list-timers security-report.timer
journalctl --user -u security-report.service -n 50
```

If the installer reported older per-user copies of these units, remove them
as it said; until then they override the installed ones.

## Uninstalling

```bash
sudo bin/security-scan-install --uninstall
```

This stops and disables the plugin's timers, removes its system and user units,
`security-scan`, `security-report`, the `picklescan` link if it points into
`/opt/security-scan`, and the picklescan environment there. Of the uv tool
folder that versions up to 0.2.1 made, `/opt/security-scan/tools`, it removes
only picklescan, and the folder only if nothing else is in it. It removes only the exact names this
plugin installs, and only files that pass the same checks as an install, so a
unit of your own with a similar name, such as `security-scan-foo.timer`, is
never disabled or removed. A unit you have edited, a program of the same name
from somewhere else, and anything else you put in `/opt/security-scan` are
left in place and listed at the end, along with any other `security-scan*` or
`security-report*` units found, which may have depended on this plugin.

It also leaves in place, because they hold your settings, history and
baselines:

| Left in place | Holds |
|---|---|
| `/etc/security-scan` | configuration and risk register |
| `/etc/rkhunter.conf.local` | rkhunter exceptions |
| `/var/log/security-scan` | scan logs |
| `/var/lib/aide` | AIDE baselines |
| `/var/lib/security-scan` | trusted copy of limine.conf, and the package file lists of the last AIDE check |
| `~/.local/share/security-report` | weekly HTML reports |

The packages (`arch-audit`, `lynis`, `gitleaks`, `rkhunter` and `aide`) are not
removed, and neither is rkhunter's own database in `/var/lib/rkhunter`. To
delete the rest:

```bash
sudo rm -r /etc/security-scan /var/log/security-scan /var/lib/aide /var/lib/security-scan
rm -r ~/.local/share/security-report
```

To remove the widget, disable it and remove the symlink rather than the
checkout:

```bash
omarchy plugin disable brightwalker25.security-scan
rm ~/.config/omarchy/plugins/brightwalker25.security-scan
```
