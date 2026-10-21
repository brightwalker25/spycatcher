#!/usr/bin/env bash
# shellcheck disable=SC2016  # sed programs and stubs are meant to be literal
# Sandbox harness for bin/security-scan-install. Runs the installer as an
# ordinary user against a temporary directory tree, with pacman, systemctl,
# runuser, rkhunter, uv and chown stubbed, and checks what it writes, refuses
# and removes. getent is real, except in the checks for an account without a
# group of its own, which put a stub reading made-up files first on PATH. Nothing outside the temporary tree is changed, and root is
# never needed.
#
#   bash tests/sandbox-install.sh
#   INSTALLER=/path/to/other/security-scan-install bash tests/sandbox-install.sh
#
# INSTALLER runs the same checks against another copy of the installer, for
# example an earlier release, to show which checks it fails.
set -uo pipefail

REPO=${REPO:-$(cd "$(dirname "$0")/.." && pwd)}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SB="$WORK/sb"
STUB="$WORK/stub"
# Every release of this plugin whose installer is in the git history.
RELEASES=(v021:fc8cc3d v022:79c0c2e v023:de1c328 v024:0f64334 v025:c467467 v026:3f1f7d3 v027:bdf26c8
  v028:534b5dd v029:16d6f9c v0210:e2953f7 v0211:49ea46b)

pass=0 fail=0
ok() { pass=$((pass + 1)); printf 'ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }
check() {
  local d=$1
  shift
  if "$@"; then ok "$d"; else bad "$d"; fi
}

# ------------------------------------------------------------ stubs
mkdir -p "$STUB"
for c in systemctl pacman rkhunter chown; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\n' "$c" "$SB" >"$STUB/$c"
done
printf '#!/bin/sh\nshift 3\nexec "$@"\n' >"$STUB/runuser"
# uv: "tool install" lays out what uv tool made in 0.2.1, "venv" makes a
# minimal virtual environment, and "pip sync" records picklescan as
# installed in it, as the real one does.
cat >"$STUB/uv" <<EOF
#!/usr/bin/env bash
echo "uv \$*" >> "$SB/calls.log"
pyver=\$(/usr/bin/python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
case "\$1 \$2" in
  "tool install")
    d="\$UV_TOOL_DIR/picklescan"
    mkdir -p "\$d/bin" "\$UV_TOOL_BIN_DIR"
    echo receipt > "\$d/uv-receipt.toml"
    printf '#!/bin/sh\n' > "\$d/bin/picklescan"; chmod +x "\$d/bin/picklescan"
    ln -sfn "\$d/bin/picklescan" "\$UV_TOOL_BIN_DIR/picklescan"
    ;;
  venv*)
    d="\${*: -1}"
    case " \$* " in *" --clear "*) rm -rf "\$d" ;; esac
    mkdir -p "\$d/bin" "\$d/lib/python\$pyver"
    echo "home = /usr/bin" > "\$d/pyvenv.cfg"
    ln -sfn /usr/bin/python3 "\$d/bin/python"
    printf '#!/bin/sh\n' > "\$d/bin/picklescan"; chmod +x "\$d/bin/picklescan"
    ;;
  "pip sync")
    for a in "\$@"; do prev=\${cur:-}; cur=\$a; [ "\$prev" = --python ] && py=\$a; done
    d=\$(dirname "\$(dirname "\$py")")
    mkdir -p "\$d/lib/python\$pyver/site-packages/picklescan-1.0.0.dist-info"
    ;;
esac
exit 0
EOF
chmod +x "$STUB"/*

UNITDIR="$SB/etc/systemd/system"
USERDIR="$SB/etc/systemd/user"
BIN="$SB/usr/local/bin"
OPT="$SB/opt/security-scan"
VENV="$OPT/picklescan"
ETC="$SB/etc/security-scan"
RKH="$SB/etc/rkhunter.conf.local"
TIMERS=(arch-audit aide gitleaks lynis models rkhunter)
SYS_UNITS=(security-scan@.service)
for t in "${TIMERS[@]}"; do SYS_UNITS+=("security-scan-$t.timer"); done
USER_UNITS=(security-report.service security-report.timer)
UNITS=()
for u in "${SYS_UNITS[@]}"; do UNITS+=("$UNITDIR/$u"); done
for u in "${USER_UNITS[@]}"; do UNITS+=("$USERDIR/$u"); done
PROGS=("$BIN/security-scan" "$BIN/security-report")

# Point every system path the installer uses into the sandbox. The literal
# paths cover earlier releases, which have no variables for them; the current
# installer keeps each path in one variable at the top.
sandboxify() {
  sed -e "s|/etc/systemd/|$SB/etc/systemd/|g" \
    -e "s|/usr/local/bin|$SB/usr/local/bin|g" \
    -e "s|/opt/security-scan|$SB/opt/security-scan|g" \
    -e "s|/etc/rkhunter.conf.local|$SB/etc/rkhunter.conf.local|g" \
    -e "s|^ETC=/etc/security-scan|ETC=$SB/etc/security-scan|" \
    -e "s|/var/lib/|$SB/var/lib/|g" \
    -e "s|/run/user|$SB/run/user|g" \
    -e "s|^ROOT_UID=0\$|ROOT_UID=\${ROOT_UID_OVERRIDE:-$(id -u)}|" \
    -e "s|^NSSWITCH=/etc/nsswitch.conf\$|NSSWITCH=\${NSSWITCH_OVERRIDE:-/etc/nsswitch.conf}|" \
    -e "s|^GSHADOW=/etc/gshadow\$|GSHADOW=\${GSHADOW_OVERRIDE:-$WORK/gshadow-absent}|" \
    -e 's|install -D -o root -g root |install -D |g' \
    -e 's|install -d -o root -g root |install -d |g' \
    -e 's|^if \[ "\$(id -u)" -ne 0 \]; then$|if false; then|' \
    "$1" >"$2"
  chmod +x "$2"
}

# The sandboxed installer runs from a copy of the checkout, so that SRC points
# at the units, programs and templates it ships.
checkout() { # rev|WORKTREE, dir
  local rev=$1 dir=$2
  mkdir -p "$dir"
  if [ "$rev" = WORKTREE ]; then
    (cd "$REPO" && tar cf - bin system) | (cd "$dir" && tar xf -)
  else
    git -C "$REPO" archive "$rev" bin system | tar xf - -C "$dir"
  fi
  sandboxify "$dir/bin/security-scan-install" "$dir/bin/security-scan-install.sb"
}

reset() {
  rm -rf "$SB"
  mkdir -p "$UNITDIR" "$USERDIR" "$BIN" "$SB/opt" "$SB/var/lib/aide" \
    "$SB/var/lib/rkhunter/db"
  : >"$SB/calls.log"
}

run() { # installer, args...
  local s=$1
  shift
  PATH="${GETENT_STUB:+$GETENT_STUB:}$STUB:$PATH" SUDO_USER=$(id -un) bash "$s" "$@" >"$WORK/out" 2>"$WORK/err"
}

sum() { sha256sum "$1" | cut -d' ' -f1; }
snapshot() {
  find "$SB" -path "$SB/calls.log" -prune -o -print0 | sort -z |
    xargs -0 ls -ld --time-style=+%s.%N 2>/dev/null
  find "$SB" -type f ! -path "$SB/calls.log" -print0 | sort -z | xargs -0 sha256sum
}
exists() { [[ -e "$1" || -L "$1" ]]; }
absent() { ! exists "$1"; }
err_has() { grep -qF -- "$1" "$WORK/err"; }
out_has() { grep -qF -- "$1" "$WORK/out"; }
called() { grep -qF -- "$1" "$SB/calls.log"; }
not_called() { ! grep -qF -- "$1" "$SB/calls.log"; }
mode_of() { stat -c %a "$1"; }
ME=$(id -un)
shipped() { # unit name -> path of the copy in this checkout
  case "$1" in
    security-report.*) echo "$REPO/system/user/$1" ;;
    *) echo "$REPO/system/units/$1" ;;
  esac
}
units_match_checkout() {
  local f
  for f in "${UNITS[@]}"; do cmp -s "$f" "$(shipped "${f##*/}")" || return 1; done
}
no_temp_files() { [ -z "$(find "$SB" -name '.*.??????' -print -quit)" ]; }

for r in "${RELEASES[@]}"; do checkout "${r#*:}" "$WORK/${r%%:*}"; done
checkout WORKTREE "$WORK/new"
if [ -n "${INSTALLER:-}" ]; then
  sandboxify "$INSTALLER" "$WORK/new/bin/security-scan-install.sb"
fi
NEW="$WORK/new/bin/security-scan-install.sb"
old() { echo "$WORK/$1/bin/security-scan-install.sb"; }

# ------------------------------------------------------------ static
# Every version of every unit in the git history must be recognised, or an
# upgrade from that release would be refused.
for rev in $(git -C "$REPO" rev-list HEAD -- system/units system/user); do
  for f in $(git -C "$REPO" ls-tree -r --name-only "$rev" -- system/units system/user); do
    h=$(git -C "$REPO" show "$rev:$f" | sha256sum | cut -d' ' -f1)
    if [ "$h" != "$(sum "$REPO/$f" 2>/dev/null)" ]; then
      check "installer lists ${f##*/} from ${rev:0:7}" grep -q "$h" "$REPO/bin/security-scan-install"
    fi
  done
done
for u in "${SYS_UNITS[@]}" "${USER_UNITS[@]}"; do
  check "installer lists the released hash of $u" \
    grep -q "\[$u\]=$(git -C "$REPO" show "fc8cc3d:$(shipped "$u" | sed "s|^$REPO/||")" | sha256sum | cut -d' ' -f1)" \
    "$REPO/bin/security-scan-install"
done
check "units are removed by exact name, not by a glob" \
  bash -c "! grep -nE 'rm .*security-scan-\\*|security-scan-\\*\\.timer' '$REPO/bin/security-scan-install'"

# ------------------------------------------------------------ fresh install
reset
run "$NEW"
rc=$?
check "fresh install succeeds" test $rc -eq 0
check "fresh install writes every unit from the checkout" units_match_checkout
for f in "${UNITS[@]}"; do check "fresh ${f#"$SB"} mode is 644" test "$(mode_of "$f")" = 644; done
for p in "${PROGS[@]}"; do
  check "fresh ${p#"$SB"} is a copy, mode 755" \
    bash -c "[ ! -L '$p' ] && [ \"\$(stat -c %a '$p')\" = 755 ] && cmp -s '$p' '$REPO/bin/${p##*/}'"
done
check "fresh install makes the picklescan environment" test -f "$VENV/pyvenv.cfg"
check "fresh install links picklescan into it" test "$(readlink "$BIN/picklescan")" = "$VENV/bin/picklescan"
check "fresh install writes the configuration" \
  bash -c "[ -f '$ETC/scan.conf' ] && [ -f '$ETC/aide.conf' ] && [ -f '$ETC/gitleaks.toml' ] && [ -f '$ETC/risk-register.toml' ] && [ -f '$RKH' ]"
check "fresh rkhunter.conf.local mode is 640" test "$(mode_of "$RKH")" = 640
# Only the scans, as root, read gitleaks.toml and aide.conf. The report runs
# as the desktop user and reads the risk register and scan.conf through the
# user's own group. chown is stubbed, so the group shows in its call log.
check "fresh gitleaks.toml mode is 600" test "$(mode_of "$ETC/gitleaks.toml")" = 600
check "fresh aide.conf mode is 600" test "$(mode_of "$ETC/aide.conf")" = 600
check "fresh risk-register.toml mode is 640" test "$(mode_of "$ETC/risk-register.toml")" = 640
check "fresh scan.conf mode is 640" test "$(mode_of "$ETC/scan.conf")" = 640
check "fresh risk-register.toml is given to the desktop user's group" \
  called "chown root:$ME $ETC/.risk-register.toml."
check "fresh scan.conf is given to the desktop user's group" called "chown root:$ME $ETC/.scan.conf."
check "fresh gitleaks.toml stays in root's group" called "chown root:root $ETC/.gitleaks.toml."
for t in "${TIMERS[@]}"; do check "fresh install enables security-scan-$t.timer" called "systemctl enable --now security-scan-$t.timer"; done
check "fresh install enables the report timer" called "systemctl --global enable security-report.timer"
check "fresh install leaves no temporary files" no_temp_files
check "fresh install warns about nothing" test ! -s "$WORK/err"
snapshot >"$WORK/fresh.snap"

# ------------------------------------------------------------ reinstall
run "$NEW"
rc=$?
check "reinstall succeeds" test $rc -eq 0
check "reinstall leaves every file exactly as it was" \
  bash -c "diff -q <(find '$SB' -type f ! -path '$SB/calls.log' -print0 | sort -z | xargs -0 sha256sum) <(grep -E '^[0-9a-f]{64}  ' '$WORK/fresh.snap') >/dev/null"
check "reinstall does not rewrite units that are up to date" out_has "keep $UNITDIR/security-scan@.service (up to date)"

# ------------------------------------------------------------ foreign units
for f in "${UNITS[@]}"; do
  reset
  printf '[Unit]\nDescription=administrator unit\n' >"$f"
  chmod 600 "$f"
  before=$(snapshot)
  run "$NEW"
  rc=$?
  check "foreign ${f#"$SB"}: install refuses" test $rc -ne 0
  check "foreign ${f#"$SB"}: named on stderr with the reason" \
    err_has "$f (does not match any version of this unit that the plugin has shipped)"
  check "foreign ${f#"$SB"}: content, mode and everything else unchanged" test "$before" = "$(snapshot)"
  check "foreign ${f#"$SB"}: nothing installed, no package or unit command run" test ! -s "$SB/calls.log"
done

# An edited copy of the plugin's own unit is the administrator's now.
reset
run "$NEW"
sed -i 's/^OnCalendar=.*/OnCalendar=hourly/' "$UNITDIR/security-scan-lynis.timer"
cp "$UNITDIR/security-scan-lynis.timer" "$WORK/edited.timer"
before=$(snapshot)
: >"$SB/calls.log"
run "$NEW"
rc=$?
check "edited plugin unit: install refuses" test $rc -ne 0
check "edited plugin unit: named on stderr" err_has "$UNITDIR/security-scan-lynis.timer"
check "edited plugin unit: stderr points at drop-ins" err_has "systemctl edit UNIT"
check "edited plugin unit: the edit survives" cmp -s "$UNITDIR/security-scan-lynis.timer" "$WORK/edited.timer"
check "edited plugin unit: nothing else changed" test "$before" = "$(snapshot)"

# ------------------------------------------------------------ symlinks
reset
cp "$(shipped security-scan@.service)" "$SB/elsewhere"
ln -s "$SB/elsewhere" "$UNITDIR/security-scan@.service"
before=$(snapshot)
run "$NEW"
rc=$?
check "symlinked unit, even to the plugin's content: refused" test $rc -ne 0
check "symlinked unit: reason is a symlink" err_has "$UNITDIR/security-scan@.service (a symlink)"
check "symlinked unit: link and target unchanged" test "$before" = "$(snapshot)"
reset
ln -s "$SB/nowhere" "$USERDIR/security-report.timer"
run "$NEW"
rc=$?
check "dangling symlink unit: refused" test $rc -ne 0
check "dangling symlink unit: nothing created through it" absent "$SB/nowhere"
reset
mkdir "$UNITDIR/security-scan-aide.timer"
run "$NEW"
rc=$?
check "directory at a unit path: refused" test $rc -ne 0

# ------------------------------------------------------------ not owned by root
# With ROOT_UID set to another account, the sandbox's own files look like
# they belong to someone else, as a unit written by an ordinary user would.
reset
cp "$(shipped security-scan-aide.timer)" "$UNITDIR/security-scan-aide.timer"
before=$(snapshot)
ROOT_UID_OVERRIDE=65534 run "$NEW"
rc=$?
check "unit with the plugin's content but not owned by root: refused" test $rc -ne 0
check "unit not owned by root: reason given" err_has "$UNITDIR/security-scan-aide.timer (not owned by root)"
check "unit not owned by root: nothing changed" test "$before" = "$(snapshot)"

# ------------------------------------------------------------ other paths
reset
printf '#!/bin/sh\necho admin tool\n' >"$BIN/security-scan"
before=$(snapshot)
run "$NEW"
rc=$?
check "foreign /usr/local/bin/security-scan: refused" test $rc -ne 0
check "foreign program: named on stderr" err_has "$BIN/security-scan (not this plugin's program)"
check "foreign program: nothing changed" test "$before" = "$(snapshot)"

reset
mkdir -p "$VENV"
echo keep >"$VENV/data"
before=$(snapshot)
run "$NEW"
rc=$?
check "folder at the picklescan path that is not a venv: refused" test $rc -ne 0
check "not a venv: nothing emptied" test "$before" = "$(snapshot)"

reset
mkdir "$SB/elsewhere"
ln -s "$SB/elsewhere" "$OPT"
run "$NEW"
rc=$?
check "symlinked /opt/security-scan: refused" test $rc -ne 0
check "symlinked /opt/security-scan: nothing written through it" test -z "$(ls -A "$SB/elsewhere")"

reset
mkdir "$SB/elsewhere"
ln -s "$SB/elsewhere" "$ETC"
run "$NEW"
rc=$?
check "symlinked /etc/security-scan: refused" test $rc -ne 0
check "symlinked /etc/security-scan: nothing written through it" test -z "$(ls -A "$SB/elsewhere")"

reset
mkdir -p "$ETC"
echo private >"$SB/private"
chmod 600 "$SB/private"
ln -s "$SB/private" "$ETC/aide.conf"
run "$NEW"
rc=$?
check "symlinked aide.conf: refused" test $rc -ne 0
check "symlinked aide.conf: target unchanged" \
  bash -c "[ \"\$(cat '$SB/private')\" = private ] && [ \"\$(stat -c %a '$SB/private')\" = 600 ]"

reset
printf '#!/bin/sh\n' >"$SB/admin-picklescan"
ln -s "$SB/admin-picklescan" "$BIN/picklescan"
run "$NEW"
rc=$?
check "an administrator's picklescan does not block the install" test $rc -eq 0
check "an administrator's picklescan is left pointing where it did" test "$(readlink "$BIN/picklescan")" = "$SB/admin-picklescan"

# ------------------------------------------------------------ permissions
# Nothing that already exists is made more open.
reset
mkdir -m 700 "$ETC" "$OPT"
printf 'admin aide rules\n' >"$ETC/aide.conf"
chmod 600 "$ETC/aide.conf"
printf 'older backup\n' >"$ETC/aide.conf.bak-$(date +%Y%m%d)"
chmod 600 "$ETC/aide.conf.bak-$(date +%Y%m%d)"
for f in scan.conf gitleaks.toml risk-register.toml; do
  echo "mine $f" >"$ETC/$f"
  chmod 600 "$ETC/$f"
done
echo "mine rkhunter" >"$RKH"
chmod 600 "$RKH"
run "$NEW"
rc=$?
check "install with private configuration succeeds" test $rc -eq 0
check "existing /etc/security-scan keeps mode 700" test "$(mode_of "$ETC")" = 700
check "existing /opt/security-scan keeps mode 700" test "$(mode_of "$OPT")" = 700
for f in "$ETC/scan.conf" "$ETC/gitleaks.toml" "$ETC/risk-register.toml" "$RKH"; do
  check "${f#"$SB"} kept with its content and mode 600" \
    bash -c "grep -q '^mine' '$f' && [ \"\$(stat -c %a '$f')\" = 600 ]"
done
check "private aide.conf is replaced but stays mode 600" test "$(mode_of "$ETC/aide.conf")" = 600
check "earlier backup of the same day is not overwritten" grep -qx 'older backup' "$ETC/aide.conf.bak-$(date +%Y%m%d)"
check "the hand-edited aide.conf is backed up with mode 600" \
  bash -c "grep -qx 'admin aide rules' '$ETC/aide.conf.bak-$(date +%Y%m%d).1' && [ \"\$(stat -c %a '$ETC/aide.conf.bak-$(date +%Y%m%d).1')\" = 600 ]"

# ------------------------------------------------------------ private configuration
# Configuration that earlier versions left readable by everyone is made
# private on upgrade, by taking permissions away and never adding any.
reset
mkdir -p "$ETC"
for f in gitleaks.toml risk-register.toml scan.conf aide.conf.bak-20260101; do
  echo "old $f" >"$ETC/$f"
  chmod 644 "$ETC/$f"
done
echo "admin's own" >"$ETC/aide.conf.bak-20260102"
chmod 400 "$ETC/aide.conf.bak-20260102"
echo "mine" >"$RKH"
chmod 644 "$RKH"
run "$NEW"
rc=$?
check "upgrade over open configuration succeeds" test $rc -eq 0
check "open gitleaks.toml becomes 600, content kept" \
  bash -c "grep -qx 'old gitleaks.toml' '$ETC/gitleaks.toml' && [ \"\$(stat -c %a '$ETC/gitleaks.toml')\" = 600 ]"
check "open risk-register.toml becomes 640" test "$(mode_of "$ETC/risk-register.toml")" = 640
check "open scan.conf becomes 640" test "$(mode_of "$ETC/scan.conf")" = 640
check "an old aide.conf backup becomes 600" test "$(mode_of "$ETC/aide.conf.bak-20260101")" = 600
check "a backup made more private by hand keeps mode 400" test "$(mode_of "$ETC/aide.conf.bak-20260102")" = 400
check "rkhunter.conf.local, which may be the administrator's, is not changed" test "$(mode_of "$RKH")" = 644
check "the change is shown" out_has "make $ETC/risk-register.toml private (mode 0644 to 0640)"
run "$NEW"
check "a second run changes no mode" bash -c "! grep -q 'private (mode' '$WORK/out'"

# A file an administrator made more private is not opened up for the report.
reset
mkdir -p "$ETC"
echo "mine" >"$ETC/risk-register.toml"
chmod 600 "$ETC/risk-register.toml"
run "$NEW"
check "a risk register made 600 by hand stays 600" test "$(mode_of "$ETC/risk-register.toml")" = 600
check "a risk register made 600 by hand keeps its group" not_called "chown root:$ME $ETC/risk-register.toml"

# A symlink is never followed: neither it nor its target changes.
reset
mkdir -p "$ETC"
for f in gitleaks.toml risk-register.toml; do
  echo "elsewhere $f" >"$SB/elsewhere-$f"
  chmod 644 "$SB/elsewhere-$f"
  ln -s "$SB/elsewhere-$f" "$ETC/$f"
done
before=$(snapshot)
run "$NEW"
rc=$?
check "symlinked gitleaks.toml and risk register: install still succeeds" test $rc -eq 0
for f in gitleaks.toml risk-register.toml; do
  check "symlinked $f: target keeps mode 644" test "$(mode_of "$SB/elsewhere-$f")" = 644
  check "symlinked $f: still a link to the same place" test "$(readlink "$ETC/$f")" = "$SB/elsewhere-$f"
  check "symlinked $f: left with a reason" out_has "left $ETC/$f as it is (a symlink)"
  check "symlinked $f: listed for the administrator" out_has "$ETC/$f was left as it is, because it is a symlink"
  check "symlinked $f: no chown through it" not_called "$ETC/$f"
done

# A file owned by another account is not changed. Ownership needs a second
# account, so this part runs in a user namespace, where the sandbox's files
# belong to root and uid 1 is someone else. chmod is real there, so a change
# would show.
ns() { unshare --map-auto --map-root-user "$@"; }
if ns true 2>/dev/null; then
  reset
  mkdir -p "$ETC"
  for f in gitleaks.toml risk-register.toml scan.conf; do
    echo "old $f" >"$ETC/$f"
    chmod 644 "$ETC/$f"
  done
  ns chown 1:1 "$ETC/gitleaks.toml"
  ns env PATH="$STUB:$PATH" SUDO_USER="$ME" ROOT_UID_OVERRIDE=0 \
    bash "$NEW" >"$WORK/out" 2>"$WORK/err"
  rc=$?
  check "gitleaks.toml owned by another account: install still succeeds" test $rc -eq 0
  check "gitleaks.toml owned by another account: mode unchanged" test "$(mode_of "$ETC/gitleaks.toml")" = 644
  check "gitleaks.toml owned by another account: left with a reason" \
    out_has "left $ETC/gitleaks.toml as it is (not owned by root)"
  check "gitleaks.toml owned by another account: no chown" not_called "$ETC/gitleaks.toml"
  check "root's risk register in root's group: given to the desktop user's group" \
    called "chown root:$ME $ETC/risk-register.toml"
  check "root's risk register in root's group: mode 640" test "$(mode_of "$ETC/risk-register.toml")" = 640
  check "root's scan.conf in root's group: given to the desktop user's group" \
    called "chown root:$ME $ETC/scan.conf"
  ns rm -f "$ETC/gitleaks.toml"

  # A file an administrator gave to another group, such as "users", would
  # stay readable by all of its members. The report's two files move to the
  # desktop user's group; gitleaks.toml, read only by root, loses its group
  # bits, after which its group no longer matters. chown is stubbed, so the
  # move shows in its call log.
  reset
  mkdir -p "$ETC"
  for f in risk-register.toml scan.conf; do
    echo "old $f" >"$ETC/$f"
    chmod 644 "$ETC/$f"
  done
  echo "old gitleaks.toml" >"$ETC/gitleaks.toml"
  chmod 640 "$ETC/gitleaks.toml"
  ns chown 0:100 "$ETC/risk-register.toml" "$ETC/scan.conf" "$ETC/gitleaks.toml"
  ns env PATH="$STUB:$PATH" SUDO_USER="$ME" ROOT_UID_OVERRIDE=0 \
    bash "$NEW" >"$WORK/out" 2>"$WORK/err"
  rc=$?
  check "files in another group: install succeeds" test $rc -eq 0
  for f in risk-register.toml scan.conf; do
    check "$f 0644 in another group: mode 640" test "$(mode_of "$ETC/$f")" = 640
    check "$f 0644 in another group: moved to the desktop user's group" called "chown root:$ME $ETC/$f"
    check "$f 0644 in another group: the move is shown" out_has "take $ETC/$f from group"
  done
  check "gitleaks.toml 0640 in another group: mode 600" test "$(mode_of "$ETC/gitleaks.toml")" = 600
  check "gitleaks.toml 0640 in another group: content kept" grep -qx 'old gitleaks.toml' "$ETC/gitleaks.toml"
  ns rm -f "$ETC/gitleaks.toml" "$ETC/risk-register.toml" "$ETC/scan.conf"
else
  echo "skip  ownership checks: no user namespace with a second id"
fi

# ------------------------------------------------------------ no group of the user's own
# scan.conf and the risk register are shared with the desktop user's own
# group only. Without one, the installer refuses before changing anything,
# rather than leave them readable by every local user as 0.2.10 did. A getent
# stub answers from made-up passwd and group files, and made-up nsswitch.conf
# and gshadow files stand in for the real ones, so each kind of account can
# be tried without changing the machine.
GETENT_DIR="$WORK/getent"
mkdir -p "$GETENT_DIR"
cat >"$GETENT_DIR/getent" <<'EOF'
#!/bin/sh
# -s files and every other source read the same made-up files.
[ "$1" = -s ] && shift 2
case "$1" in
  passwd) f=$FAKE_PASSWD ;;
  group) f=$FAKE_GROUP ;;
  *) exec /usr/bin/getent "$@" ;;
esac
[ $# -eq 1 ] && exec cat "$f"
awk -F: -v k="$2" '$1 == k || $3 == k { print; found = 1; exit } END { exit found ? 0 : 2 }' "$f"
EOF
chmod +x "$GETENT_DIR/getent"
ME_ENTRY=$(getent passwd "$ME")
ME_GID=$(printf '%s' "$ME_ENTRY" | cut -d: -f4)
OTHER="other-account"
accounts() { # scenario -> made-up passwd and group files
  printf 'root:x:0:0::/root:/bin/sh\n%s\n' "$ME_ENTRY" >"$WORK/passwd"
  printf 'root:x:0:\n' >"$WORK/group"
  printf 'passwd: files systemd\ngroup: files [SUCCESS=merge] systemd\n' >"$WORK/nsswitch.conf"
  printf 'root:!*::\n%s:!*::\n' "$ME" >"$WORK/gshadow"
  case "$1" in
    private) echo "$ME:x:$ME_GID:" >>"$WORK/group" ;;
    no-group) echo "users:x:$ME_GID:" >>"$WORK/group" ;;
    not-primary) printf 'users:x:%s:\n%s:x:%s:\n' "$ME_GID" "$ME" "$((ME_GID + 50000))" >>"$WORK/group" ;;
    other-member) echo "$ME:x:$ME_GID:$ME,$OTHER" >>"$WORK/group" ;;
    shared-primary)
      echo "$ME:x:$ME_GID:" >>"$WORK/group"
      echo "$OTHER:x:60001:$ME_GID::/nonexistent:/bin/sh" >>"$WORK/passwd"
      ;;
    same-gid) printf '%s:x:%s:\nstaff:x:%s:%s\n' "$ME" "$ME_GID" "$ME_GID" "$OTHER" >>"$WORK/group" ;;
    gshadow-member)
      echo "$ME:x:$ME_GID:" >>"$WORK/group"
      printf 'root:!*::\n%s:!*::%s\n' "$ME" "$OTHER" >"$WORK/gshadow"
      ;;
    nss-ldap)
      echo "$ME:x:$ME_GID:" >>"$WORK/group"
      printf 'passwd: files ldap\ngroup: files ldap\n' >"$WORK/nsswitch.conf"
      ;;
    nss-sss)
      echo "$ME:x:$ME_GID:" >>"$WORK/group"
      printf 'passwd: files systemd sss\ngroup: files [SUCCESS=merge] systemd sss\n' >"$WORK/nsswitch.conf"
      ;;
  esac
}
as_accounts() { # scenario, installer, args...
  local a=$1
  shift
  accounts "$a"
  GETENT_STUB=$GETENT_DIR FAKE_PASSWD="$WORK/passwd" FAKE_GROUP="$WORK/group" \
    NSSWITCH_OVERRIDE="$WORK/nsswitch.conf" GSHADOW_OVERRIDE="$WORK/gshadow" run "$@"
}

# The stub itself must not cause a refusal: with a private group it installs.
reset
as_accounts private "$NEW"
check "getent stub with a private group: install succeeds" test $? -eq 0
check "getent stub with a private group: files shared with that group" \
  called "chown root:$ME $ETC/.scan.conf."

for a in no-group not-primary other-member shared-primary same-gid gshadow-member nss-ldap nss-sss; do
  # A fresh machine: nothing in /etc/security-scan yet.
  reset
  before=$(snapshot)
  as_accounts "$a" "$NEW"
  rc=$?
  check "$a, fresh: install refuses" test $rc -ne 0
  check "$a, fresh: reason on stderr" err_has "$ME has no group of their own"
  check "$a, fresh: nothing written or changed" test "$before" = "$(snapshot)"
  check "$a, fresh: no package or unit command run" test ! -s "$SB/calls.log"

  # An install that 0.2.10 made for such an account, with scan.conf and the
  # risk register left readable by everyone.
  reset
  as_accounts "$a" "$(old v0210)"
  # 0.2.10 saw no group of the user's own in the first four cases, and took
  # the group for private in the others.
  case "$a" in
    no-group | not-primary | other-member | shared-primary) m=644 ;;
    *) m=640 ;;
  esac
  check "$a, over 0.2.10: 0.2.10 left scan.conf at $m" test "$(mode_of "$ETC/scan.conf")" = $m
  : >"$SB/calls.log"
  before=$(snapshot)
  as_accounts "$a" "$NEW"
  rc=$?
  check "$a, over 0.2.10: install refuses" test $rc -ne 0
  check "$a, over 0.2.10: reason on stderr" err_has "$ME has no group of their own"
  check "$a, over 0.2.10: stderr says to make the old files private" err_has "chmod o-rwx $ETC/*"
  check "$a, over 0.2.10: every file, mode and time unchanged" test "$before" = "$(snapshot)"
  check "$a, over 0.2.10: no package or unit command run" test ! -s "$SB/calls.log"
done

# Uninstalling needs no group of the user's own, so it still works.
reset
run "$NEW"
: >"$SB/calls.log"
as_accounts no-group "$NEW" --uninstall
rc=$?
check "no-group: uninstall succeeds" test $rc -eq 0
check "no-group: uninstall removes every unit" bash -c "! ls ${UNITS[*]} 2>/dev/null | grep -q ."
check "no-group: uninstall removes /opt/security-scan" absent "$OPT"
check "no-group: uninstall disables the report timer" called "systemctl --global disable security-report.timer"
check "no-group: uninstall warns about nothing" test ! -s "$WORK/err"
reset
as_accounts shared-primary "$(old v0210)"
as_accounts shared-primary "$NEW" --uninstall
check "shared-primary: uninstall of a 0.2.10 install succeeds" test $? -eq 0
check "shared-primary: uninstall of a 0.2.10 install removes every unit" bash -c "! ls ${UNITS[*]} 2>/dev/null | grep -q ."

# ------------------------------------------------------------ upgrades
for r in "${RELEASES[@]}"; do
  v=${r%%:*}
  reset
  run "$(old "$v")"
  check "$v installs in the sandbox" test $? -eq 0
  : >"$SB/calls.log"
  run "$NEW"
  rc=$?
  check "upgrade from $v succeeds" test $rc -eq 0
  check "upgrade from $v: every unit matches the checkout" units_match_checkout
  check "upgrade from $v: programs are current" \
    bash -c "cmp -s '$BIN/security-scan' '$REPO/bin/security-scan' && cmp -s '$BIN/security-report' '$REPO/bin/security-report'"
  check "upgrade from $v: picklescan points at the pinned environment" test "$(readlink "$BIN/picklescan")" = "$VENV/bin/picklescan"
  check "upgrade from $v: no uv tool folder left" absent "$OPT/tools"
  check "upgrade from $v: timers enabled" called "systemctl enable --now security-scan-models.timer"
  check "upgrade from $v: nothing refused" test ! -s "$WORK/err"
  check "upgrade from $v: gitleaks.toml made private, mode 600" test "$(mode_of "$ETC/gitleaks.toml")" = 600
  check "upgrade from $v: aide.conf made private, mode 600" test "$(mode_of "$ETC/aide.conf")" = 600
  check "upgrade from $v: risk-register.toml mode 640" test "$(mode_of "$ETC/risk-register.toml")" = 640
  check "upgrade from $v: scan.conf mode 640" test "$(mode_of "$ETC/scan.conf")" = 640
  if [ "$v" != v0210 ] && [ "$v" != v0211 ]; then
    check "upgrade from $v: says it made gitleaks.toml private" out_has "make $ETC/gitleaks.toml private (mode 0644 to 0600)"
  fi
  run "$NEW" --uninstall
  check "uninstall after upgrade from $v removes every unit" bash -c "! ls ${UNITS[*]} 2>/dev/null | grep -q ."
  check "uninstall after upgrade from $v removes /opt/security-scan" absent "$OPT"
done

# ------------------------------------------------------------ uninstall
reset
run "$NEW"
: >"$SB/calls.log"
run "$NEW" --uninstall
rc=$?
check "uninstall succeeds" test $rc -eq 0
for f in "${UNITS[@]}" "${PROGS[@]}" "$BIN/picklescan"; do check "uninstall removes ${f#"$SB"}" absent "$f"; done
check "uninstall removes /opt/security-scan" absent "$OPT"
check "uninstall keeps the configuration" \
  bash -c "[ -f '$ETC/scan.conf' ] && [ -f '$ETC/aide.conf' ] && [ -f '$RKH' ]"
for t in "${TIMERS[@]}"; do check "uninstall disables security-scan-$t.timer" called "systemctl disable --now security-scan-$t.timer"; done
check "uninstall disables the report timer" called "systemctl --global disable security-report.timer"
check "uninstall warns about nothing" test ! -s "$WORK/err"

# The reviewer's case: a timer the administrator added with a similar name.
reset
run "$NEW"
printf '[Timer]\nOnCalendar=daily\n' >"$UNITDIR/security-scan-foo.timer"
printf '[Service]\nExecStart=/bin/true\n' >"$UNITDIR/security-scan-foo.service"
: >"$SB/calls.log"
run "$NEW" --uninstall
rc=$?
check "uninstall with an administrator's security-scan-foo.timer succeeds" test $rc -eq 0
check "security-scan-foo.timer survives uninstall" grep -qx 'OnCalendar=daily' "$UNITDIR/security-scan-foo.timer"
check "security-scan-foo.service survives uninstall" test -f "$UNITDIR/security-scan-foo.service"
check "security-scan-foo.timer is not disabled" not_called "security-scan-foo"
check "security-scan-foo.timer is mentioned on stderr" err_has "$UNITDIR/security-scan-foo.timer"
check "the plugin's own units are still removed" bash -c "! ls ${UNITS[*]} 2>/dev/null | grep -q ."

# A foreign or edited file at one of the plugin's own paths is left alone.
reset
run "$NEW"
printf '[Unit]\nDescription=administrator unit\n' >"$UNITDIR/security-scan-gitleaks.timer"
sed -i 's/^Description=.*/Description=edited/' "$USERDIR/security-report.service"
cp "$USERDIR/security-report.service" "$WORK/edited.service"
printf '#!/bin/sh\necho admin tool\n' >"$BIN/security-report"
echo keep >"$OPT/notes"
: >"$SB/calls.log"
run "$NEW" --uninstall
rc=$?
check "uninstall with foreign files succeeds" test $rc -eq 0
check "foreign unit at a plugin path survives" grep -qx 'Description=administrator unit' "$UNITDIR/security-scan-gitleaks.timer"
check "foreign unit is not disabled" not_called "security-scan-gitleaks.timer"
check "foreign unit reported on stderr" err_has "$UNITDIR/security-scan-gitleaks.timer"
check "edited plugin unit survives unchanged" cmp -s "$USERDIR/security-report.service" "$WORK/edited.service"
check "foreign program survives" grep -q 'admin tool' "$BIN/security-report"
check "file an administrator put in /opt/security-scan survives" test -f "$OPT/notes"
check "/opt/security-scan kept while it is not empty" test -d "$OPT"
check "the picklescan environment is still removed" absent "$VENV"
check "the other plugin units are still removed" absent "$UNITDIR/security-scan@.service"
check "the other plugin timers are still disabled" called "systemctl disable --now security-scan-aide.timer"

reset
run "$NEW"
ln -sfn "$SB/admin-picklescan" "$BIN/picklescan"
run "$NEW" --uninstall
check "an administrator's picklescan link survives uninstall" test -L "$BIN/picklescan"

# ------------------------------------------------------------ what in /opt is ours
reset
run "$NEW"
check "fresh install marks the picklescan environment as made by the installer" \
  test -f "$VENV/.security-scan-installer"

reset
mkdir -p "$OPT" "$VENV"
echo "home = /usr/bin" >"$VENV/pyvenv.cfg"
echo keep >"$VENV/precious"
run "$NEW"
rc=$?
check "an administrator's own environment at the picklescan path: refused" test $rc -ne 0
check "an administrator's own environment: left untouched" test -f "$VENV/precious"
check "an administrator's own environment: uv never runs" not_called "uv "
run "$NEW" --uninstall
check "an administrator's own environment survives uninstall" test -f "$VENV/precious"

reset
mkdir -p "$OPT/tools/picklescan" "$OPT/tools/othertool"
echo receipt >"$OPT/tools/picklescan/uv-receipt.toml"
echo keep >"$OPT/tools/othertool/precious"
: >"$OPT/tools/.lock"
run "$NEW"
check "upgrade over a uv tool folder with other tools succeeds" test $? -eq 0
check "the old picklescan tool is removed" absent "$OPT/tools/picklescan"
check "another tool in the uv tool folder survives" test -f "$OPT/tools/othertool/precious"
run "$NEW" --uninstall
check "another tool in the uv tool folder survives uninstall" test -f "$OPT/tools/othertool/precious"

reset
mkdir -p "$OPT/tools/picklescan"
echo receipt >"$OPT/tools/picklescan/uv-receipt.toml"
: >"$OPT/tools/.lock"
run "$NEW"
check "a uv tool folder holding only picklescan is removed" absent "$OPT/tools"

# ------------------------------------------------------------ open folders, root
reset
mkdir -p "$ETC"
chmod 0775 "$ETC"
run "$NEW"
rc=$?
check "group-writable /etc/security-scan: refused" test $rc -ne 0
check "group-writable /etc/security-scan: reason given" err_has "writable by group or others"
check "group-writable /etc/security-scan: nothing written" test -z "$(ls -A "$ETC")"

reset
run "$NEW" --user 0
rc=$?
check "--user 0 is refused as root" test $rc -ne 0
check "--user 0: reason given" err_has "cannot be root"
check "--user 0: nothing run" test ! -s "$SB/calls.log"

reset
mkdir -p "$ETC"
echo "# edited by hand" >"$ETC/aide.conf"
chmod 0666 "$ETC/aide.conf"
run "$NEW"
check "an open aide.conf is backed up" bash -c "ls '$ETC'/aide.conf.bak-* >/dev/null 2>&1"
check "the aide.conf backup is at most 0600" \
  bash -c "for f in '$ETC'/aide.conf.bak-*; do [ \$((8#\$(stat -c %a \"\$f\") & 8#177)) -eq 0 ] || exit 1; done"
check "the new aide.conf is at most 0600" test "$(mode_of "$ETC/aide.conf")" = 600

# ------------------------------------------------------------ dry run
reset
before=$(snapshot)
run "$NEW" --dry-run
check "dry run succeeds" test $? -eq 0
check "dry run changes nothing" test "$before" = "$(snapshot)"
check "dry run runs nothing but a read-only timer listing" \
  bash -c "! grep -v 'systemctl list-timers' '$SB/calls.log'"

echo
echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]
