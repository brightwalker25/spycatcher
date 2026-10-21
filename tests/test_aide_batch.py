"""Checks how the AIDE scan grades a large set of changes, and how it keeps
its baseline when it cannot grade them.

Run from the repository root:

    python3 -m unittest discover -s tests -v

A kernel update changes tens of thousands of files. The scan used to ask
pacman about each one in turn, which ran past the unit's 45 minute limit, so
the baseline never moved and every later run met the same pile. These tests
run a copy of bin/spycatcher-scan with aide and pacman replaced by stand-ins
that answer from files the test writes, as in test_scan_argv.py. Nothing
reads the real pacman database, /var/lib or /var/log.
"""

import gzip
import os
import shutil
import stat
import subprocess
import unittest
from pathlib import Path

from test_scan_argv import RECORD, ScanRun

ROOT = Path(__file__).resolve().parent.parent

# Answers from files: $FAKE/ql holds "package path" lines as pacman -Ql
# prints them; $FAKE/qkk.out and $FAKE/qkk.err are pacman -Qkk's output, to
# which a total line per package is added unless $FAKE/qkk.short exists;
# $FAKE/ql.fail makes -Ql fail. -Qqo reads its path from standard input, as
# spycatcher-report asks it, and looks it up in $FAKE/ql.
PACMAN = RECORD + r"""f="$FAKE"
case "$1" in
  -Ql)
    [ -e "$f/ql.fail" ] && exit 1
    cat "$f/ql" ;;
  -Qkk)
    shift
    cat "$f/qkk.out" 2>/dev/null
    cat "$f/qkk.err" >&2 2>/dev/null
    [ -e "$f/qkk.short" ] && exit 1
    for p in "$@"; do echo "$p: 1 total files, 0 altered files"; done ;;
  -Qqo)
    read -r path
    path=${path%/}
    owner=$(awk -v p="$path" '{ q = substr($0, index($0, " ") + 1); sub(/\/$/, "", q);
      if (q == p) { print $1; exit } }' "$f/ql")
    [ -n "$owner" ] || exit 1
    echo "$owner" ;;
  -Q) echo "$3 1.0-1" ;;
esac
exit 0
"""

# Prints the changes in $AIDE_OUT, writes a new baseline as aide --update
# does, and appends to pacman.log while it runs when $FAKE/txn exists.
AIDE = RECORD + r"""[ "$1" = --update ] || exit 0
[ -e "$FAKE/txn" ] && echo "[2026-10-21T09:00:00+0100] [ALPM] transaction started" >>"$PACMAN_LOG"
echo new >"$AIDE_DIR/aide.db.new.gz"
cat "$AIDE_OUT"
exit 5
"""


class AideRun(ScanRun):
    def setUp(self):
        super().setUp()
        self.fake = self.base / "fake"
        self.fake.mkdir()
        stubs = self.base / "stubs"
        (stubs / "pacman").write_text(PACMAN)
        (stubs / "aide").write_text(AIDE)
        for f in stubs.iterdir():
            f.chmod(0o755)
        # The lock file, and spycatcher-report beside the copy of the scan, as
        # it is beside the installed one.
        text = self.script.read_text()
        self.assertIn("/var/lib/pacman/db.lck", text)
        self.lock = self.state / "db.lck"
        self.script.write_text(text.replace("/var/lib/pacman/db.lck", str(self.lock)))
        shutil.copy(ROOT / "bin/spycatcher-report", self.script.parent / "spycatcher-report")
        self.aide_dir = self.state / "aide"
        self.db = self.aide_dir / "aide.db.gz"
        self.db.write_text("baseline")
        # The last check ran long before anything in the test's pacman.log.
        os.utime(self.db, (1767225600, 1767225600))  # 2026-01-01
        self.pacman_log = self.state / "pacman.log"
        self.ql = []
        self.out = self.base / "aide.out"

    def run_aide(self, changes, ql=(), qkk_out="", qkk_err="", **env):
        (self.fake / "ql").write_text("".join(f"{line}\n" for line in ql))
        (self.fake / "qkk.out").write_text(qkk_out)
        (self.fake / "qkk.err").write_text(qkk_err)
        self.out.write_text("".join(f"{line}\n" for line in changes))
        return self.scan("aide", AIDE_OUT=str(self.out), FAKE=str(self.fake),
                         AIDE_DIR=str(self.aide_dir), PACMAN_LOG=str(self.pacman_log),
                         PACMAN_WAIT="0", **env)

    def pacman_calls(self, flag):
        return [a for a in self.argv() if a[0] == "pacman" and a[1] == flag]

    def baseline_kept(self):
        return self.db.read_text() == "baseline" and not (self.aide_dir / "aide.db.new.gz").exists()


class Batched(AideRun):
    def test_thousands_of_changes_cost_one_lookup_each(self):
        files = [f"/usr/lib/modules/9.9.9-test/kernel/m{i}.ko" for i in range(3000)]
        log = self.run_aide([f"f+++++++++++++++++: {f}" for f in files],
                            ql=["kernel /usr/lib/modules/9.9.9-test/"] + [f"kernel {f}" for f in files])
        self.assertIn("summary: 0 unexplained, 0 to confirm, 3000 from package updates", log)
        self.assertEqual(len(self.pacman_calls("-Ql")), 1)
        self.assertEqual(self.pacman_calls("-Qkk"), [["pacman", "-Qkk", "kernel"]])
        self.assertEqual(self.pacman_calls("-Qqo"), [])
        self.assertEqual(self.pacman_calls("-Qii"), [])

    def test_baseline_and_package_lists_move_on_together(self):
        self.run_aide(["f ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"])
        self.assertEqual(self.db.read_text(), "new\n")
        owners = self.state / "scan/owners.gz"
        self.assertEqual(stat.S_IMODE(owners.stat().st_mode), 0o600)
        with gzip.open(owners, "rt") as f:
            self.assertEqual(f.read(), "tool /usr/bin/tool\n")


class PacmanVerdicts(AideRun):
    def test_an_edited_configuration_file_is_amber(self):
        # pacman -Qkk calls these "backup file:", which 0.2.11 ignored, so an
        # edited /etc/hosts read as verified by pacman.
        log = self.run_aide(["f ... .C... : /etc/hosts"], ql=["filesystem /etc/hosts"],
                            qkk_out="backup file: filesystem: /etc/hosts (Size mismatch)\n"
                                    "backup file: filesystem: /etc/hosts (SHA256 checksum mismatch)\n")
        self.assertIn("AMBER changed /etc/hosts (config file of filesystem, edited locally)", log)

    def test_a_file_swapped_for_a_link_is_red(self):
        log = self.run_aide(["l ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"],
                            qkk_err="warning: tool: /usr/bin/tool (File type mismatch)\n")
        self.assertIn("RED changed /usr/bin/tool (owned by tool but fails pacman's checksum)", log)

    def test_a_package_without_an_mtree_vouches_for_nothing(self):
        (self.fake / "qkk.short").touch()
        log = self.run_aide(["f ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"],
                            qkk_out="tool: no mtree file\n")
        self.assertIn("RED changed /usr/bin/tool (owned by tool but fails pacman's checksum)", log)

    def test_a_mode_change_alone_is_an_ownership_red(self):
        log = self.run_aide(["f ... p.... : /usr/bin/tool"], ql=["tool /usr/bin/tool"],
                            qkk_err="warning: tool: /usr/bin/tool (Permissions mismatch)\n")
        self.assertIn("RED changed /usr/bin/tool (owned by tool but fails pacman's ownership "
                      "or permission check)", log)

    def test_a_bare_time_mismatch_is_verified(self):
        log = self.run_aide(["f ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"],
                            qkk_err="warning: tool: /usr/bin/tool (Modification time mismatch)\n")
        self.assertIn("PKG changed /usr/bin/tool (tool, verified by pacman)", log)

    def test_unpackaged_files_keep_their_verdicts(self):
        log = self.run_aide(["f+++++++++++++++++: /usr/bin/dropped",
                             "f+++++++++++++++++: /etc/mine.conf"])
        self.assertIn("RED added /usr/bin/dropped (unpackaged file in a system code path)", log)
        self.assertIn("AMBER added /etc/mine.conf (not from a package, confirm it was you)", log)


class Removed(AideRun):
    def save_owners(self, lines):
        (self.state / "scan").mkdir(exist_ok=True)
        with gzip.open(self.state / "scan/owners.gz", "wt") as f:
            f.write("".join(f"{line}\n" for line in lines))

    def test_files_of_a_package_pacman_upgraded_since_are_package_changes(self):
        self.save_owners(["qt /usr/include/qt/old.h"])
        self.pacman_log.write_text("[2026-06-01T10:00:00+0100] [ALPM] upgraded qt (1-1 -> 2-1)\n")
        log = self.run_aide(["f-----------------: /usr/include/qt/old.h"])
        self.assertIn("PKG removed /usr/include/qt/old.h (qt's at the last check, removed when "
                      "pacman changed qt)", log)

    def test_files_of_a_package_pacman_left_alone_stay_amber(self):
        self.save_owners(["qt /usr/include/qt/old.h"])
        self.pacman_log.write_text("[2025-06-01T10:00:00+0100] [ALPM] upgraded qt (1-1 -> 2-1)\n"
                                   "[2026-06-01T10:00:00+0100] [ALPM] upgraded other (1-1 -> 2-1)\n")
        log = self.run_aide(["f-----------------: /usr/include/qt/old.h"])
        self.assertIn("AMBER removed /usr/include/qt/old.h (unpackaged file removed)", log)

    def test_without_saved_lists_removed_files_stay_amber(self):
        self.pacman_log.write_text("[2026-06-01T10:00:00+0100] [ALPM] upgraded qt (1-1 -> 2-1)\n")
        log = self.run_aide(["f-----------------: /usr/include/qt/old.h"])
        self.assertIn("AMBER removed /usr/include/qt/old.h (unpackaged file removed)", log)

    def test_a_missing_file_pacman_still_lists_is_amber(self):
        # 0.2.11 called this a package change, but no package change took it.
        log = self.run_aide(["f-----------------: /usr/bin/sudo"], ql=["sudo /usr/bin/sudo"])
        self.assertIn("AMBER removed /usr/bin/sudo (owned by sudo but missing, confirm it was you)",
                      log)

    def test_modules_of_a_kernel_that_is_gone_are_one_line(self):
        gone = "/usr/lib/modules/0.0.0-gone-test"
        changes = [f"d-----------------: {gone}"] + [
            f"f-----------------: {gone}/kernel/m{i}.ko" for i in range(500)]
        log = self.run_aide(changes)
        self.assertIn(f"PKG removed {gone} (501 entries, the modules of kernel 0.0.0-gone-test, "
                      "which is no longer installed)", log)
        self.assertNotIn("AMBER", log)
        self.assertIn("summary: 0 unexplained, 0 to confirm, 501 from package updates", log)
        self.assertEqual(len([a for a in self.argv() if "--old-kernel-modules" in a]), 1)

    def test_modules_of_an_installed_kernel_stay_amber(self):
        # The running kernel's: spycatcher-report asks the real pacman, by its
        # full path, so the stand-in cannot answer for it.
        here = f"/usr/lib/modules/{os.uname().release}"
        log = self.run_aide([f"f-----------------: {here}/kernel/m.ko"],
                            ql=[f"kernel {here}/", f"kernel {here}/vmlinuz"])
        self.assertIn(f"AMBER removed {here}/kernel/m.ko (unpackaged file removed)", log)


class CannotGrade(AideRun):
    def test_pacman_failing_keeps_the_baseline(self):
        (self.fake / "ql.fail").touch()
        log = self.run_aide(["f ... .C... : /usr/bin/tool"])
        self.assertIn("summary: error, pacman -Ql failed", log)
        self.assertNotIn("RED ", log)
        self.assertTrue(self.baseline_kept())
        self.assertFalse((self.state / "scan/owners.gz").exists())

    def test_pacman_stopping_part_way_keeps_the_baseline(self):
        (self.fake / "qkk.short").touch()
        log = self.run_aide(["f ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"])
        self.assertIn("summary: error, pacman -Qkk failed", log)
        self.assertNotIn("RED ", log)
        self.assertTrue(self.baseline_kept())

    def test_a_running_pacman_sets_the_check_aside(self):
        # pacman holds its lock file open while it runs; a process holding
        # it open stands in for one.
        self.lock.touch()
        with open(self.lock) as held:
            holder = subprocess.Popen(["sleep", "60"], stdin=held)
        self.addCleanup(holder.kill)
        log = self.run_aide(["f ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"])
        self.assertIn("summary: skipped, package update in progress", log)
        self.assertIn(f"(it holds {self.lock})", log)
        self.assertEqual(self.argv_of("aide"), [])
        self.assertTrue(self.baseline_kept())

    def test_a_lock_nobody_holds_does_not_stop_the_check(self):
        # Review M6: a lock left by a crashed pacman set every check aside.
        self.lock.touch()
        log = self.run_aide(["f ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"])
        self.assertIn("is left over from a pacman that is no longer running", log)
        self.assertIn("summary: 0 unexplained, 0 to confirm, 1 from package updates", log)
        self.assertEqual(self.db.read_text(), "new\n")

    def test_a_failed_explanation_call_is_logged(self):
        # Review L3: its exit code was not checked.
        broken = self.script.parent / "spycatcher-report"
        broken.write_text("import sys\nsys.exit(3)\n")
        log = self.run_aide(["f+++++++++++++++++: /usr/bin/dropped"])
        self.assertIn("!! spycatcher-report --explain-changes failed (exit 3)", log)
        self.assertIn("RED added /usr/bin/dropped (unpackaged file in a system code path)", log)

    def test_a_new_database_left_by_a_failed_run_is_not_used(self):
        # Review L3: a run whose aide fails must not install an old new
        # database as the baseline later.
        (self.aide_dir / "aide.db.new.gz").write_text("stale")
        (self.base / "stubs/aide").write_text(RECORD + "exit 0\n")
        self.run_aide([])
        self.assertEqual(self.db.read_text(), "baseline")

    def test_an_update_during_the_check_sets_it_aside(self):
        # On 2026-10-20 a check graded files while glibc was being replaced:
        # pacman crashed, and package files read as unpackaged reds.
        (self.fake / "txn").touch()
        log = self.run_aide(["f ... .C... : /usr/bin/tool"], ql=["tool /usr/bin/tool"])
        self.assertIn("summary: skipped, package update during the check", log)
        self.assertTrue(self.baseline_kept())

    def test_the_report_does_not_grade_a_set_aside_check(self):
        (self.fake / "txn").touch()
        self.run_aide(["f+++++++++++++++++: /usr/bin/dropped"])
        r = subprocess.run(["python3", "-I", str(ROOT / "bin/spycatcher-report"), "--json"],
                           env=dict(os.environ, LOG_DIR=str(self.logs),
                                    RISK_REGISTER=str(self.base / "none.toml")),
                           capture_output=True, text=True)
        import json
        sections = {s["title"]: s for s in json.loads(r.stdout)["sections"]}
        self.assertEqual(sections["System file integrity (AIDE)"]["headline"], "No AIDE result yet.")

    def argv_of(self, name):
        return [a for a in self.argv() if a[0] == name and a[1:2] == ["--update"]]


class ReviewPoCs(AideRun):
    """The proofs of concept from the review of da66dfa (finding H1): the
    grader skipped every path the file system called a folder, which
    followed symlinks and tested AIDE's escaped name rather than the file."""

    def test_package_dir_swapped_for_symlink_is_red(self):
        d = self.base / "sys/usr/lib/python3/site-packages"
        (d / "evil").mkdir(parents=True)
        (d / "evil/mod.py").write_text("payload")
        os.symlink(d / "evil", d / "pkgdir")
        log = self.run_aide(
            [f"l>...    : {d}/pkgdir", f"f----------------: {d}/pkgdir/mod.py"],
            ql=[f"pypkg {d}/pkgdir/", f"pypkg {d}/pkgdir/mod.py"])
        self.assertIn(f"RED changed {d}/pkgdir (owned by pypkg but fails pacman's checksum)", log)

    def test_newline_file_hidden_behind_backslash_dir(self):
        d = self.base / "sys/usr/lib/systemd/system-generators"
        d.mkdir(parents=True)
        (d / "evil\n").write_text("payload")
        (d / "evil\\012").mkdir()
        log = self.run_aide([f"f++++++++++++++++: {d}/evil\\012"])
        self.assertIn(f"RED added {d}/evil\\012 (name holds control characters", log)

    def test_world_writable_package_dir_is_red(self):
        d = self.base / "sys/etc/sudoers.d"
        d.mkdir(parents=True)
        os.chmod(d, 0o777)
        log = self.run_aide([f"d > p..         : {d}"], ql=[f"sudo {d}/"],
                            qkk_err=f"warning: sudo: {d} (Permissions mismatch)\n")
        self.assertIn(f"RED changed {d} (owned by sudo but fails pacman's ownership or "
                      "permission check)", log)

    def test_escaped_backslash_is_decoded(self):
        # AIDE writes a backslash as \\134; such a name is checked as itself.
        log = self.run_aide(["f ... .C... : /usr/bin/a\\134b"], ql=["tool /usr/bin/a\\b"])
        self.assertIn("PKG changed /usr/bin/a\\b (tool, verified by pacman)", log)


class ModeOnlyAskedAbout(AideRun):
    def test_mode_only_mismatch_is_sent_for_explanation(self):
        # R2-1: a FAT /boot gives every file the mount's mode. The scan asks
        # spycatcher-report about a package file whose only fault is its mode;
        # a stand-in answers as the real one does for such a file.
        fake = self.script.parent / "spycatcher-report"
        fake.write_text(
            "import sys\n"
            "if sys.argv[1] == '--explain-changes':\n"
            "    for rec in sys.stdin.buffer.read().split(b'\\0'):\n"
            "        owner, _, path = rec.partition(b'\\x1f')\n"
            "        if owner == b'amd-ucode':\n"
            "            sys.stdout.buffer.write(path + b'\\x1fPKG\\x1famd-ucode, mode from the mount\\0')\n")
        log = self.run_aide(["f ... p.... : /boot/amd-ucode.img"],
                            ql=["amd-ucode /boot/amd-ucode.img"],
                            qkk_err="warning: amd-ucode: /boot/amd-ucode.img (Permissions mismatch)\n")
        self.assertIn("PKG changed /boot/amd-ucode.img (amd-ucode, mode from the mount)", log)

    def test_config_file_permissions_and_rebuilt_caches_are_sent_too(self):
        fake = self.script.parent / "spycatcher-report"
        fake.write_text(
            "import sys\n"
            "if sys.argv[1] == '--explain-changes':\n"
            "    for rec in sys.stdin.buffer.read().split(b'\\0'):\n"
            "        owner, _, path = rec.partition(b'\\x1f')\n"
            "        if owner == b'cups':\n"
            "            sys.stdout.buffer.write(path + b'\\x1fAMBER\\x1fconfig file of cups, permissions changed locally\\0')\n"
            "        if path.endswith(b'gconv-modules.cache'):\n"
            "            sys.stdout.buffer.write(path + b'\\x1fPKG\\x1fcache the same as iconvconfig builds it now\\0')\n")
        log = self.run_aide(["f ... p.... : /etc/cups/printers.conf",
                             "f ... .C... : /usr/lib/gconv/gconv-modules.cache"],
                            ql=["cups /etc/cups/printers.conf"],
                            qkk_out="backup file: cups: /etc/cups/printers.conf (Permissions mismatch)\n"
                                    "backup file: cups: /etc/cups/printers.conf (GID mismatch)\n")
        self.assertIn("AMBER changed /etc/cups/printers.conf (config file of cups, permissions "
                      "changed locally)", log)
        self.assertIn("PKG changed /usr/lib/gconv/gconv-modules.cache (cache the same as "
                      "iconvconfig builds it now)", log)


LIVE_CUPS = "/etc/cups/printers.conf"


def live_cups_tightened():
    try:
        st = os.lstat(LIVE_CUPS)
    except OSError:
        return False
    return st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and os.path.exists(
        "/usr/bin/pacman") and subprocess.run(["/usr/bin/pacman", "-Q", "cups"],
                                              capture_output=True).returncode == 0


@unittest.skipUnless(live_cups_tightened(), "needs cups installed with printers.conf 0600 root")
class LiveCups(AideRun):
    """Round 4, C1, end to end on this machine's own printers.conf: the scan
    with pacman -Qkk answering in pacman 7.1's words, as it does for root,
    and spycatcher-report reading the real file, backup list and package
    mode. Only pacman -Qkk is a stand-in, since as a user it cannot read the
    file to check its content."""

    def test_printers_conf_tightened_by_cupsd_is_amber(self):
        qkk = f"warning: cups: {LIVE_CUPS} (Permissions mismatch)\n"
        wrapper = self.script.parent / "spycatcher-report"
        wrapper.write_text(
            "import importlib.machinery, importlib.util, sys\n"
            f"loader = importlib.machinery.SourceFileLoader('r', {str(ROOT / 'bin/spycatcher-report')!r})\n"
            "spec = importlib.util.spec_from_loader('r', loader)\n"
            "r = importlib.util.module_from_spec(spec)\n"
            "loader.exec_module(r)\n"
            f"r._qkk = lambda owner: {qkk!r} if owner == 'cups' else ''\n"
            "sys.exit(r.main())\n")
        log = self.run_aide([f"f ... p.... : {LIVE_CUPS}"], ql=[f"cups {LIVE_CUPS}"], qkk_err=qkk)
        self.assertIn(f"AMBER changed {LIVE_CUPS} (config file of cups, permissions changed "
                      "locally)", log)


if __name__ == "__main__":
    unittest.main()
