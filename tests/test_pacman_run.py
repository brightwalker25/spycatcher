"""Checks for the pacman runs read from pacman.log, and for the rule of last
resort that grades an unpackaged file in a system code path amber when it
was written during one.

Run from the repository root:

    python3 -m unittest discover -s tests -v

Real files in a temporary folder give real change times; pacman.log is a
stand-in, and the other rules are switched off so only this one decides.
"""

import datetime as dt
import importlib.machinery
import importlib.util
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/security-report"
SCAN = ROOT / "bin/security-scan"


def load_report():
    loader = importlib.machinery.SourceFileLoader("security_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("security_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def stamp(epoch, offset=0):
    """A pacman.log time for `epoch` seconds plus `offset`."""
    t = dt.datetime.fromtimestamp(int(epoch) + offset).astimezone()
    return t.strftime("%Y-%m-%dT%H:%M:%S%z")


def pacman_log(base, lines):
    """pacman.log text from (offset, message) pairs, each an [ALPM] line at
    `base` plus the offset; a message starting with "[" is written as is."""
    out = []
    for offset, msg in lines:
        tag = "" if msg.startswith("[") else "[ALPM] "
        out.append(f"[{stamp(base, offset)}] {tag}{msg}")
    return "\n".join(out) + "\n"


def hook(name):
    return f"running '{name}'..."


# One package update as pacman 7 logs it: pre-transaction hooks, the
# transaction, then post-transaction hooks.
UPDATE = [
    (0, "[PACMAN] Running 'pacman -Syu'"),
    (10, hook("00-guard.hook")),
    (10, hook("10-linux-modules-pre.hook")),
    (12, hook("71-dkms-remove.hook")),
    (16, "transaction started"),
    (20, "upgraded linux (7.2.10-arch1-1 -> 7.2.11-arch1-1)"),
    (60, "transaction completed"),
    (61, hook("60-depmod.hook")),
    (65, hook("70-dkms-install.hook")),
    # The DKMS build runs for seven minutes and pacman logs nothing.
    (65 + 420, hook("90-last.hook")),
]


class Runs(unittest.TestCase):
    def setUp(self):
        self.r = load_report()
        self.base = int(time.time()) - 86400

    def runs(self, lines):
        return [(int(a - self.base), int(b - self.base))
                for a, b in self.r._pacman_runs(pacman_log(self.base, lines))]

    def test_single_run_from_pre_hooks_to_last_post_hook(self):
        self.assertEqual(self.runs(UPDATE), [(10, 485)])

    def test_run_without_pre_hooks_starts_at_transaction(self):
        lines = [(0, "transaction started"), (5, "installed tool (1.0-1)"),
                 (6, "transaction completed")]
        self.assertEqual(self.runs(lines), [(0, 6)])

    def test_hooks_after_transaction_completed_belong_to_it(self):
        lines = [(0, "transaction started"), (5, "transaction completed"),
                 (6, hook("30-a.hook")), (9, hook("35-b.hook"))]
        self.assertEqual(self.runs(lines), [(0, 9)])

    def test_long_silent_hook_stays_in_the_run(self):
        lines = [(0, "transaction started"), (5, "transaction completed"),
                 (6, hook("70-dkms-install.hook")), (6 + 1800, hook("80-next.hook"))]
        self.assertEqual(self.runs(lines), [(0, 1806)])

    def test_gap_longer_than_a_step_closes_the_run(self):
        lines = [(0, "transaction started"), (5, "transaction completed"),
                 (6, hook("70-dkms-install.hook")), (6 + 1801, hook("80-next.hook"))]
        self.assertEqual(self.runs(lines), [(0, 6)])

    def test_pre_hook_after_a_gap_starts_the_next_run(self):
        lines = [(0, "transaction started"), (5, "transaction completed"),
                 (5000, hook("00-guard.hook")), (5003, "transaction started"),
                 (5004, "transaction completed")]
        self.assertEqual(self.runs(lines), [(0, 5), (5000, 5004)])

    def test_two_runs_back_to_back(self):
        # The first run's post-transaction hooks and the second run's
        # pre-transaction hooks meet with no line between them; the names
        # starting again from a lower one mark where the second run begins.
        lines = [(0, "transaction started"), (5, "transaction completed"),
                 (5, hook("30-systemd-daemon-reload-system.hook")),
                 (6, hook("90-omarchy-black-ops-watch.hook")),
                 (300, hook("00-omarchy-update-guard.hook")),
                 (300, hook("10-linux-modules-pre.hook")),
                 (306, "transaction started"), (310, "transaction completed"),
                 (311, hook("60-depmod.hook"))]
        self.assertEqual(self.runs(lines), [(0, 6), (300, 311)])

    def test_scriptlet_lines_do_not_extend_a_run(self):
        lines = [(0, "transaction started"), (5, "transaction completed"),
                 (900, "[ALPM-SCRIPTLET] ==> late output")]
        self.assertEqual(self.runs(lines), [(0, 5)])

    def test_lines_without_a_transaction_are_no_run(self):
        self.assertEqual(self.runs([(0, hook("60-depmod.hook"))]), [])

    def test_run_at_holds_one_second_before_and_two_after(self):
        log = pacman_log(self.base, UPDATE)
        at = self.r.pacman_run_at
        self.assertEqual(at(self.base + 300, log), (self.base + 10, self.base + 485))
        self.assertIsNotNone(at(self.base + 9, log))
        self.assertIsNotNone(at(self.base + 487, log))
        self.assertIsNone(at(self.base + 8, log))
        self.assertIsNone(at(self.base + 488, log))


class Files(unittest.TestCase):
    """A temporary folder standing for the file system."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(os.path.realpath(self.tmp.name))
        self.path = self.make("usr/lib/tool/plugin.so")
        self.c = os.lstat(self.path).st_ctime
        # Every other rule finds nothing, so only the pacman run decides.
        for name in ("rebuilt_by_hook", "scriptlet_link_package", "listed_link_package",
                     "depmod_rebuilt", "dkms_built", "scriptlet_wrote", "owned_all_along",
                     "config_mode_tightened", "mount_mode_explains", "hook_patched"):
            patcher = mock.patch.object(self.r, name, return_value=None)
            patcher.start()
            self.addCleanup(patcher.stop)

    def make(self, name, text="x"):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return str(p)

    def log_around(self, ctime, before=30, after=30):
        """pacman.log text with one run from `before` seconds before `ctime`
        to `after` seconds after it; negative values put it elsewhere."""
        base = int(ctime) - before
        span = before + after
        return pacman_log(base, [(0, "transaction started"),
                                 (span // 2, "transaction completed"),
                                 (span, hook("90-last.hook"))])

    def explain(self, records, log):
        return list(self.r.explain_changes(records, "", log))


class InRun(Files):
    def test_unpackaged_file_written_in_a_run_is_amber(self):
        log = self.log_around(self.c)
        start = dt.datetime.fromtimestamp(int(self.c) - 30).astimezone()
        out = self.explain([("", self.path)], log)
        self.assertEqual(out, [(self.path, "AMBER",
                                f"appeared during the package update of {start:%a %d %b %H:%M}, "
                                "which no rule explains; confirm")])

    def test_written_outside_every_run_stays_red(self):
        self.assertEqual(self.explain([("", self.path)], self.log_around(self.c, 200, -100)), [])
        self.assertEqual(self.explain([("", self.path)], self.log_around(self.c, -100, 200)), [])
        self.assertEqual(self.explain([("", self.path)], ""), [])

    def test_missing_file_stays_red(self):
        log = self.log_around(self.c)
        os.unlink(self.path)
        self.assertEqual(self.explain([("", self.path)], log), [])

    def test_other_rules_come_first(self):
        self.r.scriptlet_wrote.return_value = ("tool", "PKG")
        out = self.explain([("", self.path)], self.log_around(self.c))
        self.assertEqual(out[0][1], "PKG")

    def test_link_is_judged_by_its_own_change_time(self):
        # The link's target was written during the run; the link was made
        # after it, outside it, and is what changed.
        log = self.log_around(self.c, 30, 0)
        time.sleep(3.2)
        link = str(self.dir / "usr/lib/tool/link.so")
        os.symlink(self.path, link)
        self.assertEqual(self.explain([("", link)], log), [])
        self.assertTrue(self.explain([("", self.path)], log))

    def test_dangling_link_written_in_a_run_is_amber(self):
        link = str(self.dir / "usr/lib/tool/gone.so")
        os.symlink(self.dir / "nowhere", link)
        out = self.explain([("", link)], self.log_around(os.lstat(link).st_ctime))
        self.assertEqual(out[0][:2], (link, "AMBER"))

    def test_packaged_file_failing_pacman_is_unaffected(self):
        self.assertEqual(self.explain([("tool", self.path)], self.log_around(self.c)), [])

    def test_boot_and_amber_folders_are_not_system_code(self):
        log = self.log_around(time.time())
        for path in ("/boot/vmlinuz-linux", "/etc/tool.conf", "/usr/local/bin/tool",
                     "/opt/tool/bin", "/root/x", "/home/x/y"):
            self.assertIsNone(self.r.written_in_pacman_run(path, log), path)


class OldLine(Files):
    def check(self, log, until, current=False):
        line = f"added {self.path} (unpackaged file in a system code path)"
        return self.r.unpackaged_explains(line, {}, log, None, until, current)

    def test_old_red_line_in_a_run_is_amber(self):
        later = dt.datetime.now().astimezone() + dt.timedelta(minutes=1)
        self.assertEqual(self.check(self.log_around(self.c), later), "AMBER")

    def test_current_line_is_not_rechecked(self):
        later = dt.datetime.now().astimezone() + dt.timedelta(minutes=1)
        self.assertIsNone(self.check(self.log_around(self.c), later, current=True))

    def test_changed_since_the_run_stays_red(self):
        earlier = dt.datetime.fromtimestamp(self.c - 60).astimezone()
        self.assertIsNone(self.check(self.log_around(self.c), earlier))

    def test_outside_every_run_stays_red(self):
        later = dt.datetime.now().astimezone() + dt.timedelta(minutes=1)
        self.assertIsNone(self.check(self.log_around(self.c, 200, -100), later))

    def test_packaged_line_is_not_graded_by_the_run(self):
        later = dt.datetime.now().astimezone() + dt.timedelta(minutes=1)
        line = f"changed {self.path} (owned by tool but fails pacman's checksum)"
        self.assertIsNone(self.r.unpackaged_explains(line, {}, self.log_around(self.c),
                                                     None, later))


class RulesVersion(unittest.TestCase):
    def test_scan_and_report_agree(self):
        m = re.search(r'log "graded by security-scan rules (\d+)"', SCAN.read_text())
        self.assertEqual(int(m.group(1)), load_report().RULES_VERSION)
        self.assertEqual(load_report().RULES_VERSION, 4)


if __name__ == "__main__":
    unittest.main()
