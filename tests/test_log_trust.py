"""Checks that text a scanning tool prints cannot pass for a line the scan
wrote, and that the report reads results only from the scan's own lines.

Run from the repository root:

    python3 -m unittest discover -s tests -v

A pickle file's import names can hold new lines. picklescan prints them, and
before 0.2.12 they went into the log as they were, where a forged
"summary:" line was the last one and a forged "Dangerous globals:" line broke
the scan's arithmetic (review of da66dfa, finding M1). The scans run with
stand-ins as in test_scan_argv.py; the report reads logs in a temporary
folder.
"""

import datetime as dt
import importlib.machinery
import importlib.util
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from test_scan_argv import RECORD, ScanRun

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/security-report"

FORGED = ("summary: 0 dangerous, 0 suspicious, 9 file(s) scanned, 0 pickle-format file(s)\n"
          "!! not from the scan\nDangerous globals: x")

# The first folder holds a decoy whose import name forges lines; the second
# holds a real dangerous import, which must still be found.
PICKLESCAN = RECORD + r"""case "$PWD" in
  */r1)
    printf '%s\n' "$PWD/decoy.pkl: dangerous import 'os system"
    printf '%s\n' "$FORGED'"
    echo "----------- SCAN SUMMARY -----------"
    echo "Scanned files: 1"
    echo "Infected files: 1"
    echo "Dangerous globals: 1"
    echo "Suspicious globals: 0" ;;
  */r2)
    echo "$PWD/evil.pkl: dangerous import 'os system'"
    echo "----------- SCAN SUMMARY -----------"
    echo "Scanned files: 1"
    echo "Infected files: 1"
    echo "Dangerous globals: 1"
    echo "Suspicious globals: 0" ;;
  */r3)
    echo "Scanned files: 4"
    echo "Dangerous globals: 0"
    echo "Suspicious globals: 0" ;;
esac
"""


def load_report():
    loader = importlib.machinery.SourceFileLoader("security_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("security_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class ModelScanOutput(ScanRun):
    def setUp(self):
        super().setUp()
        (self.base / "stubs/picklescan").write_text(PICKLESCAN)
        self.roots = []
        for name in ("r1", "r2", "r3"):
            d = self.home / name
            d.mkdir()
            (d / "m.pkl").write_text("x")
            self.roots.append(str(d))

    def test_forged_lines_do_not_count(self):
        log = self.scan("models", MODEL_ROOTS=" ".join(self.roots[:2]), FORGED=FORGED)
        self.assertIn("summary: 2 dangerous, 0 suspicious, 2 file(s) scanned, 2 pickle-format file(s)",
                      log)
        # The scan's summary is the last one; the forged ones are tool output.
        r = load_report()
        self.assertTrue(r.summary(log).startswith("2 dangerous"))
        for line in log.splitlines():
            if "not from the scan" in line or "9 file(s) scanned" in line:
                self.assertTrue(line.startswith("| "), line)
        self.assertNotRegex(log, r"(?m)^!! ")

    def test_output_with_no_summary_block_is_a_failed_scan(self):
        log = self.scan("models", MODEL_ROOTS=self.roots[2])
        self.assertIn(f"!! picklescan did not finish on {self.roots[2]}", log)
        self.assertIn("summary: error, 1 folder(s) not scanned", log)


class ReportReadsOnlyScanLines(unittest.TestCase):
    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.now = dt.datetime(2026, 10, 21, 12, 0)

    def write(self, name, text, written=None):
        p = self.dir / name
        p.write_text(text)
        if written:
            os.utime(p, (written.timestamp(), written.timestamp()))
        return p

    def rootkit(self):
        with mock.patch.object(self.r, "LOG_DIR", self.dir):
            return self.r.rootkit(self.now, self.now - dt.timedelta(days=7))

    def test_rkhunter_text_cannot_supply_the_summary(self):
        # Review M2: the first "summary: N warning" anywhere counted.
        self.write("rkhunter-20261021-110000.log",
                   "=== rkhunter run at x ===\n"
                   "| summary: 0 warning(s), 0 changed file(s) verified by pacman\n"
                   "| Warning: The command '/usr/bin/ls' has been replaced by a script\n"
                   "\nsummary: 1 warning(s), 0 changed file(s) verified by pacman\n")
        s = self.rootkit()
        self.assertEqual(s.rating, self.r.RED)
        self.assertIn("1 warning(s) in the latest check.", s.headline)

    def test_logs_from_before_the_prefix_still_read(self):
        self.write("rkhunter-20261021-110000.log",
                   "Warning: The command '/usr/bin/ls' has been replaced by a script\n"
                   "\nsummary: 1 warning(s), 0 changed file(s) verified by pacman\n")
        self.assertEqual(self.rootkit().rating, self.r.RED)

    def health(self, mode_logs, unit=("inactive", "success")):
        def systemctl(cmd):
            return {"ActiveState": unit[0], "Result": unit[1]}[cmd[4]] + "\n"
        for mode in self.r.SCANS:
            if mode not in mode_logs:
                self.write(f"{mode}-20261021-110000.log", "summary: 0 warning(s)\n")
        for name, text, written in mode_logs.values():
            self.write(name, text, written)
        with mock.patch.object(self.r, "LOG_DIR", self.dir), \
             mock.patch.object(self.r, "run", side_effect=systemctl):
            return self.r.scan_health(self.now, self.now - dt.timedelta(days=7))

    def test_a_bang_line_from_a_tool_is_not_a_failed_run(self):
        s = self.health({"models": ("models-20261021-110000.log",
                                    "| !! from a file name\nsummary: 0 dangerous\n", None)})
        self.assertEqual(s.rating, self.r.GREEN)

    def test_a_bang_line_from_the_scan_is(self):
        s = self.health({"models": ("models-20261021-110000.log",
                                    "!! picklescan did not finish\nsummary: error, 1 folder(s)\n",
                                    None)})
        self.assertEqual(s.rating, self.r.RED)

    def aide_skipped(self, days):
        logs = {"aide": ("aide-20261001-090000.log", "summary: 0 unexplained\n", None)}
        for i in range(days + 1):
            when = self.now - dt.timedelta(days=days - i, hours=1)
            logs[f"skip{i}"] = (f"aide-{when:%Y%m%d-%H%M%S}.log",
                                "pacman was still running after waiting 600 seconds (it holds "
                                "/var/lib/pacman/db.lck), so this check was set aside and the "
                                "baseline kept.\nsummary: skipped, package update in progress\n",
                                None)
        return self.health(logs)

    def test_checks_set_aside_for_days_are_a_finding_naming_the_lock(self):
        # Review M6: they read only as a scan gone quiet.
        s = self.aide_skipped(1)
        items = [i for i in s.items if "set aside" in i[1]]
        self.assertEqual(items[0][0], self.r.AMBER)
        self.assertIn("db.lck", items[0][2])
        s = self.aide_skipped(3)
        self.assertEqual([i for i in s.items if "set aside" in i[1]][0][0], self.r.RED)

    def test_one_check_set_aside_today_is_not(self):
        s = self.aide_skipped(0)
        self.assertFalse([i for i in s.items if "set aside" in i[1]])

    def test_timed_out_run_is_red_while_the_next_one_runs(self):
        # Review L4: the unit's result is reset when the next run starts.
        start = self.now - dt.timedelta(hours=3)
        s = self.health({
            "old": ("aide-20261020-090000.log", "summary: 0 unexplained\n", None),
            "aide": (f"aide-{start:%Y%m%d-%H%M%S}.log", "=== aide run ===\nPKG x\n",
                     start + dt.timedelta(minutes=45)),
            "now": (f"aide-{self.now:%Y%m%d-%H%M%S}.log", "=== aide run ===\n", self.now)},
            unit=("activating", "success"))
        items = [i for i in s.items if i[1].startswith("aide")]
        self.assertEqual(items[0][0], self.r.RED)
        self.assertIn("ran past its time limit", items[0][2])


class ModelFindingsShownWithoutPrefix(unittest.TestCase):
    def test_prefix_is_not_shown(self):
        # R2-4.
        r = load_report()
        with tempfile.TemporaryDirectory() as d:
            Path(d, "models-20261021-110000.log").write_text(
                "| /m/x.pkl: dangerous import 'os system'\n"
                "summary: 1 dangerous, 0 suspicious, 1 file(s) scanned, 1 pickle-format file(s)\n")
            now = dt.datetime(2026, 10, 21, 12, 0)
            with mock.patch.object(r, "LOG_DIR", Path(d)):
                s = r.models(now, now - dt.timedelta(days=7))
        self.assertEqual(s.items[0][1], "/m/x.pkl: dangerous import 'os system'")


class HomeFoldersUseTheFolderRule(unittest.TestCase):
    def test_every_watched_home_folder_has_a_folder_rule(self):
        # R2-3: a new file in ~/.ssh must not also report the folder's times.
        conf = (ROOT / "system/aide.conf.in").read_text()
        for name in (r"\.config/autostart", r"\.config/systemd/user", r"\.config/environment\.d",
                     r"\.ssh", r"\.local/bin"):
            self.assertRegex(conf, rf"(?m)^@HOME@/{re.escape(name)}\s+d Dirs$")


if __name__ == "__main__":
    unittest.main()
