"""Checks that a scan run which never finished does not read as on schedule.

Run from the repository root:

    python3 -m unittest discover -s tests -v

On 2026-10-21 the AIDE check ran into its 45 minute limit and was stopped
before it wrote a summary line. Its log had no "!!" line and no "summary:
error", so the report counted it as a run on schedule, and the section was
green. Logs are written to a temporary folder; systemctl is a stand-in.
"""

import datetime as dt
import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/security-report"
NOW = dt.datetime(2026, 10, 21, 12, 0)
DONE = "=== aide run at x ===\nsummary: 0 unexplained, 0 to confirm, 5 from package updates\n"
STOPPED = "=== aide run at x ===\nPKG changed /usr/bin/ls (coreutils, verified by pacman)\n"


def load_report():
    loader = importlib.machinery.SourceFileLoader("security_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("security_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Health(unittest.TestCase):
    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        # Every other scan ran cleanly an hour ago.
        for mode in self.r.SCANS:
            if mode != "aide":
                self.write(mode, NOW - dt.timedelta(hours=1), "summary: 0 warning(s)\n")

    def write(self, mode, when, text, written=None):
        p = self.dir / f"{mode}-{when:%Y%m%d-%H%M%S}.log"
        p.write_text(text)
        t = (written or when).timestamp()
        os.utime(p, (t, t))
        return p

    def aide(self, state="inactive", result="success"):
        def systemctl(cmd):
            prop = cmd[4]
            return {"ActiveState": state, "Result": result}[prop] + "\n"
        with mock.patch.object(self.r, "LOG_DIR", self.dir), \
             mock.patch.object(self.r, "run", side_effect=systemctl):
            s = self.r.scan_health(NOW, NOW - dt.timedelta(days=7))
        return [i for i in s.items if i[1].startswith("aide")], s

    def test_finished_run_is_green(self):
        self.write("aide", NOW - dt.timedelta(hours=2), DONE)
        items, s = self.aide()
        self.assertEqual(items[0][0], self.r.GREEN)
        self.assertEqual(s.rating, self.r.GREEN)

    def test_run_stopped_by_its_time_limit_is_red(self):
        self.write("aide", NOW - dt.timedelta(days=1), DONE)
        self.write("aide", NOW - dt.timedelta(hours=3), STOPPED,
                   written=NOW - dt.timedelta(hours=2, minutes=15))
        items, s = self.aide(result="timeout")
        self.assertEqual(items[0][0], self.r.RED)
        self.assertIn("did not finish", items[0][1])
        self.assertIn("ran past its time limit", items[0][2])
        self.assertEqual(s.rating, self.r.RED)

    def test_one_stopped_run_is_amber(self):
        # Most often the machine shut down mid-run.
        self.write("aide", NOW - dt.timedelta(days=1), DONE)
        self.write("aide", NOW - dt.timedelta(hours=3), STOPPED)
        items, _ = self.aide(result="signal")
        self.assertEqual(items[0][0], self.r.AMBER)

    def test_two_stopped_runs_in_a_row_are_red(self):
        self.write("aide", NOW - dt.timedelta(days=1), STOPPED)
        self.write("aide", NOW - dt.timedelta(hours=3), STOPPED)
        items, _ = self.aide(result="signal")
        self.assertEqual(items[0][0], self.r.RED)

    def test_run_in_progress_grades_the_one_before(self):
        self.write("aide", NOW - dt.timedelta(hours=5), DONE)
        self.write("aide", NOW - dt.timedelta(minutes=30), STOPPED, written=NOW)
        items, _ = self.aide()
        self.assertEqual(items[0][0], self.r.GREEN)
        self.assertIn("last ran 5 hours ago", items[0][1])

    def test_run_in_progress_after_a_stopped_one(self):
        self.write("aide", NOW - dt.timedelta(hours=5), STOPPED)
        self.write("aide", NOW - dt.timedelta(minutes=30), "=== aide run at x ===\n")
        items, _ = self.aide(state="activating", result="timeout")
        self.assertEqual(items[0][0], self.r.RED)

    def test_quiet_log_while_the_unit_runs_is_in_progress(self):
        self.write("aide", NOW - dt.timedelta(hours=5), DONE)
        self.write("aide", NOW - dt.timedelta(minutes=40), "=== aide run at x ===\n")
        items, _ = self.aide(state="activating")
        self.assertEqual(items[0][0], self.r.GREEN)

    def test_first_run_in_progress(self):
        self.write("aide", NOW - dt.timedelta(minutes=5), "=== aide run at x ===\n", written=NOW)
        items, _ = self.aide()
        self.assertEqual(items[0][0], self.r.GREEN)
        self.assertIn("first run in progress", items[0][1])

    def test_set_aside_check_is_not_a_result(self):
        self.write("aide", NOW - dt.timedelta(hours=5), DONE)
        self.write("aide", NOW - dt.timedelta(hours=1),
                   "=== aide run at x ===\nsummary: skipped, package update during the check\n")
        items, _ = self.aide()
        self.assertEqual(items[0][0], self.r.GREEN)
        self.assertIn("last ran 5 hours ago", items[0][1])


if __name__ == "__main__":
    unittest.main()
