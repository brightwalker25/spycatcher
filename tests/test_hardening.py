"""Checks that lynis warnings are listed but never grade the report.

Run from the repository root:

    python3 -m unittest discover -s tests -v

On 2026-10-21 the hardening section was amber because lynis warned that
systemd-timesyncd had not synchronised the time recently. Spycatcher looks
for signs that someone has been in the machine, and hardening advice is not
one, so the section stays green. A missing audit is grey here and graded in
the scan health section. Logs are written to a temporary folder.
"""

import datetime as dt
import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/spycatcher-report"
NOW = dt.datetime(2026, 10, 21, 12, 0)
AUDIT = ("summary: hardening index 70, 2 warning(s), 40 suggestion(s)\n"
         "--- warnings ---\n"
         "warning[]=TIME-3185|systemd-timesyncd did not synchronized the time recently.|-|-|\n"
         "warning[]=PKGS-7322|Found one or more vulnerable packages.|-|-|\n")


def load_report():
    loader = importlib.machinery.SourceFileLoader("spycatcher_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spycatcher_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class Hardening(unittest.TestCase):
    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def section(self):
        with mock.patch.object(self.r, "LOG_DIR", self.dir):
            return self.r.hardening(NOW, NOW - dt.timedelta(days=7))

    def test_warnings_are_listed_but_green(self):
        when = NOW - dt.timedelta(days=17)
        (self.dir / f"lynis-{when:%Y%m%d-%H%M%S}.log").write_text(AUDIT)
        s = self.section()
        self.assertEqual(s.rating, self.r.GREEN)
        self.assertEqual(len(s.items), 2)
        self.assertTrue(all(i[0] == self.r.GREEN for i in s.items))
        self.assertIn("70/100", s.headline)

    def test_no_audit_is_grey(self):
        s = self.section()
        self.assertEqual(s.rating, self.r.GREY)


if __name__ == "__main__":
    unittest.main()
