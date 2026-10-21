"""Checks that security-report keeps what it finds to the desktop user.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The HTML report names repositories, rules and changed files, so the page must
be readable by its owner only, and the folder the weekly timer keeps pages in
must be closed to other users. A path the report asks pacman about must not
go on pacman's command line, which any local user can read in the process
list. The gitleaks section must count a repository whose path has a space in
it, or the section shows green while the log holds findings.

Everything runs in a temporary folder. Nothing reads the real home folder,
/etc or /var/log, and nothing is sent anywhere.
"""

import datetime as dt
import importlib.machinery
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/security-report"


def load_report():
    loader = importlib.machinery.SourceFileLoader("security_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("security_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


R = load_report()


def mode(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


class HtmlReportFiles(unittest.TestCase):
    """Runs the report with --html as the weekly timer and the bar widget do,
    with HOME and the log folder in a temporary folder and an open umask."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.logs = Path(self.tmp.name) / "logs"
        self.logs.mkdir()
        self.dir = self.home / ".local/share/security-report"

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, page):
        env = dict(os.environ, HOME=str(self.home), LOG_DIR=str(self.logs),
                   RISK_REGISTER=str(Path(self.tmp.name) / "register.toml"),
                   SCAN_CONF=str(Path(self.tmp.name) / "scan.conf"),
                   PACMAN_LOG=str(Path(self.tmp.name) / "pacman.log"))
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--html", str(page)],
                           env=env, capture_output=True, text=True, timeout=120,
                           preexec_fn=lambda: os.umask(0o022))
        self.assertIn(r.returncode, (0, 1), r.stderr)
        return r

    def test_a_new_page_and_folder_are_private(self):
        page = self.dir / "report-2026-10-12.html"
        self.report(page)
        self.assertTrue(page.read_text().startswith("<!doctype html>"))
        self.assertEqual(mode(page), 0o600)
        self.assertEqual(mode(self.dir), 0o700)

    def test_the_bar_widget_page_is_private(self):
        page = self.dir / "latest-widget.html"
        self.report(page)
        self.assertEqual(mode(page), 0o600)

    def test_an_existing_open_folder_and_pages_are_closed(self):
        self.dir.mkdir(parents=True, mode=0o755)
        os.chmod(self.dir, 0o755)
        old = self.dir / "report-2026-10-05.html"
        old.write_text("last week")
        os.chmod(old, 0o644)
        (self.dir / "latest.html").symlink_to(old)
        page = self.dir / "report-2026-10-12.html"
        page.write_text("written earlier today")
        os.chmod(page, 0o644)
        self.report(page)
        self.assertEqual(mode(self.dir), 0o700)
        self.assertEqual(mode(page), 0o600)
        self.assertNotEqual(page.read_text(), "written earlier today")
        self.assertEqual(mode(old), 0o600)
        self.assertEqual(old.read_text(), "last week")
        self.assertTrue((self.dir / "latest.html").is_symlink())

    def test_a_symlink_at_the_page_is_replaced_not_followed(self):
        self.dir.mkdir(parents=True)
        target = Path(self.tmp.name) / "elsewhere.html"
        target.write_text("not the report's")
        os.chmod(target, 0o644)
        page = self.dir / "latest-widget.html"
        page.symlink_to(target)
        self.report(page)
        self.assertFalse(page.is_symlink())
        self.assertEqual(mode(page), 0o600)
        self.assertEqual(target.read_text(), "not the report's")
        self.assertEqual(mode(target), 0o644)

    def test_a_folder_given_on_the_command_line_keeps_its_mode(self):
        other = Path(self.tmp.name) / "shared"
        other.mkdir()
        os.chmod(other, 0o755)
        page = other / "report.html"
        self.report(page)
        self.assertEqual(mode(other), 0o755)
        self.assertEqual(mode(page), 0o600)

    def test_no_temporary_file_is_left(self):
        page = self.dir / "report.html"
        self.report(page)
        self.assertEqual([p.name for p in self.dir.iterdir()], ["report.html"])


class PacmanArguments(unittest.TestCase):
    """A path asked about with pacman -Qqo goes on standard input."""

    def test_a_path_is_not_on_the_command_line(self):
        path = "/home/someone/Private Repo/bin/tool"
        done = subprocess.CompletedProcess([], 0, stdout="pkg\n", stderr="")
        with mock.patch.object(R.subprocess, "run", return_value=done) as run:
            self.assertEqual(R._pacman("-Qqo", "--", path), "pkg\n")
        argv = run.call_args.args[0]
        self.assertFalse(any("Private Repo" in a or "someone" in a for a in argv), argv)
        self.assertEqual(argv, ["/usr/bin/pacman", "-Qqo", "-"])
        self.assertEqual(run.call_args.kwargs.get("input"), path + "\n")

    def test_a_path_with_a_newline_is_not_asked_about(self):
        with mock.patch.object(R.subprocess, "run") as run:
            self.assertIsNone(R._pacman("-Qqo", "--", "/usr/bin/a\n/usr/bin/b"))
        run.assert_not_called()

    def test_every_owner_query_in_an_integrity_check_keeps_paths_off_the_command_line(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "Private Repo" / "tool"
            target.parent.mkdir()
            target.write_text("#!/bin/sh\n")
            link = Path(d) / "link"
            link.symlink_to(target)
            calls = []

            def run(argv, **kw):
                calls.append(list(argv))
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")

            with mock.patch.object(R.subprocess, "run", side_effect=run):
                R.scriptlet_link_explains(f"added {link} (unpackaged file in a system code path)")
                R.scriptlet_setgid(str(target))
        self.assertTrue(calls)
        for argv in calls:
            self.assertFalse(any("Private Repo" in a for a in argv), argv)


class GitleaksSection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self.tmp.name)
        self.now = dt.datetime.now().replace(microsecond=0)
        self.since = self.now - dt.timedelta(days=7)

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, *repos, total=None):
        """A gitleaks log as security-scan writes it, one block per
        (path, rule) pair."""
        lines = ["=== gitleaks run at 2026-10-12T03:00:00+01:00 ==="]
        for path, rule in repos:
            lines += ["", f"--- {path}: 1 finding(s) ---",
                      f'[{{"RuleID": "{rule}", "File": "app.py"}}]']
        n = len(repos) if total is None else total
        lines += ["", f"summary: {n} finding(s) across 4 repo(s)"]
        stamp = (self.now - dt.timedelta(days=1)).strftime("%Y%m%d-%H%M%S")
        (self.logs / f"gitleaks-{stamp}.log").write_text("\n".join(lines) + "\n")

    def section(self, reg=None):
        with mock.patch.object(R, "LOG_DIR", self.logs):
            return R.secrets(self.now, self.since, reg or {})

    def test_a_repository_with_a_space_in_its_path_is_reported(self):
        self.scan(("/home/someone/Work/My Project", "generic-api-key"))
        s = self.section()
        self.assertEqual(s.rating, R.RED)
        self.assertEqual(len(s.items), 1)
        self.assertTrue(s.items[0][1].startswith("My Project: 1 possible secret(s)"), s.items)
        self.assertIn("generic-api-key", s.items[0][1])

    def test_a_colon_in_the_path_is_kept(self):
        self.scan(("/home/someone/Work/notes: draft", "private-key"))
        s = self.section()
        self.assertTrue(s.items[0][1].startswith("notes: draft: 1 possible secret(s)"), s.items)

    def test_each_block_keeps_its_own_rules(self):
        self.scan(("/home/someone/a b", "rule-one"), ("/home/someone/c", "rule-two"))
        s = self.section()
        self.assertEqual(sorted(i[1] for i in s.items),
                         ["a b: 1 possible secret(s) (rule-one)",
                          "c: 1 possible secret(s) (rule-two)"])

    def test_the_risk_register_matches_a_path_with_a_space(self):
        self.scan(("/home/someone/Work/My Project", "generic-api-key"))
        reg = {"secrets": {"fixture": {
            "repo": "/home/someone/Work/My Project", "rule": "generic-api-key",
            "rating": "amber", "risk": "a test key", "finding": "fake", "action": "none"}}}
        s = self.section(reg)
        self.assertEqual(s.rating, R.AMBER)
        self.assertEqual(s.items[0][1], "My Project: a test key")

    def test_findings_no_repository_line_accounts_for_are_not_green(self):
        self.scan(("/home/someone/x", "rule-one"), total=3)
        s = self.section()
        self.assertEqual(s.rating, R.RED)
        self.assertIn("3 finding(s)", s.headline)
        self.assertTrue(any("could not match" in i[1] for i in s.items), s.items)

    def test_a_clean_scan_is_green(self):
        self.scan()
        s = self.section()
        self.assertEqual(s.rating, R.GREEN)
        self.assertEqual(s.items, [])


if __name__ == "__main__":
    unittest.main()
