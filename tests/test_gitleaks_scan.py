"""Checks that the gitleaks scan keeps repository names out of command lines.

Run from the repository root:

    python3 -m unittest discover -s tests -v

A command line can be read by any local user through the process list, so the
scan must not hand a repository path to gitleaks or put one in a notification.
The test runs bin/spycatcher-scan with gitleaks and runuser replaced by
stand-ins that record how they were called, against repositories in a
temporary folder. Nothing reads the real home folder, /etc or /var/log, no
notification is shown, and nothing is sent anywhere.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/spycatcher-scan"

GITLEAKS = """#!/usr/bin/env bash
[ "$1 $2" = "dir --help" ] && exit 0
printf '%s\\n' "cwd=$PWD" "$@" >>"$CALLS/gitleaks"
report=""
while [ $# -gt 0 ]; do
  [ "$1" = "--report-path" ] && report="$2"
  shift
done
if [ -e .leak ]; then
  printf '[{"RuleID": "generic-api-key", "File": "app.py"}]\\n' >"$report"
  exit 1
fi
printf '[]\\n' >"$report"
"""

RUNUSER = """#!/usr/bin/env bash
printf '%s\\n' "$@" >>"$CALLS/runuser"
"""


class GitleaksScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.calls = base / "calls"
        self.logs = base / "logs"
        self.root = base / "Work"
        stubs = base / "bin"
        for d in (self.calls, self.logs, self.root, stubs):
            d.mkdir()
        for name, text in (("gitleaks", GITLEAKS), ("runuser", RUNUSER)):
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)

        (self.root / "private-client-repo/.git").mkdir(parents=True)
        (self.root / "private-client-repo/.leak").touch()
        (self.root / "clean-repo/.git").mkdir(parents=True)

        env = dict(os.environ,
                   PATH=f"{stubs}:{os.environ['PATH']}",
                   CALLS=str(self.calls),
                   SCAN_CONF=str(base / "absent.conf"),
                   LOG_DIR=str(self.logs),
                   GITLEAKS_CONFIG=str(base / "gitleaks.toml"),
                   DESKTOP_USER=subprocess.check_output(["id", "-un"], text=True).strip(),
                   SCAN_ROOT=str(self.root))
        self.run_ = subprocess.run(["bash", str(SCRIPT), "gitleaks"], env=env,
                                   capture_output=True, text=True)

    def tearDown(self):
        self.tmp.cleanup()

    def calls_to(self, name):
        f = self.calls / name
        return f.read_text() if f.exists() else ""

    def test_scan_runs(self):
        self.assertEqual(self.run_.returncode, 0, self.run_.stderr)

    def test_gitleaks_command_line_has_no_repository_path(self):
        calls = self.calls_to("gitleaks")
        args = [line for line in calls.splitlines() if not line.startswith("cwd=")]
        self.assertIn(".", args)
        for line in args:
            self.assertNotIn(str(self.root), line)
            self.assertNotIn("private-client-repo", line)

    def test_gitleaks_runs_inside_each_repository(self):
        cwds = {line[4:] for line in self.calls_to("gitleaks").splitlines()
                if line.startswith("cwd=")}
        self.assertEqual(cwds, {str(self.root / "private-client-repo"),
                                str(self.root / "clean-repo")})

    def test_log_still_names_the_repository(self):
        log = next(self.logs.glob("gitleaks-*.log")).read_text()
        self.assertIn(f"--- {self.root / 'private-client-repo'}: 1 finding(s) ---", log)
        self.assertIn("summary: 1 finding(s) across 2 repo(s)", log)

    @unittest.skipUnless(Path(f"/run/user/{os.getuid()}/bus").is_socket(),
                         "no session bus, so the scan sends no notification")
    def test_notification_gives_counts_only(self):
        calls = self.calls_to("runuser")
        self.assertIn("Secrets found in 1 of 2 repo(s)", calls)
        self.assertNotIn("private-client-repo", calls)
        self.assertNotIn(str(self.root), calls)


if __name__ == "__main__":
    unittest.main()
