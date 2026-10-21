"""Checks that the aide, rkhunter, models and gitleaks scans keep private
paths out of command lines, and that gitleaks errors are not read as clean.

Run from the repository root:

    python3 -m unittest discover -s tests -v

A command line can be read by any local user through the process list, so no
command the scan starts may be handed a path inside the desktop user's home
folder, a repository name or a finding. The tests run a copy of
bin/spycatcher-scan with the scanners, pacman, getent and runuser replaced by
stand-ins, and every other command it uses wrapped so its arguments are
recorded before the real command runs. The home folder is a temporary one;
system paths the scan reads or writes (/var/lib/aide, /var/log/pacman.log and
so on) are pointed into the same temporary folder in the copy. Nothing reads
the real home folder, /etc or /var/log, no notification is shown, and nothing
is sent anywhere.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/spycatcher-scan"

# Real commands the scan runs, wrapped to record their arguments.
WRAPPED = ("awk basename cat cmp cp cut date dirname env find grep head id install ls "
           "mktemp mv python3 readlink realpath rm sed sort stat tail tr wc xargs").split()

WRAPPER = """#!/bin/bash
printf '%s\\x1f' "{name}" "$@" >>"$CALLS/all"
printf '\\x1e' >>"$CALLS/all"
exec {real} "$@"
"""

# Stand-ins. Each records its arguments the same way, then fakes a result.
RECORD = """#!/bin/bash
printf '%s\\x1f' "${0##*/}" "$@" >>"$CALLS/all"
printf '\\x1e' >>"$CALLS/all"
"""

GETENT = RECORD + """printf 'user:x:1000:1000::%s:/bin/bash\\n' "$FAKE_HOME"
"""

RUNUSER = RECORD

# One package owns /usr/bin/fakebin and verifies clean; nothing else is owned.
PACMAN = RECORD + """case "$1" in
  -Qqo) [ "${@: -1}" = /usr/bin/fakebin ] && echo fakepkg ;;
  -Q) echo "fakepkg 1.0-1" ;;
  -Ql) printf 'fakepkg /usr/\\nfakepkg /usr/bin/\\nfakepkg /usr/bin/fakebin\\n' ;;
  -Qkk) shift; for p in "$@"; do echo "$p: 1 total files, 0 altered files"; done ;;
esac
exit 0
"""

AIDE = RECORD + """[ "$1" = --update ] || exit 0
cat "$AIDE_OUT"
exit 5
"""

RKHUNTER = RECORD + """[ "$1" = --check ] || exit 0
cat "$RKHUNTER_OUT"
"""

# Prints a summary like picklescan's when the folder it is given can be read.
PICKLESCAN = RECORD + """[ "$1" = -p ] && target="$2"
[ "$target" = . ] && target="$PWD"
if ! [ -r "$target" ] || ! [ -x "$target" ]; then
  echo "Traceback (most recent call last):"
  exit 1
fi
echo "----------- SCAN SUMMARY -----------"
echo "Scanned files: 2"
echo "Infected files: 0"
echo "Dangerous globals: 0"
echo "Suspicious globals: 1"
"""

# Behaves like gitleaks: a leak exits with --exit-code (1 when not given), a
# broken run (.broken in the repo) prints an error and exits 1.
GITLEAKS = RECORD + """[ "$1 $2" = "dir --help" ] && exit 0
report="" code=1
while [ $# -gt 0 ]; do
  [ "$1" = "--report-path" ] && report="$2"
  [ "$1" = "--exit-code" ] && code="$2"
  shift
done
if [ -e .broken ]; then
  echo "error: failed to load config" >&2
  exit 1
fi
if [ -e .leak ]; then
  printf '[{"RuleID": "generic-api-key", "File": "app.py"}]\\n' >"$report"
  exit "$code"
fi
printf '[]\\n' >"$report"
"""

STUBS = {"getent": GETENT, "runuser": RUNUSER, "pacman": PACMAN, "aide": AIDE,
         "rkhunter": RKHUNTER, "picklescan": PICKLESCAN, "gitleaks": GITLEAKS}


class ScanRun(unittest.TestCase):
    """A temporary home folder, stand-ins on PATH and a copy of the scan."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.base = base
        self.home = base / "home/user"
        self.calls = base / "calls"
        self.logs = base / "logs"
        self.state = base / "state"
        stubs = base / "stubs"
        for d in (self.home, self.calls, self.logs, self.state / "aide", stubs,
                  base / "scan"):
            d.mkdir(parents=True)
        (self.calls / "all").touch()

        path = os.environ["PATH"]
        for name in WRAPPED:
            real = shutil.which(name, path=path)
            if real:
                (stubs / name).write_text(WRAPPER.format(name=name, real=real))
        for name, text in STUBS.items():
            (stubs / name).write_text(text)
        for f in stubs.iterdir():
            f.chmod(0o755)

        # Point the system paths the scan uses into the temporary folder.
        text = SCRIPT.read_text()
        for old, new in (("/var/lib/aide", self.state / "aide"),
                         ("/var/lib/spycatcher", self.state / "scan"),
                         ("/boot/limine.conf", self.state / "no-limine.conf"),
                         ("/var/log/pacman.log", self.state / "pacman.log")):
            self.assertIn(old, text)
            text = text.replace(old, str(new))
        self.script = base / "scan/spycatcher-scan"
        self.script.write_text(text)
        (self.state / "pacman.log").write_text("")

        self.env = dict(os.environ,
                        PATH=f"{stubs}:{path}",
                        CALLS=str(self.calls),
                        FAKE_HOME=str(self.home),
                        SCAN_CONF=str(base / "absent.conf"),
                        LOG_DIR=str(self.logs),
                        DESKTOP_USER=subprocess.check_output(["id", "-un"], text=True).strip())

    def tearDown(self):
        # Unlock any folder a test locked, so it can be removed.
        for d, subdirs, _ in os.walk(self.base):
            for s in subdirs:
                p = os.path.join(d, s)
                if not os.path.islink(p):
                    os.chmod(p, 0o755)
        self.tmp.cleanup()

    def scan(self, mode, **env):
        run = subprocess.run(["bash", str(self.script), mode], env=dict(self.env, **env),
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        return next(self.logs.glob(f"{mode}-*.log")).read_text()

    def argv(self):
        """Every recorded command line, as a list of arguments."""
        # Calls end in \x1e rather than a new line, since an argument such
        # as an awk program may hold new lines.
        return [rec.split("\x1f")[:-1] for rec in
                (self.calls / "all").read_text().split("\x1e") if rec]

    def assert_no_argv_has(self, needle, allow=()):
        for args in self.argv():
            if args[0] in allow:
                continue
            for a in args:
                self.assertNotIn(needle, a, f"{args[0]} was given {a!r}")


class AideHomePaths(ScanRun):
    def setUp(self):
        super().setUp()
        h = self.home
        (h / ".local/bin").mkdir(parents=True)
        (h / ".ssh").mkdir()
        (h / ".ssh/id_client_secret").write_text("x")
        os.symlink("/usr/bin/true", h / ".local/bin/linked-tool")
        # A link outside the home folder that resolves into it.
        self.outside = self.base / "sys/into-home"
        self.outside.parent.mkdir()
        os.symlink(h / ".ssh/id_client_secret", self.outside)
        (self.state / "aide/aide.db.gz").write_text("baseline")
        out = self.base / "aide.out"
        out.write_text(
            f"f+++++++++++++++++: {h}/.ssh/id_client_secret\n"
            f"f ... .C... : {h}/.local/bin/linked-tool\n"
            f"f-----------------: {h}/.ssh/id_old_client\n"
            f"d ... m.... : {h}/.ssh\n"
            "f ... .C... : /usr/bin/fakebin\n"
            "f+++++++++++++++++: /etc/fake-local.conf\n"
            f"l+++++++++++++++++: {self.outside}\n")
        self.log = self.scan("aide", AIDE_OUT=str(out))

    def test_no_command_is_given_a_home_path(self):
        self.assert_no_argv_has(str(self.home))
        self.assert_no_argv_has("id_client_secret")

    def test_home_paths_get_the_unpackaged_verdicts(self):
        # The temporary home is outside /home. Since 0.2.12 the desktop
        # user's home folder is amber wherever it is, not only under /home.
        h = self.home
        self.assertIn(f"AMBER added {h}/.ssh/id_client_secret (not from a package, confirm it was you)",
                      self.log)
        self.assertIn(f"AMBER changed {h}/.local/bin/linked-tool (not from a package, confirm it was "
                      "you)", self.log)
        self.assertIn(f"AMBER removed {h}/.ssh/id_old_client (unpackaged file removed)", self.log)
        # A folder whose mode or owner changed is graded like a file since
        # 0.2.12, by AIDE's type letter, not by looking at the path.
        self.assertIn(f"AMBER changed {h}/.ssh (not from a package, confirm it was you)", self.log)
        # A system link that points into the home folder is not in it.
        self.assertIn(f"RED added {self.outside} (unpackaged file in a system code path)", self.log)

    def test_system_paths_are_still_checked_with_pacman(self):
        # Once for the whole run, never once per file: a kernel update
        # changes tens of thousands of files.
        calls = [a for a in self.argv() if a[0] == "pacman"]
        self.assertEqual(calls.count(["pacman", "-Ql"]), 1)
        self.assertEqual([a for a in calls if a[1] == "-Qkk"], [["pacman", "-Qkk", "fakepkg"]])
        self.assertFalse([a for a in calls if a[1] == "-Qqo"])
        self.assertIn("PKG changed /usr/bin/fakebin (fakepkg, verified by pacman)", self.log)
        self.assertIn("AMBER added /etc/fake-local.conf (not from a package, confirm it was you)",
                      self.log)
        self.assertIn("summary: 1 unexplained, 5 to confirm, 1 from package updates", self.log)


class RkhunterHomePaths(ScanRun):
    def setUp(self):
        super().setUp()
        out = self.base / "rkhunter.out"
        out.write_text(
            "Warning: The file properties have changed:\n"
            "         File: /usr/bin/fakebin\n"
            f"         File: {self.home}/.local/bin/tool\n"
            "Warning: Something else\n")
        self.log = self.scan("rkhunter", RKHUNTER_OUT=str(out))

    def test_no_command_is_given_a_home_path(self):
        self.assert_no_argv_has(str(self.home))

    def test_home_file_stays_unverified(self):
        self.assertIn(f"UNVERIFIED {self.home}/.local/bin/tool", self.log)
        self.assertIn("summary: 2 warning(s), 1 changed file(s) verified by pacman", self.log)


class ModelFolders(ScanRun):
    def setUp(self):
        super().setUp()
        ai = self.home / "AI"
        hf = self.home / ".cache/huggingface"
        for f in (ai / "model.ckpt", ai / "sub/x.pt", ai / ".venv/lib/y.pt", hf / "z.bin",
                  hf / "w.safetensors"):
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("x")
        self.roots = f"{ai} {hf}"

    def test_no_command_is_given_a_model_folder(self):
        self.scan("models", MODEL_ROOTS=self.roots)
        self.assert_no_argv_has(str(self.home))
        pick = [a for a in self.argv() if a[0] == "picklescan"]
        self.assertEqual(len(pick), 2)
        for a in pick:
            self.assertEqual(a[1:3], ["-p", "."])

    def test_counts_and_log_context_survive(self):
        log = self.scan("models", MODEL_ROOTS=self.roots)
        self.assertIn(f"--- {self.home / 'AI'} ---", log)
        self.assertIn(f"--- {self.home / '.cache/huggingface'} ---", log)
        self.assertIn("summary: 0 dangerous, 2 suspicious, 4 file(s) scanned, "
                      "3 pickle-format file(s)", log)

    @unittest.skipIf(os.geteuid() == 0, "root can enter any folder")
    def test_folder_that_cannot_be_entered_is_a_failed_scan(self):
        locked = self.home / "locked"
        locked.mkdir()
        locked.chmod(0)
        log = self.scan("models", MODEL_ROOTS=f"{self.roots} {locked}")
        self.assertIn(f"!! picklescan did not finish on {locked}", log)
        self.assertIn("summary: error, 1 folder(s) not scanned", log)
        self.assert_no_argv_has(str(self.home))


class GitleaksExitCode(ScanRun):
    def setUp(self):
        super().setUp()
        self.root = self.home / "Work"
        (self.root / "private-client-repo/.git").mkdir(parents=True)
        (self.root / "private-client-repo/.leak").touch()
        (self.root / "clean-repo/.git").mkdir(parents=True)
        self.config = self.base / "gitleaks.toml"
        self.config.write_text("[extend]\nuseDefault = true\n")

    def run_gitleaks(self, config=None):
        return self.scan("gitleaks", SCAN_ROOT=str(self.root),
                         GITLEAKS_CONFIG=str(config or self.config))

    def test_leaks_are_given_their_own_exit_code(self):
        log = self.run_gitleaks()
        calls = [a for a in self.argv() if a[0] == "gitleaks" and a[1:3] != ["dir", "--help"]]
        self.assertTrue(calls)
        for a in calls:
            self.assertIn("--exit-code", a)
            i = a.index("--exit-code")
            self.assertEqual(a[i + 1], "3")
        self.assertNotIn("!! ", log)
        self.assertIn("summary: 1 finding(s) across 2 repo(s)", log)

    def test_a_failed_run_is_logged_as_an_error(self):
        (self.root / "clean-repo/.broken").touch()
        log = self.run_gitleaks()
        self.assertIn(f"!! gitleaks errored on {self.root / 'clean-repo'} (exit 1)", log)
        self.assertNotIn("errored on " + str(self.root / "private-client-repo"), log)

    def test_missing_config_is_logged(self):
        missing = self.base / "missing.toml"
        log = self.run_gitleaks(config=missing)
        self.assertIn(f"!! gitleaks config {missing} is missing or unreadable", log)

    def test_no_command_is_given_a_repository_name(self):
        self.run_gitleaks()
        self.assert_no_argv_has("private-client-repo")
        self.assert_no_argv_has("clean-repo")
        # SCAN_ROOT itself is a configured folder and only find may see it.
        self.assert_no_argv_has(str(self.root), allow=("find",))


if __name__ == "__main__":
    unittest.main()
