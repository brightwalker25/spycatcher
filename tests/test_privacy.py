"""Checks for the Privacy (Black Ops) section of spycatcher-report.

Run from the repository root:

    python3 -m unittest discover -s tests -v

Each case feeds a fixture from tests/fixtures/black-ops to the report through
BLACK_OPS_SUMMARY, in a temporary folder. In the fixtures, a `generatedAt` or
`lastScan` of 0 stands for the time the test runs, so that a fresh summary
stays fresh. Nothing here reads the real home folder, /etc or /var/log, and
nothing is sent anywhere.
"""

import contextlib
import datetime as dt
import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/spycatcher-report"
FIXTURES = ROOT / "tests/fixtures/black-ops"


def load_report():
    loader = importlib.machinery.SourceFileLoader("spycatcher_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spycatcher_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


R = load_report()


class PrivacySection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.now = dt.datetime.now().replace(microsecond=0)

    def tearDown(self):
        self.tmp.cleanup()

    def summary(self, name):
        """Copy a fixture into the sandbox, filling in the current time."""
        text = (FIXTURES / name).read_text()
        try:
            data = json.loads(text)
        except ValueError:
            out = self.dir / name
            out.write_text(text)
            return out
        stamp = int(time.time()) - 60
        if data.get("generatedAt") == 0:
            data["generatedAt"] = stamp
        if isinstance(data.get("watch"), dict) and data["watch"].get("lastScan") == 0:
            data["watch"]["lastScan"] = stamp
        out = self.dir / name
        out.write_text(json.dumps(data))
        return out

    def section(self, name=None, reg=None, path=None):
        if path is None:
            path = self.summary(name) if name else self.dir / "absent.json"
        return R.privacy(self.now, reg or {}, (path, ""))

    def ratings(self, s):
        return [r for r, *_ in s.items]

    # --- the cases the section must handle ---------------------------------

    def test_missing_file_is_grey(self):
        s = self.section()
        self.assertEqual(s.rating, "grey")
        self.assertIn("not installed", s.headline)
        self.assertEqual(self.ratings(s), ["grey"])

    def test_off_is_grey(self):
        s = self.section("off.json")
        self.assertEqual(s.rating, "grey")
        self.assertIn("switched off", s.headline)

    def test_clean_is_green(self):
        s = self.section("clean.json")
        self.assertEqual(s.rating, "green")
        self.assertEqual(set(self.ratings(s)), {"green"})
        self.assertIn("nothing needs a look", s.headline)

    def test_listen_and_watch_off_is_not_a_problem(self):
        s = self.section("partial.json")
        self.assertEqual(s.rating, "green")
        self.assertEqual(self.ratings(s).count("grey"), 2)
        self.assertIn("Listen mode and the software watch are off", s.headline)

    def test_amber(self):
        s = self.section("amber.json")
        self.assertEqual(s.rating, "amber")
        whats = " ".join(w for _, w, *_ in s.items)
        self.assertIn("1 finding(s) not yet reviewed", whats)
        self.assertIn("2 protection(s) were in place and have slipped", whats)
        self.assertNotIn("red", self.ratings(s))

    def test_red_only_for_a_leak(self):
        s = self.section("red.json")
        self.assertEqual(s.rating, "red")
        self.assertEqual(self.ratings(s).count("red"), 1)
        self.assertIn("telemetry service", s.headline)

    def test_stale_is_amber(self):
        s = self.section("stale.json")
        self.assertEqual(s.rating, "amber")
        self.assertIn("out of date", s.headline)
        self.assertTrue(any("last written" in w for _, w, *_ in s.items))

    def test_malformed_is_amber(self):
        s = self.section("malformed.json")
        self.assertEqual(s.rating, "amber")
        self.assertIn("not valid JSON", s.items[0][1])

    def test_unknown_schema_is_amber(self):
        path = self.dir / "future.json"
        path.write_text(json.dumps({"schema": 2}))
        self.assertEqual(self.section(path=path).rating, "amber")

    # --- the risk register ---------------------------------------------------

    def test_register_downgrades_an_item(self):
        reg = {"privacy": {"watch-unreviewed": {"rating": "green", "count": 1,
                                                "finding": "Checked by hand.", "action": "None needed."},
                           "slipped": {"rating": "green"}}}
        self.assertEqual(self.section("amber.json", reg).rating, "green")

    def test_register_does_not_hide_new_findings(self):
        reg = {"privacy": {"watch-unreviewed": {"rating": "green", "count": 0},
                           "slipped": {"rating": "green"}}}
        self.assertEqual(self.section("amber.json", reg).rating, "amber")

    def test_register_cannot_accept_a_leak(self):
        reg = {"privacy": {"listen-leak": {"rating": "green"}}}
        self.assertEqual(self.section("red.json", reg).rating, "red")

    def test_register_cannot_raise_a_rating(self):
        reg = {"privacy": {"holding": {"rating": "red"}}}
        self.assertEqual(self.section("clean.json", reg).rating, "green")

    # --- counts only ---------------------------------------------------------

    def test_names_in_the_file_are_never_shown(self):
        path = self.summary("clean.json")
        data = json.loads(path.read_text())
        data["host"] = "http-intake.logs.example.com"
        data["listen"]["program"] = "someapp"
        path.write_text(json.dumps(data))
        text = json.dumps([(s.title, s.headline, s.items) for s in [self.section(path=path)]])
        self.assertNotIn("example.com", text)
        self.assertNotIn("someapp", text)


class Location(unittest.TestCase):
    def pw(self, home):
        return lambda _: type("pw", (), {"pw_dir": home})()

    def test_user_with_xdg_state(self):
        path, note = R.summary_location({"XDG_STATE_HOME": "/sandbox/state"}, 1000)
        self.assertEqual(path, Path("/sandbox/state/black-ops/summary.json"))
        self.assertEqual(note, "")

    def test_user_without_xdg_state(self):
        path, _ = R.summary_location({}, 1000, getpwuid=self.pw("/sandbox/home"))
        self.assertEqual(path, Path("/sandbox/home/.local/state/black-ops/summary.json"))

    def test_root_through_sudo_reads_the_invoking_user(self):
        path, note = R.summary_location({"SUDO_USER": "someone", "HOME": "/root"}, 0,
                                        getpwnam=self.pw("/sandbox/home"))
        self.assertEqual(path, Path("/sandbox/home/.local/state/black-ops/summary.json"))
        self.assertIn("sudo", note)
        self.assertNotIn("someone", note)

    def test_root_without_sudo_reads_nothing(self):
        path, note = R.summary_location({"HOME": "/root"}, 0)
        self.assertIsNone(path)
        s = R.privacy(dt.datetime.now(), {}, (path, note))
        self.assertEqual(s.rating, "grey")
        self.assertIn("run the report as that user", s.headline)


class Overall(unittest.TestCase):
    """The privacy rating reaches --status, --json, --html and the text report."""

    def run_main(self, fixture, *args):
        green = lambda *a, **k: R.Section("Stub", R.GREEN, "fine")
        names = ["scan_health", "packages", "integrity", "rootkit", "models", "secrets", "hardening", "standing"]
        saved = {n: getattr(R, n) for n in names}
        saved_iv = R.installed_versions
        with tempfile.TemporaryDirectory() as tmp:
            case = PrivacySection()
            case.dir, case.now = Path(tmp), dt.datetime.now()
            path = case.summary(fixture) if fixture else Path(tmp) / "absent.json"
            env = {"BLACK_OPS_SUMMARY": str(path), "RISK_REGISTER": str(Path(tmp) / "none.toml")}
            old_env = {k: os.environ.get(k) for k in env}
            old_argv = sys.argv
            try:
                for n in names:
                    setattr(R, n, green)
                R.installed_versions = lambda: {}
                R.REGISTER = Path(env["RISK_REGISTER"])
                os.environ.update(env)
                sys.argv = ["spycatcher-report", *[a.replace("{tmp}", tmp) for a in args]]
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = R.main()
                html = (Path(tmp) / "r.html").read_text() if "--html" in args else ""
            finally:
                for n, f in saved.items():
                    setattr(R, n, f)
                R.installed_versions = saved_iv
                sys.argv = old_argv
                for k, v in old_env.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
        return code, out.getvalue(), html

    def test_status_red_on_leak(self):
        code, out, _ = self.run_main("red.json", "--status")
        self.assertTrue(out.startswith("RED:"))
        self.assertEqual(code, 1)

    def test_status_amber(self):
        _, out, _ = self.run_main("amber.json", "--status")
        self.assertTrue(out.startswith("AMBER:"))

    def test_status_green_when_not_installed(self):
        code, out, _ = self.run_main(None, "--status")
        self.assertTrue(out.startswith("GREEN:"), out)
        self.assertEqual(code, 0)

    def test_json_carries_the_section(self):
        _, out, _ = self.run_main("off.json", "--json")
        data = json.loads(out)
        self.assertEqual(data["overall"], "green")
        sec = data["sections"][-1]
        self.assertEqual((sec["title"], sec["rating"]), ("Privacy (Black Ops)", "grey"))

    def test_html_and_text(self):
        _, _, html = self.run_main("red.json", "--html", "{tmp}/r.html")
        self.assertIn("Privacy (Black Ops)", html)
        self.assertIn('class="card red"', html)
        _, text, _ = self.run_main("clean.json", "--plain")
        self.assertIn("Privacy (Black Ops)", text)


class Script(unittest.TestCase):
    def test_script_runs_in_a_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, LOG_DIR=tmp, RISK_REGISTER=str(Path(tmp) / "none.toml"),
                       BLACK_OPS_SUMMARY=str(Path(tmp) / "absent.json"))
            out = subprocess.run([sys.executable, str(SCRIPT), "--json"], env=env,
                                 capture_output=True, text=True, timeout=60)
            titles = [s["title"] for s in json.loads(out.stdout)["sections"]]
            self.assertEqual(titles[-1], "Privacy (Black Ops)")


if __name__ == "__main__":
    unittest.main()
