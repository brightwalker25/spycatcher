"""Checks that the scan shares its logs only with a group that is the desktop
user's alone.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The logs name repositories, files and findings. Run as root, the scan gives
the log folder and the lynis report copy to the group named after the
desktop user only when that group is private to them: their primary group,
the only group with its GID, with no other member in the group file or
gshadow, no other account using it as a primary group, and accounts and
groups looked up only in the local files and systemd. Otherwise the folder
is kept 0700 for root and the lynis copy 0600, and the scan says so on
stderr.

The tests run a copy of bin/spycatcher-scan in lynis mode with id reporting
root, getent reading a fake passwd and group file, and lynis and runuser
replaced by stand-ins. install is wrapped to record its arguments and then
run without -o and -g, so the modes are real while no ownership is changed.
nsswitch.conf, gshadow and the lynis report are temporary files. Nothing
reads the real /etc or /var/log, no notification is shown, and nothing is
sent anywhere.
"""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/spycatcher-scan"

RECORD = """#!/bin/bash
printf '%s\\x1f' "${0##*/}" "$@" >>"$CALLS/all"
printf '\\n' >>"$CALLS/all"
"""

# Root to the scan itself; any other account is unknown, so notify() stops.
ID = RECORD + """if [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0; exit 0; fi
[ "$1" = -u ] && exit 1
exec {real} "$@"
"""

GETENT = RECORD + """case "$1" in
  passwd) f=$FAKE_PASSWD ;;
  group) f=$FAKE_GROUP ;;
  *) exit 1 ;;
esac
[ -n "${2-}" ] || exec cat "$f"
awk -F: -v k="$2" '$1 == k { print; found = 1 } END { exit !found }' "$f" || exit 2
"""

# Records the call, then installs with the modes asked for but no -o or -g.
INSTALL = RECORD + """args=()
while [ $# -gt 0 ]; do
  case "$1" in
    -o | -g) shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec {real} "${args[@]}"
"""

STUB = RECORD + "exit 0\n"

NSSWITCH = """passwd: files systemd
group: files [SUCCESS=merge] systemd
shadow: files systemd
hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns
"""

PASSWD = """root:x:0:0::/root:/bin/bash
user:x:1000:1000::{home}:/bin/bash
guest:x:1001:1001::/nonexistent:/bin/bash
"""

GROUP = """root:x:0:
user:x:1000:
guest:x:1001:
"""

GSHADOW = """root:!*::
user:!*::
guest:!*::
"""

MESSAGE = "has no group of their own"


def mode(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


class LogGroup(unittest.TestCase):
    """A copy of the scan run as a simulated root, in lynis mode."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.base = base
        self.home = base / "home/user"
        self.calls = base / "calls"
        self.logs = base / "logs"
        stubs = base / "stubs"
        for d in (self.home, self.calls, stubs, base / "scan"):
            d.mkdir(parents=True)
        (self.calls / "all").touch()

        path = os.environ["PATH"]
        texts = {"id": ID.replace("{real}", shutil.which("id", path=path)),
                 "getent": GETENT,
                 "install": INSTALL.replace("{real}", shutil.which("install", path=path)),
                 "lynis": STUB, "runuser": STUB}
        for name, text in texts.items():
            (stubs / name).write_text(text)
            (stubs / name).chmod(0o755)

        self.nsswitch = base / "nsswitch.conf"
        self.gshadow = base / "gshadow"
        self.passwd = base / "passwd"
        self.group = base / "group"
        self.report = base / "lynis-report.dat"
        self.nsswitch.write_text(NSSWITCH)
        self.gshadow.write_text(GSHADOW)
        self.passwd.write_text(PASSWD.format(home=self.home))
        self.group.write_text(GROUP)
        self.report.write_text("hardening_index=70\n")

        text = SCRIPT.read_text()
        for old, new in (("NSSWITCH=/etc/nsswitch.conf", f"NSSWITCH={self.nsswitch}"),
                         ("GSHADOW=/etc/gshadow", f"GSHADOW={self.gshadow}"),
                         ("/var/log/lynis-report.dat", str(self.report))):
            self.assertIn(old, text)
            text = text.replace(old, new)
        self.script = base / "scan/spycatcher-scan"
        self.script.write_text(text)

        self.env = dict(os.environ,
                        PATH=f"{stubs}:{path}",
                        CALLS=str(self.calls),
                        FAKE_PASSWD=str(self.passwd),
                        FAKE_GROUP=str(self.group),
                        SCAN_CONF=str(base / "absent.conf"),
                        LOG_DIR=str(self.logs),
                        DESKTOP_USER="user")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self):
        run = subprocess.run(["bash", str(self.script), "lynis"], env=self.env,
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run

    def installs(self):
        return [line.split("\x1f")[:-1] for line in
                (self.calls / "all").read_text().splitlines()
                if line.startswith("install\x1f")]

    def dat(self):
        return next(self.logs.glob("lynis-*-report.dat"))

    def assert_shared(self):
        run = self.scan()
        self.assertNotIn(MESSAGE, run.stderr)
        self.assertEqual(mode(self.logs), 0o750)
        self.assertEqual(mode(self.dat()), 0o640)
        calls = self.installs()
        self.assertIn(["install", "-d", "-m", "0750", "-o", "root", "-g", "user",
                       str(self.logs)], calls)
        self.assertTrue(any(c[:5] == ["install", "-m", "0640", "-g", "user"] for c in calls),
                        calls)

    def assert_root_only(self):
        run = self.scan()
        self.assertIn(MESSAGE, run.stderr)
        self.assertEqual(mode(self.logs), 0o700)
        self.assertEqual(mode(self.dat()), 0o600)
        calls = self.installs()
        self.assertIn(["install", "-d", "-m", "0700", "-o", "root", "-g", "root",
                       str(self.logs)], calls)
        self.assertTrue(any(c[:5] == ["install", "-m", "0600", "-g", "root"] for c in calls),
                        calls)
        for c in calls:
            self.assertNotIn("user", c)

    def test_private_group_shares_the_logs(self):
        self.assert_shared()

    def test_no_group_with_the_user_name(self):
        self.group.write_text(GROUP.replace("user:x:1000:", "staff:x:1000:"))
        self.assert_root_only()

    def test_group_with_another_member(self):
        self.group.write_text(GROUP.replace("user:x:1000:", "user:x:1000:guest"))
        self.assert_root_only()

    def test_second_group_with_the_same_gid(self):
        self.group.write_text(GROUP + "alias:x:1000:\n")
        self.assert_root_only()

    def test_primary_group_shared_with_another_account(self):
        self.passwd.write_text(PASSWD.format(home=self.home).replace(
            "guest:x:1001:1001:", "guest:x:1001:1000:"))
        self.assert_root_only()

    def test_member_listed_only_in_gshadow(self):
        self.gshadow.write_text(GSHADOW.replace("user:!*::", "user:!*::guest"))
        self.assert_root_only()

    def test_groups_looked_up_in_ldap(self):
        self.nsswitch.write_text(NSSWITCH.replace("group: files", "group: files ldap"))
        self.assert_root_only()

    def test_existing_shared_folder_is_closed(self):
        self.logs.mkdir(mode=0o750)
        self.logs.chmod(0o750)
        self.group.write_text(GROUP.replace("user:x:1000:", "user:x:1000:guest"))
        self.assert_root_only()


if __name__ == "__main__":
    unittest.main()
