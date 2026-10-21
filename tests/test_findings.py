"""Checks for the AIDE findings of 0.3.0: a path logged by several runs is
one finding, findings are grouped by folder and day, reds stay until they
are acknowledged, and an acknowledgement covers only lines logged before it
while each file is in the state root saw. Also checks that the scan's log
pruning keeps the logs the report says still hold a red.

Run from the repository root:

    python3 -m unittest discover -s tests -v

AIDE logs are written in the scan's format to a temporary log folder, and
the acknowledgements and risk register are temporary files. Real files in a
temporary folder give real inodes, sizes and change times. Nothing runs as
root: os.geteuid and os.chown are stand-ins.
"""

import contextlib
import datetime as dt
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/spycatcher-report"
SCAN = ROOT / "bin/spycatcher-scan"

REASON_RED = "unpackaged file in a system code path"
REASON_AMBER = "not from a package, confirm it was you"
REASON_REMOVED = "unpackaged file removed"


def load_report():
    loader = importlib.machinery.SourceFileLoader("spycatcher_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spycatcher_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def red(path, what="added"):
    return f"RED {what} {path} ({REASON_RED})"


def amber(path, what="changed"):
    return f"AMBER {what} {path} ({REASON_AMBER})"


def removed(path):
    return f"AMBER removed {path} ({REASON_REMOVED})"


def write_log(folder, when, *lines, rules=4):
    """An AIDE log for a run at `when`, in the scan's format."""
    stamp = when.astimezone().isoformat()
    text = (f"=== aide run at {stamp} ===\n"
            f"graded by spycatcher rules {rules}\n"
            + "".join(line + "\n" for line in lines)
            + "summary: 0 unexplained, 0 to confirm, 0 from package updates\n"
            f"=== done at {stamp} ===\n")
    p = Path(folder) / f"aide-{when:%Y%m%d-%H%M%S}.log"
    p.write_text(text)
    return p


class Files(unittest.TestCase):
    """A temporary folder standing for the file system, with the log
    folder, acknowledgements and risk register inside it."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(os.path.realpath(self.tmp.name))
        self.logdir = self.dir / "log"
        self.logdir.mkdir()
        self.acks = self.dir / "etc/acknowledged.json"
        self.acks.parent.mkdir()
        self.register = self.dir / "etc/risk-register.toml"
        self.register.write_text("")
        self.now = dt.datetime.now().replace(microsecond=0)
        # The grade recheck() gives a red line's path; None keeps it red.
        self.grades = {}
        for name, value in (("LOG_DIR", self.logdir), ("ACKS", self.acks),
                            ("REGISTER", self.register)):
            self.patch(name, new=value)
        self.patch("listed_links", return_value={})
        self.patch("prefetch_owners", return_value=None)
        self.patch("recheck",
                   side_effect=lambda line, *a: self.grades.get(self.r.line_path(line)))
        self.run_cmd = self.patch_obj(self.r.subprocess, "run")

    def patch(self, name, **kw):
        return self.patch_obj(self.r, name, **kw)

    def patch_obj(self, obj, name, **kw):
        p = mock.patch.object(obj, name, **kw)
        started = p.start()
        self.addCleanup(p.stop)
        return started

    def make(self, name, text="x"):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return str(p)

    def day(self, days_ago, hour=10, minute=0):
        """A time on the day `days_ago` days before now."""
        d = self.now - dt.timedelta(days=days_ago)
        return d.replace(hour=hour, minute=minute, second=0)

    def log(self, when, *lines):
        return write_log(self.logdir, when, *lines, rules=self.r.RULES_VERSION)

    def integrity(self, days=7):
        return self.r.integrity(self.now, self.now - dt.timedelta(days=days))

    def items(self, s, rating):
        return [i for i in s.items if i[0] == rating]

    def ack_file(self, *records):
        self.acks.write_text(json.dumps({"version": 1, "acks": list(records)}))

    def record(self, paths, gid="0000aaaa", when=None, by="alice", reason="checked"):
        when = (when or self.now).isoformat()
        return {"id": gid, "when": when, "by": by, "reason": reason, "paths": paths}


class Findings(Files):
    def test_a_path_logged_by_three_runs_is_one_finding_dated_by_the_first(self):
        first = self.day(3)
        for when in (first, self.day(2), self.day(1)):
            self.log(when, red("/usr/lib/tool/a"))
        s = self.integrity()
        reds = self.items(s, self.r.RED)
        self.assertEqual(len(reds), 1)
        self.assertEqual(reds[0][1], f"added /usr/lib/tool/a ({REASON_RED})")
        self.assertIn(f"first seen {first:%a %d %b}", reds[0][2])
        self.assertIn("(1 file(s))", s.headline)
        self.assertEqual(s.rating, self.r.RED)

    def test_reds_outside_the_window_still_show_ambers_do_not(self):
        self.log(self.day(10), red("/usr/lib/tool/a"), amber("/etc/tool/x"))
        self.log(self.day(1))
        s = self.integrity()
        self.assertEqual(len(self.items(s, self.r.RED)), 1)
        self.assertEqual(self.items(s, self.r.AMBER), [])
        self.assertIn(f"first seen {self.day(10):%a %d %b}", self.items(s, self.r.RED)[0][2])

    def test_a_red_the_rules_now_call_amber_shows_only_inside_the_window(self):
        self.grades = {"/usr/lib/tool/old": "AMBER", "/usr/lib/tool/new": "AMBER"}
        self.log(self.day(10), red("/usr/lib/tool/old"))
        self.log(self.day(1), red("/usr/lib/tool/new"))
        s = self.integrity()
        self.assertEqual(self.items(s, self.r.RED), [])
        ambers = self.items(s, self.r.AMBER)
        self.assertEqual(len(ambers), 1)
        self.assertIn("/usr/lib/tool/new", ambers[0][2])
        self.assertNotIn("/usr/lib/tool/old", ambers[0][2])

    def test_a_red_the_rules_now_explain_is_gone(self):
        self.grades = {"/usr/lib/tool/a": "PKG"}
        self.log(self.day(10), red("/usr/lib/tool/a"))
        self.log(self.day(1), red("/usr/lib/tool/a"))
        s = self.integrity()
        self.assertEqual(self.items(s, self.r.RED), [])
        self.assertEqual(s.rating, self.r.GREEN)
        self.assertEqual(self.r.OPEN_RED_LOGS, set())

    def test_the_rules_version_is_read_under_the_old_and_the_new_name(self):
        # Logs written before 0.4.0, as Security Scan, name the rules by the
        # project's earlier name. Both forms mark a log graded by the current
        # rules; a log with neither line is re-checked as an old one.
        stamp = self.day(1).astimezone().isoformat()
        for name, current in (("spycatcher", True), ("security-scan", True), (None, False)):
            with self.subTest(name=name):
                for p in self.logdir.iterdir():
                    p.unlink()
                rules = f"graded by {name} rules {self.r.RULES_VERSION}\n" if name else ""
                (self.logdir / "aide-20261019-100000.log").write_text(
                    f"=== aide run at {stamp} ===\n{rules}{red('/usr/lib/tool/a')}\n"
                    "summary: 0 unexplained, 0 to confirm, 0 from package updates\n"
                    f"=== done at {stamp} ===\n")
                self.r.recheck.reset_mock()
                self.integrity()
                self.assertTrue(self.r.recheck.called)
                self.assertEqual(self.r.recheck.call_args.args[-1], current)
        self.assertIsNone(self.r.RULES_LINE.search("| graded by spycatcher rules 4\n"))

    def test_reds_in_one_folder_on_one_day_are_one_item(self):
        self.log(self.day(2, 9), red("/usr/lib/tool/a"))
        self.log(self.day(2, 15), red("/usr/lib/tool/sub/b"), red("/usr/lib/tool/c"))
        s = self.integrity()
        reds = self.items(s, self.r.RED)
        self.assertEqual(len(reds), 1)
        self.assertEqual(reds[0][1], "3 unexplained changes in 2 folder(s) under /usr/lib/tool")
        self.assertIn(f"first seen {self.day(2):%a %d %b}", reds[0][2])
        self.assertIn("For example:", reds[0][2])
        self.assertIn("1 item(s) of unexplained changes to system files (3 file(s)).", s.headline)

    def test_reds_in_one_folder_on_two_days_are_two_items(self):
        self.log(self.day(3), red("/usr/lib/tool/a"))
        self.log(self.day(2), red("/usr/lib/tool/b"))
        s = self.integrity()
        self.assertEqual(len(self.items(s, self.r.RED)), 2)
        self.assertEqual(len(self.r.FOUND_GROUPS), 2)

    def test_reds_in_two_folders_on_one_day_are_two_items(self):
        self.log(self.day(2), red("/usr/lib/tool/a"), red("/usr/bin/b"))
        s = self.integrity()
        self.assertEqual(len(self.items(s, self.r.RED)), 2)

    def test_ambers_in_one_folder_over_several_days_are_one_item(self):
        self.log(self.day(5), amber("/etc/tool/a"))
        self.log(self.day(3), amber("/etc/tool/b"))
        self.log(self.day(1), amber("/etc/tool/c"), amber("/etc/tool/a"))
        s = self.integrity()
        ambers = self.items(s, self.r.AMBER)
        self.assertEqual(len(ambers), 1)
        self.assertEqual(ambers[0][1], "Changed outside a package: /etc/tool")
        self.assertIn("3 files, e.g.", ambers[0][2])
        self.assertIn(f"first seen {self.day(5):%a %d %b}", ambers[0][2])
        self.assertIn("1 item(s) to confirm (3 file(s))", s.headline)
        self.assertEqual(s.rating, self.r.AMBER)

    def test_removed_unlisted_ambers_group_per_day_across_folders(self):
        self.log(self.day(2), removed("/usr/lib/one/x"), removed("/usr/share/two/y"),
                 removed("/opt/three/z"))
        self.log(self.day(1), removed("/usr/lib/four/w"))
        s = self.integrity()
        ambers = sorted(i[1] for i in self.items(s, self.r.AMBER))
        self.assertEqual(ambers, [
            "1 file(s) removed that no package listed at the last check",
            "3 file(s) removed that no package listed at the last check",
        ])
        self.assertEqual(len(self.r.AMBER_GROUPS), 2)

    def test_a_path_red_and_amber_is_reported_red_only(self):
        self.log(self.day(3), red("/usr/lib/tool/a"))
        self.log(self.day(1), amber("/usr/lib/tool/a"))
        s = self.integrity()
        self.assertEqual(len(self.items(s, self.r.RED)), 1)
        self.assertEqual(self.items(s, self.r.AMBER), [])

    def test_package_lines_are_counted_from_the_window_only(self):
        self.log(self.day(10), "PKG changed /usr/bin/ls (coreutils, verified by pacman)")
        self.log(self.day(1), "PKG changed /usr/bin/cp (coreutils, verified by pacman)",
                 "PKG changed /usr/bin/mv (coreutils, verified by pacman)")
        s = self.integrity()
        self.assertIn("(2 files)", s.headline)
        self.assertEqual(s.rating, self.r.GREEN)

    def test_a_path_with_spaces(self):
        path = "/usr/lib/my tool/a (copy) b"
        self.log(self.day(2), red(path))
        s = self.integrity()
        reds = self.items(s, self.r.RED)
        self.assertEqual(len(reds), 1)
        self.assertEqual(reds[0][1], f"added {path} ({REASON_RED})")
        self.assertEqual(list(self.r.FOUND_GROUPS.values()), [[path]])

    def test_line_path(self):
        lp = self.r.line_path
        self.assertEqual(lp(f"added /usr/lib/x y ({REASON_RED})"), "/usr/lib/x y")
        self.assertEqual(lp("changed /a (b) c (owned by p but fails pacman's checksum)"),
                         "/a (b) c")
        self.assertIsNone(lp("added relative/path (reason)"))
        self.assertIsNone(lp("added /no/reason"))


class GroupIds(Files):
    def expected(self, kind, folder, day, paths):
        h = hashlib.sha256(f"aide\x1f{kind}\x1f{folder}\x1f{day}".encode())
        for p in sorted(paths):
            h.update(b"\x00" + p.encode())
        return h.hexdigest()[:8]

    def test_ids_are_stable_across_two_calls(self):
        self.log(self.day(3), red("/usr/lib/tool/a"), amber("/etc/tool/b"))
        self.integrity()
        first = dict(self.r.FOUND_GROUPS)
        self.integrity()
        self.assertEqual(self.r.FOUND_GROUPS, first)
        self.assertEqual(set(first), {
            self.expected("red", "/usr/lib/tool", self.day(3).date().isoformat(),
                          ["/usr/lib/tool/a"]),
            self.expected("amber", "/etc/tool", "", ["/etc/tool/b"]),
        })

    def test_ids_do_not_depend_on_who_runs_the_report(self):
        self.log(self.day(3), red("/usr/lib/tool/a"), removed("/opt/x/y"))
        seen = []
        for uid, env in ((1000, {"USER": "alice", "HOME": "/home/alice"}),
                         (0, {"USER": "root", "HOME": "/root", "SUDO_USER": "bob"})):
            with mock.patch.object(self.r.os, "geteuid", return_value=uid), \
                 mock.patch.object(self.r.os, "getuid", return_value=uid), \
                 mock.patch.dict(os.environ, env):
                self.integrity()
                seen.append(sorted(self.r.FOUND_GROUPS))
        self.assertEqual(seen[0], seen[1])

    def test_the_id_names_kind_folder_day_and_members(self):
        g = self.r.group_id
        self.assertEqual(g("red", "/usr/lib/tool", "2026-10-20", ["/usr/lib/tool/b", "/usr/lib/tool/a"]),
                         self.expected("red", "/usr/lib/tool", "2026-10-20",
                                       ["/usr/lib/tool/a", "/usr/lib/tool/b"]))
        a = ["/usr/lib/tool/a"]
        ids = {g("red", "/usr/lib/tool", "2026-10-20", a), g("amber", "/usr/lib/tool", "2026-10-20", a),
               g("red", "/usr/lib/other", "2026-10-20", a), g("red", "/usr/lib/tool", "2026-10-21", a),
               g("red", "/usr/lib/tool", "2026-10-20", a + ["/usr/lib/tool/b"])}
        self.assertEqual(len(ids), 5)

    def test_the_id_changes_when_a_file_joins_the_group(self):
        self.log(self.day(4), amber("/etc/tool/a"))
        self.log(self.day(3, 9), red("/usr/lib/tool/a"))
        self.integrity()
        before = set(self.r.FOUND_GROUPS)
        self.log(self.day(2), amber("/etc/tool/b"))
        self.log(self.day(3, 15), red("/usr/lib/tool/b"))
        self.integrity()
        after = set(self.r.FOUND_GROUPS)
        self.assertEqual(len(before), 2)
        self.assertEqual(len(after), 2)
        self.assertEqual(before & after, set())

    def test_each_item_names_its_id_and_the_command(self):
        self.log(self.day(3), red("/usr/lib/tool/a"))
        s = self.integrity()
        (gid,) = self.r.FOUND_GROUPS
        item = self.items(s, self.r.RED)[0]
        self.assertIn(f"Item {gid},", item[2])
        self.assertIn(f"sudo spycatcher-report --ack {gid} --reason", item[3])


class FindingGroups(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def test_largest_group_first(self):
        t = dt.datetime(2026, 10, 20, 10, 0)
        found = {"/usr/bin/a": (t, f"added /usr/bin/a ({REASON_RED})"),
                 "/usr/lib/x/b": (t, f"added /usr/lib/x/b ({REASON_RED})"),
                 "/usr/lib/x/c": (t, f"added /usr/lib/x/c ({REASON_RED})")}
        groups = self.r.finding_groups(self.r.RED, found)
        self.assertEqual([g[1] for g in groups], ["/usr/lib/x", "/usr/bin"])
        self.assertEqual([len(g[3]) for g in groups], [2, 1])

    def test_a_file_at_the_root_is_in_the_root_folder(self):
        t = dt.datetime(2026, 10, 20, 10, 0)
        groups = self.r.finding_groups(self.r.RED, {"/vmlinuz": (t, f"added /vmlinuz ({REASON_RED})")})
        self.assertEqual(groups[0][1], "/")

    def test_entries_sorted_and_dated_by_the_earliest(self):
        early, late = dt.datetime(2026, 10, 20, 8, 0), dt.datetime(2026, 10, 20, 18, 0)
        found = {"/etc/x/b": (late, f"changed /etc/x/b ({REASON_AMBER})"),
                 "/etc/x/a": (early, f"changed /etc/x/a ({REASON_AMBER})")}
        (gid, folder, seen, entries), = self.r.finding_groups(self.r.AMBER, found)
        self.assertEqual(seen, early)
        self.assertEqual([e[1] for e in entries], ["/etc/x/a", "/etc/x/b"])


class FileState(Files):
    def test_file(self):
        f = self.make("usr/bin/tool")
        st = os.lstat(f)
        self.assertEqual(self.r.file_state(f),
                         f"file:{st.st_ino}:{st.st_size}:{st.st_ctime_ns}")

    def test_absent(self):
        self.assertEqual(self.r.file_state(str(self.dir / "nothing")), "absent")

    def test_link_records_its_target(self):
        link = self.dir / "link"
        os.symlink("/usr/bin/true", link)
        self.assertTrue(self.r.file_state(str(link)).startswith("link:/usr/bin/true:"))

    def test_folder(self):
        d = self.dir / "folder"
        d.mkdir(mode=0o750)
        st = os.lstat(d)
        self.assertEqual(self.r.file_state(str(d)),
                         f"folder:{st.st_mode:o}:{st.st_uid}:{st.st_gid}")

    def test_other_kind(self):
        fifo = self.dir / "fifo"
        os.mkfifo(fifo)
        self.assertTrue(self.r.file_state(str(fifo)).startswith("other:"))

    @unittest.skipIf(os.geteuid() == 0, "root may search any folder")
    def test_unsearchable_folder_is_unknown(self):
        f = self.make("locked/usr/bin/tool")
        os.chmod(self.dir / "locked", 0)
        self.addCleanup(os.chmod, self.dir / "locked", 0o700)
        self.assertEqual(self.r.file_state(f), "unknown")


class Acknowledged(Files):
    """An acknowledged red disappears while its file is as root saw it."""

    def setUp(self):
        super().setUp()
        self.f = self.make("usr/bin/tool")
        self.log(self.day(3), red(self.f))

    def ack_now(self, *paths, when=None):
        self.ack_file(self.record({p: self.r.file_state(p) for p in paths}, when=when))

    def reds(self):
        return self.items(self.integrity(), self.r.RED)

    def test_acknowledged_red_disappears(self):
        self.ack_now(self.f)
        s = self.integrity()
        self.assertEqual(self.items(s, self.r.RED), [])
        self.assertEqual(s.rating, self.r.GREEN)
        self.assertEqual(self.r.OPEN_RED_LOGS, set())
        self.assertTrue(s.headline.endswith(" 1 acknowledgement(s) on record."), s.headline)

    def test_returns_when_the_change_time_changes(self):
        self.ack_now(self.f)
        time.sleep(0.05)
        os.chmod(self.f, 0o600)
        self.assertEqual(len(self.reds()), 1)

    def test_returns_when_the_size_changes(self):
        self.ack_now(self.f)
        with open(self.f, "a") as fh:
            fh.write("more")
        self.assertEqual(len(self.reds()), 1)

    def test_returns_when_the_file_is_replaced(self):
        self.ack_now(self.f)
        new = self.make("usr/bin/tool.new", "x")
        os.replace(new, self.f)
        self.assertEqual(len(self.reds()), 1)

    def test_returns_when_replaced_by_a_link(self):
        self.ack_now(self.f)
        os.remove(self.f)
        os.symlink("/usr/bin/true", self.f)
        self.assertEqual(len(self.reds()), 1)

    def test_a_line_logged_after_the_acknowledgement_is_a_new_finding(self):
        self.ack_now(self.f, when=self.day(2))
        self.assertEqual(self.reds(), [])
        self.log(self.day(1), red(self.f))
        reds = self.reds()
        self.assertEqual(len(reds), 1)
        self.assertIn(f"first seen {self.day(1):%a %d %b}", reds[0][2])

    def test_an_absent_path_stays_hidden_while_absent(self):
        gone = str(self.dir / "usr/bin/gone")
        self.log(self.day(2), red(gone))
        self.ack_now(self.f, gone)
        self.assertEqual(self.reds(), [])
        Path(gone).write_text("back")
        reds = self.reds()
        self.assertEqual(len(reds), 1)
        self.assertIn(gone, reds[0][1])

    def test_an_acknowledged_red_does_not_turn_amber(self):
        self.log(self.day(1), amber(self.f))
        self.ack_now(self.f)
        s = self.integrity()
        self.assertEqual(self.items(s, self.r.RED), [])
        self.assertEqual(self.items(s, self.r.AMBER), [])

    def test_only_the_acknowledged_file_of_a_group_is_hidden(self):
        other = self.make("usr/bin/other")
        self.log(self.day(3, 11), red(other))
        self.ack_now(self.f)
        reds = self.reds()
        self.assertEqual(len(reds), 1)
        self.assertIn(other, reds[0][1])

    def test_a_path_with_spaces(self):
        spaced = self.make("usr/bin/my tool (2)")
        self.log(self.day(2), red(spaced))
        self.ack_now(self.f, spaced)
        self.assertEqual(self.reds(), [])

    def test_acknowledgements_are_listed_as_green_items(self):
        later, earlier = dt.datetime(2026, 10, 20, 9, 30), dt.datetime(2026, 10, 19, 8, 0)
        self.ack_file(self.record({self.f: self.r.file_state(self.f)}, gid="bbbb2222",
                                  when=later, by="alice", reason="my build"),
                      self.record({"/x": "absent", "/y": "absent"}, gid="aaaa1111",
                                  when=earlier, by="root", reason="old kernel"))
        s = self.integrity()
        greens = self.items(s, self.r.GREEN)
        self.assertEqual([g[1] for g in greens],
                         ["Acknowledged aaaa1111: old kernel", "Acknowledged bbbb2222: my build"])
        self.assertEqual(greens[0][2], f"2 file(s), {earlier:%a %d %b %H:%M} by root")
        self.assertEqual(greens[1][2], f"1 file(s), {later:%a %d %b %H:%M} by alice")
        self.assertIn(" 2 acknowledgement(s) on record.", s.headline)

    def test_a_malformed_file_acknowledges_nothing(self):
        state = self.r.file_state(self.f)
        for text in ("{not json", "[]", '{"acks": "x"}', '{"acks": [{"id": "a", "paths": "x"}]}',
                     json.dumps({"acks": [{"id": "a", "when": self.now.isoformat(),
                                           "paths": {self.f: 5}}]}),
                     json.dumps({"acks": [{"id": "a", "when": "yesterday",
                                           "paths": {self.f: state}}]}),
                     json.dumps({"acks": [{"id": "a", "paths": {self.f: state}}]}),
                     ""):
            self.acks.write_text(text)
            self.assertEqual(len(self.reds()), 1, text)

    def test_a_missing_file_acknowledges_nothing(self):
        self.assertFalse(self.acks.exists())
        self.assertEqual(self.r.load_acks(), [])
        self.assertEqual(len(self.reds()), 1)


class AckHelpers(Files):
    def test_load_acks_drops_records_without_paths_or_a_time(self):
        ok = {"id": "b", "when": "2026-10-20T09:00:00", "paths": {}}
        self.acks.write_text(json.dumps({"acks": [{"id": "a", "when": ok["when"]}, "x", ok,
                                                  {"id": "c", "when": "soon", "paths": {}}]}))
        self.assertEqual(self.r.load_acks(), [ok])

    def test_acked_until_is_the_latest_acknowledgement_that_still_covers(self):
        f = self.make("usr/bin/tool")
        state = self.r.file_state(f)
        acks = [self.record({f: state}, when=dt.datetime(2026, 10, 1, 9)),
                self.record({f: state}, when=dt.datetime(2026, 10, 5, 9)),
                self.record({f: "absent"}, when=dt.datetime(2026, 10, 9, 9)),
                self.record({"/other": "absent"}, when=dt.datetime(2026, 10, 10, 9))]
        self.assertEqual(self.r.acked_until(f, acks), dt.datetime(2026, 10, 5, 9))
        self.assertIsNone(self.r.acked_until(str(self.dir / "nothing"), acks))

    def test_a_time_with_an_offset_reads_as_wall_clock(self):
        a = [{"id": "a", "when": "2026-10-20T09:00:00+01:00", "paths": {"/x": "absent"}}]
        self.assertEqual(self.r.acked_until("/x", a), dt.datetime(2026, 10, 20, 9, 0))

    def test_acked_until_uses_and_fills_the_state_cache(self):
        acks = [self.record({"/p": "file:1:2:3"})]
        states = {}
        with mock.patch.object(self.r, "file_state", return_value="file:1:2:3") as fs:
            self.r.acked_until("/p", acks, states)
            self.r.acked_until("/p", acks, states)
        self.assertEqual(fs.call_count, 1)
        self.assertEqual(states, {"/p": "file:1:2:3"})

    def test_unknown_state(self):
        when = self.now
        with mock.patch.object(self.r, "file_state", return_value="unknown"):
            # Acknowledged as a file root could see: the report cannot tell,
            # so it takes the file as unchanged.
            self.assertEqual(self.r.acked_until("/p", [self.record({"/p": "file:1:2:3"})]), when)
            # Acknowledged while absent: a file that reappears is logged
            # again, and that later line is not covered.
            self.assertEqual(self.r.acked_until("/p", [self.record({"/p": "absent"})]), when)
            # Never acknowledged.
            self.assertIsNone(self.r.acked_until("/p", []))


class UnknownState(Files):
    """A file under a folder the desktop user cannot read."""

    def setUp(self):
        super().setUp()
        self.path = "/root/locked/tool"
        self.log(self.day(3), red(self.path))
        self.patch("file_state", return_value="unknown")

    def test_hidden_for_earlier_lines_reopened_by_a_later_one(self):
        self.ack_file(self.record({self.path: "file:1:2:3"}, when=self.day(2)))
        self.assertEqual(self.items(self.integrity(), self.r.RED), [])
        later = self.log(self.day(1), red(self.path))
        s = self.integrity()
        reds = self.items(s, self.r.RED)
        self.assertEqual(len(reds), 1)
        self.assertIn(f"first seen {self.day(1):%a %d %b}", reds[0][2])
        self.assertEqual(self.r.OPEN_RED_LOGS, {later})

    def test_acknowledged_absent_is_covered_until_logged_again(self):
        self.ack_file(self.record({self.path: "absent"}, when=self.day(2)))
        self.assertEqual(self.items(self.integrity(), self.r.RED), [])
        self.log(self.day(1), red(self.path))
        self.assertEqual(len(self.items(self.integrity(), self.r.RED)), 1)

    @unittest.skipIf(os.geteuid() == 0, "root may search any folder")
    def test_a_real_unsearchable_folder(self):
        # A fresh copy of the report, whose file_state is the real one.
        r = load_report()
        f = self.make("locked/usr/bin/tool")
        state = r.file_state(f)
        os.chmod(self.dir / "locked", 0)
        self.addCleanup(os.chmod, self.dir / "locked", 0o700)
        self.assertEqual(r.acked_until(f, [self.record({f: state})]), self.now)
        self.assertEqual(r.acked_until(f, [self.record({f: "absent"})]), self.now)


class Acknowledge(Files):
    """sudo spycatcher-report --ack / --unack."""

    def setUp(self):
        super().setUp()
        self.euid = self.patch_obj(self.r.os, "geteuid", return_value=0)
        self.chown = self.patch_obj(self.r.os, "chown")
        self.f = self.make("usr/bin/tool")
        self.log(self.day(3), red(self.f), amber("/etc/tool/a"), removed("/opt/x/y"),
                 amber("/etc/sudoers.d/extra"))
        self.integrity()
        self.red_id = next(i for i, paths in self.r.FOUND_GROUPS.items() if self.f in paths)
        self.sudoers_id = next(i for i, paths in self.r.FOUND_GROUPS.items()
                               if "/etc/sudoers.d/extra" in paths)
        self.amber_ids = set(self.r.AMBER_GROUPS)
        self.assertEqual(len(self.amber_ids), 2)
        self.assertNotIn(self.sudoers_id, self.amber_ids)

    def ack(self, ids, reason="my own build", unack=None, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env or {}), contextlib.redirect_stderr(err), \
             contextlib.redirect_stdout(out):
            code = self.r.acknowledge(ids, reason, unack, self.now,
                                      self.now - dt.timedelta(days=7))
        self.out = out.getvalue()
        return code, err.getvalue()

    def saved(self):
        return json.loads(self.acks.read_text())["acks"]

    def test_refuses_without_root(self):
        self.euid.return_value = 1000
        code, err = self.ack([self.red_id])
        self.assertEqual(code, 2)
        self.assertIn("needs root", err)
        self.assertFalse(self.acks.exists())

    def test_refuses_without_a_reason(self):
        for reason in (None, "", "   "):
            code, err = self.ack([self.red_id], reason=reason)
            self.assertEqual(code, 2, reason)
            self.assertIn("--reason", err)
        self.assertFalse(self.acks.exists())

    def test_rejects_an_unknown_id(self):
        code, err = self.ack([self.red_id, "deadbeef"])
        self.assertEqual(code, 1)
        self.assertIn("deadbeef", err)
        self.assertFalse(self.acks.exists())

    def test_records_each_file_state_reason_and_sudo_user(self):
        state = self.r.file_state(self.f)
        code, _ = self.ack([self.red_id], reason="my\nown build", env={"SUDO_USER": "alice"})
        self.assertEqual(code, 0)
        (rec,) = self.saved()
        self.assertEqual(rec["id"], self.red_id)
        self.assertEqual(rec["by"], "alice")
        self.assertEqual(rec["reason"], "my?own build")
        self.assertEqual(rec["paths"], {self.f: state})
        self.assertEqual(rec["when"], self.now.isoformat())
        s = self.integrity()
        self.assertEqual(self.items(s, self.r.RED), [])
        self.assertTrue(any(i[1] == f"Acknowledged {self.red_id}: my?own build"
                            for i in self.items(s, self.r.GREEN)))

    def test_prints_what_it_covers_by_folder(self):
        self.ack([self.red_id])
        self.assertEqual(self.out, f"  {self.red_id}:      1 in {os.path.dirname(self.f)}\n"
                                   f"acknowledged {self.red_id}: 1 file(s)\n")

    def test_by_root_without_sudo(self):
        env = dict(os.environ)
        env.pop("SUDO_USER", None)
        with mock.patch.dict(os.environ, env, clear=True):
            code, _ = self.ack([self.red_id])
        self.assertEqual(code, 0)
        self.assertEqual(self.saved()[0]["by"], "root")

    def test_written_0640_with_the_register_group(self):
        self.ack([self.red_id])
        gid = os.stat(self.register).st_gid
        self.chown.assert_called_once_with(self.acks.with_name(self.acks.name + ".new"), 0, gid)
        mode = stat.S_IMODE(os.stat(self.acks).st_mode)
        self.assertEqual(mode, 0o640 if gid else 0o600)
        self.assertFalse(self.acks.with_name(self.acks.name + ".new").exists())

    def test_written_0600_without_a_register(self):
        self.register.unlink()
        self.ack([self.red_id])
        self.chown.assert_called_once_with(self.acks.with_name(self.acks.name + ".new"), 0, 0)
        self.assertEqual(stat.S_IMODE(os.stat(self.acks).st_mode), 0o600)

    def test_noted_in_the_journal(self):
        self.ack([self.red_id], env={"SUDO_USER": "alice"})
        cmds = [c.args[0] for c in self.run_cmd.call_args_list]
        self.assertIn(["logger", "-t", "spycatcher-report",
                       f"alice acknowledged {self.red_id} (1 file(s)): my own build"], cmds)

    def test_amber_stands_for_every_open_amber_item_outside_sensitive_folders(self):
        code, _ = self.ack(["amber"])
        self.assertEqual(code, 0)
        self.assertEqual({a["id"] for a in self.saved()}, self.amber_ids)
        s = self.integrity()
        ambers = self.items(s, self.r.AMBER)
        self.assertEqual(len(ambers), 1)
        self.assertIn(f"Item {self.sudoers_id},", ambers[0][2])
        self.assertEqual(len(self.items(s, self.r.RED)), 1)

    def test_a_sensitive_amber_by_its_own_id(self):
        code, _ = self.ack([self.sudoers_id])
        self.assertEqual(code, 0)
        self.assertEqual([a["id"] for a in self.saved()], [self.sudoers_id])

    def test_sensitive(self):
        for p in ("/etc/sudoers", "/etc/sudoers.d/x", "/etc/systemd/system/x.service",
                  "/usr/local/bin/tool", "/etc/pam.d/login", "/boot/vmlinuz-linux"):
            self.assertTrue(self.r.sensitive(p), p)
        for p in ("/etc/tool/a", "/usr/lib/x", "/opt/x/y"):
            self.assertFalse(self.r.sensitive(p), p)

    def test_amber_with_a_red_id(self):
        self.ack(["amber", self.red_id])
        self.assertEqual({a["id"] for a in self.saved()}, self.amber_ids | {self.red_id})

    def test_acknowledgements_are_added_to(self):
        self.ack([self.red_id])
        self.ack(["amber"])
        self.assertEqual(len(self.saved()), 3)

    def test_unack_removes(self):
        self.ack([self.red_id])
        code, _ = self.ack([], reason=None, unack=self.red_id)
        self.assertEqual(code, 0)
        self.assertEqual(self.saved(), [])
        self.assertEqual(len(self.items(self.integrity(), self.r.RED)), 1)

    def test_unack_of_an_unknown_id(self):
        self.ack([self.red_id])
        code, err = self.ack([], reason=None, unack="deadbeef")
        self.assertEqual(code, 1)
        self.assertIn("no acknowledgement deadbeef", err)
        self.assertEqual(len(self.saved()), 1)

    def test_unack_needs_root(self):
        self.ack([self.red_id])
        self.euid.return_value = 1000
        code, _ = self.ack([], reason=None, unack=self.red_id)
        self.assertEqual(code, 2)
        self.assertEqual(len(self.saved()), 1)


class Main(Files):
    """The --acks, --keep-logs, --ack and --unack options."""

    def main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["spycatcher-report", *args]), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.r.main()
        return code, out.getvalue(), err.getvalue()

    def test_acks_lists_acknowledgements(self):
        self.ack_file(self.record({"/a": "absent", "/b": "absent"}, gid="aaaa1111",
                                  when=dt.datetime(2026, 10, 20, 9, 30), by="alice",
                                  reason="kernel\x1bupdate"))
        code, out, _ = self.main("--acks")
        self.assertEqual(code, 0)
        self.assertEqual(out, "aaaa1111  2026-10-20 09:30  alice  2 file(s)  kernel?update\n")

    def test_acks_with_a_malformed_file_lists_nothing(self):
        self.acks.write_text("{")
        self.assertEqual(self.main("--acks")[:2], (0, ""))

    def test_keep_logs_prints_exactly_the_logs_that_hold_an_open_red(self):
        f = self.make("usr/bin/acked")
        old = self.log(self.day(10), red("/usr/lib/tool/old"))
        first = self.log(self.day(3), red("/usr/lib/tool/a"))
        again = self.log(self.day(2), red("/usr/lib/tool/a"), red(f))
        only_acked = self.log(self.day(2, 12), red(f))
        self.log(self.day(1), amber("/etc/tool/x"), "PKG changed /usr/bin/ls (coreutils, "
                 "verified by pacman)")
        explained = self.log(self.day(1, 12), red("/usr/lib/tool/explained"))
        self.grades = {"/usr/lib/tool/explained": "PKG"}
        self.ack_file(self.record({f: self.r.file_state(f)}))
        code, out, _ = self.main("--keep-logs")
        self.assertEqual(code, 0)
        self.assertEqual(out.splitlines(), sorted([str(old), str(first), str(again)]))
        self.assertNotIn(str(explained), out)
        self.assertNotIn(str(only_acked), out)

    def test_keep_logs_with_no_red_prints_nothing(self):
        self.log(self.day(1), amber("/etc/tool/x"))
        self.assertEqual(self.main("--keep-logs")[:2], (0, ""))

    def test_ack_and_unack(self):
        self.patch_obj(self.r.os, "geteuid", return_value=0)
        self.patch_obj(self.r.os, "chown")
        self.log(self.day(2), red("/usr/lib/tool/a"))
        self.integrity()
        (gid,) = self.r.FOUND_GROUPS
        code, out, _ = self.main("--ack", gid, "--reason", "checked it")
        self.assertEqual(code, 0)
        self.assertTrue(out.endswith(f"acknowledged {gid}: 1 file(s)\n"), out)
        self.assertEqual(self.main("--keep-logs")[1], "")
        code, out, _ = self.main("--unack", gid)
        self.assertEqual((code, out), (0, f"removed {gid}\n"))
        self.assertNotEqual(self.main("--keep-logs")[1], "")

    def test_ack_without_root(self):
        self.patch_obj(self.r.os, "geteuid", return_value=1000)
        self.log(self.day(2), red("/usr/lib/tool/a"))
        code, _, err = self.main("--ack", "amber", "--reason", "x")
        self.assertEqual(code, 2)
        self.assertIn("needs root", err)
        self.assertFalse(self.acks.exists())


class Prune(unittest.TestCase):
    """spycatcher-scan's prune(), taken from the script with its log() and run
    in bash with $0 naming a script beside a stand-in spycatcher-report."""

    KEEP = 2

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(os.path.realpath(self.tmp.name))
        self.bin = base / "bin"
        self.bin.mkdir()
        (self.bin / "spycatcher-scan").write_text("")
        self.logdir = base / "log"
        self.logdir.mkdir()
        self.scanlog = base / "scan.log"
        self.scanlog.write_text("")

    def logs(self, mode, n, lines=()):
        """`n` logs, oldest first, a day apart and ending yesterday; the
        first holds `lines`."""
        out = []
        start = dt.datetime.now().replace(microsecond=0) - dt.timedelta(days=n)
        for i in range(n):
            when = start + dt.timedelta(days=i)
            p = write_log(self.logdir, when, *(lines if i == 0 else ()))
            if mode != "aide":
                p = p.rename(self.logdir / p.name.replace("aide-", f"{mode}-"))
            os.utime(p, (when.timestamp(), when.timestamp()))
            out.append(str(p))
        return out

    def report(self, lines, code=0):
        (self.bin / "spycatcher-report").write_text(
            f"import sys\nsys.stdout.write({''.join(l + chr(10) for l in lines)!r})\n"
            f"sys.exit({code})\n")

    def prune(self, mode, script_path=None):
        script = ('eval "$(sed -n -e \'/^log() /p\' -e \'/^prune() {/,/^}/p\' "$SCAN")"\n'
                  f'MODE=$1 LOG_DIR=$2 LOG=$3 KEEP={self.KEEP}\nprune\n')
        r = subprocess.run(["bash", "-c", script, str(script_path or self.bin / "spycatcher-scan"),
                            mode, str(self.logdir), str(self.scanlog)],
                           env={"PATH": os.environ["PATH"], "SCAN": str(SCAN)},
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return sorted(str(p) for p in self.logdir.iterdir())

    def test_keeps_old_logs_the_report_lists(self):
        logs = self.logs("aide", 5)
        self.report([logs[1]])
        self.assertEqual(self.prune("aide"), sorted([logs[1], logs[3], logs[4]]))

    def test_keeps_several_listed_logs(self):
        logs = self.logs("aide", 5)
        self.report([logs[0], logs[2], logs[4]])
        self.assertEqual(self.prune("aide"), sorted([logs[0], logs[2], logs[3], logs[4]]))

    def test_nothing_listed_removes_every_old_log(self):
        logs = self.logs("aide", 5)
        self.report([])
        self.assertEqual(self.prune("aide"), sorted(logs[3:]))
        self.assertEqual(self.scanlog.read_text(), "")

    def test_a_listed_name_must_match_the_whole_path(self):
        logs = self.logs("aide", 4)
        self.report([logs[0][:-4], "x" + logs[1]])
        self.assertEqual(self.prune("aide"), sorted(logs[2:]))

    def test_a_failing_report_removes_nothing_and_says_so(self):
        logs = self.logs("aide", 5)
        self.report([logs[0]], code=1)
        self.assertEqual(self.prune("aide"), sorted(logs))
        self.assertIn("!! could not tell which old logs hold an open red, so none were removed",
                      self.scanlog.read_text())

    def test_other_scans_do_not_ask_the_report(self):
        logs = self.logs("rkhunter", 4)
        self.report([logs[0]], code=1)
        self.assertEqual(self.prune("rkhunter"), sorted(logs[2:]))

    def test_with_the_real_report(self):
        # The report is given LOG_DIR, so it reads these logs; nothing here
        # is acknowledged, since no acknowledgement names these paths.
        logs = self.logs("aide", 5, lines=[red("/nonexistent/spycatcher-test/tool")])
        self.assertEqual(self.prune("aide", script_path=SCAN), sorted([logs[0]] + logs[3:]))


if __name__ == "__main__":
    unittest.main()
