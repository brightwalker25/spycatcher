"""Checks for how spycatcher-report re-reads RED lines in the integrity section.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The system calls are replaced with stand-ins, so nothing here reads the real
/usr, /var/lib/pacman or /var/log, and nothing is sent anywhere.
"""

import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/spycatcher-report"

LINK = "/usr/bin/tool"
TARGET = "/usr/lib/tool/tool-avx512"
OTHER = "/usr/lib/tool/tool-debug"
LINE = f"changed {LINK} (unpackaged file in a system code path)"
SCRIPT_TEXT = f'ln -sf {TARGET} {LINK}\n'


def load_report():
    loader = importlib.machinery.SourceFileLoader("spycatcher_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spycatcher_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class ScriptletLinkTest(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def explains(self, line=LINE, islink=True, isfile=True, owner="tool-bin\n",
                 version="tool-bin 1.1.0-1\n", qkk="", script=SCRIPT_TEXT, points_at=TARGET):
        def pacman(*args):
            return {"-Qqo": owner, "-Q": version}[args[0]]

        def read_text(path_self):
            if script is None:
                raise OSError("no install script")
            self.assertEqual(str(path_self), "/var/lib/pacman/local/tool-bin-1.1.0-1/install")
            return script

        def realpath(path):
            # The link resolves to points_at; every other path is itself.
            return points_at if path == LINK else os.path.normpath(path)

        done = subprocess.CompletedProcess([], 0, stdout=qkk, stderr="")
        with mock.patch.object(self.r.os.path, "islink", return_value=islink), \
             mock.patch.object(self.r.os.path, "realpath", side_effect=realpath), \
             mock.patch.object(self.r.os.path, "isfile", return_value=isfile), \
             mock.patch.object(self.r, "_pacman", side_effect=pacman), \
             mock.patch.object(self.r.subprocess, "run", return_value=done), \
             mock.patch.object(self.r.Path, "read_text", read_text):
            return self.r.scriptlet_link_explains(line)

    def test_link_made_by_the_install_script_is_explained(self):
        self.assertTrue(self.explains())

    def test_added_link_is_explained_too(self):
        self.assertTrue(self.explains(line=f"added {LINK} (unpackaged file in a system code path)"))

    def test_a_real_file_is_not(self):
        self.assertFalse(self.explains(islink=False))

    def test_a_dangling_link_is_not(self):
        self.assertFalse(self.explains(isfile=False))

    def test_a_link_repointed_to_another_file_of_the_package_is_not(self):
        # The finding in omacom/omarchy-plugin-marketplace#8732: the package
        # owns and verifies OTHER too, but its install script never points
        # the link there.
        self.assertFalse(self.explains(points_at=OTHER, qkk=""))

    def test_a_target_held_in_a_variable_is_not(self):
        self.assertFalse(self.explains(script=f'ln -sf "$target" {LINK}\n'))

    def test_two_different_targets_are_not(self):
        script = (f"if fast; then\n  ln -sf {TARGET} {LINK}\nelse\n"
                  f"  ln -sf {OTHER} {LINK}\nfi\n")
        self.assertFalse(self.explains(script=script))
        self.assertFalse(self.explains(script=script, points_at=OTHER))

    def test_the_same_target_twice_is_explained(self):
        script = f"ln -sf {TARGET} {LINK}\nln -snf {TARGET} {LINK}\n"
        self.assertTrue(self.explains(script=script))

    def test_a_relative_target_resolves_from_the_link_folder(self):
        self.assertTrue(self.explains(script=f"ln -sf ../lib/tool/tool-avx512 {LINK}\n"))

    def test_a_hard_link_is_not(self):
        self.assertFalse(self.explains(script=f"ln -f {TARGET} {LINK}\n"))

    def test_an_option_it_does_not_know_is_not(self):
        self.assertFalse(self.explains(script=f"ln -sf -S .old {TARGET} {LINK}\n"))

    def test_ln_after_other_commands_on_the_line_is_read(self):
        script = f'rm -f {LINK} && /usr/bin/ln -s -- "{TARGET}" {LINK} 2>/dev/null || true\n'
        self.assertTrue(self.explains(script=script))

    def test_a_continued_line_is_read(self):
        self.assertTrue(self.explains(script=f"ln -sf \\\n    {TARGET} \\\n    {LINK}\n"))

    def test_a_commented_out_ln_is_ignored(self):
        self.assertFalse(self.explains(script=f"# ln -sf {TARGET} {LINK}\n"))

    def test_the_link_as_a_source_is_not_a_target(self):
        self.assertFalse(self.explains(script=f"ln -sf {LINK} /usr/bin/tool-alias\n"))

    def test_a_target_no_package_owns_is_not(self):
        self.assertFalse(self.explains(owner=""))

    def test_a_target_that_fails_pacman_is_not(self):
        qkk = f"warning: tool-bin: {TARGET} (SHA256 checksum mismatch)\n"
        self.assertFalse(self.explains(qkk=qkk.replace("SHA256 checksum", "checksum")))

    def test_a_bare_mtime_mismatch_does_not_count(self):
        qkk = f"warning: tool-bin: {TARGET} (Modification time mismatch)\n"
        self.assertTrue(self.explains(qkk=qkk))

    def test_a_package_without_an_install_script_is_not(self):
        self.assertFalse(self.explains(script=None))

    def test_a_script_that_never_names_the_link_is_not(self):
        self.assertFalse(self.explains(script='ln -sf "$target" /usr/bin/other\n'))

    def test_a_longer_path_is_not_the_link(self):
        self.assertFalse(self.explains(script=f"ln -sf {TARGET} {LINK}-osd\n"))

    def test_other_red_lines_are_left_alone(self):
        line = f"changed {LINK} (owned by tool-bin but fails pacman's checksum)"
        self.assertFalse(self.explains(line=line))


class ScriptletLinkTargetCommandTest(unittest.TestCase):
    """The hidden --scriptlet-link-target option that spycatcher-scan calls, run
    as a real process against real links in a temporary folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.realpath(self.tmp.name)
        os.makedirs(f"{self.dir}/lib")
        for name in ("fast", "slow"):
            Path(f"{self.dir}/lib/{name}").write_text("")
        self.link = f"{self.dir}/bin/tool"

    def target(self, script):
        path = Path(self.dir, "install")
        path.write_text(script)
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--scriptlet-link-target",
                            str(path), self.link], capture_output=True, text=True, env={})
        return r.stdout.strip() if r.returncode == 0 else None

    def test_a_literal_target_is_printed_resolved(self):
        self.assertEqual(self.target(f"ln -sf {self.dir}/lib/fast {self.link}\n"),
                         f"{self.dir}/lib/fast")

    def test_a_variable_target_exits_1(self):
        self.assertIsNone(self.target(f'ln -sf "$t" {self.link}\n'))

    def test_two_targets_exit_1(self):
        script = f"ln -sf {self.dir}/lib/fast {self.link}\nln -sf {self.dir}/lib/slow {self.link}\n"
        self.assertIsNone(self.target(script))

    def test_no_ln_for_the_link_exits_1(self):
        self.assertIsNone(self.target(f"rm -f {self.link}\n"))


class ListedLinkTest(unittest.TestCase):
    """Links listed in scan.conf's SCRIPTLET_LINKS, whose target the install
    script picks at run time. Real links and files in a temporary folder;
    pacman and the install script are stand-ins."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.realpath(self.tmp.name)
        os.makedirs(f"{self.dir}/bin")
        os.makedirs(f"{self.dir}/lib")
        for name in ("fast", "slow", "foreign"):
            Path(f"{self.dir}/lib/{name}").write_text("")
        self.link = f"{self.dir}/bin/tool"
        os.symlink(f"{self.dir}/lib/fast", self.link)
        self.line = f"changed {self.link} (unpackaged file in a system code path)"
        self.script = (f"if fast; then target={self.dir}/lib/fast; "
                       f"else target={self.dir}/lib/slow; fi\n"
                       f'ln -sf "$target" {self.link}\n')
        self.owners = {f"{self.dir}/lib/fast": "tool-bin\n",
                       f"{self.dir}/lib/slow": "tool-bin\n",
                       f"{self.dir}/lib/foreign": "other-bin\n"}

    def explains(self, links=None, qkk="", script=None, owners=None):
        links = {self.link: "tool-bin"} if links is None else links
        script = self.script if script is None else script
        owners = self.owners if owners is None else owners
        versions = {"tool-bin": "tool-bin 1.1.0-1\n", "other-bin": "other-bin 2.0-1\n"}

        def pacman(*args):
            if args[0] == "-Qqo":
                return owners.get(args[-1])
            return versions.get(args[-1])

        def read_text(path_self):
            self.assertEqual(str(path_self), "/var/lib/pacman/local/tool-bin-1.1.0-1/install")
            return script

        done = subprocess.CompletedProcess([], 0, stdout=qkk, stderr="")
        with mock.patch.object(self.r, "_pacman", side_effect=pacman), \
             mock.patch.object(self.r.subprocess, "run", return_value=done), \
             mock.patch.object(self.r.Path, "read_text", read_text):
            return self.r.listed_link_explains(self.line, links)

    def repoint(self, name):
        os.remove(self.link)
        os.symlink(f"{self.dir}/lib/{name}", self.link)

    def test_a_listed_link_to_a_verified_file_of_the_package_is_explained(self):
        self.assertTrue(self.explains())
        self.repoint("slow")
        self.assertTrue(self.explains())

    def test_the_general_rule_still_refuses_it(self):
        # The variable target is why the list exists. scriptlet_link_target()
        # must keep refusing it, as settled in the marketplace review #8732.
        self.assertIsNone(self.r.scriptlet_link_target(self.script, self.link))

    def test_a_listed_link_to_a_file_of_another_package_is_not(self):
        self.repoint("foreign")
        self.assertFalse(self.explains())

    def test_a_listed_link_to_a_file_of_two_packages_is_not(self):
        owners = dict(self.owners)
        owners[f"{self.dir}/lib/fast"] = "tool-bin\nother-bin\n"
        self.assertFalse(self.explains(owners=owners))

    def test_a_listed_link_to_an_unpackaged_file_is_not(self):
        self.assertFalse(self.explains(owners={}))

    def test_a_listed_path_that_is_a_regular_file_is_not(self):
        # voxtype's install script can also write a wrapper script there.
        os.remove(self.link)
        Path(self.link).write_text(f'#!/bin/sh\nexec {self.dir}/lib/fast "$@"\n')
        self.assertFalse(self.explains())

    def test_a_dangling_listed_link_is_not(self):
        self.repoint("missing")
        self.assertFalse(self.explains())

    def test_a_target_that_fails_pacman_is_not(self):
        qkk = f"warning: tool-bin: {self.dir}/lib/fast (SHA256 checksum mismatch)\n"
        self.assertFalse(self.explains(qkk=qkk))

    def test_a_script_without_ln_for_the_path_is_not(self):
        self.assertFalse(self.explains(script=f'ln -sf "$target" {self.link}-osd\n'))
        self.assertFalse(self.explains(script=f"rm -f {self.link}\n"))
        self.assertFalse(self.explains(script=f'# ln -sf "$target" {self.link}\n'))

    def test_a_hard_link_in_the_script_is_not(self):
        self.assertFalse(self.explains(script=f'ln -f "$target" {self.link}\n'))

    def test_the_link_as_a_source_is_not(self):
        self.assertFalse(self.explains(script=f'ln -sf {self.link} "$alias"\n'))

    def test_an_unlisted_variable_target_link_is_not(self):
        self.assertFalse(self.explains(links={f"{self.dir}/bin/other": "tool-bin"}))
        self.assertFalse(self.explains(links={}))

    def test_a_listed_link_named_for_another_package_is_not(self):
        self.assertFalse(self.explains(links={self.link: "other-bin"}))

    def test_other_red_lines_are_left_alone(self):
        self.line = f"changed {self.link} (owned by tool-bin but fails pacman's checksum)"
        self.assertFalse(self.explains())


class ListedLinksConfTest(unittest.TestCase):
    """Reading SCRIPTLET_LINKS from scan.conf."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conf = Path(self.tmp.name, "scan.conf")

    def links(self, text, root_only=True):
        self.conf.write_text(text)
        with mock.patch.object(self.r, "_root_only", return_value=root_only):
            return self.r.listed_links(self.conf)

    def test_the_example_lists_nothing(self):
        text = (ROOT / "system/scan.conf.example").read_text()
        self.assertEqual(self.links(text), {})

    def test_the_example_line_uncommented(self):
        text = (ROOT / "system/scan.conf.example").read_text()
        line = next(ln for ln in text.splitlines() if ln.startswith("# SCRIPTLET_LINKS="))
        self.assertEqual(self.links(line[2:] + "\n"), {
            "/usr/bin/voxtype": "voxtype-bin",
            "/usr/lib/voxtype/voxtype-onnx-cuda": "voxtype-bin"})

    def test_a_value_over_several_lines(self):
        text = 'A=1\nSCRIPTLET_LINKS="\n  /usr/bin/a=a-bin\n  /usr/bin/b=b-bin\n"  # note\nB=2\n'
        self.assertEqual(self.links(text), {"/usr/bin/a": "a-bin", "/usr/bin/b": "b-bin"})

    def test_the_last_assignment_wins(self):
        text = 'SCRIPTLET_LINKS="/usr/bin/a=a-bin"\nSCRIPTLET_LINKS=""\n'
        self.assertEqual(self.links(text), {})

    def test_a_variable_or_command_empties_the_list(self):
        for value in ('"/usr/bin/a=a-bin $MORE"', '"/usr/bin/a=$(echo a-bin)"',
                      "`echo /usr/bin/a=a-bin`", '"/usr/bin/a=a-bin \\\n"'):
            self.assertEqual(self.links(f"SCRIPTLET_LINKS={value}\n"), {}, value)

    def test_malformed_entries_are_skipped(self):
        text = ('SCRIPTLET_LINKS="usr/bin/a=a-bin /usr/bin/../b=b-bin /usr/bin/c= '
                '/usr/bin/d=D /usr/bin/e=e-bin"\n')
        self.assertEqual(self.links(text), {"/usr/bin/e": "e-bin"})

    def test_an_unclosed_quote_empties_the_list(self):
        self.assertEqual(self.links('SCRIPTLET_LINKS="/usr/bin/a=a-bin\n'), {})

    def test_a_file_that_is_not_roots_alone_is_ignored(self):
        self.assertEqual(self.links('SCRIPTLET_LINKS="/usr/bin/a=a-bin"\n', root_only=False), {})

    def test_root_only(self):
        def st(mode, uid):
            return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))
        self.assertTrue(self.r._root_only(st(0o100644, 0)))
        self.assertFalse(self.r._root_only(st(0o100664, 0)))
        self.assertFalse(self.r._root_only(st(0o100646, 0)))
        self.assertFalse(self.r._root_only(st(0o100644, 1000)))


class EmptyListChangesNothingTest(unittest.TestCase):
    """With nothing listed, the integrity section grades exactly as before."""

    def setUp(self):
        self.r = load_report()

    def grade(self, links):
        now = self.r.dt.datetime(2026, 9, 30, 12, 0)
        lines = (f"RED {LINE}\n"
                 "PKG changed /usr/bin/ls (coreutils, verified by pacman)\n"
                 "=== done at 2026-09-30T12:00:00+01:00 ===\n")
        # Everything a listed link needs is true, so only the list decides.
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        answers = {"-Qqo": "tool-bin\n", "-Q": "tool-bin 1.1.0-1\n"}
        with mock.patch.object(self.r, "logs", return_value=([(now, "log")], None)), \
             mock.patch.object(self.r, "read", return_value=lines), \
             mock.patch.object(self.r, "listed_links", return_value=links), \
             mock.patch.object(self.r, "scriptlet_link_explains", return_value=False), \
             mock.patch.object(self.r, "unchanged_since", return_value=True), \
             mock.patch.object(self.r.os.path, "islink", return_value=True), \
             mock.patch.object(self.r.os.path, "realpath", return_value=TARGET), \
             mock.patch.object(self.r.os.path, "isfile", return_value=True), \
             mock.patch.object(self.r, "_pacman", side_effect=lambda *a: answers[a[0]]), \
             mock.patch.object(self.r.subprocess, "run", return_value=done), \
             mock.patch.object(self.r.Path, "read_text",
                               lambda _: f'ln -sf "$target" {LINK}\n'):
            return self.r.integrity(now, now)

    def test_an_empty_list_leaves_the_line_red(self):
        s = self.grade({})
        self.assertEqual(s.rating, self.r.RED)
        self.assertEqual([i[1] for i in s.items], [LINE])

    def test_the_same_line_is_a_package_change_once_listed(self):
        s = self.grade({LINK: "tool-bin"})
        self.assertEqual(s.rating, self.r.GREEN)


class ListedLinkCommandTest(unittest.TestCase):
    """The hidden --listed-link option that spycatcher-scan calls, run as a
    real process. A scan.conf in a temporary folder is not root's, so it
    must be ignored and the link left red."""

    def run_it(self, conf, link):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "--listed-link", conf, link],
                              capture_output=True, text=True, env={})

    def test_a_conf_that_is_not_roots_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            os.makedirs(f"{tmp}/lib")
            Path(f"{tmp}/lib/fast").write_text("")
            os.symlink(f"{tmp}/lib/fast", f"{tmp}/tool")
            conf = Path(tmp, "scan.conf")
            conf.write_text(f'SCRIPTLET_LINKS="{tmp}/tool=tool-bin"\n')
            r = self.run_it(str(conf), f"{tmp}/tool")
            self.assertEqual((r.returncode, r.stdout), (1, ""))

    def test_a_missing_conf_exits_1(self):
        r = self.run_it("/nonexistent/scan.conf", "/usr/bin/tool")
        self.assertEqual((r.returncode, r.stdout), (1, ""))

# A made-up limine.conf in the shape limine-entry-tool and limine-snapper-sync
# write. The machine folder, partition id and hashes are placeholders.
CMDLINE = ("cryptdevice=PARTUUID=00000000-0000-0000-0000-000000000000:root root=/dev/mapper/root "
           "rootflags=subvol=@ rw rootfstype=btrfs quiet splash")
UKI_HASH = "#" + "ab" * 64
HIST = "boot():/0123456789abcdef0123456789abcdef/limine_history/os_linux.efi_sha256_" + "cd" * 32


def snapshot(n, date, cmdline=CMDLINE, path=HIST + UKI_HASH):
    snap = cmdline.replace("subvol=@", f"subvol=/@/.snapshots/{n}/snapshot")
    return (f"     ///{n} \u2502 {date}\n"
            "     comment: 4.0.4-1\n"
            "     ////linux\n"
            "     comment: kernel-id=linux\n"
            "     protocol: efi\n"
            f"     path: {path}\n"
            f"     cmdline: {snap}\n")


def limine_conf(snaps, cmdline=CMDLINE, extra=""):
    menu = ""
    if snaps is not None:
        menu = ("\n     //Snapshots\n"
                "     ### Auto-generated by limine-snapper-sync\n"
                f"     comment: {len(snaps)} snapshots\n" + "".join(snaps))
    return ("timeout: 3\n"
            "default_entry: 2\n"
            "/+Linux\n"
            "comment: order-priority=50\n"
            "  //linux\n"
            "  protocol: efi\n"
            f"  path: boot():/EFI/Linux/os_linux.efi{UKI_HASH}\n"
            f"  cmdline: {cmdline}\n"
            f"{extra}{menu}\n"
            "/EFI fallback\n"
            "protocol: efi\n"
            "path: boot():/EFI/BOOT/BOOTX64.EFI\n")


REFERENCE = limine_conf([snapshot(33, "2026-09-25 17:55:51"), snapshot(34, "2026-09-26 17:20:37")])
ROTATED = limine_conf([snapshot(34, "2026-09-26 17:20:37"), snapshot(38, "2026-09-30 12:13:48")])
JSON_PATH = "/boot/0123456789abcdef0123456789abcdef/limine_history/snapshots.json"
WROTE_AT = 1790766828


class LimineSnapshotTest(unittest.TestCase):
    """limine_snapshot_change, which spycatcher-scan runs through the hidden
    --limine-snapshot-change option for a boot file that changed with no
    package update."""

    def setUp(self):
        self.r = load_report()

    def explains(self, path="/boot/limine.conf", text=ROTATED, reference=REFERENCE,
                 journal=((WROTE_AT, "Updated: /boot/limine.conf"),), mtime=WROTE_AT):
        files = {path: text, "/var/lib/spycatcher/limine.conf": reference}

        def read_text(path_self):
            content = files.get(str(path_self))
            if content is None:
                raise OSError("no such file")
            return content

        lines = "".join(json.dumps({"__REALTIME_TIMESTAMP": str(int(t * 1e6)), "MESSAGE": m}) + "\n"
                        for t, m in journal)

        def run(cmd, **kw):
            self.assertEqual(cmd[0], "/usr/bin/journalctl")
            self.assertIn(f"_EXE={self.r.LIMINE_SYNC_EXE}", cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout=lines, stderr="")

        stat = os.stat_result((0o100600, 0, 0, 1, 0, 0, len(text), mtime, mtime, mtime))
        with mock.patch.object(self.r.Path, "read_text", read_text), \
             mock.patch.object(self.r.subprocess, "run", side_effect=run), \
             mock.patch.object(self.r.os, "stat", return_value=stat):
            return self.r.limine_snapshot_change(path, "/var/lib/spycatcher/limine.conf",
                                                 WROTE_AT - 3600)

    def test_a_snapshot_menu_only_change_is_explained(self):
        self.assertTrue(self.explains())

    def test_the_old_copy_is_explained_on_the_same_record(self):
        self.assertTrue(self.explains(path="/boot/limine.conf.old"))

    def test_a_changed_kernel_command_line_stays_red(self):
        text = limine_conf([snapshot(34, "2026-09-26 17:20:37"), snapshot(38, "2026-09-30 12:13:48")],
                           cmdline=CMDLINE + " init=/bin/sh")
        self.assertFalse(self.explains(text=text))

    def test_a_new_command_line_in_a_snapshot_entry_stays_red(self):
        text = limine_conf([snapshot(34, "2026-09-26 17:20:37"),
                            snapshot(38, "2026-09-30 12:13:48", cmdline=CMDLINE + " init=/bin/sh")])
        self.assertFalse(self.explains(text=text))

    def test_a_snapshot_entry_booting_another_snapshot_stays_red(self):
        entry = snapshot(38, "2026-09-30 12:13:48").replace(".snapshots/38/", ".snapshots/12/")
        self.assertFalse(self.explains(text=limine_conf([snapshot(34, "2026-09-26 17:20:37"), entry])))

    def test_a_changed_kernel_path_stays_red(self):
        text = ROTATED.replace("/EFI/Linux/os_linux.efi", "/EFI/Linux/other.efi", 1)
        self.assertFalse(self.explains(text=text))

    def test_a_snapshot_entry_booting_an_unknown_file_stays_red(self):
        entry = snapshot(38, "2026-09-30 12:13:48", path=HIST + "#" + "ef" * 64)
        self.assertFalse(self.explains(text=limine_conf([snapshot(34, "2026-09-26 17:20:37"), entry])))

    def test_a_history_copy_of_the_booted_kernel_is_explained(self):
        other = HIST.replace("cd" * 32, "ee" * 32) + UKI_HASH
        entry = snapshot(38, "2026-09-30 12:13:48", path=other)
        self.assertTrue(self.explains(text=limine_conf([snapshot(34, "2026-09-26 17:20:37"), entry])))

    def test_an_option_the_tool_does_not_write_stays_red(self):
        entry = snapshot(38, "2026-09-30 12:13:48") + "     resolution: 800x600\n"
        self.assertFalse(self.explains(text=limine_conf([snapshot(34, "2026-09-26 17:20:37"), entry])))

    def test_a_new_entry_outside_the_menu_stays_red(self):
        extra = "  //rescue\n  protocol: efi\n  path: boot():/EFI/Linux/os_linux.efi" + UKI_HASH + "\n"
        text = limine_conf([snapshot(34, "2026-09-26 17:20:37"), snapshot(38, "2026-09-30 12:13:48")],
                           extra=extra)
        self.assertFalse(self.explains(text=text))

    def test_a_menu_that_was_not_there_before_stays_red(self):
        self.assertFalse(self.explains(reference=limine_conf(None)))

    def test_no_limine_snapper_sync_record_stays_red(self):
        self.assertFalse(self.explains(journal=()))

    def test_a_record_for_another_write_stays_red(self):
        self.assertFalse(self.explains(mtime=WROTE_AT + 600))

    def test_a_record_for_another_file_stays_red(self):
        self.assertFalse(self.explains(journal=((WROTE_AT, f"Saved: {JSON_PATH}"),)))

    def test_a_missing_trusted_copy_stays_red(self):
        self.assertFalse(self.explains(reference=None))

    def test_other_boot_files_stay_red(self):
        self.assertFalse(self.explains(path="/boot/EFI/Linux/os_linux.efi"))

    def test_snapshots_json_with_known_command_lines_is_explained(self):
        text = json.dumps({"snapshotEntries": [{"kernelEntries": [{"cmdlineDetails": [
            {"cmdline": CMDLINE}]}]}]})
        self.assertTrue(self.explains(path=JSON_PATH, text=text,
                                      journal=((WROTE_AT, f"Saved: {JSON_PATH}"),)))

    def test_snapshots_json_with_a_new_command_line_stays_red(self):
        text = json.dumps({"snapshotEntries": [{"kernelEntries": [{"cmdlineDetails": [
            {"cmdline": CMDLINE + " init=/bin/sh"}]}]}]})
        self.assertFalse(self.explains(path=JSON_PATH, text=text,
                                       journal=((WROTE_AT, f"Saved: {JSON_PATH}"),)))


class LimineSnapshotCommandTest(unittest.TestCase):
    """The hidden --limine-snapshot-change option, run as a real process."""

    def run_option(self, *args):
        return subprocess.run([sys.executable, "-I", str(SCRIPT), "--limine-snapshot-change", *args],
                              capture_output=True, text=True, env={}).returncode

    def test_a_missing_trusted_copy_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_option("/boot/limine.conf", f"{tmp}/none", "0"), 1)

    def test_a_bad_time_exits_1(self):
        self.assertEqual(self.run_option("/boot/limine.conf", "/nonexistent", "soon"), 1)


class WindowTest(unittest.TestCase):
    """A window shorter than a scan's cadence still grades its latest run."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        patcher = mock.patch.object(self.r, "LOG_DIR", self.dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, name, text="summary: 0 warning(s)\n"):
        (self.dir / name).write_text(text)

    def test_latest_run_counts_when_older_than_window(self):
        self.write("rkhunter-20260928-184922.log")
        since = self.r.dt.datetime(2026, 10, 2)
        recent, latest = self.r.logs("rkhunter", since)
        self.assertEqual(recent, [latest])
        self.assertEqual(latest[0], self.r.dt.datetime(2026, 9, 28, 18, 49, 22))

    def test_older_runs_drop_out_when_window_has_one(self):
        self.write("aide-20260929-193307.log", "RED changed /boot/limine.conf\nsummary: 1 unexplained\n")
        self.write("aide-20261002-185919.log", "summary: 0 unexplained\n")
        since = self.r.dt.datetime(2026, 10, 1)
        recent, _ = self.r.logs("aide", since)
        self.assertEqual([w.day for w, _ in recent], [2])

    def test_no_logs_at_all(self):
        self.assertEqual(self.r.logs("rkhunter", self.r.dt.datetime(2026, 10, 2)), ([], None))



PREV_RUN = ("=== aide run at 2026-09-28T19:05:35+01:00 ===\n"
            "summary: 0 unexplained, 0 to confirm, 0 from package updates\n"
            "=== done at 2026-09-28T19:08:10+01:00 ===\n")
BOOT_RED = ("=== aide run at 2026-09-29T19:33:07+01:00 ===\n"
            "RED changed /boot/limine.conf (boot file changed with no package update)\n"
            "summary: 1 unexplained, 0 to confirm, 0 from package updates\n"
            "=== done at 2026-09-29T19:33:58+01:00 ===\n")


class BootRedPacmanTest(unittest.TestCase):
    """A boot red logged when a package transaction had in fact run since the
    previous check, which the scanner missed for reinstalls before 0.2.6."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        (self.dir / "logs").mkdir()
        (self.dir / "logs/aide-20260928-190535.log").write_text(PREV_RUN)
        (self.dir / "logs/aide-20260929-193307.log").write_text(BOOT_RED)
        for name, value in (("LOG_DIR", self.dir / "logs"), ("PACMAN_LOG", self.dir / "pacman.log"),
                            ("SCAN_CONF", self.dir / "scan.conf")):
            patcher = mock.patch.object(self.r, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def grade(self, pacman):
        (self.dir / "pacman.log").write_text(pacman)
        return self.r.integrity(self.r.dt.datetime(2026, 10, 3), self.r.dt.datetime(2026, 9, 26))

    def test_reinstall_between_runs_explains_it(self):
        s = self.grade("[2026-09-29T18:13:08+0100] [ALPM] reinstalled archlinux-keyring (20260902-1)\n")
        self.assertEqual(s.rating, self.r.GREEN)

    def test_downgrade_explains_it(self):
        s = self.grade("[2026-09-29T10:00:00+0100] [ALPM] downgraded foo (2-1 -> 1-1)\n")
        self.assertEqual(s.rating, self.r.GREEN)

    def test_no_transaction_stays_red(self):
        s = self.grade("[2026-09-29T18:13:08+0100] [ALPM] running '30-systemd-daemon-reload-system.hook'...\n")
        self.assertEqual(s.rating, self.r.RED)

    def test_transaction_before_previous_run_ended_stays_red(self):
        s = self.grade("[2026-09-28T19:00:00+0100] [ALPM] upgraded foo (1-1 -> 2-1)\n")
        self.assertEqual(s.rating, self.r.RED)

    def test_transaction_after_the_run_stays_red(self):
        # A later package update says nothing about the change already logged.
        s = self.grade("[2026-09-30T12:00:00+0100] [ALPM] upgraded foo (1-1 -> 2-1)\n")
        self.assertEqual(s.rating, self.r.RED)

    def test_transaction_while_the_run_was_going_stays_red(self):
        # AIDE may already have read the file by then.
        s = self.grade("[2026-09-29T19:33:30+0100] [ALPM] upgraded foo (1-1 -> 2-1)\n")
        self.assertEqual(s.rating, self.r.RED)

    def test_clocks_going_back_do_not_reorder(self):
        # 01:30+0000 on 25 Oct is 45 minutes after a run that started at
        # 01:45+01:00, though it reads earlier as plain text.
        (self.dir / "logs/aide-20261024-190000.log").write_text(
            PREV_RUN.replace("2026-09-28", "2026-10-24"))
        (self.dir / "logs/aide-20261025-014500.log").write_text(
            BOOT_RED.replace("2026-09-29T19:33:07+01:00", "2026-10-25T01:45:00+01:00")
                    .replace("2026-09-29T19:33:58+01:00", "2026-10-25T01:46:00+01:00"))
        (self.dir / "pacman.log").write_text("[2026-10-25T01:30:00+0000] [ALPM] upgraded foo (1-1 -> 2-1)\n")
        s = self.r.integrity(self.r.dt.datetime(2026, 10, 26), self.r.dt.datetime(2026, 10, 25))
        self.assertEqual(s.rating, self.r.RED)

    def test_logged_window_is_used_when_present(self):
        windowed = BOOT_RED.replace(
            "RED changed", "pacman window: 2026-09-29T19:00:00+01:00 to 2026-09-29T19:34:00+01:00\nRED changed")
        (self.dir / "logs/aide-20260929-193307.log").write_text(windowed)
        self.assertEqual(self.grade("[2026-09-29T18:13:08+0100] [ALPM] reinstalled k (1-1)\n").rating,
                         self.r.RED)
        self.assertEqual(self.grade("[2026-09-29T19:33:30+0100] [ALPM] reinstalled k (1-1)\n").rating,
                         self.r.GREEN)

    def test_no_earlier_run_stays_red(self):
        (self.dir / "logs/aide-20260928-190535.log").unlink()
        s = self.grade("[2026-09-29T18:13:08+0100] [ALPM] reinstalled archlinux-keyring (20260902-1)\n")
        self.assertEqual(s.rating, self.r.RED)

    def test_unreadable_pacman_log_stays_red(self):
        s = self.r.integrity(self.r.dt.datetime(2026, 10, 3), self.r.dt.datetime(2026, 9, 26))
        self.assertEqual(s.rating, self.r.RED)

    def test_other_red_reasons_are_not_touched(self):
        (self.dir / "logs/aide-20260929-193307.log").write_text(
            BOOT_RED.replace("(boot file changed with no package update)",
                             "(unpackaged file in a system code path)").replace("/boot/limine.conf", "/usr/bin/x"))
        s = self.grade("[2026-09-29T18:13:08+0100] [ALPM] reinstalled archlinux-keyring (20260902-1)\n")
        self.assertEqual(s.rating, self.r.RED)


class ScannerPacmanPatternTest(unittest.TestCase):
    """The scanner's awk count of package transactions, run on a sample log."""

    def count(self, log, since="2026-09-28T19:08:10"):
        src = (ROOT / "bin/spycatcher-scan").read_text()
        prog = re.search(r"'(/\\\[ALPM\\\] \(upgraded[^']*)'", src).group(1)
        with tempfile.NamedTemporaryFile("w", suffix=".log") as f:
            f.write(log)
            f.flush()
            out = subprocess.run(["awk", "-v", f"t={since}", prog, f.name],
                                 capture_output=True, text=True, check=True).stdout
        return int(out)

    def test_counts_reinstall_and_downgrade(self):
        log = ("[2026-09-29T18:13:08+0100] [ALPM] reinstalled archlinux-keyring (20260902-1)\n"
               "[2026-09-29T18:14:00+0100] [ALPM] downgraded foo (2-1 -> 1-1)\n"
               "[2026-09-29T18:15:00+0100] [ALPM] upgraded bar (1-1 -> 2-1)\n"
               "[2026-09-29T18:16:00+0100] [ALPM] running 'x.hook'...\n"
               "[2026-09-27T18:16:00+0100] [ALPM] installed old (1-1)\n")
        self.assertEqual(self.count(log), 3)


HELPER = "/opt/App/app-helper"
SETGID_SCRIPT = f"""GROUP_NAME="appgroup"

setup_helper() {{
    HELPER_PATH="{HELPER}"
    chgrp "${{GROUP_NAME}}" $HELPER_PATH
    chmod g+s $HELPER_PATH
}}

post_upgrade() {{
    setup_helper
}}
"""


class ScriptletSetgidGroupTest(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def group(self, script, path=HELPER):
        return self.r.scriptlet_setgid_group(script, path)

    def test_variables_set_once_are_resolved(self):
        self.assertEqual(self.group(SETGID_SCRIPT), "appgroup")

    def test_literal_words_are_read(self):
        self.assertEqual(self.group(f"chgrp appgroup {HELPER}\nchmod g+s {HELPER}\n"), "appgroup")

    def test_chgrp_without_setgid_is_not(self):
        self.assertIsNone(self.group(f"chgrp appgroup {HELPER}\n"))

    def test_setgid_without_chgrp_is_not(self):
        self.assertIsNone(self.group(f"chmod g+s {HELPER}\n"))

    def test_any_other_chmod_is_not(self):
        self.assertIsNone(self.group(f"chgrp appgroup {HELPER}\nchmod 4755 {HELPER}\n"))
        self.assertIsNone(self.group(f"chgrp appgroup {HELPER}\nchmod g+s,u+s {HELPER}\n"))

    def test_a_chown_is_not(self):
        self.assertIsNone(self.group(
            f"chgrp appgroup {HELPER}\nchmod g+s {HELPER}\nchown nobody {HELPER}\n"))

    def test_two_groups_are_not(self):
        self.assertIsNone(self.group(
            f"chgrp appgroup {HELPER}\nchgrp wheel {HELPER}\nchmod g+s {HELPER}\n"))

    def test_options_are_not(self):
        self.assertIsNone(self.group(f"chgrp -h appgroup {HELPER}\nchmod g+s {HELPER}\n"))

    def test_a_variable_set_twice_is_not(self):
        self.assertIsNone(self.group('G="appgroup"\nG="wheel"\n' + f"chgrp $G {HELPER}\nchmod g+s {HELPER}\n"))

    def test_a_computed_variable_is_not(self):
        self.assertIsNone(self.group('G=$(id -gn)\n' + f"chgrp $G {HELPER}\nchmod g+s {HELPER}\n"))

    def test_an_unknown_operand_anywhere_is_not(self):
        # It could name the file, so the whole script is unreadable.
        self.assertIsNone(self.group(
            f"chgrp appgroup {HELPER}\nchmod g+s {HELPER}\nchmod 4755 $ELSEWHERE\n"))

    def test_a_glob_is_not(self):
        self.assertIsNone(self.group("chgrp appgroup /opt/App/*\nchmod g+s /opt/App/*\n"))

    def test_another_file_is_not(self):
        self.assertIsNone(self.group(SETGID_SCRIPT, "/opt/App/other"))

    def test_a_commented_out_command_is_ignored(self):
        self.assertIsNone(self.group(f"# chgrp appgroup {HELPER}\nchmod g+s {HELPER}\n"))

    def test_text_in_a_heredoc_is_not(self):
        self.assertIsNone(self.group(
            f"cat <<EOF\n  chgrp appgroup {HELPER}\n  chmod g+s {HELPER}\nEOF\n"))

    def test_a_function_nothing_calls_is_not(self):
        self.assertIsNone(self.group(
            f"unused() {{\n  chgrp appgroup {HELPER}\n  chmod g+s {HELPER}\n}}\n"))

    def test_a_one_line_function_is_not(self):
        self.assertIsNone(self.group(f"f() {{ chgrp appgroup {HELPER}; chmod g+s {HELPER}; }}\n"))

    def test_inside_an_if_is_not(self):
        self.assertIsNone(self.group(
            f"post_install() {{\n  if false; then\n    chgrp appgroup {HELPER}\n"
            f"    chmod g+s {HELPER}\n  fi\n}}\n"))
        self.assertIsNone(self.group(
            f"if false; then chgrp appgroup {HELPER}; chmod g+s {HELPER}; fi\n"))

    def test_after_and_or_or_is_not(self):
        self.assertIsNone(self.group(f"true && chgrp appgroup {HELPER}\nchmod g+s {HELPER}\n"))

    def test_after_a_closed_if_is_explained(self):
        self.assertEqual(self.group(
            f"post_install() {{\n  if true; then\n    groupadd appgroup\n  fi\n"
            f"  chgrp appgroup {HELPER}\n  chmod g+s {HELPER}\n}}\n"), "appgroup")

    def test_a_variable_changed_another_way_is_not(self):
        for change in ("G+=x", "for G in wheel; do :; done", "read G", "printf -v G wheel"):
            self.assertIsNone(self.group(
                f"G=appgroup\n{change}\nchgrp $G {HELPER}\nchmod g+s {HELPER}\n"), change)

    def test_the_real_1password_scripts_are_read(self):
        for pkg, path, group in (("1password", "/opt/1Password/1Password-BrowserSupport", "onepassword"),
                                 ("1password-cli", "/usr/bin/op", "onepassword-cli")):
            found = list(Path("/var/lib/pacman/local").glob(f"{pkg}-[0-9]*/install"))
            if not found:
                self.skipTest(f"{pkg} not installed")
            self.assertEqual(self.group(found[0].read_text(), path), group)


class ScriptletSetgidTest(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def explains(self, qkk=f"warning: app: {HELPER} (GID mismatch)\n"
                          f"warning: app: {HELPER} (Permissions mismatch)\n",
                 script=SETGID_SCRIPT, group="appgroup", mode=0o2755, uid=0,
                 mtree={"mode": "755", "uid": "0", "gid": "0"}, islink=False):
        def pacman(*args):
            return {"-Qqo": "app\n", "-Q": "app 1.0-1\n"}[args[0]]

        st = mock.Mock(st_uid=uid, st_gid=1001, st_mode=0o100000 | mode)
        done = subprocess.CompletedProcess([], 0, stdout="", stderr=qkk)
        with mock.patch.object(self.r.os.path, "islink", return_value=islink), \
             mock.patch.object(self.r.os.path, "isfile", return_value=True), \
             mock.patch.object(self.r, "_pacman", side_effect=pacman), \
             mock.patch.object(self.r.subprocess, "run", return_value=done), \
             mock.patch.object(self.r.Path, "read_text", return_value=script), \
             mock.patch.object(self.r, "_mtree_entry", return_value=mtree), \
             mock.patch.object(self.r.os, "stat", return_value=st), \
             mock.patch.object(self.r.grp, "getgrgid", return_value=mock.Mock(gr_name=group)):
            return self.r.scriptlet_setgid(HELPER) == "app"

    def test_group_and_setgid_from_the_install_script_are_explained(self):
        self.assertTrue(self.explains())

    def test_a_time_mismatch_alongside_is_explained(self):
        self.assertTrue(self.explains(qkk=f"warning: app: {HELPER} (GID mismatch)\n"
                                          f"warning: app: {HELPER} (Modification time mismatch)\n"))

    def test_a_checksum_pacman_could_not_calculate_is_not(self):
        # What pacman prints when run as a user who cannot read the file.
        self.assertFalse(self.explains(
            qkk=f"warning: app: {HELPER} (Permissions mismatch)\n"
                f"warning: app: {HELPER} (failed to calculate SHA256 checksum)\n"))

    def test_a_checksum_mismatch_is_not(self):
        self.assertFalse(self.explains(qkk=f"warning: app: {HELPER} (GID mismatch)\n"
                                           f"warning: app: {HELPER} (SHA256 checksum mismatch)\n"))

    def test_a_uid_mismatch_is_not(self):
        self.assertFalse(self.explains(qkk=f"warning: app: {HELPER} (UID mismatch)\n"))

    def test_no_mismatch_is_not(self):
        self.assertFalse(self.explains(qkk=""))

    def test_another_group_is_not(self):
        self.assertFalse(self.explains(group="wheel"))

    def test_setuid_as_well_is_not(self):
        self.assertFalse(self.explains(mode=0o6755))

    def test_group_write_as_well_is_not(self):
        self.assertFalse(self.explains(mode=0o2775))

    def test_another_owner_is_not(self):
        self.assertFalse(self.explains(uid=1000))

    def test_a_file_not_in_the_mtree_is_not(self):
        self.assertFalse(self.explains(mtree=None))

    def test_a_link_is_not(self):
        self.assertFalse(self.explains(islink=True))

    def test_a_script_that_does_not_explain_it_is_not(self):
        self.assertFalse(self.explains(script=f"chmod g+s {HELPER}\n"))



class MtreeEntryTest(unittest.TestCase):
    def test_defaults_and_overrides(self):
        r = load_report()
        import gzip as gz
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "app-1.0-1"
            root.mkdir()
            with gz.open(root / "mtree", "wt") as f:
                f.write("#mtree\n/set type=file uid=0 gid=0 mode=644\n/set mode=755\n"
                        "./opt/App/app\\040helper time=1 size=2\n./opt/App/data mode=600\n")
            real_open = gz.open
            with mock.patch.object(r.gzip, "open",
                                   side_effect=lambda p, *a, **k: real_open(
                                       str(p).replace("/var/lib/pacman/local", d), *a, **k)):
                self.assertEqual(r._mtree_entry("app", "1.0-1", "/opt/App/app helper")["mode"], "755")
                self.assertEqual(r._mtree_entry("app", "1.0-1", "/opt/App/data")["mode"], "600")
                self.assertIsNone(r._mtree_entry("app", "1.0-1", "/opt/App/missing"))


if __name__ == "__main__":
    unittest.main()
