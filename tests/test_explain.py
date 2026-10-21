"""Checks for the rules that explain files written while pacman ran: by a
package's own install script, by depmod, or by a local hook listed in
scan.conf, and for the modules of a kernel that is gone.

Run from the repository root:

    python3 -m unittest discover -s tests -v

Real files in a temporary folder give real change times; pacman, the
package database and pacman.log are stand-ins.
"""

import datetime as dt
import hashlib
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
SCRIPT = ROOT / "bin/spycatcher-report"


def load_report():
    loader = importlib.machinery.SourceFileLoader("spycatcher_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("spycatcher_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    # The machine's own acknowledgements must not hide what a test logs.
    mod.ACKS = Path("/nonexistent/spycatcher/acknowledged.json")
    return mod


def stamp(epoch, offset=0):
    """A pacman.log time for `epoch` seconds plus `offset`."""
    t = dt.datetime.fromtimestamp(int(epoch) + offset).astimezone()
    return t.strftime("%Y-%m-%dT%H:%M:%S%z")


class ScriptNames(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def names(self, script, path="/usr/lib/tool/config8"):
        return self.r._script_names(script, path)

    def test_absolute_path(self):
        self.assertTrue(self.names("rm -f /usr/lib/tool/config8\n"))

    def test_path_relative_to_root(self):
        self.assertTrue(self.names("post_install() {\n\trm -f usr/lib/tool/config8\n}\n"))

    def test_brace_list(self):
        self.assertTrue(self.names("rm -f usr/lib/tool/config{,6,8}\n"))
        self.assertFalse(self.names("rm -f usr/lib/tool/config{,6,7}\n"))

    def test_assignment(self):
        self.assertTrue(self.names('FILE="/usr/lib/tool/config8"\nsed -i s/a/b/ "$FILE"\n'))

    def test_comment_does_not_count(self):
        self.assertFalse(self.names("# rm -f /usr/lib/tool/config8\n"))
        self.assertFalse(self.names("true  # /usr/lib/tool/config8\n"))

    def test_path_built_from_a_variable_does_not_count(self):
        self.assertFalse(self.names('rm -f "$dir/config8"\n'))
        self.assertFalse(self.names('rm -f ${root}/usr/lib/tool/config8\n'))

    def test_longer_path_does_not_count(self):
        self.assertFalse(self.names("rm -f /usr/lib/tool/config8.bak\n"))

    def test_unreadable_line_still_counts_outside_a_comment(self):
        self.assertTrue(self.names("echo 'unclosed /usr/lib/tool/config8\n"))


class Files(unittest.TestCase):
    """A temporary folder standing for the file system."""

    def setUp(self):
        self.r = load_report()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(os.path.realpath(self.tmp.name))

    def make(self, name, text="x"):
        p = self.dir / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return str(p)

    def ctime(self, path):
        return os.lstat(path).st_ctime


class ScriptWrites(unittest.TestCase):
    """Which commands of an install script write a path (review M3)."""

    def setUp(self):
        self.r = load_report()

    def writes(self, script, path="/usr/lib/tool/config8"):
        return self.r._script_writes(script, path)

    def test_redirection(self):
        self.assertTrue(self.writes("dot -c > /usr/lib/tool/config8\n"))
        self.assertTrue(self.writes("{ echo a; } >>usr/lib/tool/config8\n"))

    def test_last_operand_of_cp_mv_install_ln(self):
        for cmd in ("cp /tmp/x", "mv /tmp/x", "install -m644 /tmp/x", "ln -sf /tmp/x"):
            self.assertTrue(self.writes(f"{cmd} /usr/lib/tool/config8\n"), cmd)

    def test_source_operand_is_not_written(self):
        self.assertFalse(self.writes("cp /usr/lib/tool/config8 /tmp/x\n"))

    def test_sed_in_place_through_variables(self):
        # 1password: POLICY_FILE=...; policy="${1:-$POLICY_FILE}"; sed -i ... "$policy"
        script = ('FILE="/usr/lib/tool/config8"\n'
                  'edit() {\n    local f="${1:-$FILE}"\n    sed -i "s|a|b|" "$f"\n}\n')
        self.assertTrue(self.writes(script))
        self.assertFalse(self.writes('FILE="/usr/lib/tool/config8"\nsed "s|a|b|" "$FILE"\n'))

    def test_removing_or_naming_is_not_writing(self):
        self.assertFalse(self.writes("rm -f usr/lib/tool/config{,6,8}\nusr/bin/dot -c\n"))
        self.assertFalse(self.writes('test -e /usr/lib/tool/config8 && echo yes\n'))
        self.assertTrue(self.r._script_names("rm -f usr/lib/tool/config{,6,8}\n",
                                             "/usr/lib/tool/config8"))

    def test_variable_with_two_values_is_not_resolved(self):
        script = 'F=/usr/lib/tool/config8\nF=/tmp/other\ntouch "$F"\n'
        self.assertFalse(self.writes(script))


class ScriptletWrote(Files):
    def setUp(self):
        super().setUp()
        self.path = self.make("usr/lib/tool/config8")
        self.c = self.ctime(self.path)
        self.script = f"post_install() {{\n  dot -c > {self.path}\n}}\n"
        self.installed = "tool 2.0-1\n"
        self.owner = ""        # pacman -Qqo for the file
        self.qkk = ""

    def log(self, before=0, after=5, line="upgraded tool (1.0-1 -> 2.0-1)"):
        return (f"[{stamp(self.c, -before)}] [ALPM] transaction started\n"
                f"[{stamp(self.c, -before)}] [ALPM] {line}\n"
                f"[{stamp(self.c, -before)}] [ALPM-SCRIPTLET] some output\n"
                f"[{stamp(self.c, after)}] [ALPM] transaction completed\n")

    def wrote(self, log, owner=None, path=None):
        def pacman(*args):
            if args[0] == "-Q":
                return self.installed
            if args[0] == "-Qqo":
                return self.owner or None
            raise AssertionError(args)
        done = subprocess.CompletedProcess([], 0, stdout=self.qkk, stderr="")
        with mock.patch.object(self.r, "_pacman", side_effect=pacman), \
             mock.patch.object(self.r, "_install_script", return_value=self.script), \
             mock.patch.object(self.r.subprocess, "run", return_value=done):
            return self.r.scriptlet_wrote(path or self.path, owner, log)

    def test_written_by_its_install_script(self):
        self.assertEqual(self.wrote(self.log()), ("tool", "PKG"))

    def test_only_named_by_its_install_script_is_amber(self):
        # graphviz removes its plugin list and has `dot -c` write it again.
        self.script = f"post_install() {{\n  rm -f {self.path}\n  dot -c\n}}\n"
        self.assertEqual(self.wrote(self.log()), ("tool", "AMBER"))

    def test_installed_rather_than_upgraded(self):
        self.assertEqual(self.wrote(self.log(line="installed tool (2.0-1)")), ("tool", "PKG"))

    def test_written_before_the_package_step(self):
        self.assertIsNone(self.wrote(self.log(before=-30, after=60)))

    def test_written_after_the_transaction(self):
        self.assertIsNone(self.wrote(self.log(before=120, after=-60)))

    def test_step_for_an_older_version_does_not_count(self):
        self.installed = "tool 3.0-1\n"
        self.assertIsNone(self.wrote(self.log()))

    def test_script_that_never_names_the_file(self):
        self.script = "post_install() {\n  dot -c\n}\n"
        self.assertIsNone(self.wrote(self.log()))

    def test_a_file_a_package_owns_now_is_not_unpackaged(self):
        self.owner = "other\n"
        self.assertIsNone(self.wrote(self.log()))

    def test_owned_file_with_only_its_content_changed(self):
        self.owner = "tool\n"
        self.script = f'POLICY="{self.path}"\npost_upgrade() {{\n  sed -i "s/a/b/" "$POLICY"\n}}\n'
        self.qkk = (f"warning: tool: {self.path} (Size mismatch)\n"
                    f"warning: tool: {self.path} (SHA256 checksum mismatch)\n")
        self.assertEqual(self.wrote(self.log(), owner="tool"), ("tool", "PKG"))

    def test_owned_file_whose_mode_changed_too(self):
        self.owner = "tool\n"
        self.qkk = (f"warning: tool: {self.path} (SHA256 checksum mismatch)\n"
                    f"warning: tool: {self.path} (Permissions mismatch)\n")
        self.assertIsNone(self.wrote(self.log(), owner="tool"))

    def test_owned_file_of_another_package(self):
        self.owner = "tool\n"
        self.assertIsNone(self.wrote(self.log(line="upgraded other (1-1 -> 2-1)"), owner="tool"))

    def test_link_to_a_verified_file_of_the_package(self):
        target = self.make("usr/lib/tool/tool-avx2")
        link = self.dir / "usr/bin/tool"
        link.parent.mkdir(parents=True)
        os.symlink(target, link)
        self.c = self.ctime(str(link))
        self.script = f'ln -sf "$best" {link}\n'

        def owner_of(path):
            return "tool" if path == target else ""
        with mock.patch.object(self.r, "_owner_of", side_effect=owner_of):
            self.assertEqual(self.wrote(self.log(), path=str(link)), ("tool", "PKG"))
            self.qkk = f"warning: tool: {target} (SHA256 checksum mismatch)\n"
            self.assertIsNone(self.wrote(self.log(), path=str(link)))


class HookPatched(Files):
    def setUp(self):
        super().setUp()
        self.path = self.make("usr/share/app/View.qml", "patched view")
        self.sum = hashlib.sha256(b"patched view").hexdigest()
        self.hooks = self.dir / "hooks"
        self.hooks.mkdir()
        self.hook = self.hooks / "app-fix.hook"
        self.hook.write_text("[Trigger]\n")
        self.conf = self.dir / "scan.conf"
        self.conf.write_text(f'HOOK_PATCHED="{self.path}=app-fix.hook:{self.sum}"\n')
        self.qkk = f"warning: app: {self.path} (SHA256 checksum mismatch)\n"
        self.c = self.ctime(self.path)

    def patched(self, log=None, owner="app"):
        if log is None:
            log = f"[{stamp(self.c, -2)}] [ALPM] running 'app-fix.hook'...\n"
        done = subprocess.CompletedProcess([], 0, stdout=self.qkk, stderr="")
        # Root owns the real files; here only the mode test applies.
        with mock.patch.object(self.r, "PACMAN_HOOKS", str(self.hooks)), \
             mock.patch.object(self.r, "_root_only", lambda st: not st.st_mode & 0o022), \
             mock.patch.object(self.r, "_owner_of", return_value="app"), \
             mock.patch.object(self.r.subprocess, "run", return_value=done):
            return self.r.hook_patched(self.path, owner, str(self.conf), log)

    def test_listed_file_patched_by_its_hook(self):
        self.assertEqual(self.patched(), "app")

    def test_other_content_written_in_the_window(self):
        # Review M3: a write inside the minute after the hook ran, with any
        # content, was accepted.
        Path(self.path).write_text("something else")
        self.c = self.ctime(self.path)
        self.assertIsNone(self.patched())

    def test_one_of_several_sums(self):
        other = hashlib.sha256(b"old patch").hexdigest()
        self.conf.write_text(f'HOOK_PATCHED="{self.path}=app-fix.hook:{other},{self.sum}"\n')
        self.assertEqual(self.patched(), "app")

    def test_entry_without_a_sum_is_ignored(self):
        self.conf.write_text(f'HOOK_PATCHED="{self.path}=app-fix.hook"\n')
        self.assertIsNone(self.patched())

    def test_not_listed(self):
        self.conf.write_text('HOOK_PATCHED=""\n')
        self.assertIsNone(self.patched())

    def test_list_built_from_a_variable(self):
        self.conf.write_text(f'P={self.path}\nHOOK_PATCHED="$P=app-fix.hook:{self.sum}"\n')
        self.assertIsNone(self.patched())

    def test_hook_no_longer_installed(self):
        self.hook.unlink()
        self.assertIsNone(self.patched())

    def test_hook_others_may_write(self):
        self.hook.chmod(0o666)
        self.assertIsNone(self.patched())

    def test_file_changed_long_after_the_hook_ran(self):
        log = f"[{stamp(self.c, -3600)}] [ALPM] running 'app-fix.hook'...\n"
        self.assertIsNone(self.patched(log))

    def test_another_hook_ran(self):
        log = f"[{stamp(self.c, -2)}] [ALPM] running 'other.hook'...\n"
        self.assertIsNone(self.patched(log))

    def test_mode_changed_as_well(self):
        self.qkk += f"warning: app: {self.path} (Permissions mismatch)\n"
        self.assertIsNone(self.patched())

    def test_owned_by_another_package(self):
        self.assertIsNone(self.patched(owner="other"))


class Depmod(Files):
    """The module index must be what depmod builds now (review M3)."""

    PATH = "/usr/lib/modules/9.9.9-test/modules.dep"

    def rebuilt(self, content=b"index", sums=None, path=PATH, kernel="kernel"):
        real = self.dir / "modules.dep"
        real.write_bytes(content)
        st = os.lstat(real)
        if sums is None:
            sums = {"modules.dep": hashlib.sha256(b"index").hexdigest()}
        with mock.patch.object(self.r.os, "lstat", return_value=st), \
             mock.patch.object(self.r, "_owner_of", return_value=kernel), \
             mock.patch.object(self.r, "_depmod_sums", return_value=sums), \
             mock.patch.object(self.r, "_sha256",
                               side_effect=lambda p: hashlib.sha256(real.read_bytes()).hexdigest()):
            return self.r.depmod_rebuilt(path)

    def test_same_as_depmod_builds_it(self):
        self.assertEqual(self.rebuilt(), "kernel")

    def test_other_content(self):
        self.assertIsNone(self.rebuilt(content=b"alias evil /var/tmp/x.ko"))

    def test_depmod_failed(self):
        self.assertIsNone(self.rebuilt(sums={}))

    def test_kernel_no_package_owns(self):
        self.assertIsNone(self.rebuilt(kernel=""))

    def test_only_the_files_depmod_writes(self):
        self.assertIsNone(self.rebuilt(path="/usr/lib/modules/9.9.9-test/kernel/x.ko"))
        self.assertIsNone(self.rebuilt(path="/usr/lib/modules/9.9.9-test/modules.order"))
        self.assertIsNone(self.rebuilt(path="/usr/lib/modules/9.9.9-test/sub/modules.dep"))


class DepmodSums(Files):
    """_depmod_sums builds the index in a temporary folder of links, writing
    nothing in the real module folder."""

    def test_builds_in_a_temporary_folder(self):
        src = self.dir / "modules/9.9.9-test"
        (src / "kernel").mkdir(parents=True)
        (src / "modules.order").write_text("kernel/x.ko\n")
        (src / "modules.dep").write_text("stale\n")
        seen = {}

        def depmod(cmd, **kw):
            base, version = cmd[2], cmd[3]
            dest = Path(base, "lib/modules", version)
            seen["entries"] = sorted(os.listdir(dest))
            seen["links"] = all(os.path.islink(dest / n) for n in os.listdir(dest))
            (dest / "modules.dep").write_text("fresh\n")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with mock.patch.object(self.r, "MODULES", str(self.dir / "modules")), \
             mock.patch.object(self.r.subprocess, "run", side_effect=depmod):
            sums = self.r._depmod_sums("9.9.9-test")
        self.assertEqual(seen["entries"], ["kernel", "modules.order"])
        self.assertTrue(seen["links"])
        self.assertEqual(sums["modules.dep"], hashlib.sha256(b"fresh\n").hexdigest())
        self.assertEqual((src / "modules.dep").read_text(), "stale\n")


class Dkms(Files):
    """A module dkms built must be its own build, installed while pacman ran
    the dkms hook, from a source a package owns."""

    PATH = "/usr/lib/modules/9.9.9-test/updates/dkms/nvidia.ko.zst"
    CONF = "/src/nvidia-615.78.08/dkms.conf"

    def setUp(self):
        super().setUp()
        self.module = self.make("installed/nvidia.ko.zst", "build")
        self.copy = self.make("tree/nvidia/615.78.08/9.9.9-test/x86_64/module/nvidia.ko.zst",
                              "build")
        c = self.ctime(self.module)
        self.log = (f"[{stamp(c, -60)}] [ALPM] running '70-dkms-install.hook'...\n"
                    f"[{stamp(c, 60)}] [ALPM] running '90-mkinitcpio-install.hook'...\n")
        self.owners = {"/usr/lib/modules/9.9.9-test/": "linux",
                       str(self.dir) + self.CONF: "nvidia-open-dkms"}
        self.source = self.dir / "src/nvidia-615.78.08"
        self.source.mkdir(parents=True)
        self.root_only = True
        self.qkk = "nvidia-open-dkms: 4643 total files, 0 altered files\n"

    def built(self, path=PATH, log=None):
        real_lstat = os.lstat
        module = self.module

        def lstat(p):
            return real_lstat(module if p == path else p)

        def sha(p):
            return hashlib.sha256(Path(module if p == path else p).read_bytes()).hexdigest()
        with mock.patch.object(self.r, "DKMS_TREE", str(self.dir / "tree")), \
             mock.patch.object(self.r, "DKMS_SOURCES", str(self.dir / "src")), \
             mock.patch.object(self.r.os, "lstat", side_effect=lstat), \
             mock.patch.object(self.r, "_sha256", side_effect=sha), \
             mock.patch.object(self.r, "_root_only", return_value=self.root_only), \
             mock.patch.object(self.r, "_owner_of", side_effect=lambda p: self.owners.get(p, "")), \
             mock.patch.object(self.r, "_qkk", return_value=self.qkk):
            return self.r.dkms_built(path, self.log if log is None else log)

    def test_its_own_build_while_the_hook_ran(self):
        self.assertEqual(self.built(), "nvidia-open-dkms")

    def test_other_content(self):
        Path(self.copy).write_text("other build")
        self.assertIsNone(self.built())

    def test_no_build_kept(self):
        os.unlink(self.copy)
        self.assertIsNone(self.built())

    def test_build_copy_writable_by_others(self):
        self.root_only = False
        self.assertIsNone(self.built())

    def test_build_copy_is_a_link(self):
        os.unlink(self.copy)
        os.symlink(self.module, self.copy)
        self.assertIsNone(self.built())

    def test_written_outside_the_hook(self):
        c = self.ctime(self.module)
        log = (f"[{stamp(c, -600)}] [ALPM] running '70-dkms-install.hook'...\n"
               f"[{stamp(c, -500)}] [ALPM] running '90-mkinitcpio-install.hook'...\n")
        self.assertIsNone(self.built(log=log))

    def test_another_hook_ran(self):
        self.assertIsNone(self.built(log=self.log.replace("70-dkms-install", "60-depmod")))

    def test_no_pacman_log(self):
        self.assertIsNone(self.built(log=""))

    def test_kernel_no_package_owns(self):
        # dkms remove can restore modules into the folder of a kernel that is
        # no longer installed.
        del self.owners["/usr/lib/modules/9.9.9-test/"]
        self.assertIsNone(self.built())

    def test_source_no_package_owns(self):
        self.owners.pop(str(self.dir) + self.CONF)
        self.assertIsNone(self.built())

    def test_source_fails_pacman(self):
        # Review: an edited .c file in the source builds a different module.
        self.qkk = (f"warning: nvidia-open-dkms: {self.source}/kernel/nvidia.c "
                    "(SHA256 checksum mismatch)\n")
        self.assertIsNone(self.built())

    def test_other_files_of_the_package_do_not_count(self):
        self.qkk = ("warning: nvidia-open-dkms: /usr/share/doc/nvidia/README "
                    "(SHA256 checksum mismatch)\n")
        self.assertEqual(self.built(), "nvidia-open-dkms")

    def test_source_without_a_file_list(self):
        self.qkk = "nvidia-open-dkms: no mtree file\n"
        self.assertIsNone(self.built())

    def test_source_folder_is_a_link(self):
        # Review: pacman -Qo follows links in the folder part of a path.
        real = self.dir / "elsewhere"
        self.source.rename(real)
        os.symlink(real, self.source)
        self.assertIsNone(self.built())

    def test_build_folder_is_a_link(self):
        # Review: a link to a folder others may write breaks the root-only copy.
        folder = self.dir / "tree/nvidia/615.78.08/9.9.9-test/x86_64/module"
        elsewhere = self.dir / "writable"
        folder.rename(elsewhere)
        os.symlink(elsewhere, folder)
        self.assertIsNone(self.built())

    def test_explained_for_the_scan(self):
        with mock.patch.object(self.r, "dkms_built", return_value="nvidia-open-dkms"), \
             mock.patch.object(self.r, "rebuilt_by_hook", return_value=None), \
             mock.patch.object(self.r, "scriptlet_link_package", return_value=None), \
             mock.patch.object(self.r, "listed_link_package", return_value=None), \
             mock.patch.object(self.r, "depmod_rebuilt", return_value=None):
            out = list(self.r.explain_changes([("", self.PATH)], "", ""))
        self.assertEqual(out, [(self.PATH, "PKG", "kernel module dkms built from "
                                "nvidia-open-dkms while pacman ran its hook")])

    def test_old_red_line_rechecked(self):
        line = f"added {self.PATH} (unpackaged file in a system code path)"
        later = dt.datetime.now() + dt.timedelta(minutes=1)
        with mock.patch.object(self.r, "unchanged_since", return_value=True), \
             mock.patch.object(self.r, "owned_all_along", return_value=False), \
             mock.patch.object(self.r, "rebuilt_by_hook", return_value=None), \
             mock.patch.object(self.r, "depmod_rebuilt", return_value=None), \
             mock.patch.object(self.r, "dkms_built", return_value="nvidia-open-dkms"):
            self.assertEqual(self.r.unpackaged_explains(line, {}, "", None, later), "PKG")
            self.assertIsNone(self.r.unpackaged_explains(line, {}, "", None, later, current=True))

    def test_only_modules_in_the_dkms_folder(self):
        self.assertIsNone(self.built(path="/usr/lib/modules/9.9.9-test/kernel/nvidia.ko.zst"))
        self.assertIsNone(self.built(path="/usr/lib/modules/9.9.9-test/updates/dkms/x/nvidia.ko"))
        self.assertIsNone(self.built(path="/usr/lib/modules/../etc/updates/dkms/nvidia.ko"))
        self.assertIsNone(self.built(path="/usr/lib/modules/9.9.9-test/updates/dkms/nvidia.so"))

    def test_window_closes_at_the_next_line(self):
        c = self.ctime(self.module)
        log = (f"[{stamp(c, -60)}] [ALPM] running '70-dkms-install.hook'...\n"
               f"[{stamp(c, -10)}] [ALPM] running '90-mkinitcpio-install.hook'...\n")
        self.assertIsNone(self.built(log=log))

    def test_last_hook_in_the_log(self):
        c = self.ctime(self.module)
        log = f"[{stamp(c, -60)}] [ALPM] running '70-dkms-install.hook'...\n"
        self.assertEqual(self.built(log=log), "nvidia-open-dkms")
        log = f"[{stamp(c, -2 * self.r._STEP_MAX)}] [ALPM] running '70-dkms-install.hook'...\n"
        self.assertIsNone(self.built(log=log))


class OldKernel(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def gone(self, version, exists=False, owner=None):
        with mock.patch.object(self.r.os.path, "lexists", return_value=exists), \
             mock.patch.object(self.r, "_pacman", return_value=owner):
            return self.r.old_kernel_modules(version)

    def test_gone_and_unowned(self):
        self.assertTrue(self.gone("0.0.0-old"))

    def test_folder_still_there(self):
        self.assertFalse(self.gone("0.0.0-old", exists=True))

    def test_still_owned(self):
        self.assertFalse(self.gone("0.0.0-old", owner="linux\n"))

    def test_running_kernel(self):
        self.assertFalse(self.gone(os.uname().release))

    def test_odd_version_text(self):
        self.assertFalse(self.gone("../etc"))
        self.assertFalse(self.gone(""))


class OwnedAllAlong(Files):
    def along(self, when, owner="pkg", verifies=True):
        path = self.make("file")
        with mock.patch.object(self.r, "_owner_of", return_value=owner), \
             mock.patch.object(self.r, "_pacman_verifies", return_value=verifies):
            return self.r.owned_all_along(path, when)

    def test_unchanged_since_the_run_and_verified(self):
        later = dt.datetime.now() + dt.timedelta(minutes=5)
        self.assertTrue(self.along(later))

    def test_changed_since_the_run(self):
        earlier = dt.datetime.now() - dt.timedelta(minutes=5)
        self.assertFalse(self.along(earlier))

    def test_not_verified(self):
        later = dt.datetime.now() + dt.timedelta(minutes=5)
        self.assertFalse(self.along(later, verifies=False))

    def test_not_owned(self):
        later = dt.datetime.now() + dt.timedelta(minutes=5)
        self.assertFalse(self.along(later, owner=""))


class Verifies(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def verifies(self, out):
        done = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
        with mock.patch.object(self.r.subprocess, "run", return_value=done):
            return self.r._pacman_verifies("tool", "/usr/bin/tool")

    def test_file_swapped_for_a_link(self):
        self.assertFalse(self.verifies("warning: tool: /usr/bin/tool (File type mismatch)\n"))

    def test_no_mtree(self):
        self.assertFalse(self.verifies("tool: no mtree file\n"))

    def test_clean(self):
        self.assertTrue(self.verifies("tool: 3 total files, 0 altered files\n"))


class IntegritySection(unittest.TestCase):
    def setUp(self):
        self.r = load_report()

    def grade(self, lines, gone=True):
        now = self.r.dt.datetime(2026, 10, 21, 12, 0)
        with mock.patch.object(self.r, "logs", return_value=([(now, "log")], None)), \
             mock.patch.object(self.r, "read", return_value=lines), \
             mock.patch.object(self.r, "listed_links", return_value={}), \
             mock.patch.object(self.r, "old_kernel_modules", return_value=gone) as asked:
            return self.r.integrity(now, now), asked

    def test_one_by_one_lines_of_a_gone_kernel_are_package_changes(self):
        lines = "".join(f"AMBER removed /usr/lib/modules/0.0.0-old/k/m{i}.ko (unpackaged file removed)\n"
                        for i in range(40))
        s, asked = self.grade(lines + "AMBER removed /usr/lib/modules/0.0.0-old (unpackaged file removed)\n")
        self.assertEqual(s.rating, self.r.GREEN)
        self.assertIn("(41 files)", s.headline)
        self.assertEqual(asked.call_count, 1)

    def test_lines_of_an_installed_kernel_stay_amber(self):
        s, _ = self.grade("AMBER removed /usr/lib/modules/0.0.0-old/k/m.ko (unpackaged file removed)\n",
                          gone=False)
        self.assertEqual(s.rating, self.r.AMBER)

    def test_summary_line_counts_its_entries(self):
        s, _ = self.grade("PKG removed /usr/lib/modules/0.0.0-old (4158 entries, the modules of "
                          "kernel 0.0.0-old, which is no longer installed)\n")
        self.assertIn("(4158 files)", s.headline)


class ExplainChangesCommand(unittest.TestCase):
    """The hidden --explain-changes option spycatcher-scan calls, as a real
    process: paths arrive on standard input, never as arguments."""

    def test_reads_records_and_prints_nothing_it_cannot_explain(self):
        with tempfile.TemporaryDirectory() as d:
            records = b"\x1f" + d.encode() + b"/nothing\x00pkg\x1f" + d.encode() + b"/x\x00"
            r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--explain-changes", "",
                                f"{d}/no-pacman.log"], input=records, capture_output=True,
                               env={"PATH": "/nonexistent"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, b"")


class Recheck(Files):
    """Which red lines the report re-checks, and against what (review M4)."""

    def setUp(self):
        super().setUp()
        self.path = self.make("usr/lib/tool/config8")
        self.line = f"changed {self.path} (unpackaged file in a system code path)"
        self.when = dt.datetime.now() - dt.timedelta(hours=1)

    def grade(self, until, current=False, explained=("tool", "PKG")):
        with mock.patch.object(self.r, "scriptlet_wrote", return_value=explained), \
             mock.patch.object(self.r, "depmod_rebuilt", return_value=None), \
             mock.patch.object(self.r, "owned_all_along", return_value=False), \
             mock.patch.object(self.r, "hook_explains", return_value=False), \
             mock.patch.object(self.r, "scriptlet_link_explains", return_value=False):
            return self.r.recheck(self.line, {}, "", self.when, until, current)

    def test_file_unchanged_since_the_run(self):
        later = dt.datetime.now() + dt.timedelta(minutes=1)
        self.assertEqual(self.grade(later), "PKG")

    def test_file_changed_after_the_run_stays_red(self):
        # An edit outside any window was logged red; a later upgrade that
        # rewrote the file inside a window must not clear that line.
        earlier = dt.datetime.now() - dt.timedelta(minutes=30)
        self.assertIsNone(self.grade(earlier))

    def test_file_written_while_the_run_ran_stays_red(self):
        # R2-5: the run may have read the file before that write.
        self.assertIsNone(self.grade(dt.datetime.now() - dt.timedelta(seconds=1)))

    def test_named_only_is_amber(self):
        later = dt.datetime.now() + dt.timedelta(minutes=1)
        self.assertEqual(self.grade(later, explained=("tool", "AMBER")), "AMBER")

    def test_current_logs_are_not_graded_again(self):
        later = dt.datetime.now() + dt.timedelta(minutes=1)
        self.assertIsNone(self.grade(later, current=True))


class ReportSpeed(unittest.TestCase):
    """Review M5: the report asked pacman the same questions on every red
    line. Within one run each question is asked once."""

    def setUp(self):
        self.r = load_report()

    def test_pacman_answers_are_kept_for_the_run(self):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="tool\n", stderr="")
        self.r._PACMAN_CACHE, self.r._QKK_CACHE = {}, {}
        with mock.patch.object(self.r.subprocess, "run", side_effect=run):
            for _ in range(20):
                self.r._owner_of("/usr/bin/tool")
                self.r._pacman_verifies("tool", "/usr/bin/tool")
        self.assertEqual(len(calls), 2)

    def test_lines_graded_with_the_current_rules_ask_pacman_nothing(self):
        now = self.r.dt.datetime(2026, 10, 21, 12, 0)
        lines = "".join(f"RED changed /usr/bin/t{i} (unpackaged file in a system code path)\n"
                        for i in range(50))
        lines = (f"graded by spycatcher rules {self.r.RULES_VERSION}\n" + lines
                 + "=== done at 2026-10-21T11:00:00+01:00 ===\n")
        with mock.patch.object(self.r, "logs", return_value=([(now, "log")], None)), \
             mock.patch.object(self.r, "read", return_value=lines), \
             mock.patch.object(self.r, "listed_links", return_value={}), \
             mock.patch.object(self.r, "unchanged_since", return_value=True), \
             mock.patch.object(self.r.subprocess, "run") as run:
            s = self.r.integrity(now, now)
        self.assertEqual(run.call_count, 0)
        # One folder and one day: one item that counts the 50 files.
        self.assertEqual(len([i for i in s.items if i[0] == self.r.RED]), 1)
        self.assertIn("(50 file(s))", s.headline)


class ExplainRecords(unittest.TestCase):
    def test_a_path_holding_a_separator_is_skipped(self):
        # Review L1: the answer is PATH\x1fGRADE\x1fREASON.
        with tempfile.TemporaryDirectory() as d:
            records = b"\x1f" + d.encode() + b"/a\x1fb\x00\x1f" + d.encode() + b"/c\nd\x00"
            r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--explain-changes", "",
                                f"{d}/no-pacman.log"], input=records, capture_output=True,
                               env={"PATH": "/nonexistent"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, b"")


def fake_stat(mode, uid=0, gid=0, kind=stat.S_IFREG):
    """An lstat result with the given mode and owner: files owned by root
    cannot be made without root."""
    return os.stat_result((kind | mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


class MountModes(Files):
    """Review round 2, R2-1: /boot is FAT with fmask=0077, so every packaged
    file there fails pacman's permission check after each upgrade. Round 3,
    F1: the mode and owner the mount gives must also be safe."""

    def setUp(self):
        super().setUp()
        self.boot = self.dir / "boot"
        self.path = self.make("boot/amd-ucode.img")
        self.info = self.dir / "mountinfo"
        self.mount("vfat", "rw,fmask=0077,dmask=0077")
        self.st = fake_stat(0o700)
        self.packaged = (0o644, 0, 0)
        self.qkk = f"warning: amd-ucode: {self.path} (Permissions mismatch)\n"

    def mount(self, fstype, opts, extra=""):
        self.info.write_text(
            "1 0 0:1 / / rw - ext4 /dev/root rw\n"
            f"26 1 259:3 / {self.boot} rw,relatime - {fstype} /dev/nvme0n1p3 {opts}\n" + extra)

    def explains(self, owner="amd-ucode"):
        done = subprocess.CompletedProcess([], 0, stdout=self.qkk, stderr="")
        with mock.patch.object(self.r, "MOUNTINFO", str(self.info)), \
             mock.patch.object(self.r.os, "lstat", return_value=self.st), \
             mock.patch.object(self.r, "_owner_of", return_value="amd-ucode"), \
             mock.patch.object(self.r, "_packaged", return_value=self.packaged), \
             mock.patch.object(self.r.subprocess, "run", return_value=done):
            return self.r.mount_mode_explains(self.path, owner)

    def test_mode_the_mount_gives_every_file(self):
        self.assertEqual(self.explains(), "amd-ucode")

    def test_mount_that_hands_the_files_to_a_user(self):
        # The reviewer's proof of concept: umask=0000,uid=1000 makes every
        # package file 0777 and the user's.
        self.mount("vfat", "rw,umask=0000,uid=1000")
        self.st = fake_stat(0o777, uid=1000)
        self.assertIsNone(self.explains())

    def test_mount_that_lets_others_write(self):
        self.mount("vfat", "rw,umask=0000")
        self.st = fake_stat(0o777)
        self.assertIsNone(self.explains())

    def test_a_group_other_than_root_or_the_packaged_one(self):
        self.mount("vfat", "rw,fmask=0077,gid=100")
        self.st = fake_stat(0o700, gid=100)
        self.assertIsNone(self.explains())

    def test_a_permission_the_package_does_not_give(self):
        # Read for others where the package gives none.
        self.packaged = (0o600, 0, 0)
        self.mount("vfat", "rw,fmask=0033")
        self.st = fake_stat(0o744)
        self.assertIsNone(self.explains())

    def test_the_last_of_stacked_mounts_counts(self):
        self.mount("vfat", "rw,fmask=0077",
                   extra=f"40 26 0:50 / {self.boot} rw - vfat /dev/sdz1 rw,umask=0000,uid=1000\n")
        self.assertIsNone(self.explains())

    def test_content_must_still_verify(self):
        self.qkk += f"warning: amd-ucode: {self.path} (SHA256 checksum mismatch)\n"
        self.assertIsNone(self.explains())

    def test_unreadable_content_does_not_count(self):
        self.qkk += f"warning: amd-ucode: {self.path} (failed to calculate SHA256 checksum)\n"
        self.assertIsNone(self.explains())

    def test_a_mode_the_mount_would_not_give(self):
        self.st = fake_stat(0o755)
        self.assertIsNone(self.explains())

    def test_a_file_system_with_unix_modes(self):
        self.mount("ext4", "rw")
        self.assertIsNone(self.explains())

    def test_another_owner(self):
        self.assertIsNone(self.explains(owner="other"))

    def test_old_red_line_is_re_graded(self):
        line = f"changed {self.path} (owned by amd-ucode but fails pacman's ownership or permission check)"
        later = dt.datetime.now() + dt.timedelta(minutes=1)
        with mock.patch.object(self.r, "mount_mode_explains", return_value="amd-ucode"):
            self.assertEqual(self.r.unpackaged_explains(line, {}, "", later, later), "PKG")
            self.assertIsNone(self.r.unpackaged_explains(line, {}, "", later, later, current=True))


class ConfigModeTightened(Files):
    """cupsd rewrites printers.conf 0600 root:cups; the package ships it 0644
    root:cups and lists it as a backup file. pacman 7.1 reports the mode as
    a plain warning (round 4, C1), checked against `pacman -Qkk cups` as
    root: "warning: cups: /etc/cups/printers.conf (Permissions mismatch)"."""

    def setUp(self):
        super().setUp()
        self.path = "/etc/cups/printers.conf"
        self.qkk = f"warning: cups: {self.path} (Permissions mismatch)\n"
        self.backup = {self.path, "/etc/cups/classes.conf"}

    def grade(self, st):
        done = subprocess.CompletedProcess([], 0, stdout=self.qkk, stderr="")
        with mock.patch.object(self.r.os, "lstat", return_value=st), \
             mock.patch.object(self.r, "_owner_of", return_value="cups"), \
             mock.patch.object(self.r, "_backup_files", return_value=self.backup), \
             mock.patch.object(self.r, "_packaged", return_value=(0o644, 0, 209)), \
             mock.patch.object(self.r.subprocess, "run", return_value=done):
            return list(self.r.explain_changes([("cups", self.path)], "", ""))

    def test_tighter_mode_is_amber(self):
        self.assertEqual(self.grade(fake_stat(0o600, gid=209)),
                         [(self.path, "AMBER", "config file of cups, permissions changed locally")])

    def test_a_group_change_as_well(self):
        self.qkk += f"warning: cups: {self.path} (GID mismatch)\n"
        self.assertEqual(len(self.grade(fake_stat(0o600, gid=0))), 1)

    def test_an_added_permission_stays_red(self):
        self.assertEqual(self.grade(fake_stat(0o666, gid=209)), [])

    def test_another_owner_stays_red(self):
        self.qkk += f"warning: cups: {self.path} (UID mismatch)\n"
        self.assertEqual(self.grade(fake_stat(0o600, uid=1000, gid=209)), [])

    def test_only_for_backup_files(self):
        self.backup = {"/etc/cups/cupsd.conf"}
        self.assertEqual(self.grade(fake_stat(0o600, gid=209)), [])

    def test_content_changed_as_well_is_not_this_rule(self):
        self.qkk += f"backup file: cups: {self.path} (SHA256 checksum mismatch)\n"
        self.assertEqual(self.grade(fake_stat(0o600, gid=209)), [])

    def test_backup_list_is_read_from_the_local_database(self):
        files = ("%FILES%\netc/\netc/cups/printers.conf\n\n"
                 "%BACKUP%\netc/cups/cupsd.conf\tabc\netc/cups/printers.conf\tdef\n\n")
        with mock.patch.object(self.r, "_pacman", return_value="cups 2.4-1\n"), \
             mock.patch.object(self.r.Path, "read_text", return_value=files):
            self.assertEqual(self.r._backup_files("cups"),
                             {"/etc/cups/cupsd.conf", "/etc/cups/printers.conf"})


class RebuiltCaches(Files):
    """Round 3, F2: a hook-rebuilt cache is compared with what its tool
    builds now, not by when it was written."""

    def check(self, content, fresh):
        real = self.make("gconv-modules.cache", content)
        st = os.lstat(real)
        with mock.patch.object(self.r.os, "lstat", return_value=st), \
             mock.patch.object(self.r, "Path", side_effect=lambda p: Path(real)), \
             mock.patch.object(self.r, "_cache_now", return_value=fresh):
            return self.r.rebuilt_by_hook("/usr/lib/gconv/gconv-modules.cache")

    def test_same_as_iconvconfig_builds_it(self):
        self.assertEqual(self.check("cache", b"cache"), "iconvconfig")

    def test_old_red_lines_of_rebuilt_caches_are_re_graded(self):
        # The hardware database and lib32 gconv cache from a 0.2.10 log.
        later = dt.datetime.now() + dt.timedelta(minutes=1)
        for path in ("/usr/lib/udev/hwdb.bin", "/usr/lib32/gconv/gconv-modules.cache"):
            line = f"changed {path} (unpackaged file in a system code path)"
            with mock.patch.object(self.r, "unchanged_since", return_value=True), \
                 mock.patch.object(self.r, "owned_all_along", return_value=False), \
                 mock.patch.object(self.r, "_cache_now", return_value=Path(path).read_bytes()
                                   if os.path.exists(path) else b"x"), \
                 mock.patch.object(self.r.Path, "read_bytes",
                                   return_value=Path(path).read_bytes() if os.path.exists(path) else b"x"), \
                 mock.patch.object(self.r.os, "lstat", return_value=fake_stat(0o644)):
                self.assertEqual(self.r.unpackaged_explains(line, {}, "", later, later), "PKG", path)

    def test_rewritten_and_backdated_cache_stays_red(self):
        # touch -d can put the file's time anywhere; only content counts.
        real = self.make("gconv-modules.cache", "evil")
        os.utime(real, (0, 0))
        self.assertIsNone(self.check("evil", b"cache"))

    def test_tool_failed(self):
        self.assertIsNone(self.check("cache", None))

    def test_other_paths(self):
        self.assertIsNone(self.r.rebuilt_by_hook("/usr/lib/other.cache"))


class CacheNow(unittest.TestCase):
    def test_gconv_rebuilt_into_a_temporary_file(self):
        r = load_report()
        seen = {}

        def run(cmd, **kw):
            seen["cmd"] = cmd
            Path(cmd[2]).write_bytes(b"fresh")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with mock.patch.object(r.subprocess, "run", side_effect=run):
            self.assertEqual(r._cache_now("/usr/lib/gconv/gconv-modules.cache"), b"fresh")
        self.assertEqual(seen["cmd"][:2], ["/usr/bin/iconvconfig", "-o"])
        self.assertFalse(seen["cmd"][2].startswith("/usr/"))

    def test_tools_run_by_full_path_in_a_fixed_environment(self):
        # Round 4: a session variable or a folder early in PATH must not
        # steer a rebuild or a pacman call.
        r = load_report()
        seen = []

        def run(cmd, **kw):
            seen.append((cmd[0], kw.get("env")))
            return subprocess.CompletedProcess(cmd, 1, b"", b"")
        with mock.patch.dict(os.environ, {"GCONV_PATH": "/tmp/x", "GIO_EXTRA_MODULES": "/tmp/x",
                                          "PATH": "/tmp/evil:/usr/bin"}), \
             mock.patch.object(r.subprocess, "run", side_effect=run):
            for path in ("/usr/lib/gconv/gconv-modules.cache", "/usr/lib/gtk-3.0/3.0.0/immodules.cache",
                         "/usr/share/applications/mimeinfo.cache",
                         "/usr/lib/gio/modules/giomodule.cache"):
                r._cache_now(path)
            r._pacman("-Q", "--", "cups")
            r.run(["vercmp", "1", "2"])
        self.assertEqual(len(seen), 6)
        for exe, env in seen:
            self.assertTrue(exe.startswith("/usr/bin/"), exe)
            self.assertEqual(env, {"PATH": "/usr/bin:/usr/sbin:/bin:/sbin", "LC_ALL": "C"})

    def test_lib32_gconv_as_its_hook_builds_it(self):
        r = load_report()
        seen = {}

        def run(cmd, **kw):
            seen["cmd"], seen["env"] = cmd, kw.get("env")
            Path(cmd[2].split("=", 1)[1]).write_bytes(b"lib32")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        with mock.patch.object(r.subprocess, "run", side_effect=run):
            self.assertEqual(r._cache_now("/usr/lib32/gconv/gconv-modules.cache"), b"lib32")
        self.assertEqual(seen["cmd"][0:2], ["/usr/bin/iconvconfig", "--nostdlib"])
        self.assertEqual(seen["cmd"][3], "/usr/lib32/gconv")
        self.assertEqual(seen["env"], r.SAFE_ENV)

    def test_hwdb_built_from_copies_in_a_temporary_root(self):
        r = load_report()
        with tempfile.TemporaryDirectory() as d:
            src = Path(d, "src")
            src.mkdir()
            (src / "20-pci.hwdb").write_text("pci:v*\n ID_X=1\n")
            (src / "notes.txt").write_text("not a source")
            seen = {}

            def run(cmd, **kw):
                root = cmd[1].split("=", 1)[1]
                copied = Path(root, src.as_posix().lstrip("/"))
                seen["files"] = sorted(os.listdir(copied))
                seen["links"] = any(os.path.islink(copied / n) for n in seen["files"])
                seen["root"] = root
                seen["cmd"] = cmd
                Path(root, "usr/lib/udev").mkdir(parents=True, exist_ok=True)
                Path(root, "usr/lib/udev/hwdb.bin").write_bytes(b"hwdb")
                return subprocess.CompletedProcess(cmd, 0, b"", b"")
            with mock.patch.object(r, "HWDB_SOURCES", (str(src), "/nonexistent/hwdb.d")), \
                 mock.patch.object(r.subprocess, "run", side_effect=run):
                self.assertEqual(r._cache_now("/usr/lib/udev/hwdb.bin"), b"hwdb")
        self.assertEqual(seen["files"], ["20-pci.hwdb"])
        self.assertFalse(seen["links"])
        self.assertEqual(seen["cmd"][0], "/usr/bin/systemd-hwdb")
        self.assertEqual(seen["cmd"][2:], ["--usr", "update"])
        self.assertFalse(seen["root"].startswith("/usr"))

    def test_immodules_extra_new_line_is_dropped(self):
        r = load_report()
        out = subprocess.CompletedProcess([], 0, b"a\n\n", b"")
        with mock.patch.object(r.subprocess, "run", return_value=out):
            self.assertEqual(r._cache_now("/usr/lib/gtk-3.0/3.0.0/immodules.cache"), b"a\n")


class PrefetchOwners(unittest.TestCase):
    """R2-2: pacman -Qo prints the path with its parent folder resolved."""

    def test_only_paths_printed_as_asked_are_kept(self):
        r = load_report()
        r._PACMAN_CACHE = {}
        out = subprocess.CompletedProcess(
            [], 0, stdout="/usr/bin/ls is owned by coreutils 9.12-2\n",
            stderr="error: No package owns /usr/bin/nothing\n")
        with mock.patch.object(r.subprocess, "run", return_value=out), \
             mock.patch.object(r.os.path, "islink", return_value=False):
            r.prefetch_owners(["/bin/ls", "/usr/bin/nothing", "/usr/bin/ls"])
        self.assertNotIn(("-Qqo", "--", "/bin/ls"), r._PACMAN_CACHE)
        self.assertEqual(r._PACMAN_CACHE[("-Qqo", "--", "/usr/bin/ls")], "coreutils\n")
        self.assertIsNone(r._PACMAN_CACHE[("-Qqo", "--", "/usr/bin/nothing")])


class CatchUpFlood(unittest.TestCase):
    """A run of an earlier version, still being written, that lists every
    removed module of a gone kernel one by one is folded into the count."""

    def test_unfinished_old_log_with_module_removals(self):
        r = load_report()
        now = r.dt.datetime(2026, 10, 21, 12, 0)
        lines = "".join(f"AMBER removed /usr/lib/modules/0.0.0-old/k/m{i}.ko "
                        "(unpackaged file removed)\n" for i in range(5000))
        with mock.patch.object(r, "logs", return_value=([(now, "log")], None)), \
             mock.patch.object(r, "read", return_value="=== aide run at x ===\n" + lines), \
             mock.patch.object(r, "listed_links", return_value={}), \
             mock.patch.object(r, "old_kernel_modules", return_value=True) as asked:
            s = r.integrity(now, now)
        self.assertEqual(s.rating, r.GREEN)
        self.assertEqual(s.items, [])
        self.assertIn("(5000 files)", s.headline)
        self.assertEqual(asked.call_count, 1)


if __name__ == "__main__":
    unittest.main()
