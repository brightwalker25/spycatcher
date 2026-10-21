"""Checks that text taken from scanned files cannot act as markup or as
terminal control codes wherever it is shown.

Run from the repository root:

    python3 -m unittest discover -s tests -v

A finding quotes file names, repository names, package output and the names
a pickle file imports, any of which an attacker can choose. The bar panel
draws them with Qt's Text, whose default format guesses at rich text and
would load an <img> from any URL; the HTML report is a web page; the
terminal report goes to a terminal that obeys escape codes; and many
notification daemons read the notification body as markup. These tests use
such a name at each of those places.
"""

import importlib.machinery
import importlib.util
import json
import os
import re
import unittest
from pathlib import Path
from unittest import mock

from test_scan_argv import ScanRun

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "bin/security-report"
QML = [ROOT / "Panel.qml", ROOT / "BarWidget.qml"]

EVIL = '__builtin__ eval <img src="http://attacker.example/x.png"> & "\x1b]0;owned\x07\x1b[2J\u202e'


def load_report():
    loader = importlib.machinery.SourceFileLoader("security_report", str(SCRIPT))
    spec = importlib.util.spec_from_loader("security_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def text_blocks(qml):
    """The body of every Text element in a QML file, up to its closing brace,
    including inline components declared as `component Name: Text {`."""
    blocks = []
    for m in re.finditer(r"(?<![A-Za-z.])Text\s*\{", qml):
        depth, i = 0, m.end() - 1
        while i < len(qml):
            if qml[i] == "{":
                depth += 1
            elif qml[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        blocks.append((qml.count("\n", 0, m.start()) + 1, qml[m.end():i]))
    return blocks


class QmlPlainText(unittest.TestCase):
    def test_every_text_is_plain_text(self):
        # omacom/omarchy-plugin-marketplace#8732: Panel.qml drew finding text
        # in Qt's default format, which renders rich text.
        found = 0
        for f in QML:
            for line, body in text_blocks(f.read_text()):
                found += 1
                # Only the element's own properties, not those of a child.
                own = re.sub(r"\{[^{}]*\}", "", body)
                self.assertRegex(own, r"\btextFormat:\s*Text\.PlainText\b",
                                 f"{f.name}:{line} Text without textFormat: Text.PlainText")
        self.assertGreater(found, 10)

    def test_no_rich_or_styled_text_anywhere(self):
        for f in QML:
            text = f.read_text()
            self.assertNotRegex(text, r"Text\.(RichText|StyledText|MarkdownText|AutoText)", f.name)
            self.assertNotIn("linkActivated", text, f.name)

    def test_tooltip_drops_markup_characters(self):
        # The bar's own tooltip item is not ours to configure.
        panel = (ROOT / "Panel.qml").read_text()
        m = re.search(r"readonly property string tooltip: \{(.*?)\n  \}", panel, re.S)
        self.assertIsNotNone(m)
        self.assertIn('replace(/[<>&]/g, "")', m.group(1))


class ReportOutput(unittest.TestCase):
    def setUp(self):
        self.r = load_report()
        self.now = self.r.dt.datetime(2026, 10, 21, 12, 0)
        s = self.r.Section("AI model files", self.r.GREEN, f"headline {EVIL}")
        s.add(self.r.RED, f"/models/x.pkl: dangerous import {EVIL}", f"detail {EVIL}", f"action {EVIL}")
        self.sections = [s]

    def test_html_escapes_finding_text(self):
        page = self.r.html_report(self.sections, self.r.RED, self.now, self.now)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img src=&quot;http://attacker.example/x.png&quot;&gt;", page)
        self.assertNotIn("\x1b", page)

    def test_terminal_report_has_no_control_codes(self):
        out = self.r.text_report(self.sections, self.r.RED, self.now, self.now, colour=False)
        self.assertNotRegex(out, "[\x00-\x08\x0b-\x1f\x7f\u202e]")
        self.assertIn("__builtin__ eval", out)

    def test_colour_report_has_only_its_own_colour_codes(self):
        out = self.r.text_report(self.sections, self.r.RED, self.now, self.now, colour=True)
        self.assertNotIn("\x1b]", out)
        self.assertNotIn("\x1b[2J", out)
        self.assertNotIn("\x07", out)

    def test_json_keeps_markup_as_text_without_control_codes(self):
        # The panel shows these as plain text, so markup must arrive as the
        # characters it is, not as entities the panel would show literally.
        with mock.patch.object(self.r, "scan_health", return_value=self.sections[0]), \
             mock.patch.object(self.r, "packages", return_value=self.sections[0]), \
             mock.patch.object(self.r, "integrity", return_value=self.sections[0]), \
             mock.patch.object(self.r, "rootkit", return_value=self.sections[0]), \
             mock.patch.object(self.r, "models", return_value=self.sections[0]), \
             mock.patch.object(self.r, "secrets", return_value=self.sections[0]), \
             mock.patch.object(self.r, "hardening", return_value=self.sections[0]), \
             mock.patch.object(self.r, "standing", return_value=self.sections[0]), \
             mock.patch.object(self.r, "privacy", return_value=self.sections[0]), \
             mock.patch.object(self.r, "installed_versions", return_value={}), \
             mock.patch.object(self.r.sys, "argv", ["security-report", "--json"]), \
             mock.patch("builtins.print") as printed:
            self.r.main()
        data = json.loads(printed.call_args[0][0])
        item = data["sections"][0]["items"][0]
        self.assertIn('<img src="http://attacker.example/x.png">', item["what"])
        for value in (item["what"], item["detail"], item["action"], data["sections"][0]["headline"]):
            self.assertNotRegex(value, "[\x00-\x08\x0b-\x1f\x7f\u202e]")

    def test_new_lines_and_invisible_marks_are_shown_as_question_marks(self):
        # A new line in a name could otherwise forge a line of the terminal
        # report.
        self.assertEqual(self.r.plain("a\tb\nc\rd"), "a\tb?c?d")
        for mark in "\u061c\u200b\u200c\u200d\u2028\u2029\ufeff":
            self.assertEqual(self.r.plain(f"x{mark}y"), "x?y")


@unittest.skipUnless(os.path.exists(f"/run/user/{os.getuid()}/bus"),
                     "notify() only speaks to a running desktop session")
class NotificationMarkup(ScanRun):
    """runuser is a stand-in that records its arguments, so nothing is shown."""

    def test_body_is_markup_escaped(self):
        logs = self.base / "logs <b>&amp"
        ai = self.home / "AI"
        ai.mkdir()
        (ai / "m.pkl").write_text("x")
        self.scan("models", MODEL_ROOTS=str(ai), LOG_DIR=str(logs))
        sent = [a for a in self.argv() if a[0] == "runuser"]
        self.assertTrue(sent)
        body = sent[-1][-1]
        self.assertIn("logs &lt;b&gt;&amp;amp/models-", body)
        self.assertNotIn("<b>", body)

    def scan(self, mode, **env):
        # As ScanRun.scan, but the log folder is given per test.
        import subprocess
        run = subprocess.run(["bash", str(self.script), mode], env=dict(self.env, **env),
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
