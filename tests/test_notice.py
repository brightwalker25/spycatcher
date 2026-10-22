"""Checks for the notice rating: standing advice that is listed first and
never graded.

Run from the repository root:

    python3 -m unittest discover -s tests -v
"""

import importlib.machinery
import importlib.util
import datetime as dt
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
    return mod


class Notice(unittest.TestCase):
    def setUp(self):
        self.r = load_report()
        self.s = self.r.Section("Known vulnerabilities in installed packages", self.r.GREEN, "")
        self.s.add(self.r.GREEN, "coreutils: fixed")
        self.s.add(self.r.NOTICE, "wget: sends your login on", "No fix yet.",
                   "Do not give wget a password.")

    def test_a_notice_does_not_grade_the_section_or_the_report(self):
        self.assertEqual(self.s.rating, self.r.GREEN)
        self.assertEqual(self.r.overall_of([self.s]), self.r.GREEN)
        grey = self.r.Section("Privacy", self.r.GREY, "")
        grey.add(self.r.NOTICE, "advice")
        self.assertEqual(grey.rating, self.r.GREY)

    def test_amber_and_red_still_grade(self):
        self.s.add(self.r.AMBER, "other")
        self.assertEqual(self.s.rating, self.r.AMBER)
        self.s.add(self.r.RED, "worse")
        self.assertEqual(self.s.rating, self.r.RED)
        self.assertEqual(self.r.worst(self.r.NOTICE, self.r.AMBER), self.r.AMBER)

    def test_notices_are_collected_and_counted(self):
        self.assertEqual(self.r.notices([self.s]),
                         [(self.s.title, "wget: sends your login on", "No fix yet.",
                           "Do not give wget a password.")])
        line = self.r.overall_line(self.r.GREEN, [self.s])
        self.assertEqual(line, "Nothing needs your attention. 1 piece of standing advice, listed first.")

    def test_listed_first_with_the_advice(self):
        now = dt.datetime(2026, 10, 22, 12, 0)
        other = self.r.Section("Scans ran on schedule", self.r.GREEN, "All on time.")
        out = self.r.text_report([other, self.s], self.r.GREEN, now, now, colour=False)
        advice = out.index("Standing advice")
        self.assertLess(advice, out.index("Scans ran on schedule"))
        self.assertIn("Advice: Do not give wget a password.", out)
        self.assertNotIn("What is being done: Do not give", out)
        page = self.r.html_report([other, self.s], self.r.GREEN, now, now)
        self.assertLess(page.index("Standing advice"), page.index("Scans ran on schedule"))
        self.assertIn('<span class="pill notice">NOTICE</span>', page)

    def test_no_advice_no_block(self):
        now = dt.datetime(2026, 10, 22, 12, 0)
        plain = self.r.Section("Scans ran on schedule", self.r.GREEN, "All on time.")
        self.assertNotIn("Standing advice", self.r.text_report([plain], self.r.GREEN, now, now, colour=False))
        self.assertNotIn("Standing advice", self.r.html_report([plain], self.r.GREEN, now, now))
        self.assertEqual(self.r.overall_line(self.r.GREEN, [plain]), "Nothing needs your attention.")

    def test_markup_in_advice_is_escaped_in_the_page(self):
        now = dt.datetime(2026, 10, 22, 12, 0)
        self.s.add(self.r.NOTICE, "<img src=x>", "", "<b>x</b>")
        page = self.r.html_report([self.s], self.r.GREEN, now, now)
        self.assertNotIn("<img src=x>", page)
        self.assertIn("&lt;img src=x&gt;", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)


class RegisterNotice(unittest.TestCase):
    """A notice in the risk register counts only on an open CVE entry."""

    AUDIT = "| wget is affected by multiple issues. Medium risk!\n"

    def setUp(self):
        self.r = load_report()
        self.now = dt.datetime(2026, 10, 22, 12, 0)

    def packages(self, entry, installed="1.25.0-6"):
        reg = {"cve": {"wget": {"assessed_version": "1.25.0-6", "risk": "wget leaks a login.",
                                "action": "Give wget no password.", **entry}}}
        with mock.patch.object(self.r, "logs", return_value=([], (self.now, "/x"))), \
             mock.patch.object(self.r, "read", return_value=self.AUDIT), \
             mock.patch.object(self.r, "vercmp", side_effect=lambda a, b: (a > b) - (a < b)):
            return self.r.packages(self.now, self.now, reg, {"wget": installed})

    def test_an_open_cve_notice_is_advice_and_not_graded(self):
        s = self.packages({"status": "open", "rating": "notice"})
        self.assertEqual(s.rating, self.r.GREEN)
        self.assertEqual([i[0] for i in s.items], [self.r.NOTICE])
        self.assertEqual(self.r.notices([s])[0][3], "Give wget no password.")

    def test_a_notice_on_another_status_is_amber(self):
        for status in ("stale", "accepted"):
            s = self.packages({"status": status, "rating": "notice"})
            self.assertEqual(s.rating, self.r.AMBER, status)
            self.assertEqual(self.r.notices([s]), [])

    def test_an_older_version_than_assessed_is_amber(self):
        s = self.packages({"status": "open", "rating": "notice"}, installed="1.24.0-1")
        self.assertEqual(s.rating, self.r.AMBER)

    def test_a_misspelt_rating_is_amber_not_a_crash(self):
        for rating in ("Notice", "advice", "orange"):
            self.assertEqual(self.packages({"status": "open", "rating": rating}).rating,
                             self.r.AMBER, rating)

    def test_a_standing_protection_cannot_be_a_notice(self):
        s = self.r.standing({"standing": {"x": {"rating": "notice", "risk": "A protection."}}})
        self.assertEqual(s.rating, self.r.AMBER)
        self.assertEqual(self.r.notices([s]), [])

    def test_only_open_cves_may_give_a_notice(self):
        self.assertEqual(self.r.register_rating({"rating": "notice"}), self.r.AMBER)
        self.assertEqual(self.r.register_rating({"rating": "notice"}, notice=True), self.r.NOTICE)
        self.assertEqual(self.r.register_rating({"rating": "green"}), self.r.GREEN)
        self.assertEqual(self.r.register_rating({}), self.r.AMBER)


if __name__ == "__main__":
    unittest.main()
