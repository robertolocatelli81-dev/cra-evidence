# SPDX-License-Identifier: AGPL-3.0-or-later
"""Boundaries that survived a mutant (NEMESIS 19/10/2026): equal instants."""
import unittest

from cra_evidence.applicability import art14_obligation, update_available_until, user_information


class EqualInstants(unittest.TestCase):
    def test_vulnerability_known_at_the_instant_of_its_exploitation_is_accepted(self):
        # learning of the vulnerability through its exploitation: the two instants coincide; only a LATER one is refused
        r = art14_obligation("2026-10-01T08:00:00Z", vulnerability_awareness_utc="2026-10-01T08:00:00Z")
        self.assertEqual(r["outcome"], "obligation")
        self.assertEqual(r["vulnerability_awareness_utc"], "2026-10-01T08:00:00+00:00")
        with self.assertRaises(ValueError):
            art14_obligation("2026-10-01T08:00:00Z", vulnerability_awareness_utc="2026-10-01T08:00:01Z")

    def test_support_end_equal_to_the_ten_years_is_governed_by_the_ten_years(self):
        # "whichever is longer": equal is not longer
        r = update_available_until("2026-01-01T12:00:00Z", "2036-01-02T00:00:00Z")
        self.assertEqual(r["readings"]["utc"], {"until_utc": "2036-01-02T00:00:00+00:00", "governed_by": "ten_years"})

    def test_users_informed_at_the_instant_of_awareness_is_recorded(self):
        r = user_information("2026-10-01T08:00:00Z", "2026-10-01T08:00:00Z")
        self.assertEqual(r["status"], "recorded")

    def test_severe_incident_not_marked_exploited_is_reportable(self):
        # Art. 14(3): a severe incident is reported whether or not a vulnerability is actively exploited
        from datetime import datetime, timezone
        from cra_evidence.vuln import VulnerabilityRecord
        r = VulnerabilityRecord("p", "INC-1", False, "2026-10-01T08:00:00Z", kind="incident")
        o = r.overdue(datetime(2026, 10, 10, tzinfo=timezone.utc))
        self.assertTrue(o["reporting_applicable"]); self.assertTrue(o["any_overdue"])
        self.assertEqual(o["art14_obligation"]["outcome"], "obligation")
        self.assertEqual(o["art14_obligation"]["stream"], "incident")

    def test_placed_between_the_two_starts_and_modified_after_names_both_bases(self):
        from cra_evidence.applicability import legacy_product_scope
        r = legacy_product_scope("2027-12-10T23:30:00Z", "2027-12-11T00:30:00Z")   # placed: from the date in Brussels only
        self.assertEqual(r["outcome"], "requirements_apply")
        self.assertIn("under the Europe/Brussels reading", r["basis"]); self.assertIn("10 December under the UTC reading", r["basis"])
        r = legacy_product_scope("2027-12-11T00:00:00Z")
        self.assertEqual(r["basis"], "placed on the market from 11 December 2027: the Regulation applies (Art. 71(2))")


if __name__ == "__main__":
    unittest.main()
