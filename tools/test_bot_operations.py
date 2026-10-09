import unittest
from tools import quantumvpn_bot_operations as ops


class ConfirmationTests(unittest.TestCase):
    def observation(self, condition):
        return {"schema": 1, "conditions": {"service_operator": condition}}

    def test_bad_and_recovery_require_three_spaced_samples(self):
        state = None
        for stamp in (1000, 1060, 1120):
            r = ops.confirmed_conditions(self.observation("bad"), state, now=stamp)
            state = r["state"]
            self.assertEqual(bool(r["bad"]), stamp == 1120)
        for stamp in (1180, 1240, 1300):
            r = ops.confirmed_conditions(self.observation("healthy"), state, now=stamp,
                                         open_issues=["service_operator"])
            state = r["state"]
            self.assertEqual(bool(r["healthy"]), stamp == 1300)

    def test_fast_checks_missing_data_and_stale_gap_cannot_confirm(self):
        r = ops.confirmed_conditions(self.observation("bad"), now=1000)
        for stamp in (1001, 1002):
            r = ops.confirmed_conditions(self.observation("bad"), r["state"], now=stamp)
            self.assertFalse(r["bad"])
        r = ops.confirmed_conditions(self.observation("unknown"), r["state"], now=1060)
        r = ops.confirmed_conditions(self.observation("bad"), r["state"], now=1120)
        self.assertFalse(r["bad"])
        r = ops.confirmed_conditions(self.observation("bad"), r["state"], now=1400)
        self.assertFalse(r["bad"])

    def test_delivered_bad_retained_and_clock_rollback_cannot_heal(self):
        r = ops.confirmed_conditions(self.observation("bad"), now=1000, open_issues=["service_operator"])
        self.assertTrue(r["bad"])
        r = ops.confirmed_conditions(self.observation("healthy"), r["state"], now=999)
        self.assertFalse(r["healthy"])

    def test_delivery_retry_and_success_cooldown(self):
        fact = {"should_notify": True}
        self.assertTrue(ops.delivery_due(fact, now=1000))
        self.assertFalse(ops.delivery_due(fact, now=1010, last_attempt=1000))
        self.assertTrue(ops.delivery_due(fact, now=1060, last_attempt=1000))
        self.assertFalse(ops.delivery_due(fact, now=1060, last_sent=1050))
        self.assertFalse(ops.delivery_due(fact, now=1060, last_sent=1100))
        self.assertFalse(ops.delivery_due({"should_notify": False}, now=1060))

    def test_cached_protocol_evidence_is_never_counted_three_times(self):
        observation = self.observation("bad")
        observation['sample_timestamps'] = {'service_operator': 1000}
        r = ops.confirmed_conditions(observation, now=1000)
        for now in (1060, 1120, 1180, 1240):
            r = ops.confirmed_conditions(observation, r['state'], now=now)
            self.assertFalse(r['bad'])
        for measured in (1300, 1600):
            observation['sample_timestamps']['service_operator'] = measured
            r = ops.confirmed_conditions(observation, r['state'], now=measured)
        self.assertTrue(r['bad'])

    def test_backup_summary_never_exposes_paths_or_failures(self):
        result = {"ok": True, "checked_at": 1000, "databases": ["operator.db", "rospanel.db", "SECRET"], "missing": []}
        summary = ops.backup_test_summary(result)
        self.assertEqual(summary["backup_db_count"], 2)
        self.assertNotIn("SECRET", ops.format_backup_tests(result))
        self.assertIn("не пройдена", ops.format_backup_tests({"ok": False, "error": "SECRET"}))


if __name__ == "__main__":
    unittest.main()
