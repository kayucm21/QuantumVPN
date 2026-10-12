import unittest
from pathlib import Path

import importlib.util

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("runtime_policy", ROOT / "scripts/verify-runtime-surfaces.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class RuntimePolicyRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = POLICY.production_sources(ROOT)

    def test_reviewed_production_sources_pass(self):
        POLICY.verify_source_surfaces(dict(self.baseline))

    def test_new_timer_owner_is_rejected(self):
        sources = dict(self.baseline)
        sources["app/src/main/java/com/quantumvpn/Unreviewed.kt"] = "suspend fun poll() { delay(100) }"
        with self.assertRaisesRegex(ValueError, "timer/retry"):
            POLICY.verify_source_surfaces(sources)

    def test_extra_timer_in_reviewed_owner_is_rejected(self):
        sources = dict(self.baseline)
        sources[POLICY.VPN_SERVICE] += "\nsuspend fun extra() { delay(100) }\n"
        with self.assertRaisesRegex(ValueError, "timer/retry"):
            POLICY.verify_source_surfaces(sources)

    def test_new_alarm_owner_is_rejected(self):
        sources = dict(self.baseline)
        sources["app/src/main/java/com/quantumvpn/Unreviewed.kt"] = "import android.app.AlarmManager"
        with self.assertRaisesRegex(ValueError, "AlarmManager owner"):
            POLICY.verify_source_surfaces(sources)

    def test_new_clipboard_write_is_rejected(self):
        sources = dict(self.baseline)
        sources["app/src/main/java/com/quantumvpn/Unreviewed.kt"] = "fun copy() { cm.setPrimaryClip(clip) }"
        with self.assertRaisesRegex(ValueError, "clipboard write"):
            POLICY.verify_source_surfaces(sources)

    def test_clipboard_listener_is_rejected(self):
        sources = dict(self.baseline)
        sources["app/src/main/java/com/quantumvpn/Unreviewed.kt"] = "fun watch() { cm.addPrimaryClipChangedListener(listener) }"
        with self.assertRaisesRegex(ValueError, "Clipboard history listener"):
            POLICY.verify_source_surfaces(sources)

    def test_exact_alarm_is_rejected_even_inside_reviewed_owner(self):
        sources = dict(self.baseline)
        owner = "app/src/main/java/com/quantumvpn/vpn/UpdateCheckAlarms.kt"
        sources[owner] += "\nfun unreviewed() { am.setExact(0, 0, pi) }\n"
        with self.assertRaisesRegex(ValueError, "scheduler"):
            POLICY.verify_source_surfaces(sources)

    def test_untimed_wakelock_is_rejected(self):
        sources = dict(self.baseline)
        sources[POLICY.VPN_SERVICE] = sources[POLICY.VPN_SERVICE].replace("acquire(6 * 60 * 60 * 1000L)", "acquire()")
        with self.assertRaisesRegex(ValueError, "WakeLock policy"):
            POLICY.verify_source_surfaces(sources)

    def test_duplicate_connection_event_client_is_rejected(self):
        sources = dict(self.baseline)
        sources[POLICY.VPN_SERVICE] += "\naddCommand(Libbox.CommandConnections)\n"
        with self.assertRaisesRegex(ValueError, "must not multiply"):
            POLICY.verify_source_surfaces(sources)


if __name__ == "__main__":
    unittest.main()
