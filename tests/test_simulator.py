"""
Automated Unit Test Suite for Authentication Security & Resilience Simulator
"""

import unittest
import time
from modules.entropy_analyzer import analyze_password, format_duration
from modules.mock_auth_lab import MockAuthServerState


class TestEntropyAnalyzer(unittest.TestCase):
    def test_empty_password(self):
        res = analyze_password("")
        self.assertEqual(res["entropy_bits"], 0.0)
        self.assertEqual(res["rating"], "Empty")

    def test_weak_password(self):
        res = analyze_password("password123")
        self.assertIn("Weak", res["rating"])
        self.assertTrue(len(res["warnings"]) > 0)
        self.assertLess(res["entropy_bits"], 50.0)

    def test_strong_password(self):
        res = analyze_password("K8#mP!9$vL2@qZ*wX")
        self.assertEqual(res["rating"], "Very Strong")
        self.assertGreater(res["entropy_bits"], 80.0)
        self.assertTrue(res["character_sets"]["lowercase"])
        self.assertTrue(res["character_sets"]["uppercase"])
        self.assertTrue(res["character_sets"]["digits"])
        self.assertTrue(res["character_sets"]["symbols"])

    def test_format_duration(self):
        self.assertIn("Instant", format_duration(0.0001))
        self.assertIn("seconds", format_duration(45))
        self.assertIn("minutes", format_duration(180))
        self.assertIn("hours", format_duration(7200))
        self.assertIn("days", format_duration(86400 * 5))
        self.assertIn("years", format_duration(86400 * 365.25 * 50))


class TestMockAuthLab(unittest.TestCase):
    def test_token_bucket_exhaustion(self):
        state = MockAuthServerState(defense_mode="token-bucket")
        ip = "192.168.1.50"

        # Deplete 5 tokens
        for _ in range(5):
            status, _, _ = state.handle_login(ip, "user", "badpass")
            self.assertEqual(status, 401)

        # 6th attempt should be blocked with 429 Too Many Requests
        status, resp, _ = state.handle_login(ip, "user", "badpass")
        self.assertEqual(status, 429)
        self.assertEqual(resp["error"], "Too Many Requests")

    def test_account_lockout(self):
        state = MockAuthServerState(defense_mode="lockout")
        user = "victim_account"

        # 4 failed attempts: status 401
        for _ in range(4):
            status, _, _ = state.handle_login("1.1.1.1", user, "wrong")
            self.assertEqual(status, 401)

        # 5th attempt locks the account
        status, _, _ = state.handle_login("1.1.1.1", user, "wrong")
        self.assertEqual(status, 401)

        # Subsequent attempt triggers 423 Locked
        status, resp, _ = state.handle_login("1.1.1.1", user, "wrong")
        self.assertEqual(status, 423)
        self.assertEqual(resp["error"], "Account Locked")

    def test_progressive_delay(self):
        state = MockAuthServerState(defense_mode="progressive-delay")
        ip = "10.0.0.99"

        # 1st attempt: 0s delay
        _, _, d1 = state.handle_login(ip, "user", "wrong")
        self.assertEqual(d1, 0.0)

        # 2nd attempt: progressive delay applied
        _, _, d2 = state.handle_login(ip, "user", "wrong")
        self.assertGreater(d2, 0.0)

        # 3rd attempt: delay should increase
        _, _, d3 = state.handle_login(ip, "user", "wrong")
        self.assertGreater(d3, d2)

    def test_valid_credentials_succeed(self):
        state = MockAuthServerState(defense_mode="token-bucket")
        status, resp, _ = state.handle_login("127.0.0.1", "admin", "CorrectHorseBatteryStaple!")
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "Authenticated")


if __name__ == "__main__":
    unittest.main()
