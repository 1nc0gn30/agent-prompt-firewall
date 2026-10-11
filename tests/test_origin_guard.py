"""Only local pages may call this server from a browser (CSRF / cross-site read guard)."""
import os, sys, unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from agent_prompt_firewall.web_radar import _is_local_origin


class TestOriginGuard(unittest.TestCase):
    def test_allowed(self):
        for o in (None, "", "http://127.0.0.1:8000", "http://localhost:3000", "http://[::1]:1"):
            self.assertTrue(_is_local_origin(o), o)

    def test_blocked(self):
        for o in ("https://evil.example", "null", "http://127.0.0.1.evil.com", "file://", "chrome-extension://abc"):
            self.assertFalse(_is_local_origin(o), o)


if __name__ == "__main__":
    unittest.main()
