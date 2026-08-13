"""Regression: the interactive (config-flow) 2FA login must speak the same
language as every other auth call, or Arlo's error/message text stops
matching what the rest of the library expects to parse and log.
"""

from unittest import TestCase
from unittest.mock import patch

from pyaarlo.backend import start_interactive_2fa_auth
from pyaarlo.errors import ArloResponse, ErrorAction


class TestInteractive2faLanguage(TestCase):
    def test_login_payload_uses_english(self):
        captured = {}

        def _fake_request(session, method, url, params=None, headers=None, timeout=60):
            if method == "POST":
                captured["params"] = params
                return ArloResponse(
                    200,
                    {
                        "authCompleted": True,
                        "userId": "u",
                        "token": "t",
                        "expiresIn": 1,
                    },
                    action=ErrorAction.OK,
                )
            return ArloResponse(200, None, action=ErrorAction.OK)

        with patch("pyaarlo.backend._auth_helper_request", side_effect=_fake_request):
            with patch("pyaarlo.backend._create_auth_helper_session", return_value=object()):
                start_interactive_2fa_auth(
                    "user@example.com", "secret", "F1", "EMAIL",
                )

        self.assertEqual(captured["params"]["language"], "en")
