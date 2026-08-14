"""Offline tests for the login, session resume and 2FA factor selection code.

Nothing here touches the network. `ArloBackEnd` is built with `object.__new__`
because its constructor logs in, and the handful of collaborators each test
needs are stubbed in `_backend` below.
"""

import logging
import shutil
import time
from unittest import TestCase

import tests.arlo
from pyaarlo.backend import ArloBackEnd, AuthResult
from pyaarlo.tfa import Arlo2FAConsole, Arlo2FAImap, Arlo2FARestAPI
from pyaarlo.util import expiry_to_epoch, seconds_until

MINUTE = 60
HOUR = 60 * MINUTE

FACTORS = [
    {"factorId": "f-mail-home", "factorType": "EMAIL", "factorRole": "PRIMARY",
     "factorNickname": "home@example.com", "displayName": "home@example.com"},
    {"factorId": "f-mail-work", "factorType": "EMAIL", "factorRole": "SECONDARY",
     "factorNickname": "work@example.com", "displayName": "work@example.com"},
    {"factorId": "f-push-pix", "factorType": "PUSH", "factorRole": "SECONDARY",
     "factorNickname": "Pixel 9", "displayName": "Pixel 9"},
]


def setUpModule():
    # Several tests deliberately trigger errors and warnings. Keep them out of
    # the test output so real failures stand out.
    logging.getLogger("pyaarlo").setLevel(logging.CRITICAL)


def _backend(arlo=None, **state):
    """Build a backend without letting its constructor log in."""
    be = object.__new__(ArloBackEnd)
    be._arlo = arlo if arlo is not None else tests.arlo.PyArlo()
    be._cookies = None
    be._session = None
    be._user_agent = "test-agent"
    be._user_device_id = "test-device"
    be._user_id = None
    be._token = None
    be._token64 = None
    be._expires_in = 0
    be._needs_pairing = True
    for name, value in state.items():
        setattr(be, "_" + name, value)
    return be


def _exploding(name):
    def _explode(*_args, **_kwargs):
        raise AssertionError(f"{name} should not have been called")
    return _explode


class TestExpiry(TestCase):
    """Arlo sends `expiresIn` as an epoch, sometimes in seconds, sometimes ms."""

    def test_expiry_to_epoch_bad_input(self):
        self.assertEqual(expiry_to_epoch(None), 0)
        self.assertEqual(expiry_to_epoch("not-a-number"), 0)
        self.assertEqual(expiry_to_epoch(0), 0)

    def test_expiry_to_epoch_units(self):
        now = time.time()
        self.assertAlmostEqual(expiry_to_epoch(now), now, places=3)
        self.assertAlmostEqual(expiry_to_epoch(now * 1000), now, places=3)

    def test_seconds_until_never_negative(self):
        self.assertEqual(seconds_until(time.time() - 1000), 0)
        self.assertEqual(seconds_until(None), 0)
        self.assertGreater(seconds_until(time.time() + 100), 90)

    def test_a_real_arlo_token_has_useful_time_on_it(self):
        # A measured value: expiresIn is an absolute epoch in seconds and the
        # token lasts about two hours. Measuring this in days rounds every real
        # token down to zero, which is what broke the original code.
        left = seconds_until(time.time() + 2 * HOUR)
        self.assertGreater(left, 100 * MINUTE)
        self.assertLess(left, 3 * HOUR)


class TestSetToken(TestCase):
    """The plain and base64 tokens must never drift apart."""

    def test_set_and_clear(self):
        be = _backend()
        be._set_token("a-token")
        self.assertEqual(be._token, "a-token")
        self.assertEqual(be._token64, "YS10b2tlbg==")
        be._set_token(None)
        self.assertIsNone(be._token)
        self.assertIsNone(be._token64)

    def test_update_auth_info_keeps_them_in_step(self):
        be = _backend()
        be._update_auth_info({
            "token": "a-token", "userId": "u1", "expiresIn": 123,
        })
        self.assertEqual(be._token64, "YS10b2tlbg==")
        self.assertEqual(be._web_id, "u1_web")
        self.assertEqual(be._sub_id, "subscriptions/u1_web")

    def test_update_auth_info_unwraps_access_token(self):
        be = _backend()
        be._update_auth_info({
            "accessToken": {"token": "a-token", "userId": "u1", "expiresIn": 123},
        })
        self.assertEqual(be._token, "a-token")
        self.assertEqual(be._user_id, "u1")


class TestResumeSession(TestCase):
    """Reusing a saved token instead of posting the password again."""

    def _fresh(self, arlo=None, validates=True, **state):
        defaults = {
            "token": "a-token",
            "token64": "YS10b2tlbg==",
            "user_id": "u1",
            "expires_in": time.time() + 2 * HOUR,
        }
        defaults.update(state)
        be = _backend(arlo=arlo, **defaults)
        be._validate = lambda: validates
        return be

    def test_resumes_a_good_token(self):
        be = self._fresh()
        self.assertTrue(be._resume_session())
        self.assertFalse(be._needs_pairing)

    def test_resumes_when_expiry_is_in_milliseconds(self):
        be = self._fresh(expires_in=(time.time() + 2 * HOUR) * 1000)
        self.assertTrue(be._resume_session())

    def test_refuses_without_a_token(self):
        be = self._fresh(token=None, token64=None)
        be._validate = _exploding("_validate")
        self.assertFalse(be._resume_session())

    def test_refuses_without_a_user_id(self):
        be = self._fresh(user_id=None)
        be._validate = _exploding("_validate")
        self.assertFalse(be._resume_session())

    def test_refuses_an_expired_token(self):
        be = self._fresh(expires_in=time.time() - HOUR)
        be._validate = _exploding("_validate")
        self.assertFalse(be._resume_session())

    def test_refuses_a_token_expiring_too_soon(self):
        # Inside the safety margin: we would risk it expiring part way through
        # startup, so log in again while we can do it cleanly.
        be = self._fresh(expires_in=time.time() + 2 * MINUTE)
        be._validate = _exploding("_validate")
        self.assertFalse(be._resume_session())

    def test_resumes_a_token_with_an_hour_left(self):
        # The realistic case: restarted an hour into a two hour token.
        be = self._fresh(expires_in=time.time() + HOUR)
        self.assertTrue(be._resume_session())

    def test_refuses_when_reuse_is_turned_off(self):
        be = self._fresh(arlo=tests.arlo.PyArlo(reuse_session=False))
        be._validate = _exploding("_validate")
        self.assertFalse(be._resume_session())

    def test_refuses_when_the_session_is_not_saved(self):
        # Nothing is persisted, so there is nothing to resume next time.
        be = self._fresh(arlo=tests.arlo.PyArlo(save_session=False))
        be._validate = _exploding("_validate")
        self.assertFalse(be._resume_session())

    def test_refuses_a_token_the_server_rejects(self):
        be = self._fresh(validates=False)
        self.assertFalse(be._resume_session())


class TestAuthenticate(TestCase):
    """`_authenticate` picks between resuming and a full login."""

    def _be(self, **state):
        be = _backend(**state)
        be._pair_auth_code = lambda: True
        be._validate = lambda: True
        return be

    def test_resume_short_circuits_the_password_login(self):
        be = self._be()
        be._resume_session = lambda: True
        be._auth = _exploding("_auth")
        self.assertEqual(be._authenticate(), AuthResult.SUCCESS)

    def test_falls_through_to_a_full_login(self):
        be = self._be()
        be._resume_session = lambda: False
        be._auth = lambda: AuthResult.SUCCESS
        self.assertEqual(be._authenticate(), AuthResult.SUCCESS)

    def test_failed_login_is_reported_as_failed(self):
        be = self._be()
        be._resume_session = lambda: False
        be._auth = lambda: AuthResult.FAILED
        be._validate = _exploding("_validate")
        self.assertEqual(be._authenticate(), AuthResult.FAILED)

    def test_retryable_login_stays_retryable(self):
        be = self._be()
        be._resume_session = lambda: False
        be._auth = lambda: AuthResult.CAN_RETRY
        be._validate = _exploding("_validate")
        self.assertEqual(be._authenticate(), AuthResult.CAN_RETRY)

    def test_validate_failure_is_retryable(self):
        # Retryable, so the cloudscraper path gets to try the next ecdh curve.
        be = self._be()
        be._resume_session = lambda: False
        be._auth = lambda: AuthResult.SUCCESS
        be._validate = lambda: False
        self.assertEqual(be._authenticate(), AuthResult.CAN_RETRY)

    def test_pairing_failure_is_retryable(self):
        be = self._be()
        be._resume_session = lambda: False
        be._auth = lambda: AuthResult.SUCCESS
        be._pair_auth_code = lambda: False
        self.assertEqual(be._authenticate(), AuthResult.CAN_RETRY)


class TestGetTfa(TestCase):
    """A bad `tfa_source` must be reported, not crash mid login."""

    def _tfa(self, source):
        return _backend(arlo=tests.arlo.PyArlo(tfa_source=source))._get_tfa()

    def test_known_sources(self):
        self.assertIsInstance(self._tfa("console"), Arlo2FAConsole)
        self.assertIsInstance(self._tfa("imap"), Arlo2FAImap)
        self.assertIsInstance(self._tfa("rest-api"), Arlo2FARestAPI)
        self.assertEqual(self._tfa("push"), "push")

    def test_unknown_source_reports_the_valid_ones(self):
        arlo = tests.arlo.PyArlo(tfa_source="imap2")
        self.assertIsNone(_backend(arlo=arlo)._get_tfa())
        self.assertIn("imap2", arlo.last_error)
        self.assertIn("console", arlo.last_error)
        self.assertIn("push", arlo.last_error)


class TestGetFactors(TestCase):
    """Reading the 2FA factor list."""

    def test_returns_the_items(self):
        be = _backend(token64="dG9rZW4=")
        be.auth_get_tuple = lambda *a, **kw: (200, {"items": FACTORS})
        self.assertEqual(be._get_factors(), FACTORS)

    def test_missing_items_is_an_empty_list(self):
        be = _backend(token64="dG9rZW4=")
        be.auth_get_tuple = lambda *a, **kw: (200, {})
        self.assertEqual(be._get_factors(), [])

    def test_failure_is_reported(self):
        arlo = tests.arlo.PyArlo()
        be = _backend(arlo=arlo, token64="dG9rZW4=")
        be.auth_get_tuple = lambda *a, **kw: (500, None)
        self.assertIsNone(be._get_factors())
        self.assertIsNotNone(arlo.last_error)

    def test_meta_error_on_a_200_is_a_failure(self):
        # The auth API reports failure inside the body on an http 200, and the
        # message comes back where the data would be. Returning that string as
        # if it were a factor list would blow up further down.
        arlo = tests.arlo.PyArlo()
        be = _backend(arlo=arlo, token64="dG9rZW4=")
        be.auth_get_tuple = lambda *a, **kw: (401, "token is not valid")
        self.assertIsNone(be._get_factors())
        self.assertIsNotNone(arlo.last_error)

    def test_builds_auth_headers_when_none_given(self):
        be = _backend(token64="dG9rZW4=", user_agent="agent", user_device_id="dev")
        seen = {}

        def _auth_get_tuple(path, params, headers, *a, **kw):
            seen["path"] = path
            seen["headers"] = headers
            return 200, {"items": []}

        be.auth_get_tuple = _auth_get_tuple
        be._get_factors()
        self.assertIn("getFactors", seen["path"])
        self.assertEqual(seen["headers"]["Authorization"], "dG9rZW4=")

    def test_uses_supplied_headers_mid_login(self):
        # During a login we pass the part authenticated headers straight in.
        be = _backend()
        seen = {}

        def _auth_get_tuple(path, params, headers, *a, **kw):
            seen["headers"] = headers
            return 200, {"items": []}

        be.auth_get_tuple = _auth_get_tuple
        be._get_factors({"Authorization": "part-auth"})
        self.assertEqual(seen["headers"], {"Authorization": "part-auth"})


class TestValidate(TestCase):
    """The auth API reports a bad token on an http 200, inside the body."""

    def test_accepts_a_good_token(self):
        be = _backend(token64="dG9rZW4=")
        be.auth_get_tuple = lambda *a, **kw: (200, {"userId": "u1"})
        self.assertTrue(be._validate())

    def test_rejects_a_meta_error_on_a_200(self):
        arlo = tests.arlo.PyArlo()
        be = _backend(arlo=arlo, token64="dG9rZW4=")
        be.auth_get_tuple = lambda *a, **kw: (401, "token is not valid")
        self.assertFalse(be._validate())
        self.assertIn("401", arlo.last_error)

    def test_rejects_a_transport_failure(self):
        be = _backend(token64="dG9rZW4=")
        be.auth_get_tuple = lambda *a, **kw: (500, None)
        self.assertFalse(be._validate())


class TestCookiePersistence(TestCase):
    """Saving and loading must agree about discardable cookies."""

    def test_session_cookie_survives_a_round_trip(self):
        import os
        import tempfile
        from http.cookiejar import Cookie

        storage = tempfile.mkdtemp(prefix="pyaarlo-test-")
        self.addCleanup(shutil.rmtree, storage, ignore_errors=True)
        arlo = tests.arlo.PyArlo(storage_dir=storage)

        be = _backend(arlo=arlo)
        be._load_cookies()
        # Arlo's browser trust cookie has no expiry, which makes it a session
        # cookie and means it is skipped unless both ends say ignore_discard.
        be._cookies.set_cookie(Cookie(
            version=0, name="arlo_trusted", value="yes", port=None,
            port_specified=False, domain="ocapi-app.arlo.com",
            domain_specified=False, domain_initial_dot=False, path="/",
            path_specified=True, secure=True, expires=None, discard=True,
            comment=None, comment_url=None, rest={}, rfc2109=False,
        ))
        be._save_cookies()
        self.assertTrue(os.path.exists(arlo.cfg.cookies_file))

        reloaded = _backend(arlo=arlo)
        reloaded._load_cookies()
        self.assertEqual([c.name for c in reloaded._cookies], ["arlo_trusted"])

    def test_missing_cookie_file_is_not_an_error(self):
        import tempfile
        storage = tempfile.mkdtemp(prefix="pyaarlo-test-")
        self.addCleanup(shutil.rmtree, storage, ignore_errors=True)
        arlo = tests.arlo.PyArlo(storage_dir=storage)

        be = _backend(arlo=arlo)
        be._load_cookies()
        self.assertEqual(list(be._cookies), [])
        self.assertIsNone(arlo.last_warning)


class TestSelectFactor(TestCase):
    """Choosing which 2FA factor Arlo should send the code to."""

    def _select(self, factors=None, **kwargs):
        arlo = tests.arlo.PyArlo(**kwargs)
        be = _backend(arlo=arlo)
        return be._select_factor(FACTORS if factors is None else factors), arlo

    def test_factor_id_wins(self):
        factor, _ = self._select(tfa_factor_id="f-push-pix")
        self.assertEqual(factor["factorId"], "f-push-pix")

    def test_factor_id_beats_type(self):
        # tfa_type says sms, but the explicit id is what the user asked for.
        factor, _ = self._select(tfa_type="SMS", tfa_factor_id="f-mail-home")
        self.assertEqual(factor["factorId"], "f-mail-home")

    def test_unknown_factor_id_lists_what_is_available(self):
        factor, arlo = self._select(tfa_factor_id="f-nope")
        self.assertIsNone(factor)
        self.assertIn("f-nope", arlo.last_error)
        self.assertIn("f-push-pix", arlo.last_error)

    def test_type_and_nickname_match(self):
        factor, _ = self._select(tfa_type="EMAIL", tfa_nickname="work@example.com")
        self.assertEqual(factor["factorId"], "f-mail-work")

    def test_push_type(self):
        factor, _ = self._select(tfa_type="PUSH", tfa_nickname="Pixel 9")
        self.assertEqual(factor["factorId"], "f-push-pix")

    def test_nickname_miss_falls_back_and_warns(self):
        factor, arlo = self._select(tfa_type="EMAIL", tfa_nickname="nobody@example.com")
        self.assertEqual(factor["factorId"], "f-mail-home")
        self.assertIn("tfa_factor_id", arlo.last_warning)

    def test_nickname_miss_with_one_candidate_is_quiet(self):
        # No real choice was made, so there is nothing to warn about.
        factor, arlo = self._select(tfa_type="PUSH", tfa_nickname="nobody")
        self.assertEqual(factor["factorId"], "f-push-pix")
        self.assertIsNone(arlo.last_warning)

    def test_missing_type_lists_what_is_available(self):
        factor, arlo = self._select(tfa_type="SMS")
        self.assertIsNone(factor)
        self.assertIn("f-mail-home", arlo.last_error)


class TestRequestPlumbing(TestCase):
    """`get`/`put`/`post` used to hand `cookies` to the wrong parameter."""

    def _be(self):
        be = _backend()
        seen = {}

        def _request(path, method="GET", params=None, headers=None, stream=False,
                     raw=False, timeout=None, host=None, authpost=False, cookies=None):
            seen.update(locals())
            return "body"

        be._request = _request
        return be, seen

    def test_get_passes_cookies_as_cookies(self):
        be, seen = self._be()
        jar = object()
        self.assertEqual(be.get("/path", cookies=jar), "body")
        self.assertIs(seen["cookies"], jar)
        self.assertFalse(seen["authpost"])

    def test_put_passes_cookies_as_cookies(self):
        be, seen = self._be()
        jar = object()
        self.assertEqual(be.put("/path", cookies=jar), "body")
        self.assertIs(seen["cookies"], jar)
        self.assertIsNone(seen["host"])

    def test_get_keeps_host(self):
        be, seen = self._be()
        be.get("/path", host="https://example.com")
        self.assertEqual(seen["host"], "https://example.com")
        self.assertFalse(seen["authpost"])

    def test_backgrounded_get_uses_keywords(self):
        # bg.run only accepts keywords, positionals used to raise TypeError.
        be, seen = self._be()
        be.get("/path", wait_for="nothing", cookies="jar")
        self.assertEqual(seen["method"], "GET")
        self.assertEqual(seen["cookies"], "jar")

    def test_backgrounded_put_uses_keywords(self):
        be, seen = self._be()
        be.put("/path", wait_for="nothing", cookies="jar")
        self.assertEqual(seen["method"], "PUT")
        self.assertEqual(seen["cookies"], "jar")

    def test_backgrounded_post_uses_keywords(self):
        be, seen = self._be()
        be.post("/path", wait_for="nothing")
        self.assertEqual(seen["method"], "POST")
