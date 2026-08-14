"""End to end login tests against a fake Arlo server.

These drive the real `ArloBackEnd._login` over real HTTP, so they cover the
parts the unit tests can't: the request plumbing, the session and cookie files,
and whether a second start actually reuses the token the first one saved.
"""

import logging
import shutil
import tempfile
import time
from unittest import TestCase

import tests.arlo
from tests.fake_arlo_server import MINUTE, FakeArloServer
from pyaarlo.backend import ArloBackEnd, LoginStep
from pyaarlo.login import ArloLogin

USERNAME = "test@example.com"
PASSWORD = "test-password"
OTP = "123456"


def setUpModule():
    logging.getLogger("pyaarlo").setLevel(logging.CRITICAL)


class FakeTfa:
    """Stands in for the console/imap handlers, hands back a known code."""

    def __init__(self, code=OTP):
        self.code = code
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        return True

    def get(self):
        return self.code

    def stop(self):
        self.stopped = True


class ExplodingTfa:
    """A 2FA handler that must never be reached, for the push tests."""

    def start(self):
        raise AssertionError("a push login must not start a code source")

    def get(self):
        raise AssertionError("a push login must not ask for a code")

    def stop(self):
        raise AssertionError("a push login must not stop a code source")


class LoginTestCase(TestCase):

    def setUp(self):
        self.storage_dir = tempfile.mkdtemp(prefix="pyaarlo-test-")
        self.addCleanup(shutil.rmtree, self.storage_dir, ignore_errors=True)

        # _session_info lives on the class, so one test could otherwise leak
        # a logged in session into the next.
        ArloBackEnd._session_info = {"version": "2"}
        self.addCleanup(setattr, ArloBackEnd, "_session_info", {})

        self.server = FakeArloServer(USERNAME, PASSWORD, OTP)
        self.server.__enter__()
        self.addCleanup(self.server.__exit__)
        self.state = self.server.state

    def backend(self, tfa=None, real_tfa=False, **kwargs):
        """Build a backend that logs in against the fake server.

        `real_tfa` leaves `_get_tfa` alone, for the tests that care how the
        configured tfa_source itself is handled.
        """
        options = dict(
            username=USERNAME,
            password=PASSWORD,
            storage_dir=self.storage_dir,
            host=self.server.url,
            auth_host=self.server.url,
            # The project default. It makes one attempt, where the cloudscraper
            # path retries once per ecdh curve and muddies the request counts.
            http_backend="curl_cffi",
        )
        options.update(kwargs)
        arlo = tests.arlo.PyArlo(**options)
        be = object.__new__(ArloBackEnd)
        if not real_tfa:
            be._get_tfa = lambda: tfa if tfa is not None else FakeTfa()
        be.__init__(arlo)
        return be

    def login(self, **kwargs):
        """Build an `ArloLogin` against the fake server, same storage dir as `backend()`."""
        options = dict(
            username=USERNAME,
            password=PASSWORD,
            storage_dir=self.storage_dir,
            host=self.server.url,
            auth_host=self.server.url,
            http_backend="curl_cffi",
        )
        options.update(kwargs)
        return ArloLogin(**options)


class TestColdLogin(LoginTestCase):
    """First ever login: password, 2FA code, then pair the browser."""

    def test_logs_in_with_2fa(self):
        tfa = FakeTfa()
        be = self.backend(tfa=tfa)

        self.assertTrue(be.is_connected)
        self.assertTrue(tfa.started, "the 2fa handler should have been started")
        self.assertTrue(tfa.stopped, "the 2fa handler should have been stopped")
        self.assertEqual(be.user_id, "u1")

        self.assertEqual(self.state.called("/api/auth"), 1)
        self.assertEqual(self.state.called("/api/finishAuth"), 1)
        self.assertEqual(self.state.called("/api/startPairingFactor"), 1)
        self.assertEqual(self.state.called("/hmsweb/users/session/v3"), 1)

    def test_wrong_password_fails_cleanly(self):
        be = self.backend(password="not-the-password")
        self.assertFalse(be.is_connected)
        self.assertEqual(self.state.called("/api/finishAuth"), 0)

    def test_wrong_2fa_code_fails(self):
        be = self.backend(tfa=FakeTfa(code="000000"))
        self.assertFalse(be.is_connected)
        self.assertEqual(self.state.called("/api/finishAuth"), 1)
        self.assertEqual(self.state.called("/api/startPairingFactor"), 0)

    def test_no_mfa_on_the_account_skips_2fa(self):
        self.state.mfa_enabled = False
        tfa = FakeTfa()
        be = self.backend(tfa=tfa)
        self.assertTrue(be.is_connected)
        self.assertFalse(tfa.started)
        self.assertEqual(self.state.called("/api/getFactors"), 0)


class TestSessionResume(LoginTestCase):
    """The point of the exercise: a second start must not resend the password."""

    def _first_login(self):
        be = self.backend()
        self.assertTrue(be.is_connected, "first login should have worked")
        be.stop()
        return be

    def test_second_login_resumes_the_saved_token(self):
        self._first_login()
        before = len(self.state.calls)

        be = self.backend(tfa=FakeTfa(code="wrong-on-purpose"))

        self.assertTrue(be.is_connected)
        self.assertEqual(self.state.called("/api/auth"), 1,
                         "the password should not have been sent a second time")
        self.assertEqual(self.state.called("/api/finishAuth"), 1,
                         "2fa should not have run a second time")
        # It did do something: validate the token, then start a session.
        self.assertGreater(len(self.state.calls), before)
        self.assertEqual(self.state.called("/api/validateAccessToken"), 2)

    def test_expired_token_falls_back_to_a_full_login(self):
        # Hand out a token that is already inside the safety margin, so the
        # session it saves is not worth resuming.
        self.state.token_lifetime = MINUTE
        self._first_login()

        be = self.backend(tfa=FakeTfa(code="unused"))

        self.assertTrue(be.is_connected)
        self.assertEqual(self.state.called("/api/auth"), 2)
        # The browser is paired now, so it takes the trusted path and never
        # needs the code.
        self.assertEqual(self.state.called("/api/getFactorId"), 2)
        self.assertEqual(self.state.called("/api/finishAuth"), 1)

    def test_rejected_token_falls_back_to_a_full_login(self):
        self._first_login()
        self.state.reject_token = True

        be = self.backend(tfa=FakeTfa(code="unused"))

        # The server refuses every token now, so the login cannot complete,
        # but it must have tried the password rather than giving up on the
        # first rejection.
        self.assertFalse(be.is_connected)
        self.assertGreaterEqual(self.state.called("/api/auth"), 2)

    def test_reuse_can_be_turned_off(self):
        self._first_login()
        be = self.backend(tfa=FakeTfa(code="unused"), reuse_session=False)
        self.assertTrue(be.is_connected)
        self.assertEqual(self.state.called("/api/auth"), 2,
                         "reuse_session=False should force a fresh login")

    def test_trusted_browser_login_needs_no_code(self):
        """With reuse off, the paired browser cookie still avoids the 2FA code."""
        self._first_login()
        tfa = FakeTfa(code="unused")
        be = self.backend(tfa=tfa, reuse_session=False)

        self.assertTrue(be.is_connected)
        self.assertFalse(tfa.started, "the trusted browser path skips the handler")
        self.assertEqual(self.state.called("/api/getFactorId"), 2)
        self.assertEqual(self.state.called("/api/finishAuth"), 1)


class TestFactorSelectionOverHttp(LoginTestCase):
    """`tfa_factor_id` and `tfa_type` against a live factor list."""

    def test_lists_the_factors(self):
        be = self.backend()
        factors = be.tfa_factors()
        self.assertEqual([f["factorId"] for f in factors],
                         ["f-mail-home", "f-push-pix"])

    def test_unknown_factor_id_stops_the_login(self):
        be = self.backend(tfa_factor_id="f-does-not-exist")
        self.assertFalse(be.is_connected)
        self.assertIn("f-does-not-exist", be._arlo.last_error)
        self.assertEqual(self.state.called("/api/startAuth"), 0)

    def test_known_factor_id_is_used(self):
        be = self.backend(tfa_factor_id="f-push-pix")
        self.assertTrue(be.is_connected)
        self.assertEqual(self.state.called("/api/startAuth"), 1)

    def test_missing_factor_type_stops_the_login(self):
        be = self.backend(tfa_type="SMS")
        self.assertFalse(be.is_connected)
        self.assertIn("sms", be._arlo.last_error)
        self.assertEqual(self.state.called("/api/startAuth"), 0)


class TestPushApproval(LoginTestCase):
    """Approving the login from the Arlo phone app instead of typing a code."""

    def _push(self, **kwargs):
        options = dict(
            tfa_source="push",
            tfa_type="PUSH",
            tfa_push_poll=0.05,
            tfa_push_timeout=2,
        )
        options.update(kwargs)
        # The handler must never be touched on a push login, so hand over one
        # that fails loudly if it is.
        return self.backend(tfa=ExplodingTfa(), **options)

    def test_approved_push_logs_in_without_a_code(self):
        be = self._push()
        self.assertTrue(be.is_connected)
        self.assertEqual(self.state.called("/api/startAuth"), 1)
        self.assertEqual(self.state.push_polls, 1)

    def test_waits_for_a_slow_user(self):
        # Three "not yet" answers before they get to their phone.
        self.state.push_polls_before_approval = 3
        be = self._push()
        self.assertTrue(be.is_connected)
        self.assertEqual(self.state.push_polls, 4)

    def test_denied_push_fails_immediately(self):
        self.state.push_denied = True
        started = time.monotonic()
        be = self._push(tfa_push_timeout=30)
        took = time.monotonic() - started

        self.assertFalse(be.is_connected)
        self.assertIn("denied", be._arlo.last_error)
        # The point: it does not sit there polling for the full 30s.
        self.assertLess(took, 5)
        self.assertEqual(self.state.push_polls, 1)

    def test_gives_up_after_the_timeout(self):
        self.state.push_polls_before_approval = 10_000  # never approved
        started = time.monotonic()
        be = self._push(tfa_push_timeout=1, tfa_push_poll=0.2)
        took = time.monotonic() - started

        self.assertFalse(be.is_connected)
        self.assertIn("nobody answered", be._arlo.last_error)
        self.assertGreaterEqual(took, 1)
        self.assertLess(took, 10)

    def test_push_factor_uses_push_even_with_another_tfa_source(self):
        # Picking a PUSH factor by id while tfa_source is still console must
        # not sit waiting for a code that is never coming.
        be = self.backend(
            tfa=ExplodingTfa(),
            tfa_factor_id="f-push-pix",
            tfa_source="console",
            tfa_push_poll=0.05,
            tfa_push_timeout=2,
        )
        self.assertTrue(be.is_connected)

    def test_push_source_with_a_code_factor_is_rejected(self):
        # tfa_source=push only makes sense against a PUSH factor.
        be = self.backend(real_tfa=True, tfa_source="push", tfa_type="EMAIL")
        self.assertFalse(be.is_connected)
        self.assertIn("push", be._arlo.last_error)
        self.assertEqual(self.state.called("/api/startAuth"), 0)

    def test_legacy_tfa_retries_still_bounds_the_wait(self):
        self.state.push_polls_before_approval = 10_000
        be = self.backend(
            tfa=ExplodingTfa(), tfa_source="push", tfa_type="PUSH",
            tfa_retries=3, tfa_push_poll=0.1,
        )
        self.assertFalse(be.is_connected)
        self.assertIn("nobody answered", be._arlo.last_error)


class TestUntrustedBrowserIsQuiet(LoginTestCase):
    """A first login is not a problem and should not read like one.

    getFactorId always fails before the browser has been paired. Warning about
    it means every cold login logs something alarming that the user can do
    nothing about.
    """

    def test_classic_backend_error_is_not_warned_about(self):
        self.state.untrusted_error = 9204
        be = self.backend()
        self.assertTrue(be.is_connected)
        self.assertIsNone(be._arlo.last_warning)

    def test_pingone_backend_error_is_not_warned_about(self):
        self.state.untrusted_error = 9261  # "Invalid factor data"
        be = self.backend()
        self.assertTrue(be.is_connected)
        self.assertIsNone(be._arlo.last_warning)

    def test_a_genuine_error_is_still_warned_about(self):
        self.state.untrusted_error = 9999
        be = self.backend()
        self.assertTrue(be.is_connected)
        self.assertIsNotNone(be._arlo.last_warning)


class TestSessionFiles(LoginTestCase):
    """What gets persisted between runs."""

    def test_session_and_cookies_are_written(self):
        import os
        be = self.backend()
        self.assertTrue(be.is_connected)
        self.assertTrue(os.path.exists(be._arlo.cfg.session_file))
        self.assertTrue(os.path.exists(be._arlo.cfg.cookies_file))

    def test_device_id_is_stable_across_logins(self):
        first = self.backend()
        device_id = first._user_device_id
        first.stop()

        second = self.backend()
        self.assertEqual(second._user_device_id, device_id,
                         "a new device id would break the browser pairing")

    def test_save_session_off_means_no_resume(self):
        first = self.backend(save_session=False)
        self.assertTrue(first.is_connected)
        first.stop()

        second = self.backend(save_session=False, tfa=FakeTfa())
        self.assertTrue(second.is_connected)
        self.assertEqual(self.state.called("/api/auth"), 2)


class TestInteractiveLogin(LoginTestCase):
    """`ArloLogin`: list the real factors and drive the login step by step,
    for a caller (e.g. a setup UI) that wants the user to pick one.
    """

    def test_creates_a_missing_storage_dir(self):
        """Unlike `backend()`/`PyArlo`, nothing has created `storage_dir` for
        us yet here - a setup flow's first-ever run looks exactly like this.
        """
        import os
        import shutil

        fresh_dir = self.storage_dir + "/not-created-yet"
        self.addCleanup(shutil.rmtree, fresh_dir, ignore_errors=True)
        self.assertFalse(os.path.exists(fresh_dir))

        login = self.login(storage_dir=fresh_dir)
        login.start()
        login.choose_factor("f-mail-home")
        self.assertEqual(login.submit_code(OTP), LoginStep.SUCCESS)
        self.assertTrue(os.path.exists(os.path.join(fresh_dir, "cookies.txt")))

    def test_start_lists_the_factors(self):
        login = self.login()
        self.assertEqual(login.start(), LoginStep.NEEDS_FACTOR)
        self.assertEqual([f["factorId"] for f in login.factors],
                         ["f-mail-home", "f-push-pix"])

    def test_start_succeeds_when_mfa_disabled(self):
        self.state.mfa_enabled = False
        login = self.login()
        self.assertEqual(login.start(), LoginStep.SUCCESS)

    def test_start_resumes_a_saved_session(self):
        be = self.backend()
        self.assertTrue(be.is_connected)
        be.stop()

        login = self.login()
        self.assertEqual(login.start(), LoginStep.SUCCESS)
        self.assertEqual(self.state.called("/api/auth"), 1,
                         "a resumed session must not resend the password")

    def test_start_succeeds_on_trusted_browser_without_resume(self):
        # A short lifetime means the saved session is outside the reuse
        # window, so this exercises the paired-browser fast path instead.
        self.state.token_lifetime = MINUTE
        be = self.backend()
        self.assertTrue(be.is_connected)
        be.stop()

        login = self.login()
        self.assertEqual(login.start(), LoginStep.SUCCESS)
        self.assertEqual(self.state.called("/api/getFactorId"), 2)

    def test_unknown_factor_id_fails(self):
        login = self.login()
        login.start()
        self.assertEqual(login.choose_factor("does-not-exist"), LoginStep.FAILED)
        self.assertIn("does-not-exist", login.last_error)

    def test_email_factor_needs_the_right_code(self):
        login = self.login()
        login.start()
        self.assertEqual(login.choose_factor("f-mail-home"), LoginStep.AWAITING_CODE)

        self.assertEqual(login.submit_code("000000"), LoginStep.FAILED)
        self.assertEqual(login.submit_code(OTP), LoginStep.SUCCESS)

    def test_push_factor_waits_then_succeeds(self):
        self.state.push_polls_before_approval = 2
        login = self.login(tfa_push_timeout=5)
        login.start()
        self.assertEqual(login.choose_factor("f-push-pix"), LoginStep.AWAITING_PUSH)

        step = login.poll_push()
        while step == LoginStep.AWAITING_PUSH:
            step = login.poll_push()
        self.assertEqual(step, LoginStep.SUCCESS)
        self.assertEqual(self.state.push_polls, 3)

    def test_push_factor_denied(self):
        self.state.push_denied = True
        login = self.login(tfa_push_timeout=5)
        login.start()
        login.choose_factor("f-push-pix")

        self.assertEqual(login.poll_push(), LoginStep.FAILED)
        self.assertIn("denied", login.last_error)

    def test_push_factor_times_out(self):
        self.state.push_polls_before_approval = 10_000  # never approved
        login = self.login(tfa_push_timeout=0.05)
        login.start()
        login.choose_factor("f-push-pix")

        time.sleep(0.1)
        self.assertEqual(login.poll_push(), LoginStep.FAILED)
        self.assertIn("nobody answered", login.last_error)

    def test_interactive_success_can_be_resumed_normally(self):
        """The point of the exercise: a normal `PyArlo`/`ArloBackEnd` login
        afterward reuses the session this flow saved, instead of asking for
        the password or a 2FA code again.
        """
        login = self.login()
        login.start()
        login.choose_factor("f-mail-home")
        self.assertEqual(login.submit_code(OTP), LoginStep.SUCCESS)

        be = self.backend(tfa=FakeTfa(code="wrong-on-purpose"))
        self.assertTrue(be.is_connected)
        self.assertEqual(self.state.called("/api/auth"), 1,
                         "the interactive login's session should be reused, not repeated")
