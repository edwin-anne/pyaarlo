import os
import pickle
import tempfile
import threading
from http.cookiejar import LWPCookieJar
from unittest import TestCase

import tests.arlo
from pyaarlo.backend import ArloBackEnd, AuthResult
from pyaarlo.errors import ArloResponse, ErrorAction
from pyaarlo.sseclient import SSEStatusError


class FakeMqttClient:
    def __init__(self):
        self.disconnected = False
        self.subscribed = []

    def disconnect(self):
        self.disconnected = True

    def subscribe(self, topics):
        self.subscribed.append(topics)


class FakeMqttMessage:
    def __init__(self, payload, topic="u/x/in/userSession/disconnect"):
        self.topic = topic
        self.payload = payload.encode("utf-8")


class BackendFixture(TestCase):
    """A backend with a real storage dir but no network and no __init__."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        storage = self._tmp.name

        self.be = object.__new__(ArloBackEnd)
        self.be._arlo = tests.arlo.PyArlo(
            storage_dir=storage, username="user@example.com", password="secret"
        )
        self.be._lock = threading.Condition()
        self.be._req_lock = threading.Lock()
        self.be._session = None
        self.be._last_auth_action = None
        self.be._validate_action = ErrorAction.OK
        self.be._needs_pairing = False
        self.be._stop_thread = False
        self.be._event_client = None

        # A saved session that has not expired by the clock.
        self.be._user_id = "USER-1"
        self.be._web_id = "USER-1_web"
        self.be._sub_id = "subscriptions/USER-1_web"
        self.be._token = "a-token"
        self.be._token64 = "YS10b2tlbg=="
        self.be._expires_in = 2 ** 31
        self.be._browser_auth_code = "browser-code"
        self.be._user_device_id = "device-1"

        ArloBackEnd._session_info = {"version": "2"}

        self.cookies_file = self.be._arlo.cfg.cookies_file
        self.session_file = self.be._arlo.cfg.session_file
        self.be._cookies = LWPCookieJar(self.cookies_file)
        self.be._cookies.save(ignore_discard=True)

    def saved_session(self):
        with open(self.session_file, "rb") as handle:
            return pickle.load(handle)[self.be._arlo.cfg.username]


class TestDiscardSavedSession(BackendFixture):
    def test_token_is_cleared_and_persisted(self):
        self.be._discard_saved_session("test")
        self.assertIsNone(self.be._token)
        self.assertIsNone(self.be._token64)
        self.assertEqual(self.be._expires_in, 0)
        self.assertIsNone(self.be._browser_auth_code)
        # ...and on disk too, otherwise the next run reloads the dead token.
        self.assertIsNone(self.saved_session()["token"])

    def test_has_saved_session_is_false_afterwards(self):
        self.assertTrue(self.be._has_saved_session())
        self.be._discard_saved_session("test")
        self.assertFalse(self.be._has_saved_session())

    def test_cookies_are_removed(self):
        self.assertTrue(os.path.exists(self.cookies_file))
        self.be._discard_saved_session("test")
        self.assertFalse(os.path.exists(self.cookies_file))
        self.assertEqual(len(self.be._cookies), 0)

    def test_device_id_is_kept(self):
        # The device id is how Arlo recognises this client; a new one would have
        # to earn trust from scratch.
        self.be._discard_saved_session("test")
        self.assertEqual(self.be._user_device_id, "device-1")

    def test_missing_cookie_file_is_not_an_error(self):
        os.remove(self.cookies_file)
        self.be._discard_saved_session("test")


class TestReuseSavedSession(BackendFixture):
    def _validate_returns(self, action):
        def _validate(quiet=False):
            self.be._validate_action = action
            return action is ErrorAction.OK

        self.be._validate = _validate

    def test_accepted_when_the_server_agrees(self):
        self._validate_returns(ErrorAction.OK)
        self.assertTrue(self.be._reuse_saved_session())
        self.assertFalse(self.be._needs_pairing)
        self.assertEqual(self.be._token, "a-token")

    def test_regression_rejected_session_is_discarded(self):
        # The field failure: validation came back 9276 and the session was kept
        # and accepted anyway, so every later attempt replayed the same dead
        # path and a full login never happened.
        self._validate_returns(ErrorAction.AUTH_PENDING)
        self.assertFalse(self.be._reuse_saved_session())
        self.assertIsNone(self.be._token)
        self.assertFalse(os.path.exists(self.cookies_file))

    def test_auth_pending_asks_for_pairing_again(self):
        self._validate_returns(ErrorAction.AUTH_PENDING)
        self.be._reuse_saved_session()
        self.assertTrue(self.be._needs_pairing)

    def test_session_expired_is_discarded(self):
        self._validate_returns(ErrorAction.REAUTH)
        self.assertFalse(self.be._reuse_saved_session())
        self.assertIsNone(self.be._token)

    def test_transport_failure_keeps_the_session(self):
        # A timeout says nothing about the token. Throwing it away would force a
        # pointless full 2FA login every time the network hiccups.
        self._validate_returns(ErrorAction.RETRY)
        self.assertFalse(self.be._reuse_saved_session())
        self.assertEqual(self.be._token, "a-token")
        self.assertTrue(os.path.exists(self.cookies_file))

    def test_clock_expiry_is_checked_before_asking(self):
        self.be._expires_in = 1
        called = []
        self.be._validate = lambda quiet=False: called.append(True)
        self.assertFalse(self.be._reuse_saved_session())
        self.assertEqual(called, [])

    def test_invalid_expiry_is_rejected(self):
        self.be._expires_in = "not-a-number"
        self.assertFalse(self.be._reuse_saved_session())

    def test_no_saved_session(self):
        self.be._token = None
        self.assertFalse(self.be._reuse_saved_session())


class TestLoginFailureReason(BackendFixture):
    def test_unclassified_failure_stays_retryable(self):
        # Guessing "permanent" would leave the integration dead until a restart.
        self.assertFalse(self.be._login_failed())
        self.assertEqual(self.be.last_auth_action, ErrorAction.RETRY)
        self.assertFalse(self.be.auth_failed_permanently)

    def test_classified_failure_is_kept(self):
        self.be._last_auth_action = ErrorAction.FATAL
        self.assertFalse(self.be._login_failed())
        self.assertEqual(self.be.last_auth_action, ErrorAction.FATAL)
        self.assertTrue(self.be.auth_failed_permanently)

    def test_explicit_action_wins(self):
        self.be._last_auth_action = ErrorAction.FATAL
        self.be._login_failed(ErrorAction.RETRY)
        self.assertEqual(self.be.last_auth_action, ErrorAction.RETRY)

    def test_rejected_is_permanent(self):
        self.be._last_auth_action = ErrorAction.REJECTED
        self.assertTrue(self.be.auth_failed_permanently)

    def test_auth_pending_is_not_permanent(self):
        self.be._last_auth_action = ErrorAction.AUTH_PENDING
        self.assertFalse(self.be.auth_failed_permanently)


class TestV2Session(BackendFixture):
    def _responses(self, *responses):
        self.calls = []
        queue = list(responses)

        def _request_full(path, **kwargs):
            self.calls.append(path)
            return queue.pop(0)

        self.be._request_full = _request_full

    def test_success(self):
        self._responses(ArloResponse(200, {"supportsMultiLocation": True}))
        self.assertTrue(self.be._v2_session())
        self.assertTrue(self.be._multi_location)

    def test_transient_failure_does_not_reauth(self):
        self._responses(
            ArloResponse(503, None, message="down", action=ErrorAction.RETRY)
        )
        reauthed = []
        self.be._auth_or_reuse_saved_session = lambda: reauthed.append(True)
        self.assertFalse(self.be._v2_session())
        self.assertEqual(reauthed, [])
        self.assertEqual(self.be.last_auth_action, ErrorAction.RETRY)

    def test_rejected_session_is_retried_once_after_reauth(self):
        self._responses(
            ArloResponse(401, None, arlo_error=9002, action=ErrorAction.REAUTH),
            ArloResponse(200, {"supportsMultiLocation": False}),
        )
        self.be._auth_or_reuse_saved_session = lambda: AuthResult.SUCCESS
        self.be._headers = lambda: {}
        self.be._session = type("S", (), {"headers": {}})()
        self.assertTrue(self.be._v2_session())
        self.assertEqual(len(self.calls), 2)
        # The dead token was dropped before trying again.
        self.assertIsNone(self.be._token)

    def test_reauth_is_not_attempted_twice(self):
        rejected = ArloResponse(401, None, arlo_error=9002, action=ErrorAction.REAUTH)
        self._responses(rejected, rejected)
        self.be._auth_or_reuse_saved_session = lambda: AuthResult.SUCCESS
        self.be._headers = lambda: {}
        self.be._session = type("S", (), {"headers": {}})()
        self.assertFalse(self.be._v2_session())
        # Two calls, not an endless recursion.
        self.assertEqual(len(self.calls), 2)

    def test_failed_reauth_reports_the_reason(self):
        self._responses(
            ArloResponse(401, None, arlo_error=9002, action=ErrorAction.REAUTH)
        )
        self.be._auth_or_reuse_saved_session = lambda: AuthResult.FAILED
        self.assertFalse(self.be._v2_session())
        self.assertEqual(self.be.last_auth_action, ErrorAction.REAUTH)


class TestSseStatus(BackendFixture):
    def test_error_carries_the_status(self):
        err = SSEStatusError(401)
        self.assertEqual(err.status_code, 401)
        self.assertIn("401", str(err))

    def test_rejected_stream_discards_the_session(self):
        # A 401 on the stream means the token is dead, so the next iteration
        # must do a full login rather than reusing it.
        self.be._headers = lambda: {}

        def boom(*_args, **_kwargs):
            raise SSEStatusError(401)

        import pyaarlo.backend as backend_module

        original = backend_module.SSEClient
        backend_module.SSEClient = boom
        try:
            self.be._sse_main()
        finally:
            backend_module.SSEClient = original
        self.assertIsNone(self.be._token)

    def test_server_error_keeps_the_session(self):
        def boom(*_args, **_kwargs):
            raise SSEStatusError(502)

        import pyaarlo.backend as backend_module

        original = backend_module.SSEClient
        backend_module.SSEClient = boom
        self.be._headers = lambda: {}
        try:
            self.be._sse_main()
        finally:
            backend_module.SSEClient = original
        self.assertEqual(self.be._token, "a-token")


class TestMqttLogout(BackendFixture):
    def setUp(self):
        super().setUp()
        self.be._event_client = FakeMqttClient()
        self.be._event_client_id = "user_USER-1_123"
        self.be._event_connected = False

    def test_foreign_logout_breaks_the_loop(self):
        # paho would otherwise reconnect using the token the server just
        # revoked, retrying forever with a dead credential.
        self.be._mqtt_on_message(
            None, None, FakeMqttMessage('{"action":"logout","clientId":"someone_else"}')
        )
        self.assertTrue(self.be._event_client.disconnected)
        self.assertIsNone(self.be._token)

    def test_our_own_logout_echo_is_ignored(self):
        self.be._mqtt_on_message(
            None,
            None,
            FakeMqttMessage('{"action":"logout","clientId":"user_USER-1_123"}'),
        )
        self.assertFalse(self.be._event_client.disconnected)
        self.assertEqual(self.be._token, "a-token")

    def test_logout_without_client_id_still_breaks_the_loop(self):
        self.be._mqtt_on_message(None, None, FakeMqttMessage('{"action":"logout"}'))
        self.assertTrue(self.be._event_client.disconnected)

    def test_broken_json_does_not_raise(self):
        self.be._mqtt_on_message(None, None, FakeMqttMessage("not json"))


class TestMqttConnectResult(BackendFixture):
    def setUp(self):
        super().setUp()
        self.be._event_client = FakeMqttClient()
        self.be._event_client_id = "user_USER-1_123"
        self.be._event_connected = False
        self.be._arlo._devices = []

    def test_not_authorised_discards_the_session(self):
        self.be._mqtt_on_connect(None, None, None, 5)
        self.assertTrue(self.be._event_client.disconnected)
        self.assertIsNone(self.be._token)
        self.assertFalse(self.be._event_connected)

    def test_bad_credentials_discards_the_session(self):
        self.be._mqtt_on_connect(None, None, None, 4)
        self.assertIsNone(self.be._token)

    def test_other_failure_stops_without_discarding(self):
        self.be._mqtt_on_connect(None, None, None, 3)
        self.assertTrue(self.be._event_client.disconnected)
        self.assertEqual(self.be._token, "a-token")

    def test_success_subscribes(self):
        self.be._mqtt_subscribe = lambda: None
        self.be._mqtt_on_connect(None, None, None, 0)
        self.assertFalse(self.be._event_client.disconnected)
        self.assertTrue(self.be._event_connected)
