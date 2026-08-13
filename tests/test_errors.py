import threading
from unittest import TestCase

import tests.arlo
from pyaarlo.backend import ArloBackEnd
from pyaarlo.errors import (
    ArloApiError,
    ArloResponse,
    ErrorAction,
    classify,
    describe,
    message_for,
)


class FakeResponse:
    """Minimal stand-in for a requests/curl_cffi response."""

    def __init__(self, status_code=200, json_body=None, text=None, content_type=None):
        self.status_code = status_code
        self._json = json_body
        self.text = text if text is not None else ""
        if content_type is None:
            content_type = "application/json" if json_body is not None else "text/html"
        self.headers = {"Content-Type": content_type}

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class FakeSession:
    def __init__(self, response=None, raises=None):
        self._response = response
        self._raises = raises
        self.calls = []

    def _handle(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self._raises is not None:
            raise self._raises
        return self._response

    def get(self, url, **kwargs):
        return self._handle("GET", url, **kwargs)

    def put(self, url, **kwargs):
        return self._handle("PUT", url, **kwargs)

    def post(self, url, **kwargs):
        return self._handle("POST", url, **kwargs)

    def options(self, url, **kwargs):
        return self._handle("OPTIONS", url, **kwargs)


def make_backend(session):
    """Build a backend without running __init__, which would try to log in."""
    be = object.__new__(ArloBackEnd)
    be._arlo = tests.arlo.PyArlo()
    be._lock = threading.Condition()
    be._req_lock = threading.Lock()
    be._session = session
    be._logged_in = False
    be._event_client = None
    be._use_mqtt = False
    return be


class TestClassify(TestCase):
    def test_session_expired_needs_reauth(self):
        for code in (9002, 9022, 9025, 9328):
            self.assertEqual(classify(400, code), ErrorAction.REAUTH, f"code {code}")

    def test_auth_pending_is_not_a_failure(self):
        # 9233 is returned repeatedly while a PUSH factor is unanswered, so
        # treating it as a hard error would break the push login flow.
        for code in (9233, 9276, 9278, 9306, 9307):
            self.assertEqual(
                classify(400, code), ErrorAction.AUTH_PENDING, f"code {code}"
            )

    def test_credential_errors_are_fatal(self):
        for code in (9001, 9004, 9015, 9016, 9019, 9058, 9340):
            self.assertEqual(classify(400, code), ErrorAction.FATAL, f"code {code}")

    def test_account_lockout_is_retryable_not_fatal(self):
        # 9017 unlocks itself after 5 minutes, unlike the codes above where the
        # credentials themselves have to change. FATAL would send the user to a
        # "Reconfigure" card for nothing.
        self.assertEqual(classify(400, 9017), ErrorAction.RETRY)

    def test_otp_errors_ask_for_a_new_code(self):
        for code in (9234, 9236, 9237, 9238, 9243, 9301):
            self.assertEqual(classify(400, code), ErrorAction.OTP_RETRY, f"code {code}")

    def test_rejected(self):
        self.assertEqual(classify(400, 9239), ErrorAction.REJECTED)

    def test_device_offline_is_not_an_auth_problem(self):
        for code in (2059, 2222):
            self.assertEqual(
                classify(500, code), ErrorAction.DEVICE_OFFLINE, f"code {code}"
            )

    def test_untrusted_browser_needs_a_full_login(self):
        self.assertEqual(classify(401, 9204), ErrorAction.REAUTH)

    def test_transient_codes_retry(self):
        for code in (0, 9000, 9029, 9241, 9316, 9334):
            self.assertEqual(classify(400, code), ErrorAction.RETRY, f"code {code}")

    def test_unknown_arlo_code_retries_rather_than_giving_up(self):
        # A wrong FATAL would leave the integration dead until a restart, so an
        # unrecognised code must stay retryable.
        self.assertEqual(classify(400, 99999), ErrorAction.RETRY)

    def test_http_only(self):
        self.assertEqual(classify(200), ErrorAction.OK)
        self.assertEqual(classify(401), ErrorAction.REAUTH)
        self.assertEqual(classify(403), ErrorAction.REAUTH)
        self.assertEqual(classify(429), ErrorAction.RETRY)
        self.assertEqual(classify(500), ErrorAction.RETRY)
        self.assertEqual(classify(502), ErrorAction.RETRY)

    def test_arlo_code_wins_over_http_code(self):
        # meta.code is a flat 400 for wildly different causes, so the specific
        # Arlo code has to take precedence.
        self.assertEqual(classify(400, 9002), ErrorAction.REAUTH)
        self.assertEqual(classify(200, 9015), ErrorAction.FATAL)

    def test_describe_keeps_every_field(self):
        text = describe(400, 9276)
        self.assertIn("code=400", text)
        self.assertIn("error=9276", text)
        self.assertIn("action=AUTH_PENDING", text)

    def test_message_for(self):
        self.assertIn("locked", message_for(9017))
        self.assertIsNone(message_for(123456))
        self.assertEqual(message_for(123456, "fallback"), "fallback")


class TestArloApiError(TestCase):
    def test_carries_the_action(self):
        err = ArloApiError(400, 9015)
        self.assertEqual(err.action, ErrorAction.FATAL)
        self.assertTrue(err.is_permanent)
        self.assertIn("error=9015", str(err))

    def test_transient_is_not_permanent(self):
        self.assertFalse(ArloApiError(500).is_permanent)


class TestArloAuthError(TestCase):
    """The config flow branches on this, so it has to carry the reason."""

    def test_wrong_password_is_a_credentials_problem(self):
        from pyaarlo.backend import ArloAuthError

        err = ArloAuthError(
            "login failed",
            response=ArloResponse(400, None, arlo_error=9015, action=ErrorAction.FATAL),
        )
        self.assertEqual(err.action, ErrorAction.FATAL)
        self.assertEqual(err.arlo_error, 9015)
        self.assertTrue(err.is_credentials_problem)

    def test_bad_otp_is_a_credentials_problem(self):
        from pyaarlo.backend import ArloAuthError

        err = ArloAuthError(
            "bad code",
            response=ArloResponse(400, None, arlo_error=9236, action=ErrorAction.OTP_RETRY),
        )
        self.assertTrue(err.is_credentials_problem)

    def test_network_failure_is_not(self):
        # Reporting this as bad credentials would send someone looking at their
        # password when the problem is their network.
        from pyaarlo.backend import ArloAuthError

        err = ArloAuthError("request failed: ConnectionError", action=ErrorAction.RETRY)
        self.assertFalse(err.is_credentials_problem)

    def test_defaults_to_retryable(self):
        from pyaarlo.backend import ArloAuthError

        self.assertEqual(ArloAuthError("boom").action, ErrorAction.RETRY)


class TestParseAuthHelperResponse(TestCase):
    """The config-flow helpers share the main envelope parser."""

    def _parse(self, response):
        from pyaarlo.backend import _parse_auth_helper_response

        return _parse_auth_helper_response(response)

    def test_success(self):
        result = self._parse(FakeResponse(200, {"meta": {"code": 200}, "data": {"a": 1}}))
        self.assertTrue(result.ok)
        self.assertEqual(result.body, {"a": 1})

    def test_wrong_password_is_classified(self):
        result = self._parse(
            FakeResponse(
                200,
                {"meta": {"code": 400, "error": 9015, "message": "Password not correct"}},
            )
        )
        self.assertEqual(result.arlo_error, 9015)
        self.assertEqual(result.action, ErrorAction.FATAL)

    def test_arlo_code_survives_a_non_200(self):
        # The helper used to discard the body on any non-200, so meta.error was
        # unreachable exactly when it mattered most.
        result = self._parse(
            FakeResponse(401, {"meta": {"code": 401, "error": 9017, "message": "locked"}})
        )
        self.assertEqual(result.arlo_error, 9017)
        self.assertEqual(result.action, ErrorAction.RETRY)

    def test_malformed_envelope_does_not_raise(self):
        result = self._parse(FakeResponse(200, {"meta": {"code": 400}}))
        self.assertFalse(result.ok)
        self.assertIsNone(result.arlo_error)

    def test_html_error_page(self):
        result = self._parse(
            FakeResponse(503, None, text="<html>meta</html>", content_type="text/html")
        )
        self.assertEqual(result.code, 503)
        self.assertEqual(result.action, ErrorAction.RETRY)


class TestParseEnvelope(TestCase):
    def test_meta_success(self):
        has, code, error, message, data = ArloBackEnd._parse_envelope(
            {"meta": {"code": 200}, "data": {"a": 1}}
        )
        self.assertTrue(has)
        self.assertEqual(code, 200)
        self.assertIsNone(error)
        self.assertEqual(data, {"a": 1})

    def test_meta_failure(self):
        has, code, error, message, data = ArloBackEnd._parse_envelope(
            {
                "meta": {
                    "code": 400,
                    "error": 9276,
                    "message": "Current authentication is not completed",
                }
            }
        )
        self.assertTrue(has)
        self.assertEqual(code, 400)
        self.assertEqual(error, 9276)
        self.assertEqual(message, "Current authentication is not completed")
        self.assertIsNone(data)

    def test_meta_without_error_or_message_does_not_raise(self):
        # These keys used to be indexed unguarded, so a KeyError escaped the
        # whole request path.
        has, code, error, message, _ = ArloBackEnd._parse_envelope(
            {"meta": {"code": 400}}
        )
        self.assertTrue(has)
        self.assertEqual(code, 400)
        self.assertIsNone(error)
        self.assertIsNone(message)

    def test_string_body_mentioning_meta_does_not_raise(self):
        # `"meta" in body` also matched strings, giving a TypeError on any
        # non-JSON error page that happened to contain the word.
        has, code, _, _, _ = ArloBackEnd._parse_envelope("<html>meta</html>")
        self.assertFalse(has)
        self.assertIsNone(code)

    def test_non_numeric_codes_are_tolerated(self):
        has, code, error, _, _ = ArloBackEnd._parse_envelope(
            {"meta": {"code": "oops", "error": "nope"}}
        )
        self.assertTrue(has)
        self.assertIsNone(code)
        self.assertIsNone(error)

    def test_legacy_success_style(self):
        has, code, _, _, data = ArloBackEnd._parse_envelope(
            {"success": True, "data": {"b": 2}}
        )
        self.assertTrue(has)
        self.assertEqual(code, 200)
        self.assertEqual(data, {"b": 2})

    def test_legacy_success_without_data_gives_empty_data(self):
        has, code, _, _, data = ArloBackEnd._parse_envelope({"success": True})
        self.assertTrue(has)
        self.assertEqual(code, 200)
        self.assertEqual(data, {})

    def test_legacy_failure_exposes_device_offline_code(self):
        # Base-station notify failures carry the code in data.error, which is
        # where 2059/2222 ("base station is not responding") arrive.
        has, code, error, message, _ = ArloBackEnd._parse_envelope(
            {"success": False, "data": {"error": 2059, "message": "offline"}}
        )
        self.assertTrue(has)
        self.assertEqual(error, 2059)
        self.assertEqual(message, "offline")
        self.assertEqual(classify(code, error), ErrorAction.DEVICE_OFFLINE)

    def test_unrecognised_body(self):
        has, _, _, _, _ = ArloBackEnd._parse_envelope({"something": "else"})
        self.assertFalse(has)


class TestRequestFull(TestCase):
    def _request(self, response=None, raises=None, **kwargs):
        be = make_backend(FakeSession(response=response, raises=raises))
        return be._request_full("/path", authpost=True, **kwargs)

    def test_regression_meta_400_is_a_failure(self):
        # The exact response that used to be accepted as a valid session: HTTP
        # 200 carrying meta.code 400 / meta.error 9276. The body-only accessors
        # returned the message string, which is not None, so every `is None`
        # check read it as success.
        body = {
            "meta": {
                "code": 400,
                "error": 9276,
                "message": "Current authentication is not completed",
            }
        }
        result = self._request(FakeResponse(200, body))
        self.assertFalse(result.ok)
        self.assertEqual(result.code, 400)
        self.assertEqual(result.arlo_error, 9276)
        self.assertEqual(result.action, ErrorAction.AUTH_PENDING)

    def test_regression_body_only_accessor_reports_failure_as_none(self):
        # Same response through the body-only path: it must be None, otherwise
        # callers such as _validate and location.mode treat it as a success.
        body = {"meta": {"code": 400, "error": 9276, "message": "not completed"}}
        be = make_backend(FakeSession(FakeResponse(200, body)))
        self.assertIsNone(be.auth_get("/path"))

    def test_success_returns_data(self):
        result = self._request(FakeResponse(200, {"meta": {"code": 200}, "data": [1]}))
        self.assertTrue(result.ok)
        self.assertEqual(result.body, [1])

    def test_http_error_still_exposes_the_arlo_code(self):
        # The body used to be discarded whenever the status was not 200, which
        # made meta.error unreadable on any real 4xx.
        body = {"meta": {"code": 401, "error": 9002, "message": "expired"}}
        result = self._request(FakeResponse(401, body))
        self.assertEqual(result.arlo_error, 9002)
        self.assertEqual(result.action, ErrorAction.REAUTH)

    def test_http_error_without_body(self):
        result = self._request(FakeResponse(503, None, text="down"))
        self.assertEqual(result.code, 503)
        self.assertEqual(result.action, ErrorAction.RETRY)
        self.assertIsNone(result.body)

    def test_timeout_is_retryable(self):
        class ReadTimeout(Exception):
            pass

        result = self._request(raises=ReadTimeout("slow"))
        self.assertEqual(result.code, 500)
        self.assertEqual(result.action, ErrorAction.RETRY)
        self.assertIn("ReadTimeout", result.message)

    def test_unreadable_body_is_retryable(self):
        result = self._request(
            FakeResponse(200, None, text="not json", content_type="application/json")
        )
        self.assertEqual(result.action, ErrorAction.RETRY)
        self.assertIsNone(result.body)

    def test_missing_content_type_header_does_not_raise(self):
        response = FakeResponse(200, {"meta": {"code": 200}, "data": {}})
        response.headers = {}
        result = self._request(response)
        # Falls back to text, which is not an envelope we recognise.
        self.assertFalse(result.ok)
        self.assertEqual(result.action, ErrorAction.RETRY)

    def test_raw_returns_the_untouched_body(self):
        body = {"anything": True}
        result = self._request(FakeResponse(200, body), raw=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.body, body)

    def test_raw_failure_keeps_the_status(self):
        result = self._request(FakeResponse(404, None, text=""), raw=True)
        self.assertEqual(result.code, 404)
        self.assertFalse(result.ok)


class TestRequestKeywords(TestCase):
    """The wrappers used to pass arguments positionally and misalign them."""

    def test_get_forwards_cookies_and_not_authpost(self):
        session = FakeSession(FakeResponse(200, {"meta": {"code": 200}, "data": {}}))
        be = make_backend(session)
        jar = {"cookie": "value"}
        be.get("/path", cookies=jar, host="https://example.com")
        _method, url, kwargs = session.calls[0]
        self.assertIs(kwargs["cookies"], jar)
        # authpost stayed False, so the transaction id is still applied.
        self.assertIn("x-transaction-id", kwargs["headers"])
        self.assertTrue(url.startswith("https://example.com/path"))

    def test_put_does_not_use_cookies_as_the_host(self):
        session = FakeSession(FakeResponse(200, {"meta": {"code": 200}, "data": {}}))
        be = make_backend(session)
        jar = {"cookie": "value"}
        be.put("/path", cookies=jar)
        _method, url, kwargs = session.calls[0]
        self.assertIs(kwargs["cookies"], jar)
        self.assertTrue(url.startswith(be._arlo.cfg.host))
