from __future__ import annotations

import json
import os
import pickle
import pprint
import re
import ssl
import threading
import time
import traceback
import uuid
import random

import paho.mqtt.client as mqtt
import requests
import requests.adapters

from enum import IntEnum
from http.cookiejar import LWPCookieJar

from .constant import (
    AUTH_FINISH_PATH,
    AUTH_GET_FACTORID,
    AUTH_GET_FACTORS,
    AUTH_PATH,
    AUTH_START_PAIRING,
    AUTH_START_PATH,
    AUTH_VALIDATE_PATH,
    DEFAULT_AUTH_HOST,
    DEFAULT_RESOURCES,
    DEVICES_PATH,
    EVENT_LOGIN_RETRY_MAX,
    EVENT_LOGIN_RETRY_MIN,
    LOGOUT_PATH,
    MQTT_HOST,
    MQTT_PATH,
    MQTT_RC_BAD_CREDENTIALS,
    MQTT_RC_NOT_AUTHORISED,
    MQTT_URL_KEY,
    NOTIFY_PATH,
    ORIGIN_HOST,
    REFERER_HOST,
    SESSION_PATH,
    SUBSCRIBE_PATH,
    TFA_CONSOLE_SOURCE,
    TFA_IMAP_SOURCE,
    TFA_PUSH_SOURCE,
    TFA_REST_API_SOURCE,
    TRANSID_PREFIX,
    USER_AGENTS,
)
from .errors import (
    QUIET,
    ArloResponse,
    ErrorAction,
    classify,
    describe,
    is_permanent,
)
from .sseclient import SSEClient, SSEStatusError
from .tfa import Arlo2FAConsole, Arlo2FAImap, Arlo2FARestAPI
from .util import now_strftime, time_to_arlotime, to_b64


class AuthResult(IntEnum):
    CAN_RETRY = -1,
    SUCCESS = 0,
    FAILED = 1


class ArloAuthError(Exception):
    """Raised when an Arlo authentication helper call fails.

    Carries the classification as well as the text, so a caller - the config
    flow, mainly - can tell "that password is wrong" from "Arlo is unreachable"
    and say something useful. It used to be a bare string, leaving the caller to
    guess, which meant every failure was reported as a connection problem.
    """

    def __init__(self, message, response=None, action=None):
        super().__init__(message)
        self.response = response
        if action is not None:
            self.action = action
        elif response is not None:
            self.action = response.action
        else:
            self.action = ErrorAction.RETRY
        self.arlo_error = response.arlo_error if response is not None else None

    @property
    def is_credentials_problem(self):
        """True when the user has to fix something before this can work."""
        return is_permanent(self.action) or self.action is ErrorAction.OTP_RETRY


class ArloManualAuthSession:
    """State for an interactive 2FA login started from a config flow."""

    def __init__(self, session, headers, username, user_id, token, expires_in, device_id, factor_auth_code):
        self.session = session
        self.headers = headers
        self.username = username
        self.user_id = user_id
        self.token = token
        self.expires_in = expires_in
        self.device_id = device_id
        self.factor_auth_code = factor_auth_code


def _resolve_user_agent(agent):
    if agent.startswith("!"):
        return agent[1:]
    agent = agent.lower()
    if agent == "random":
        return _resolve_user_agent(random.choice(list(USER_AGENTS.keys())))
    return USER_AGENTS.get(agent, USER_AGENTS["linux"])


def _auth_helper_headers(user_device_id, user_agent, send_source=False):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8",
        "Cache-Control": "no-cache",
        "Content-Type": "application/json",
        "Origin": ORIGIN_HOST,
        "Pragma": "no-cache",
        "Priority": "u=1, i",
        "Referer": REFERER_HOST,
        "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "source": "arloCamWeb",
        "User-Agent": _resolve_user_agent(user_agent),
        "x-service-version": "v3",
        "X-User-Device-Automation-Name": "QlJPV1NFUg==",
        "X-User-Device-Id": user_device_id,
        "X-User-Device-Type": "BROWSER",
    }
    if send_source:
        headers["Source"] = "arloCamWeb"
    return headers


def _create_auth_helper_session(http_backend, curl_cffi_impersonate):
    if http_backend == "curl_cffi":
        from curl_cffi import requests as cffi_requests
        for impersonate in _curl_cffi_impersonations(curl_cffi_impersonate):
            try:
                return cffi_requests.Session(impersonate=impersonate)
            except Exception:
                continue
        return cffi_requests.Session(impersonate=curl_cffi_impersonate)

    import cloudscraper
    return cloudscraper.create_scraper(
        disableCloudflareV1=True,
        ecdhCurve="secp384r1",
        debug=False,
    )


def _curl_cffi_impersonations(configured):
    if configured == "chrome131":
        return ("chrome", "chrome136", "chrome133", "chrome131")
    return (configured,)


def _parse_auth_helper_response(response):
    """Turn a helper response into an :class:`ArloResponse`.

    Shares `ArloBackEnd._parse_envelope` with the main request path rather than
    reimplementing it, so both stay honest about malformed envelopes and both see
    `meta.error` on a non-200.
    """
    try:
        body = response.json()
    except Exception:
        body = response.text

    has_envelope, meta_code, arlo_error, message, data = ArloBackEnd._parse_envelope(body)

    if has_envelope and meta_code == 200:
        return ArloResponse(200, data)

    if has_envelope:
        code = meta_code if meta_code is not None else response.status_code
        return ArloResponse(
            code,
            message,
            arlo_error=arlo_error,
            message=message,
            action=classify(code, arlo_error),
        )

    if response.status_code != 200:
        return ArloResponse(
            response.status_code,
            None,
            message="http error",
            action=classify(response.status_code),
        )

    return ArloResponse(
        500, None, message="unrecognised response", action=ErrorAction.RETRY
    )


def _auth_helper_request(session, method, url, params=None, headers=None, timeout=60):
    try:
        if method == "OPTIONS":
            session.options(url, json=params, headers=headers, timeout=timeout)
            return ArloResponse(200, None)
        if method == "GET":
            response = session.get(url, headers=headers, timeout=timeout)
        else:
            response = session.post(url, json=params, headers=headers, timeout=timeout)
    except Exception as err:
        raise ArloAuthError(
            f"request failed: {type(err).__name__}", action=ErrorAction.RETRY
        ) from err

    return _parse_auth_helper_response(response)


def get_available_2fa_factors(
        username,
        password,
        auth_host=DEFAULT_AUTH_HOST,
        http_backend="curl_cffi",
        curl_cffi_impersonate="chrome131",
        user_agent="linux",
        request_timeout=60,
        send_source=False,
):
    """Authenticate enough to return the account's available 2FA factors."""
    user_device_id = str(uuid.uuid4())
    session = _create_auth_helper_session(http_backend, curl_cffi_impersonate)
    headers = _auth_helper_headers(user_device_id, user_agent, send_source)

    _auth_helper_request(
        session, "OPTIONS", auth_host + AUTH_PATH, headers=headers, timeout=request_timeout
    )
    response = _auth_helper_request(
        session,
        "POST",
        auth_host + AUTH_PATH,
        {
            "email": username,
            "password": to_b64(password),
            "language": "en",
            "EnvSource": "prod",
        },
        headers,
        request_timeout,
    )

    if response.code == 429:
        raise ArloAuthError(
            "429 - possible cloudflare issue", action=ErrorAction.RETRY
        )
    if not response.ok or response.body is None:
        raise ArloAuthError(f"login failed: {response.describe()}", response=response)
    body = response.body
    if body.get("authCompleted", False):
        return []

    token = body.get("accessToken", body)["token"]
    headers["Authorization"] = to_b64(token)

    factors_url = auth_host + AUTH_GET_FACTORS + "?data = {}".format(int(time.time()))
    _auth_helper_request(
        session, "OPTIONS", auth_host + AUTH_GET_FACTORS, headers=headers, timeout=request_timeout
    )
    response = _auth_helper_request(
        session, "GET", factors_url, headers=headers, timeout=request_timeout
    )
    if not response.ok or response.body is None:
        raise ArloAuthError(
            f"2fa factors failed: {response.describe()}", response=response
        )
    factors = response.body

    return [
        {
            "factor_id": factor.get("factorId"),
            "factor_type": str(factor.get("factorType", "")).lower(),
            "factor_nickname": factor.get("factorNickname", ""),
        }
        for factor in factors.get("items", [])
        if factor.get("factorId") and factor.get("factorType")
    ]


def start_interactive_2fa_auth(
        username,
        password,
        factor_id,
        factor_type,
        auth_host=DEFAULT_AUTH_HOST,
        http_backend="curl_cffi",
        curl_cffi_impersonate="chrome131",
        user_agent="linux",
        request_timeout=60,
        send_source=False,
):
    """Start an interactive 2FA auth and return state for OTP completion."""
    user_device_id = str(uuid.uuid4())
    session = _create_auth_helper_session(http_backend, curl_cffi_impersonate)
    headers = _auth_helper_headers(user_device_id, user_agent, send_source)
    headers["Auth-Version"] = "2"

    _auth_helper_request(
        session, "OPTIONS", auth_host + AUTH_PATH, headers=headers, timeout=request_timeout
    )
    response = _auth_helper_request(
        session,
        "POST",
        auth_host + AUTH_PATH,
        {
            "email": username,
            "password": to_b64(password),
            "language": "fr",
            "EnvSource": "prod",
        },
        headers,
        request_timeout,
    )
    if not response.ok or response.body is None:
        raise ArloAuthError(f"login failed: {response.describe()}", response=response)
    body = response.body
    if body.get("authCompleted", False):
        token_body = body.get("accessToken", body)
        return ArloManualAuthSession(
            session,
            headers,
            username,
            token_body["userId"],
            token_body["token"],
            token_body["expiresIn"],
            user_device_id,
            None,
        )

    token_body = body.get("accessToken", body)
    headers["Authorization"] = to_b64(token_body["token"])

    attempts = [
        {"factorId": factor_id, "factorType": "", "userId": token_body["userId"]},
        {"factorId": factor_id, "factorType": str(factor_type or "").upper(), "userId": token_body["userId"]},
        {"factorId": factor_id, "userId": token_body["userId"]},
    ]
    last = ArloResponse(500, None, action=ErrorAction.RETRY)
    for payload in attempts:
        _auth_helper_request(
            session, "OPTIONS", auth_host + AUTH_START_PATH, headers=headers, timeout=request_timeout
        )
        last = _auth_helper_request(
            session, "POST", auth_host + AUTH_START_PATH, payload, headers, request_timeout
        )
        if last.ok and isinstance(last.body, dict):
            return ArloManualAuthSession(
                session,
                headers,
                username,
                token_body["userId"],
                token_body["token"],
                token_body["expiresIn"],
                user_device_id,
                last.body["factorAuthCode"],
            )
        if is_permanent(last.action):
            # No point trying the other payload shapes: the account itself is
            # the problem, not the way we asked.
            break

    raise ArloAuthError(f"start failed: {last.describe()}", response=last)


def finish_interactive_2fa_auth(
        auth_session,
        otp,
        storage_dir,
        auth_host=DEFAULT_AUTH_HOST,
        request_timeout=60,
):
    """Finish interactive 2FA auth and save a pyaarlo-compatible session."""
    headers = auth_session.headers
    _auth_helper_request(
        auth_session.session,
        "OPTIONS",
        auth_host + AUTH_FINISH_PATH,
        headers=headers,
        timeout=request_timeout,
    )
    response = _auth_helper_request(
        auth_session.session,
        "POST",
        auth_host + AUTH_FINISH_PATH,
        {
            "factorAuthCode": auth_session.factor_auth_code,
            "otp": otp,
            "isBrowserTrusted": True,
        },
        headers,
        request_timeout,
    )
    if not response.ok or not isinstance(response.body, dict):
        raise ArloAuthError(
            f"finish failed: {response.describe()}", response=response
        )

    body = response.body
    token_body = body.get("accessToken", body)
    browser_auth_code = body.get("browserAuthCode")
    headers["Authorization"] = to_b64(token_body["token"])

    if browser_auth_code:
        _auth_helper_request(
            auth_session.session,
            "OPTIONS",
            auth_host + AUTH_START_PAIRING,
            headers=headers,
            timeout=request_timeout,
        )
        pairing = _auth_helper_request(
            auth_session.session,
            "POST",
            auth_host + AUTH_START_PAIRING,
            {
                "factorAuthCode": browser_auth_code,
                "factorData": "",
                "factorType": "BROWSER",
            },
            headers,
            request_timeout,
        )
        if not pairing.ok:
            raise ArloAuthError(
                f"pairing failed: {pairing.describe()}", response=pairing
            )

    os.makedirs(storage_dir, exist_ok=True)
    session_file = os.path.join(storage_dir, "session.pickle")
    try:
        with open(session_file, "rb") as dump:
            session_info = pickle.load(dump)
            if session_info.get("version") != "2":
                session_info = {"version": "2", auth_session.username: session_info}
    except Exception:
        session_info = {"version": "2"}

    user_id = token_body["userId"]
    session_info[auth_session.username] = {
        "user_id": user_id,
        "web_id": f"{user_id}_web",
        "sub_id": f"subscriptions/{user_id}_web",
        "token": token_body["token"],
        "expires_in": token_body["expiresIn"],
        "browser_auth_code": browser_auth_code,
        "device_id": auth_session.device_id,
    }
    with open(session_file, "wb") as dump:
        pickle.dump(session_info, dump)

    return True


# include token and session details
class ArloBackEnd(object):

    _session_lock = threading.Lock()
    _session_info = {}
    _multi_location = False
    _user_device_id = None
    _browser_auth_code = None
    _user_id: str | None = None
    _web_id: str | None = None
    _sub_id: str | None = None
    _token: str | None = None
    _token64: str | None = None
    _expires_in: int | None = None
    _needs_pairing: bool = False

    def __init__(self, arlo):

        self._arlo = arlo
        self._lock = threading.Condition()
        self._req_lock = threading.Lock()

        self._dump_file = self._arlo.cfg.dump_file
        self._use_mqtt = False

        self._requests = {}
        self._callbacks = {}
        self._resource_types = DEFAULT_RESOURCES

        self._load_session()
        if self._user_device_id is None:
            self._arlo.debug("created new user ID")
            self._user_device_id = str(uuid.uuid4())

        # event thread stuff
        self._event_thread = None
        self._event_client = None
        self._event_connected = False
        self._stop_thread = False

        # login
        self._session = None
        self._last_auth_action = None
        self._validate_action = ErrorAction.OK
        # Set before the first request: the response hook reads it, and while we
        # are still logging in it must see False so it stays out of the way.
        self._logged_in = False
        self._load_cookies()
        self._logged_in = self._login()
        if not self._logged_in:
            return

    @staticmethod
    def _redact_session_info(session_info):
        if not isinstance(session_info, dict):
            return session_info
        redacted = {}
        for username, values in session_info.items():
            if not isinstance(values, dict):
                redacted[username] = values
                continue
            redacted[username] = {
                key: "***" if key in ("token", "browser_auth_code") else value
                for key, value in values.items()
            }
        return redacted

    def _load_session(self):
        self._user_id = None
        self._web_id = None
        self._sub_id = None
        self._token = None
        self._token64 = None
        self._expires_in = 0
        self._browser_auth_code = None
        self._user_device_id = None
        if not self._arlo.cfg.save_session:
            return
        try:
            with ArloBackEnd._session_lock:
                with open(self._arlo.cfg.session_file, "rb") as dump:
                    ArloBackEnd._session_info = pickle.load(dump)
                    version = ArloBackEnd._session_info.get("version", 1)
                    if version == "2":
                        session_info = ArloBackEnd._session_info.get(self._arlo.cfg.username, None)
                    else:
                        session_info = ArloBackEnd._session_info
                        ArloBackEnd._session_info = {
                            "version": "2",
                            self._arlo.cfg.username: session_info,
                        }
                    if session_info is not None:
                        self._user_id = session_info["user_id"]
                        self._web_id = session_info["web_id"]
                        self._sub_id = session_info["sub_id"]
                        self._token = session_info["token"]
                        self._token64 = to_b64(self._token)
                        self._expires_in = session_info["expires_in"]
                        if "browser_auth_code" in session_info:
                            self._browser_auth_code = session_info["browser_auth_code"]
                        if "device_id" in session_info:
                            self._user_device_id = session_info["device_id"]
                        self.debug(
                            "loadv{}:session_info={}".format(
                                version,
                                self._redact_session_info(ArloBackEnd._session_info),
                            )
                        )
                    else:
                        self.debug(f"loadv{version}:failed")
        except Exception:
            self.debug("session file not read")
            ArloBackEnd._session_info = {
                "version": "2",
            }

    def _save_session(self):
        if not self._arlo.cfg.save_session:
            return
        try:
            with ArloBackEnd._session_lock:
                with open(self._arlo.cfg.session_file, "wb") as dump:
                    ArloBackEnd._session_info[self._arlo.cfg.username] = {
                        "user_id": self._user_id,
                        "web_id": self._web_id,
                        "sub_id": self._sub_id,
                        "token": self._token,
                        "expires_in": self._expires_in,
                        "browser_auth_code": self._browser_auth_code,
                        "device_id": self._user_device_id,
                    }
                    pickle.dump(ArloBackEnd._session_info, dump)
                    self.debug(
                        "savev2:session_info={}".format(
                            self._redact_session_info(ArloBackEnd._session_info)
                        )
                    )
        except Exception as e:
            self._arlo.warning("session file not written" + str(e))

    def _save_cookies(self, requests_cookiejar):
        if self._cookies is not None:
            self._cookies.save(ignore_discard=True)
            self.debug("saving cookies")

    def _load_cookies(self):
        self._cookies = LWPCookieJar(self._arlo.cfg.cookies_file)
        try:
            self._cookies.load()
        except:
            pass
        self.debug(f"loading {len(self._cookies)} cookies")

    def _discard_saved_session(self, reason):
        """Throw away a token the server has refused.

        Without this the rejected token stays on disk - `_save_session()` only
        runs after a successful login - so every subsequent attempt burns
        another doomed validation round-trip against the same dead token, and
        the retry loop can never make progress.

        Deliberately narrow. The cookies, the browser auth code and the device
        id all survive, because they are what makes this a *trusted* browser: a
        dead token says nothing about that trust, and throwing it away would
        turn a silent re-login into a two-factor prompt the user has to answer
        by hand. Trust is only re-established when the browser factor itself is
        refused, which `_auth()` already handles by setting `_needs_pairing`.
        """
        self._arlo.debug(f"discarding saved session: {reason}")
        self._token = None
        self._token64 = None
        self._expires_in = 0
        self._user_id = None
        self._web_id = None
        self._sub_id = None
        self._save_session()

    def _transaction_id(self):
        return 'FE!' + str(uuid.uuid4())

    def _build_url(self, url, tid):
        sep = "&" if "?" in url else "?"
        now = time_to_arlotime()
        return f"{url}{sep}eventId={tid}&time={now}"

    @staticmethod
    def _transport_action(err):
        """Classify a transport failure.

        The two supported HTTP backends (``requests``/cloudscraper and
        ``curl_cffi``) have entirely separate exception hierarchies, so match on
        the name rather than isinstance to stay backend agnostic.
        """
        name = type(err).__name__
        if "Timeout" in name or "ConnectionError" in name or "Timedout" in name:
            return ErrorAction.RETRY
        if "SSL" in name or "Certificate" in name:
            # Usually a proxy or a clock problem: retrying rarely helps, but
            # calling it fatal would disable the integration until a restart.
            return ErrorAction.RETRY
        return ErrorAction.RETRY

    @staticmethod
    def _parse_envelope(body):
        """Pull ``meta``/``success`` apart without ever raising.

        ``meta.error`` and ``meta.message`` used to be indexed unguarded, so a
        non-200 envelope missing either key raised KeyError out of the request
        path; and the membership test used to match plain strings too, giving a
        TypeError on any non-JSON body. Both are now impossible.

        :returns: ``(has_envelope, code, arlo_error, message, data)``
        """
        if not isinstance(body, dict):
            return False, None, None, None, None

        meta = body.get("meta")
        if isinstance(meta, dict):
            code = meta.get("code")
            try:
                code = int(code)
            except (TypeError, ValueError):
                code = None
            arlo_error = meta.get("error")
            try:
                arlo_error = int(arlo_error) if arlo_error is not None else None
            except (TypeError, ValueError):
                arlo_error = None
            return True, code, arlo_error, meta.get("message"), body.get("data")

        if "success" in body:
            if body.get("success"):
                # Success with no payload: hand back empty data rather than None
                # so callers can tell it apart from a failure.
                return True, 200, None, None, body.get("data", {})
            error = body.get("data", {})
            arlo_error = error.get("error") if isinstance(error, dict) else None
            try:
                arlo_error = int(arlo_error) if arlo_error is not None else None
            except (TypeError, ValueError):
                arlo_error = None
            message = error.get("message") if isinstance(error, dict) else None
            return True, 500, arlo_error, message, None

        return False, None, None, None, None

    def _force_event_restart(self):
        """Break the event loop so the event thread logs in again.

        Clearing `_logged_in` on its own is not enough: the event thread is
        parked inside the SSE iterator or `loop_forever()` and never looks at
        it. The official web client does the same thing on a 401 - it tears the
        push handler down and goes back to login.
        """
        client = self._event_client
        if client is None:
            return
        try:
            if self._use_mqtt:
                self._mqtt_stop_loop()
            else:
                client.stop()
        except Exception as e:
            self.debug(f"could not stop the event client: {type(e).__name__}")

    def _note_response(self, response, path):
        """React to a response saying our session is gone.

        Without this an expired token made every call quietly return None -
        surfacing as "failed to set mode.", "failed to read modes." and so on -
        while `is_connected` still claimed True, so nothing above ever learned
        that the session had died.
        """
        if response.action is not ErrorAction.REAUTH:
            return

        # Only act on the first one. Later calls see _logged_in already False,
        # which keeps a burst of failing requests from each kicking off a login.
        if not self._logged_in:
            return

        self._arlo.warning(
            f"session rejected on {path}: {response.describe()}, re-authenticating"
        )
        self._logged_in = False
        self._discard_saved_session("an API call was rejected")
        self._force_event_restart()
        with self._lock:
            self._lock.notify_all()

    def _request_full(
            self,
            path,
            method="GET",
            params=None,
            headers=None,
            stream=False,
            raw=False,
            timeout=None,
            host=None,
            authpost=False,
            cookies=None
    ):
        """Make a request, and react if it tells us the session is gone."""
        response = self._do_request(
            path=path, method=method, params=params, headers=headers, stream=stream,
            raw=raw, timeout=timeout, host=host, authpost=authpost, cookies=cookies,
        )
        # Auth calls are excluded: they are how we recover, so letting them
        # trigger a recovery would recurse.
        if not authpost:
            self._note_response(response, path)
        return response

    def _do_request(
            self,
            path,
            method="GET",
            params=None,
            headers=None,
            stream=False,
            raw=False,
            timeout=None,
            host=None,
            authpost=False,
            cookies=None
    ):
        """Make a request and return everything we learned about the outcome."""
        if params is None:
            params = {}
        if headers is None:
            headers = {}
        if timeout is None:
            timeout = self._arlo.cfg.request_timeout
        try:
            with self._req_lock:
                if host is None:
                    host = self._arlo.cfg.host
                if authpost:
                    url = host + path
                else:
                    tid = self._transaction_id()
                    url = self._build_url(host + path, tid)
                    headers['x-transaction-id'] = tid

                self.vdebug("request-url={}".format(url))
                self.vdebug("request-params=\n{}".format(pprint.pformat(params)))
                self.vdebug("request-headers=\n{}".format(pprint.pformat(headers)))

                if method == "GET":
                    r = self._session.get(
                        url,
                        params=params,
                        headers=headers,
                        stream=stream,
                        timeout=timeout,
                        cookies=cookies,
                    )
                    if stream is True:
                        return ArloResponse(200, r)
                elif method == "PUT":
                    r = self._session.put(
                        url, json=params, headers=headers, timeout=timeout, cookies=cookies,
                    )
                elif method == "POST":
                    r = self._session.post(
                        url, json=params, headers=headers, timeout=timeout, cookies=cookies,
                    )
                elif method == "OPTIONS":
                    self._session.options(
                        url, json=params, headers=headers, timeout=timeout
                    )
                    return ArloResponse(200, None)
        except Exception as e:
            self._arlo.warning("request-error={}".format(type(e).__name__))
            return ArloResponse(
                500,
                None,
                message="request failed: {}".format(type(e).__name__),
                action=self._transport_action(e),
            )

        try:
            if "application/json" in r.headers.get("Content-Type", ""):
                body = r.json()
            else:
                body = r.text
            self.vdebug("request-body=\n{}".format(pprint.pformat(body)))
        except Exception as e:
            self._arlo.warning("body-error={}".format(type(e).__name__))
            self._arlo.debug(f"request-text={r.text}")
            return ArloResponse(
                500,
                None,
                message="unreadable body: {}".format(type(e).__name__),
                action=ErrorAction.RETRY,
            )

        self.vdebug("request-end={}".format(r.status_code))

        # Parse the envelope *before* looking at the HTTP status. Arlo returns
        # its real verdict in meta.error, and it does so on 4xx responses too;
        # discarding the body on a non-200 threw away the only field that says
        # what actually went wrong.
        has_envelope, meta_code, arlo_error, message, data = self._parse_envelope(body)

        if raw:
            # Raw callers want the payload untouched, so only the status decides.
            if r.status_code != 200:
                return ArloResponse(
                    r.status_code,
                    None,
                    arlo_error=arlo_error,
                    message=message,
                    action=classify(r.status_code, arlo_error),
                )
            return ArloResponse(200, body)

        if has_envelope:
            if meta_code == 200:
                return ArloResponse(200, data)

            code = meta_code if meta_code is not None else r.status_code
            action = classify(code, arlo_error)
            # Codes that are an expected step of logging in are not warnings.
            # Previously only 9204 was quiet, so a normal 2FA handshake logged
            # alarming warnings while real failures looked the same.
            if arlo_error in QUIET:
                self._arlo.debug("expected auth response=" + str(body))
            else:
                self._arlo.warning("error in new response=" + str(body))
            return ArloResponse(
                code,
                message,
                arlo_error=arlo_error,
                message=message,
                action=action,
            )

        if r.status_code != 200:
            return ArloResponse(
                r.status_code,
                None,
                message="http error",
                action=classify(r.status_code),
            )

        # A 200 we cannot make sense of: neither envelope style matched.
        self._arlo.warning("unrecognised response=" + str(body)[:256])
        return ArloResponse(
            500, None, message="unrecognised response", action=ErrorAction.RETRY
        )

    def _request_tuple(
            self,
            path,
            method="GET",
            params=None,
            headers=None,
            stream=False,
            raw=False,
            timeout=None,
            host=None,
            authpost=False,
            cookies=None
    ):
        response = self._request_full(
            path=path, method=method, params=params, headers=headers, stream=stream,
            raw=raw, timeout=timeout, host=host, authpost=authpost, cookies=cookies,
        )
        return response.code, response.body

    def _request(
            self,
            path,
            method="GET",
            params=None,
            headers=None,
            stream=False,
            raw=False,
            timeout=None,
            host=None,
            authpost=False,
            cookies=None
    ):
        response = self._request_full(
            path=path, method=method, params=params, headers=headers, stream=stream,
            raw=raw, timeout=timeout, host=host, authpost=authpost, cookies=cookies,
        )
        return response.body if response.ok else None

    def gen_trans_id(self, trans_type=TRANSID_PREFIX):
        return trans_type + "!" + str(uuid.uuid4())

    def _event_dispatcher(self, response):

        # get message type(s) and id(s)
        responses = []
        resource = response.get("resource", "")

        err = response.get("error", None)
        if err is not None:
            self._arlo.info(
                "error: code="
                + str(err.get("code", "xxx"))
                + ",message="
                + str(err.get("message", "XXX"))
            )

        #
        # I'm trying to keep this as generic as possible... but it needs some
        # smarts to figure out where to send responses - the packets from Arlo
        # are anything but consistent...
        # See docs/packets for and idea of what we're parsing.
        #

        # Answer for async ping. Note and finish.
        # Packet type #1
        if resource.startswith("subscriptions/"):
            self.vdebug("packet: async ping response " + resource)
            return

        # These is a base station mode response. Find base station ID and
        # forward response.
        # Packet type #2
        if resource == "activeAutomations":
            self.debug("packet: base station mode response")
            for device_id in response:
                if device_id != "resource":
                    responses.append((device_id, resource, response[device_id]))

        # Mode update response
        # XXX these might be deprecated
        elif "states" in response:
            self.debug("packet: mode update")
            device_id = response.get("from", None)
            if device_id is not None:
                responses.append((device_id, "states", response["states"]))

        # These are individual device updates, they are usually used to signal
        # things like motion detection or temperature changes.
        # Packet type #3
        elif [x for x in self._resource_types if resource.startswith(x + "/")]:
            self.debug("packet: device update")
            device_id = resource.split("/")[1]
            responses.append((device_id, resource, response))

        # Base station its child device statuses. We split this apart here
        # and pass directly to the referenced devices.
        # Packet type #4
        elif resource == 'devices':
            self.debug("packet: base and child statuses")
            for device_id in response.get('devices', {}):
                self._arlo.debug(f"DEVICES={device_id}")
                props = response['devices'][device_id]
                responses.append((device_id, resource, props))

        # These are base station responses. Which can be about the base station
        # or devices on it... Check if property is list.
        # XXX these might be deprecated
        elif resource in self._resource_types:
            prop_or_props = response.get("properties", [])
            if isinstance(prop_or_props, list):
                for prop in prop_or_props:
                    device_id = prop.get("serialNumber", None)
                    if device_id is None:
                        device_id = response.get("from", None)
                    responses.append((device_id, resource, prop))
            else:
                device_id = response.get("from", None)
                responses.append((device_id, resource, response))

        # ArloBabyCam packets.
        elif resource.startswith("audioPlayback"):
            device_id = response.get("from")
            properties = response.get("properties")
            if resource == "audioPlayback/status":
                # Wrap the status event to match the 'audioPlayback' event
                properties = {"status": response.get("properties")}

            self._arlo.info(
                "audio playback response {} - {}".format(resource, response)
            )
            if device_id is not None and properties is not None:
                responses.append((device_id, resource, properties))

        # This a list ditch effort to funnel the answer the correct place...
        #  Check for device_id
        #  Check for unique_id
        #  Check for locationId
        # If none of those then is unhandled
        else:
            device_id = response.get("deviceId",
                                     response.get("uniqueId",
                                                  response.get("locationId", None)))
            if device_id is not None:
                responses.append((device_id, resource, response))
            else:
                self.debug(f"unhandled response {resource} - {response}")

        # Now find something waiting for this/these.
        for device_id, resource, response in responses:
            cbs = []
            self.debug("sending {} to {}".format(resource, device_id))
            with self._lock:
                if device_id and device_id in self._callbacks:
                    cbs.extend(self._callbacks[device_id])
                if "all" in self._callbacks:
                    cbs.extend(self._callbacks["all"])
            for cb in cbs:
                self._arlo.bg.run(cb, resource=resource, event=response)

    def _event_handle_response(self, response):

        # Debugging.
        if self._dump_file is not None:
            with open(self._dump_file, "a") as dump:
                time_stamp = now_strftime("%Y-%m-%d %H:%M:%S.%f")
                dump.write(
                    "{}: {}\n".format(
                        time_stamp, pprint.pformat(response, indent=2)
                    )
                )
        self.vdebug(
            "packet-in=\n{}".format(pprint.pformat(response, indent=2))
        )

        # Run the dispatcher to set internal state and run callbacks.
        self._event_dispatcher(response)

        # is there a notify/post waiting for this response? If so, signal to waiting entity.
        tid = response.get("transId", None)
        resource = response.get("resource", None)
        device_id = response.get("from", None)
        with self._lock:
            # Transaction ID
            # Simple. We have a transaction ID, look for that. These are
            # usually returned by notify requests.
            if tid and tid in self._requests:
                self._requests[tid] = response
                self._lock.notify_all()

            # Resource
            # These are usually returned after POST requests. We trap these
            # to make async calls sync.
            if resource:
                # Historical. We are looking for a straight matching resource.
                if resource in self._requests:
                    self.vdebug("{} found by text!".format(resource))
                    self._requests[resource] = response
                    self._lock.notify_all()

                else:
                    # Complex. We are looking for a resource and-or
                    # deviceid matching a regex.
                    if device_id:
                        resource = "{}:{}".format(resource, device_id)
                        self.vdebug("{} bounded device!".format(resource))
                    for request in self._requests:
                        if re.match(request, resource):
                            self.vdebug(
                                "{} found by regex {}!".format(resource, request)
                            )
                            self._requests[request] = response
                            self._lock.notify_all()

    def _event_stop_loop(self):
        self._stop_thread = True
        with self._lock:
            self._lock.notify_all()

    def _event_main(self):
        self.debug("event thread starting")

        while not self._stop_thread:

            # say we're starting
            if self._dump_file is not None:
                with open(self._dump_file, "a") as dump:
                    time_stamp = now_strftime("%Y-%m-%d %H:%M:%S.%f")
                    dump.write("{}: {}\n".format(time_stamp, "event_thread start"))

            # Log in again if this is not the first iteration; that also creates
            # a new session. Back off between attempts: this used to retry every
            # five seconds forever, which meant a wrong password or a locked
            # account (9017, "try again after 5 minutes") got hammered
            # indefinitely, keeping the lockout alive.
            delay = EVENT_LOGIN_RETRY_MIN
            while not self._logged_in and not self._stop_thread:
                with self._lock:
                    self._lock.wait(delay)
                if self._stop_thread:
                    break
                self.debug("re-logging in")
                self._logged_in = self._login()
                if self._logged_in:
                    break
                if self.auth_failed_permanently:
                    # Retrying cannot fix credentials. Stop, and leave the
                    # failure visible so the integration above can ask the user
                    # rather than us looping in the background forever.
                    self._arlo.error(
                        "giving up on re-login, credentials need attention "
                        f"({self.last_auth_action.name})"
                    )
                    return
                delay = min(delay * 2, EVENT_LOGIN_RETRY_MAX)
                self.debug(f"next login attempt in {delay}s")

            if self._use_mqtt:
                self._mqtt_main()
            else:
                self._sse_main()
            self.debug("exited the event loop")

            # clear down and signal out
            with self._lock:
                self._client_connected = False
                self._requests = {}
                self._lock.notify_all()

            # restart login...
            self._event_client = None
            self._logged_in = False

    def _mqtt_topics(self):
        topics = []
        for device in self._arlo.devices:
            for topic in device.get("allowedMqttTopics", []):
                topics.append((topic, 0))
        return topics

    def _mqtt_subscribe(self):
        # Make sure we are listening to library events and individual base
        # station events. This seems sufficient for now.
        self._event_client.subscribe([
            (f"u/{self._user_id}/in/userSession/connect", 0),
            (f"u/{self._user_id}/in/userSession/disconnect", 0),
            (f"u/{self._user_id}/in/library/add", 0),
            (f"u/{self._user_id}/in/library/update", 0),
            (f"u/{self._user_id}/in/library/remove", 0)
        ])

        topics = self._mqtt_topics()
        self.debug("topics=\n{}".format(pprint.pformat(topics)))
        self._event_client.subscribe(topics)

    def _mqtt_on_connect(self, _client, _userdata, _flags, rc):
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        self.debug(f"mqtt: connected={str(rc)}")

        # The broker password is the session token, so a credentials rejection
        # here means the token is dead. Without this the result code was ignored
        # and paho happily retried the same dead token.
        if rc in (MQTT_RC_BAD_CREDENTIALS, MQTT_RC_NOT_AUTHORISED):
            self._arlo.warning(f"mqtt: session rejected by broker (rc={rc})")
            self._discard_saved_session(f"mqtt broker rejected the token (rc={rc})")
            self._mqtt_stop_loop()
            return
        if rc != 0:
            self._arlo.warning(f"mqtt: connect failed (rc={rc})")
            self._mqtt_stop_loop()
            return

        self._mqtt_subscribe()
        with self._lock:
            self._event_connected = True
            self._lock.notify_all()

    def _mqtt_on_log(self, _client, _userdata, _level, msg):
        self.vdebug(f"mqtt: log={str(msg)}")

    def _mqtt_on_message(self, _client, _userdata, msg):
        self.debug(f"mqtt: topic={msg.topic}")
        try:
            response = json.loads(msg.payload.decode("utf-8"))

            # deal with mqtt specific pieces
            if response.get("action", "") == "logout":
                # Our own client id echoing back is just our own session, not an
                # eviction, so ignore it - the web client makes the same
                # distinction.
                client_id = response.get("clientId")
                if client_id and client_id == self._event_client_id:
                    self.debug("mqtt: ignoring our own logout echo")
                    return

                # Someone else signed in and Arlo revoked this session. The
                # broker password *is* the session token, so letting paho
                # reconnect just retries with a credential the server has
                # already thrown away. Break the loop instead and let the event
                # thread log in again properly.
                self._arlo.warning(
                    "logged out by the server, did you log in from elsewhere?"
                )
                self._discard_saved_session("server logged this session out")
                self._mqtt_stop_loop()
                return

            # pass on to general handler
            self._event_handle_response(response)

        except json.decoder.JSONDecodeError as e:
            self.debug("reopening: json error " + str(e))

    def _mqtt_stop_loop(self):
        """Break out of `loop_forever()` so the event thread can re-login."""
        try:
            self._event_client.disconnect()
        except Exception as e:
            self.debug(f"mqtt: disconnect failed {type(e).__name__}")

    def _mqtt_main(self):

        try:
            self.debug("(re)starting mqtt event loop")
            headers = {
                "Host": MQTT_HOST,
                "Origin": ORIGIN_HOST,
            }

            # Build a new client_id per login. The last 10 numbers seem to need to be random.
            self._event_client_id = f"user_{self._user_id}_" + "".join(
                str(random.randint(0, 9)) for _ in range(10)
            )
            self.debug(f"mqtt: client_id={self._event_client_id}")

            # Create and set up the MQTT client.
            self._event_client = mqtt.Client(
                client_id=self._event_client_id, transport=self._arlo.cfg.mqtt_transport
            )
            self._event_client.on_log = self._mqtt_on_log
            self._event_client.on_connect = self._mqtt_on_connect
            self._event_client.on_message = self._mqtt_on_message
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = self._arlo.cfg.mqtt_hostname_check
            self._event_client.tls_set_context(ssl_context)
            self._event_client.username_pw_set(f"{self._user_id}", self._token)
            self._event_client.ws_set_options(path=MQTT_PATH, headers=headers)
            self.debug(f"mqtt: host={self._arlo.cfg.mqtt_host}, "
                       f"check={self._arlo.cfg.mqtt_hostname_check}, "
                       f"transport={self._arlo.cfg.mqtt_transport}")

            # Connect.
            self._event_client.connect(self._arlo.cfg.mqtt_host, port=self._arlo.cfg.mqtt_port, keepalive=60)
            self._event_client.loop_forever()

        except Exception as e:
            # self._arlo.warning('general exception ' + str(e))
            self._arlo.error(
                "mqtt-error={}\n{}".format(
                    type(e).__name__, traceback.format_exc()
                )
            )

    def _sse_reconnected(self):
        self.debug("fetching device list after ev-reconnect")
        self.devices()

    def _sse_reconnect(self):
        self.debug("trying to reconnect")
        if self._event_client is not None:
            self._event_client.stop()

    def _sse_main(self):

        # get stream, restart after requested seconds of inactivity or forced close
        try:
            if self._arlo.cfg.stream_timeout == 0:
                self.debug("starting stream with no timeout")
                self._event_client = SSEClient(
                    self._arlo,
                    self._arlo.cfg.host + SUBSCRIBE_PATH,
                    headers=self._headers(),
                    reconnect_cb=self._sse_reconnected,
                )
            else:
                self.debug(
                    "starting stream with {} timeout".format(
                        self._arlo.cfg.stream_timeout
                    )
                )
                self._event_client = SSEClient(
                    self._arlo,
                    self._arlo.cfg.host + SUBSCRIBE_PATH,
                    headers=self._headers(),
                    reconnect_cb=self._sse_reconnected,
                    timeout=self._arlo.cfg.stream_timeout,
                )

            for event in self._event_client:

                # stopped?
                if event is None:
                    self.debug("reopening: no event")
                    break

                # dig out response
                try:
                    response = json.loads(event.data)
                except json.decoder.JSONDecodeError as e:
                    self.debug("reopening: json error " + str(e))
                    break

                # deal with SSE specific pieces
                # logged out? signal exited
                if response.get("action", "") == "logout":
                    self._arlo.warning("logged out? did you log in from elsewhere?")
                    break

                # connected - yay!
                if response.get("status", "") == "connected":
                    with self._lock:
                        self._event_connected = True
                        self._lock.notify_all()
                    continue

                # pass on to general handler
                self._event_handle_response(response)

        except SSEStatusError as e:
            action = classify(e.status_code)
            if action is ErrorAction.REAUTH:
                # The stream refused our token, so reusing it on the next
                # iteration would fail exactly the same way. Drop it now so the
                # re-login does a full authentication.
                self._arlo.warning(
                    f"event loop rejected our session: {describe(e.status_code)}"
                )
                self._discard_saved_session("event stream rejected the token")
            else:
                self._arlo.warning(
                    f"event loop closed by server: {describe(e.status_code)}"
                )
        except requests.exceptions.ConnectionError:
            self._arlo.warning("event loop timeout")
        except requests.exceptions.HTTPError:
            self._arlo.warning("event loop closed by server")
        except AttributeError as e:
            self._arlo.warning("forced close " + str(e))
        except Exception as e:
            # self._arlo.warning('general exception ' + str(e))
            self._arlo.error(
                "sse-error={}\n{}".format(
                    type(e).__name__, traceback.format_exc()
                )
            )

    def _select_backend(self):
        # determine backend to use
        if self._arlo.cfg.event_backend == 'auto':
            if len(self._mqtt_topics()) == 0:
                self.debug("auto chose SSE backend")
                self._use_mqtt = False
            else:
                self.debug("auto chose MQTT backend")
                self._use_mqtt = True
        elif self._arlo.cfg.event_backend == 'mqtt':
            self.debug("user chose MQTT backend")
            self._use_mqtt = True
        else:
            self.debug("user chose SSE backend")
            self._use_mqtt = False

    def start_monitoring(self):
        self._select_backend()
        self._event_client = None
        self._event_connected = False
        self._event_thread = threading.Thread(
            name="ArloEventStream", target=self._event_main, args=()
        )
        self._event_thread.daemon = True

        with self._lock:
            self._event_thread.start()
            count = 0
            while not self._event_connected and count < 30:
                self.debug("waiting for stream up")
                self._lock.wait(1)
                count += 1

        # start logout daemon for sse clients
        if not self._use_mqtt:
            if self._arlo.cfg.reconnect_every != 0:
                self.debug("automatically reconnecting")
                self._arlo.bg.run_every(self._sse_reconnect, self._arlo.cfg.reconnect_every)

        self.debug("stream up")
        return True
    
    def _get_tfa(self):
        """Return the 2FA type we're using."""
        tfa_type = self._arlo.cfg.tfa_source
        if tfa_type == TFA_CONSOLE_SOURCE:
            return Arlo2FAConsole(self._arlo)
        elif tfa_type == TFA_IMAP_SOURCE:
            return Arlo2FAImap(self._arlo)
        elif tfa_type == TFA_REST_API_SOURCE:
            return Arlo2FARestAPI(self._arlo)
        else:
            return tfa_type

    def _update_auth_info(self, body):
        if "accessToken" in body:
            body = body["accessToken"]
        self._token = body["token"]
        self._token64 = to_b64(self._token)
        self._user_id = body["userId"]
        self._web_id = self._user_id + "_web"
        self._sub_id = "subscriptions/" + self._web_id
        self._expires_in = body["expiresIn"]
        if "browserAuthCode" in body:
            self.debug("browser auth code received")
            self._browser_auth_code = body["browserAuthCode"]

    def _auth_headers(self):
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8",
            "Cache-Control": "no-cache",
            "Content-Type": "application/json",
            # "Dnt": "1",
            "Origin": ORIGIN_HOST,
            "Pragma": "no-cache",
            "Priority": "u=1, i",
            "Referer": REFERER_HOST,
            # "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            # "Sec-Ch-Ua-Mobile": "?0",
            # "Sec-Ch-Ua-Platform": "Linux",
            # "Sec-Fetch-Dest": "empty",
            # "Sec-Fetch-Mode": "cors",
            # "Sec-Fetch-Site": "same-site",
            "sec-ch-ua": '"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Linux"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "source": "arloCamWeb",
            "User-Agent": self._user_agent,
            "x-service-version": "v3",
            "X-User-Device-Automation-Name": "QlJPV1NFUg==",
            "X-User-Device-Id": self._user_device_id,
            "X-User-Device-Type": "BROWSER",
        }

        # Add Source if asked for.
        if self._arlo.cfg.send_source:
            headers.update({
                "Source": "arloCamWeb",
            })

        return headers

    def _select_tfa_factor(self, factors):
        factors_of_type = []

        for factor in factors or []:
            if (
                self._arlo.cfg.tfa_factor_id
                and factor.get("factorId") == self._arlo.cfg.tfa_factor_id
            ):
                return factor
            if str(factor.get("factorType", "")).lower() == self._arlo.cfg.tfa_type:
                factors_of_type.append(factor)

        for factor in factors_of_type:
            nicknames = (
                factor.get("factorNickname"),
                factor.get("displayName"),
            )
            if self._arlo.cfg.tfa_nickname in nicknames:
                return factor

        if factors_of_type:
            return factors_of_type[0]

        return None

    def _log_selected_tfa_factor(self, factor):
        if not isinstance(factor, dict):
            return
        factor_id = str(factor.get("factorId", ""))
        safe_id = factor_id[-8:] if factor_id else ""
        self.debug(
            "selected 2FA factor type={}, role={}, nickname={}, id_suffix={}".format(
                factor.get("factorType"),
                factor.get("factorRole"),
                factor.get("factorNickname") or factor.get("displayName"),
                safe_id,
            )
        )

    def _get_secondary_factors(self, headers):
        factors = self.auth_get(
            AUTH_GET_FACTORS + "?data = {}".format(int(time.time())), {}, headers
        )
        if not isinstance(factors, dict):
            return None
        return factors.get("items", [])

    def _start_pingone_auth(self, headers):
        self.debug("starting PingOne auth discovery")
        self.auth_options(AUTH_START_PATH, headers)
        code, body = self.auth_post(
            AUTH_START_PATH, {"factorType": "", "userId": self._user_id}, headers
        )
        if code != 200 or not isinstance(body, dict):
            self.debug(f"PingOne auth discovery failed: {code} - {body}")
            return None, None

        factor = self._select_tfa_factor(body.get("factors", []))
        if factor is None:
            self.debug("PingOne auth discovery returned no matching factor")
            return None, None

        self._log_selected_tfa_factor(factor)
        factor_type = str(factor.get("factorType", "")).lower()
        self.debug(f"PingOne auth selected {factor_type}")
        return factor.get("factorId"), body.get("factorAuthCode")

    def _start_factor_auth(self, headers, factor_id, factor_type):
        self.debug(f"starting auth with {factor_type}")
        self.auth_options(AUTH_START_PATH, headers)
        return self.auth_post(
            AUTH_START_PATH,
            {"factorId": factor_id, "factorType": "", "userId": self._user_id},
            headers,
        )

    def _headers(self):
        return {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-GB,en;q=0.9,en-US;q=0.8",
            "Auth-Version": "2",
            "Authorization": self._token,
            "Cache-Control": "no-cache",
            "Content-Type": "application/json; charset=utf-8;",
            # "Dnt": "1",
            "Origin": ORIGIN_HOST,
            "Pragma": "no-cache",
            "Priority": "u=1, i",
            "Referer": REFERER_HOST,
            "SchemaVersion": "1",
            # "Sec-Ch-Ua": '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
            # "Sec-Ch-Ua-Mobile": "?0",
            # "Sec-Ch-Ua-Platform": "Linux",
            # "Sec-Fetch-Dest": "empty",
            # "Sec-Fetch-Mode": "cors",
            # "Sec-Fetch-Site": "same-site",
            "User-Agent": self._user_agent,
        }

    def _auth(self) -> AuthResult:
        headers = self._auth_headers()

        # Arlo sporadically rejects the first login attempt, so blind-retry a
        # couple of times before giving up.
        attempt = 0
        code = 0
        body = None
        response = None
        while attempt < 3:
            attempt += 1
            self.debug("login attempt #{}".format(attempt))
            self.auth_options(AUTH_PATH, headers)

            response = self.auth_post_full(
                AUTH_PATH,
                {
                    "email": self._arlo.cfg.username,
                    "password": to_b64(self._arlo.cfg.password),
                    "language": "en",
                    "EnvSource": "prod",
                },
                headers,
            )
            code, body = response.code, response.body
            self._last_auth_action = response.action
            if code == 200 or code == 401:
                break
            # Never burn the remaining attempts on something retrying cannot
            # fix. It matters most for 9017, where the account is locked for
            # five minutes and each extra try prolongs it.
            if response.action in (ErrorAction.FATAL, ErrorAction.REJECTED):
                break
            time.sleep(3)

        if response is not None and response.action in (
            ErrorAction.FATAL,
            ErrorAction.REJECTED,
        ):
            self._arlo.error(f"login failed: {response.describe()}")
            return AuthResult.FAILED
        if body is None:
            self._arlo.error(f"login failed: {code} - possible cloudflare issue")
            return AuthResult.CAN_RETRY
        if code != 200:
            self._arlo.error(f"login failed: {response.describe()}")
            return AuthResult.FAILED

        # save new login information
        self._update_auth_info(body)

        # Looks like we need 2FA. So, request a code be sent to our email address.
        if not body["authCompleted"]:
            self.debug("need 2FA...")

            # update headers and create 2fa instance
            headers["Authorization"] = self._token64
            tfa = self._get_tfa()
            if tfa == "manual":
                self._arlo.error("login failed: manual 2fa requires config flow reauth")
                return AuthResult.FAILED

            # get available 2fa choices,
            self.debug("getting tfa choices")

            self.auth_options(AUTH_GET_FACTORID, headers)

            # look for code source choice
            self.debug(f"looking for {self._arlo.cfg.tfa_type}/{self._arlo.cfg.tfa_nickname}")
            factor_id = None
            factor_auth_code = None

            payload = {
                "factorType": "BROWSER",
                "factorData": "",
                "userId": self._user_id
            }

            code, body = self.auth_post(
                AUTH_GET_FACTORID, payload, headers, cookies=self._cookies
            )

            if code == 200:
                self._needs_pairing = False
                factor_id = body["factorId"]
            else:
                self._needs_pairing = True
                factor_id, factor_auth_code = self._start_pingone_auth(headers)

            if factor_id is None:
                factors = self._get_secondary_factors(headers)
                if factors is None:
                    self._arlo.error("login failed: 2fa: no secondary choices available")
                    return AuthResult.FAILED

                factor = self._select_tfa_factor(factors)
                if factor is not None:
                    self._log_selected_tfa_factor(factor)
                    factor_id = factor.get("factorId")

            if factor_id is None:
                self._arlo.error("login failed: 2fa: no secondary choices available")
                return AuthResult.FAILED

            quick_start_complete = False
            if code == 200 and factor_auth_code is None:
                payload = {
                    "factorId": factor_id,
                    "factorType": "BROWSER",
                    "userId": self._user_id
                }
                self.auth_options(AUTH_START_PATH, headers)
                code, body = self.auth_post(AUTH_START_PATH, payload, headers)
                if code == 200:
                    quick_start_complete = True
                else:
                    self._arlo.warning(
                        f"quick start failed: {code} - {body}; trying configured 2FA"
                    )
                    self._needs_pairing = True
                    factor_id = None
                    factor_auth_code = None

                    factor_id, factor_auth_code = self._start_pingone_auth(headers)

                    if factor_id is None:
                        factors = self._get_secondary_factors(headers)
                        if factors is None:
                            self._arlo.error("login failed: 2fa: no secondary choices available")
                            return AuthResult.FAILED

                        factor = self._select_tfa_factor(factors)
                        if factor is not None:
                            self._log_selected_tfa_factor(factor)
                            factor_id = factor.get("factorId")

                    if factor_id is None:
                        self._arlo.error("login failed: 2fa: no secondary choices available")
                        return AuthResult.FAILED

            if not quick_start_complete and tfa != TFA_PUSH_SOURCE:
                # snapshot 2fa before sending in request
                if not tfa.start():
                    self._arlo.error("login failed: 2fa: startup failed")
                    return AuthResult.FAILED

                # start authentication with email
                self.debug(
                    "starting auth with {} using default factor type".format(
                        self._arlo.cfg.tfa_type
                    )
                )
                payload = {
                    "factorId": factor_id,
                    "factorType": "",
                    "userId": self._user_id
                }
                if factor_auth_code is None:
                    code, body = self._start_factor_auth(
                        headers, factor_id, self._arlo.cfg.tfa_type
                    )
                    if code != 200:
                        self._arlo.error(f"login failed: start failed: {code} - {body}")
                        return AuthResult.CAN_RETRY
                    factor_auth_code = body["factorAuthCode"]
                else:
                    self.debug("using PingOne factor auth code")

                # get code from TFA source
                code = tfa.get()
                if code is None:
                    self._arlo.error("login failed: 2fa: code retrieval failed")
                    return AuthResult.CAN_RETRY

                # tidy 2fa
                tfa.stop()

                # finish authentication
                self.debug("finishing auth")
                code, body = self.auth_post(
                    AUTH_FINISH_PATH, {
                        "factorAuthCode": factor_auth_code,
                        "otp": code,
                        "isBrowserTrusted": True
                    },
                    headers,
                )
                if code != 200:
                    self._arlo.error(f"login failed: finish failed: {code} - {body}")
                    return AuthResult.FAILED
            elif not quick_start_complete:
                # start authentication
                self.debug(
                    "starting auth with {} using default factor type".format(
                        self._arlo.cfg.tfa_type
                    )
                )
                payload = {
                    "factorId": factor_id,
                    "factorType": "",
                    "userId": self._user_id
                }
                if factor_auth_code is None:
                    code, body = self._start_factor_auth(
                        headers, factor_id, self._arlo.cfg.tfa_type
                    )
                    if code != 200:
                        self._arlo.error(f"login failed: start failed: {code} - {body}")
                        return AuthResult.FAILED
                    factor_auth_code = body["factorAuthCode"]
                else:
                    self.debug("using PingOne factor auth code")
                tries = 1
                while True:
                    # finish authentication
                    self.debug("finishing auth")
                    code, body = self.auth_post(
                        AUTH_FINISH_PATH, {
                            "factorAuthCode": factor_auth_code,
                            "isBrowserTrusted": True
                        },
                        headers,
                    )
                    if code != 200:
                        self._arlo.warning("2fa finishAuth - tries {}".format(tries))
                        if tries < self._arlo.cfg.tfa_retries:
                            time.sleep(self._arlo.cfg.tfa_delay)
                            tries += 1
                        else:
                            self._arlo.error(f"login failed: finish failed: {code} - {body}")
                            return AuthResult.FAILED
                    else:
                        break

            # save new login information
            self._update_auth_info(body)

        return AuthResult.SUCCESS

    def _validate(self, quiet=False):
        headers = self._auth_headers()
        headers["Authorization"] = self._token64

        # Ask the server whether the token is still good. Never infer this from
        # the clock: a token well inside its expiry can already be dead server
        # side, and only this call knows.
        response = self.auth_get_full(
            AUTH_VALIDATE_PATH + "?data = {}".format(int(time.time())), {}, headers
        )
        self._validate_action = response.action
        if not response.ok or response.body is None:
            message = f"token validation failed: {response.describe()}"
            if quiet:
                self._arlo.debug(message)
            else:
                self._arlo.error(message)
            return False
        return True

    def _has_saved_session(self):
        return all((
            self._user_id,
            self._web_id,
            self._sub_id,
            self._token,
            self._token64,
            self._expires_in,
        ))

    def _reuse_saved_session(self):
        if not self._has_saved_session():
            return False

        try:
            expires_in = int(self._expires_in)
        except (TypeError, ValueError):
            self._arlo.debug("saved session has invalid expiry")
            return False

        if expires_in <= int(time.time()) + 60:
            self._arlo.debug("saved session expired")
            return False

        self._arlo.debug("validating saved trusted session")
        if not self._validate(quiet=True):
            # The server refused the token, so it is worthless. Anything other
            # than a transport blip means keeping it only guarantees the same
            # failure next time, so drop it and fall through to a full login.
            if self._validate_action is not ErrorAction.RETRY:
                self._discard_saved_session(
                    f"validation rejected it ({self._validate_action.name})"
                )
                # 9276/9233 mean two-step auth was never completed for this
                # session, so the browser has to be paired again.
                if self._validate_action is ErrorAction.AUTH_PENDING:
                    self._needs_pairing = True
            return False

        self._needs_pairing = False
        self._save_cookies(self._cookies)
        self._arlo.debug("saved trusted session accepted")
        return True

    def _auth_or_reuse_saved_session(self):
        if self._reuse_saved_session():
            return AuthResult.SUCCESS

        success = self._auth()
        if success == AuthResult.SUCCESS and not (self._validate() and self._pair_auth_code()):
            return AuthResult.FAILED
        return success

    def _pair_auth_code(self):
        headers = self._auth_headers()
        headers["Authorization"] = self._token64

        if not self._needs_pairing:
            self._arlo.debug("no pairing required")
            self._save_cookies(self._cookies)
            return True
        if self._browser_auth_code is None:
            self._arlo.debug("pairing postponed")
            return True

        # self._cookies = self._load_cookies()
        payload = {
            "factorAuthCode": self._browser_auth_code,
            "factorData": "",
            "factorType": "BROWSER"
        }
        self.auth_options(AUTH_START_PAIRING, headers)
        code, body = self.auth_post(AUTH_START_PAIRING, payload, headers, cookies=self._cookies)
        self._save_cookies(self._cookies)

        if code != 200:
            self._arlo.error(f"pairing: failed: {code} - {body}")
            return False

        self._arlo.debug("pairing succeeded")
        return True

    def _v2_session(self, allow_reauth=True):
        response = self._request_full(SESSION_PATH)
        if not response.ok:
            # "session start failed" used to be the whole story, so a dead token
            # and an Arlo outage read identically. Keep the code, and when the
            # session is the problem earn a new one rather than failing the
            # login outright - but only once, so this cannot recurse.
            if allow_reauth and response.action is ErrorAction.REAUTH:
                self._arlo.debug(
                    f"session start rejected ({response.describe()}), re-authenticating"
                )
                self._discard_saved_session("session start was rejected")
                if self._auth_or_reuse_saved_session() != AuthResult.SUCCESS:
                    self._arlo.error(f"session start failed: {response.describe()}")
                    self._last_auth_action = response.action
                    return False
                self._session.headers.update(self._headers())
                return self._v2_session(allow_reauth=False)

            self._arlo.error(f"session start failed: {response.describe()}")
            self._last_auth_action = response.action
            return False

        v2_session = response.body
        self._multi_location = v2_session.get('supportsMultiLocation', False)
        self._arlo.debug(f"multilocation is {self._multi_location}")

        # If Arlo provides an MQTT URL key use it to set the backend.
        if MQTT_URL_KEY in v2_session:
            self._arlo.cfg.update_mqtt_from_url(v2_session[MQTT_URL_KEY])
            self._arlo.debug(f"back={self._arlo.cfg.event_backend};url={self._arlo.cfg.mqtt_host}:{self._arlo.cfg.mqtt_port}")
        return True

    def _create_session(self, curve=None):
        """Create the HTTP session using the configured backend."""
        if self._arlo.cfg.http_backend == "curl_cffi":
            from curl_cffi import requests as cffi_requests
            for impersonate in _curl_cffi_impersonations(self._arlo.cfg.curl_cffi_impersonate):
                try:
                    self._session = cffi_requests.Session(impersonate=impersonate)
                    self.debug(f"curl_cffi impersonate={impersonate}")
                    break
                except Exception:
                    continue
            else:
                self._session = cffi_requests.Session(impersonate=self._arlo.cfg.curl_cffi_impersonate)
                self.debug(f"curl_cffi impersonate={self._arlo.cfg.curl_cffi_impersonate}")
        else:
            import cloudscraper
            self._session = cloudscraper.create_scraper(
                disableCloudflareV1=True,
                ecdhCurve=curve,
                debug=False,
            )
        if self._cookies is not None:
            self._session.cookies = self._cookies

    def _login(self):
        # Reset the reason: a caller reading it after we return must see this
        # attempt's outcome, not a stale one from an earlier try.
        self._last_auth_action = None

        # pickup user configured user agent
        self._user_agent = self.user_agent(self._arlo.cfg.user_agent)

        # we always login but and let the backend determine if we need to
        # use 2fa
        success = AuthResult.FAILED
        if self._arlo.cfg.http_backend == "curl_cffi":
            self._create_session()
            success = self._auth_or_reuse_saved_session()
            if success == AuthResult.FAILED:
                return self._login_failed()
        else:
            for curve in self._arlo.cfg.ecdh_curves:
                self.debug(f"CloudFlare curve set to: {curve}")
                self._create_session(curve=curve)

                # Try to authenticate. We retry if it was a cloud flare
                # error or we failed to get the 2FA code.
                success = self._auth_or_reuse_saved_session()
                if success == AuthResult.FAILED:
                    return self._login_failed()
                if success == AuthResult.SUCCESS:
                    break
                success = AuthResult.FAILED
                self.debug("login failed, trying another ecdh_curve")

        if success != AuthResult.SUCCESS:
            # Every curve was exhausted without a definitive answer, so this is
            # worth another go later rather than a permanent failure.
            return self._login_failed(ErrorAction.RETRY)

        # update sessions headers
        headers = self._headers()
        self._session.headers.update(headers)

        # Grab a session. Needed for new session and used to check existing
        # session. (May not really be needed for existing but will fail faster.)
        if not self._v2_session():
            return self._login_failed()

        # save session now we know the credentials actually work; saving any
        # earlier persists tokens that every later run would blindly reuse
        self._save_session()
        self._last_auth_action = ErrorAction.OK
        return True

    def _login_failed(self, action=None):
        """Record why the login failed, then report the failure.

        `_login()` returns a bare bool, which used to throw away the only thing
        a caller needs in order to decide between trying again later and asking
        the user for new credentials.
        """
        if action is not None:
            self._last_auth_action = action
        elif self._last_auth_action in (None, ErrorAction.OK):
            # Nothing classified the failure, so assume it is worth retrying: a
            # wrong "permanent" verdict would keep us down until a restart.
            self._last_auth_action = ErrorAction.RETRY
        self.debug(f"failed to log in ({self._last_auth_action.name})")
        return False

    @property
    def last_auth_action(self):
        """How the last login attempt failed, as an :class:`ErrorAction`."""
        return self._last_auth_action or ErrorAction.RETRY

    @property
    def auth_failed_permanently(self):
        """True when retrying the login cannot possibly help.

        Credentials are wrong or expired, or the account is locked. Callers
        should stop retrying and ask the user, instead of hammering the API.
        """
        return is_permanent(self.last_auth_action)

    def _notify_full(self, base, body, trans_id=None):
        """As :meth:`_notify`, but keeping the classified response.

        Base-station failures carry their code in the legacy `data.error` field -
        2059 and 2222 both mean the base station is not answering - which a
        body-only caller cannot tell apart from a dead session.
        """
        if trans_id is None:
            trans_id = self.gen_trans_id()

        body["to"] = base.device_id
        if "from" not in body:
            body["from"] = self._web_id
        body["transId"] = trans_id

        return self._request_full(
            NOTIFY_PATH + base.device_id,
            "POST",
            params=body,
            headers={"xcloudId": base.xcloud_id},
        )

    def _notify(self, base, body, trans_id=None):
        if trans_id is None:
            trans_id = self.gen_trans_id()

        response = self._notify_full(base, body, trans_id=trans_id)
        return trans_id if response.ok else None

    def _start_transaction(self, tid=None):
        if tid is None:
            tid = self.gen_trans_id()
        self.vdebug("starting transaction-->{}".format(tid))
        with self._lock:
            self._requests[tid] = None
        return tid

    def _wait_for_transaction(self, tid, timeout):
        if timeout is None:
            timeout = self._arlo.cfg.request_timeout
        mnow = time.monotonic()
        mend = mnow + timeout

        self.vdebug("finishing transaction-->{}".format(tid))
        with self._lock:
            try:
                while mnow < mend and self._requests[tid] is None:
                    self._lock.wait(mend - mnow)
                    mnow = time.monotonic()
                response = self._requests.pop(tid)
            except KeyError:
                self.debug("got a key error")
                response = None
        self.vdebug("finished transaction-->{}".format(tid))
        return response

    @property
    def is_connected(self):
        return self._logged_in

    def stop(self):
        """Stop the event stream thread and wait for it to exit.

        Without this, dropping a PyArlo reference leaves ghost threads
        that hold stale connections and attempt their own re-logins,
        interfering with any new PyArlo instance in the same process.
        See https://github.com/twrecked/pyaarlo/issues/71
        """
        self.debug("stopping backend")
        self._event_stop_loop()
        if self._event_client is not None:
            try:
                if self._use_mqtt:
                    self._event_client.disconnect()
                else:
                    self._event_client.stop()
            except Exception:
                pass
        if self._event_thread is not None and self._event_thread.is_alive():
            self._event_thread.join(timeout=10)

    def logout(self):
        """Stop the event stream and log out of the Arlo API."""
        self.debug("trying to logout")
        self.stop()
        self.put(LOGOUT_PATH)

    def notify(self, base, body, timeout=None, wait_for=None):
        """Send in a notification.

        Notifications are Arlo's way of getting stuff done - turn on a light, change base station mode,
        start recording. Pyaarlo will post a notification and Arlo will post a reply on the event
        stream indicating if it worked or not or of a state change.

        How Pyaarlo treats notifications depends on the mode it's being run in. For asynchronous mode - the
        default - it sends the notification and returns immediately. For synchronous mode it sends the
        notification and waits for the event related to the notification to come back. To use the default
        settings leave `wait_for` as `None`, to force asynchronous set `wait_for` to `nothing` and to force
        synchronous set `wait_for` to `event`.

        There is a third way to send a notification where the code waits for the initial response to come back
        but that must be specified by setting `wait_for` to `response`.

        :param base: base station to use
        :param body: notification message
        :param timeout: how long to wait for response before failing, only applied if `wait_for` is `event`.
        :param wait_for: what to wait for, either `None`, `event`, `response` or `nothing`.
        :return: either a response packet or an event packet
        """
        if wait_for is None:
            wait_for = "event" if self._arlo.cfg.synchronous_mode else "nothing"

        if wait_for == "event":
            self.vdebug("notify+event running")
            tid = self._start_transaction()
            self._notify(base, body=body, trans_id=tid)
            return self._wait_for_transaction(tid, timeout)
            # return self._notify_and_get_event(base, body, timeout=timeout)
        elif wait_for == "response":
            self.vdebug("notify+response running")
            return self._notify(base, body=body)
        else:
            self.vdebug("notify+ sent")
            self._arlo.bg.run(self._notify, base=base, body=body)

    def notify_full(self, base, body):
        """Send a notification, waiting for the response and keeping its detail.

        Use this instead of `notify(wait_for="response")` when the caller has to
        distinguish "the base station is offline" from "our session is dead" -
        both of which otherwise just come back as None.
        """
        return self._notify_full(base, body)

    def get(
        self,
        path,
        params=None,
        headers=None,
        stream=False,
        raw=False,
        timeout=None,
        host=None,
        wait_for="response",
        cookies=None,
    ):
        if wait_for == "response":
            self.vdebug("get+response running")
            # Keyword arguments only: passing these positionally silently landed
            # `cookies` on `authpost`, which dropped the transaction id and left
            # the cookie jar unused.
            return self._request(
                path, "GET", params=params, headers=headers, stream=stream, raw=raw,
                timeout=timeout, host=host, cookies=cookies,
            )
        else:
            self.vdebug("get sent")
            self._arlo.bg.run(
                self._request, path, "GET", params=params, headers=headers,
                stream=stream, raw=raw, timeout=timeout, host=host, cookies=cookies,
            )

    def get_full(
        self,
        path,
        params=None,
        headers=None,
        raw=False,
        timeout=None,
        host=None,
        cookies=None,
    ):
        """As :meth:`get`, but keeping the code and the classification.

        `get`/`put`/`post` return the body alone, so a caller seeing None cannot
        say whether the token expired, the request timed out, or Arlo simply had
        nothing to give. Use this where that difference matters.
        """
        return self._request_full(
            path, "GET", params=params, headers=headers, raw=raw, timeout=timeout,
            host=host, cookies=cookies,
        )

    def put_full(
        self,
        path,
        params=None,
        headers=None,
        raw=False,
        timeout=None,
        cookies=None,
    ):
        """As :meth:`put`, but keeping the code and the classification."""
        return self._request_full(
            path, "PUT", params=params, headers=headers, raw=raw, timeout=timeout,
            cookies=cookies,
        )

    def put(
        self,
        path,
        params=None,
        headers=None,
        raw=False,
        timeout=None,
        wait_for="response",
        cookies=None,
    ):
        if wait_for == "response":
            self.vdebug("put+response running")
            # Keyword arguments only: positionally, `cookies` became `host` and
            # was used as the base URL.
            return self._request(
                path, "PUT", params=params, headers=headers, raw=raw, timeout=timeout,
                cookies=cookies,
            )
        else:
            self.vdebug("put sent")
            self._arlo.bg.run(
                self._request, path, "PUT", params=params, headers=headers, raw=raw,
                timeout=timeout, cookies=cookies,
            )

    def post(
        self,
        path,
        params=None,
        headers=None,
        raw=False,
        timeout=None,
        tid=None,
        wait_for="response"
    ):
        """Post a request to the Arlo servers.

        Posts are used to retrieve data from the Arlo servers. Mostly. They are also used to change
        base station modes.

        The default mode of operation is to wait for a response from the http request. The `wait_for`
        variable can change the operation. Setting it to `response` waits for a http response.
        Setting it to `resource` waits for the resource in the `params` parameter to appear in the event
        stream. Setting it to `nothing` causing the post to run in the background. Setting it to `None`
        uses `resource` in synchronous mode and `response` in asynchronous mode.
        """
        if wait_for is None:
            wait_for = "resource" if self._arlo.cfg.synchronous_mode else "response"

        if wait_for == "resource":
            self.vdebug("notify+resource running")
            if tid is None:
                tid = list(params.keys())[0]
            tid = self._start_transaction(tid)
            self._request(path, "POST", params=params, headers=headers, raw=raw, timeout=timeout)
            return self._wait_for_transaction(tid, timeout)
        if wait_for == "response":
            self.vdebug("post+response running")
            return self._request(path, "POST", params=params, headers=headers, raw=raw, timeout=timeout)
        else:
            self.vdebug("post sent")
            self._arlo.bg.run(
                self._request, path, "POST", params=params, headers=headers, raw=raw,
                timeout=timeout,
            )

    def auth_post(self, path, params=None, headers=None, raw=False, timeout=None, cookies=None):
        return self._request_tuple(
            path, "POST", params=params, headers=headers, raw=raw, timeout=timeout,
            host=self._arlo.cfg.auth_host, authpost=True, cookies=cookies,
        )

    def auth_post_full(self, path, params=None, headers=None, raw=False, timeout=None, cookies=None):
        """As :meth:`auth_post`, but keeping the classified error detail."""
        return self._request_full(
            path, "POST", params=params, headers=headers, raw=raw, timeout=timeout,
            host=self._arlo.cfg.auth_host, authpost=True, cookies=cookies,
        )

    def auth_get(
        self, path, params=None, headers=None, stream=False, raw=False, timeout=None, cookies=None
    ):
        return self._request(
            path, "GET", params=params, headers=headers, stream=stream, raw=raw,
            timeout=timeout, host=self._arlo.cfg.auth_host, authpost=True, cookies=cookies,
        )

    def auth_get_tuple(
        self, path, params=None, headers=None, stream=False, raw=False, timeout=None, cookies=None
    ):
        return self._request_tuple(
            path, "GET", params=params, headers=headers, stream=stream, raw=raw,
            timeout=timeout, host=self._arlo.cfg.auth_host, authpost=True, cookies=cookies,
        )

    def auth_get_full(
        self, path, params=None, headers=None, stream=False, raw=False, timeout=None, cookies=None
    ):
        """As :meth:`auth_get`, but keeping the classified error detail."""
        return self._request_full(
            path, "GET", params=params, headers=headers, stream=stream, raw=raw,
            timeout=timeout, host=self._arlo.cfg.auth_host, authpost=True, cookies=cookies,
        )

    def auth_options(
        self, path, headers=None, timeout=None
     ):
        return self._request(
            path, "OPTIONS", headers=headers, timeout=timeout,
            host=self._arlo.cfg.auth_host, authpost=True,
        )

    @property
    def session(self):
        return self._session

    @property
    def sub_id(self):
        return self._sub_id

    @property
    def user_id(self):
        return self._user_id

    @property
    def multi_location(self):
        return self._multi_location

    def add_listener(self, device, callback):
        with self._lock:
            if device.device_id not in self._callbacks:
                self._callbacks[device.device_id] = []
            self._callbacks[device.device_id].append(callback)
            if device.unique_id not in self._callbacks:
                self._callbacks[device.unique_id] = []
            self._callbacks[device.unique_id].append(callback)

    def add_any_listener(self, callback):
        with self._lock:
            if "all" not in self._callbacks:
                self._callbacks["all"] = []
            self._callbacks["all"].append(callback)

    def del_listener(self, device, callback):
        pass

    def devices(self):
        return self.get(DEVICES_PATH + "?t={}".format(time_to_arlotime()))

    def user_agent(self, agent):
        """Map `agent` to a real user agent.

        User provides a default user agent they want for most interactions but it can be overridden
        for stream operations.

        `!real-string` will use the provided string as-is, used when passing user agent
        from a browser.

        `random` will provide a different user agent for each log in attempt.
        """
        if agent.startswith("!"):
            self.debug(f"using user supplied user_agent {agent[:70]}")
            return agent[1:]
        agent = agent.lower()
        self.debug(f"looking for user_agent {agent}")
        if agent == "random":
            return self.user_agent(random.choice(list(USER_AGENTS.keys())))
        return USER_AGENTS.get(agent, USER_AGENTS["linux"])

    def ev_inject(self, response):
        self._event_dispatcher(response)

    def debug(self, msg):
        self._arlo.debug(f"backend: {msg}")

    def vdebug(self, msg):
        self._arlo.vdebug(f"backend: {msg}")
