"""A stand in for the Arlo auth and API hosts, good enough to log in against.

It implements the handful of endpoints `ArloBackEnd._login` walks through, with
the same response envelopes the real thing uses - `meta` on the auth host,
`success` on the api host - and records every request so tests can assert on
what the client actually did.

Browser trust is modelled the way Arlo does it: `startPairingFactor` sets a
cookie, and `getFactorId` only hands back a BROWSER factor when it sees that
cookie come back.
"""

import json
import threading
import time
from base64 import b64encode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MINUTE = 60
HOUR = 60 * MINUTE

TRUST_COOKIE = "arlo_trusted"

FACTORS = [
    {"factorId": "f-mail-home", "factorType": "EMAIL", "factorRole": "PRIMARY",
     "factorNickname": "home@example.com", "displayName": "home@example.com"},
    {"factorId": "f-push-pix", "factorType": "PUSH", "factorRole": "SECONDARY",
     "factorNickname": "Pixel 9", "displayName": "Pixel 9"},
]


class FakeArlo:
    """The state and policy behind the server, so tests can poke at it."""

    def __init__(self, username, password, otp="123456"):
        self.username = username
        self.password = password
        self.otp = otp

        # Knobs for the tests.
        self.token = "token-1"
        # What a real Arlo token was measured at. `expiresIn` comes back as an
        # absolute epoch in seconds, not a duration.
        self.token_lifetime = 2 * HOUR
        self.reject_token = False
        self.mfa_enabled = True
        # What getFactorId answers when the browser has never been paired.
        # 9204 on the classic backend, 9261 on the PingOne one.
        self.untrusted_error = 9204

        # Push approval. By default the user taps approve straight away; set
        # push_polls_before_approval to make them take their time, or
        # push_denied to have them tap deny.
        self.push_polls = 0
        self.push_polls_before_approval = 0
        self.push_denied = False

        # Recorded traffic.
        self.calls = []
        self.paired_browsers = set()

    def called(self, path):
        return sum(1 for c in self.calls if c == path)

    def expires_in(self):
        return time.time() + self.token_lifetime

    def access_token(self, browser_auth_code=None):
        body = {
            "token": self.token,
            "userId": "u1",
            "expiresIn": self.expires_in(),
            "authCompleted": True,
        }
        if browser_auth_code is not None:
            body["browserAuthCode"] = browser_auth_code
        return body

    def token_is_valid(self, authorization):
        if self.reject_token:
            return False
        expected = b64encode(self.token.encode()).decode()
        return authorization == expected


def _handler_for(state):

    class Handler(BaseHTTPRequestHandler):

        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        # -- plumbing ----------------------------------------------------

        def _body(self):
            """Read and decode the request body.

            Always call this, even when the body is not wanted. Anything left
            in the socket gets read as the head of the next request on a
            keep-alive connection. Note pyaarlo sends a `{}` body on its OPTIONS
            preflights, which a browser would not.
            """
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return {}
            raw = self.rfile.read(length)
            try:
                return json.loads(raw)
            except ValueError:
                return {}

        def _path(self):
            return self.path.split("?")[0]

        def _send(self, payload, code=200, cookie=None):
            raw = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            if cookie is not None:
                self.send_header("Set-Cookie", f"{TRUST_COOKIE}={cookie}; Path=/")
            self.end_headers()
            self.wfile.write(raw)

        def _meta(self, data, code=200, cookie=None):
            """Auth host envelope."""
            self._send({"meta": {"code": code, "error": 0, "message": "ok"},
                        "data": data}, code=200, cookie=cookie)

        def _meta_error(self, code, error, message):
            self._send({"meta": {"code": code, "error": error, "message": message}},
                       code=200)

        def _success(self, data):
            """Api host envelope."""
            self._send({"success": True, "data": data})

        def _trusted(self):
            return TRUST_COOKIE in (self.headers.get("Cookie") or "")

        # -- routes ------------------------------------------------------

        def do_OPTIONS(self):
            self._body()
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            self._body()
            path = self._path()
            state.calls.append(path)

            if path == "/api/validateAccessToken":
                if not state.token_is_valid(self.headers.get("Authorization")):
                    return self._meta_error(401, 9204, "token is not valid")
                return self._meta({"userId": "u1", "email": state.username,
                                   "emailConfirmed": True})

            if path == "/api/getFactors":
                return self._meta({"items": FACTORS})

            if path == "/hmsweb/users/session/v3":
                return self._success({"supportsMultiLocation": False})

            return self._send({"error": "not found"}, code=404)

        def do_PUT(self):
            self._body()
            state.calls.append(self._path())
            return self._success({})

        def do_POST(self):
            path = self._path()
            state.calls.append(path)
            body = self._body()

            if path == "/api/auth":
                password = b64encode(state.password.encode()).decode()
                if body.get("email") != state.username or body.get("password") != password:
                    return self._meta_error(401, 9000, "bad credentials")
                data = state.access_token()
                data["mfa"] = state.mfa_enabled
                data["authCompleted"] = not state.mfa_enabled
                return self._meta(data)

            if path == "/api/getFactorId":
                # Only a browser we have paired before gets the fast path.
                if not self._trusted():
                    return self._meta_error(
                        401, state.untrusted_error, "browser is not trusted")
                return self._meta({"factorId": "f-browser"})

            if path == "/api/startAuth":
                # Dispatch on the factor, not on factorType. pyaarlo sends
                # factorType BROWSER even when starting an EMAIL or SMS code,
                # where the web app sends "", and the real server clearly
                # tolerates that or nobody's imap 2FA would work.
                if body.get("factorId") == "f-browser":
                    # Trusted browser, straight to a full token.
                    return self._meta({"accessToken": state.access_token()})
                return self._meta({"factorAuthCode": "fac-1"})

            if path == "/api/finishAuth":
                if body.get("factorAuthCode") != "fac-1":
                    return self._meta_error(400, 9001, "unknown factorAuthCode")

                if "otp" not in body:
                    # No otp means the push flow: the client is asking whether
                    # the user has tapped approve yet.
                    state.push_polls += 1
                    if state.push_denied:
                        # 9239 is what the web app maps to a denied push.
                        return self._meta_error(400, 9239, "denied")
                    if state.push_polls <= state.push_polls_before_approval:
                        return self._meta_error(400, 9001, "not approved yet")
                    return self._meta(state.access_token(browser_auth_code="bac-1"))

                if body.get("otp") != state.otp:
                    return self._meta_error(400, 9001, "wrong otp")
                return self._meta(state.access_token(browser_auth_code="bac-1"))

            if path == "/api/startPairingFactor":
                if body.get("factorAuthCode") != "bac-1":
                    return self._meta_error(400, 9001, "unknown browserAuthCode")
                # This is what makes the browser trusted from here on.
                state.paired_browsers.add(self.headers.get("X-User-Device-Id"))
                return self._meta({}, cookie="yes")

            return self._send({"error": "not found"}, code=404)

    return Handler


class FakeArloServer:
    """Runs `FakeArlo` on a background thread. Use as a context manager."""

    def __init__(self, username, password, otp="123456"):
        self.state = FakeArlo(username, password, otp)
        # Threaded, otherwise a keep-alive connection blocks every other one.
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(self.state))
        self._thread = threading.Thread(target=self._server.serve_forever)
        self._thread.daemon = True

    @property
    def url(self):
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
