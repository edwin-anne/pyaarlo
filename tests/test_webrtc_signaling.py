"""Tests for pyaarlo.webrtc_signaling - the aiortc-free relay-only client.

No pytest-asyncio dependency: each test drives its coroutine with a plain
asyncio.run(), matching how the rest of this test suite avoids adding new
test-only dependencies where a stdlib approach works just as well.
"""
import asyncio
import json
from unittest.mock import patch

import pytest

from pyaarlo.webrtc_signaling import (
    WebRtcSignalingError,
    async_close_session,
    async_negotiate_offer,
    ice_server_kwargs,
)


SIP_CALL_INFO = {
    "calleeUri": "sip:AKB123_x@livestream-z1-prod.arlo.com:443",
    "id": "Conference_x_caller",
    "password": "secret",
    "domain": "livestream-z1-prod.arlo.com",
    "port": 443,
    "deviceId": "AKB123",
}


class FakeConnection:
    """Stands in for what `await websockets.connect(...)` returns."""

    def __init__(self, responses=None, raise_on_connect=None):
        self.responses = list(responses or [])
        self.sent = []
        self.closed = False
        self._raise_on_connect = raise_on_connect

    async def __aenter__(self):
        if self._raise_on_connect is not None:
            raise self._raise_on_connect
        return self

    async def __aexit__(self, *exc_info):
        self.closed = True
        return False

    async def send(self, message):
        self.sent.append(message)

    async def recv(self):
        if not self.responses:
            raise AssertionError("recv() called with no queued response")
        return self.responses.pop(0)


def _http_ok(body_obj):
    body = json.dumps(body_obj)
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body


def _patched_connect(fake):
    async def _connect(*_args, **_kwargs):
        return fake

    return patch("pyaarlo.webrtc_signaling.websockets.connect", side_effect=_connect)


class TestAsyncNegotiateOffer:
    def test_success_returns_answer_sdp(self):
        fake = FakeConnection(responses=[
            _http_ok({
                "success": True,
                "data": {"payload": {"answer": {"format": "SDP", "value": "v=0...answer"}}},
            })
        ])
        with _patched_connect(fake):
            answer = asyncio.run(
                async_negotiate_offer(SIP_CALL_INFO, "AKB123", "v=0...offer")
            )
        assert answer == "v=0...answer"

    def test_sends_the_offer_verbatim_no_sdp_surgery(self):
        # Unlike webrtc.py's aiortc path, this module must never rewrite the
        # browser's own offer - that surgery exists only to compensate for
        # aiortc not being a real browser.
        fake = FakeConnection(responses=[
            _http_ok({
                "success": True,
                "data": {"payload": {"answer": {"value": "v=0...answer"}}},
            })
        ])
        offer = "v=0...untouched offer with weird=stuff"
        with _patched_connect(fake):
            asyncio.run(async_negotiate_offer(SIP_CALL_INFO, "AKB123", offer))

        assert len(fake.sent) == 1
        _headers, _, raw_body = fake.sent[0].partition("\r\n\r\n")
        sent_body = json.loads(raw_body)
        assert sent_body["payload"]["offer"] == {"format": "SDP", "value": offer}
        assert sent_body["payload"]["cameraId"] == "AKB123"

    def test_uses_a_fresh_session_id_when_none_given(self):
        fake = FakeConnection(responses=[
            _http_ok({"success": True, "data": {"payload": {"answer": {"value": "x"}}}})
        ])
        with _patched_connect(fake):
            asyncio.run(async_negotiate_offer(SIP_CALL_INFO, "AKB123", "offer"))
        _headers, _, raw_body = fake.sent[0].partition("\r\n\r\n")
        session_id = json.loads(raw_body)["payload"]["sessionId"]
        assert session_id  # non-empty, generated

    def test_reuses_a_supplied_session_id(self):
        fake = FakeConnection(responses=[
            _http_ok({"success": True, "data": {"payload": {"answer": {"value": "x"}}}})
        ])
        with _patched_connect(fake):
            asyncio.run(
                async_negotiate_offer(SIP_CALL_INFO, "AKB123", "offer", arlo_session_id="sid-123")
            )
        _headers, _, raw_body = fake.sent[0].partition("\r\n\r\n")
        assert json.loads(raw_body)["payload"]["sessionId"] == "sid-123"

    def test_rejection_raises_with_arlos_message(self):
        fake = FakeConnection(responses=[
            _http_ok({"success": False, "message": "Login Incorrect"})
        ])
        with _patched_connect(fake):
            with pytest.raises(WebRtcSignalingError, match="Login Incorrect"):
                asyncio.run(async_negotiate_offer(SIP_CALL_INFO, "AKB123", "offer"))

    def test_missing_answer_raises(self):
        fake = FakeConnection(responses=[
            _http_ok({"success": True, "data": {"payload": {}}})
        ])
        with _patched_connect(fake):
            with pytest.raises(WebRtcSignalingError, match="no answer"):
                asyncio.run(async_negotiate_offer(SIP_CALL_INFO, "AKB123", "offer"))

    def test_transport_failure_raises_signaling_error(self):
        fake = FakeConnection(raise_on_connect=OSError("connection refused"))
        with _patched_connect(fake):
            with pytest.raises(WebRtcSignalingError, match="OSError"):
                asyncio.run(async_negotiate_offer(SIP_CALL_INFO, "AKB123", "offer"))

    def test_malformed_response_raises_signaling_error_not_a_raw_exception(self):
        fake = FakeConnection(responses=["not even close to HTTP"])
        with _patched_connect(fake):
            with pytest.raises(WebRtcSignalingError):
                asyncio.run(async_negotiate_offer(SIP_CALL_INFO, "AKB123", "offer"))


class TestAsyncCloseSession:
    def test_sends_session_disconnected(self):
        fake = FakeConnection()
        with _patched_connect(fake):
            asyncio.run(async_close_session(SIP_CALL_INFO, "AKB123", "sid-123"))
        assert len(fake.sent) == 1
        assert "sessionDisconnected" in fake.sent[0]
        _headers, _, raw_body = fake.sent[0].partition("\r\n\r\n")
        body = json.loads(raw_body)
        assert body["payload"]["sessionId"] == "sid-123"
        assert body["payload"]["cameraId"] == "AKB123"
        # deviceId/callId/conferenceId must not leak into the wire message
        assert "deviceId" not in body["sipCallInfo"]

    def test_never_raises_on_transport_failure(self):
        fake = FakeConnection(raise_on_connect=OSError("gone"))
        with _patched_connect(fake):
            asyncio.run(async_close_session(SIP_CALL_INFO, "AKB123", "sid-123"))  # no raise

    def test_noop_without_a_session(self):
        # Nothing to disconnect if a session was never established.
        with _patched_connect(FakeConnection()) as mock_connect:
            asyncio.run(async_close_session(None, "AKB123", "sid-123"))
            asyncio.run(async_close_session(SIP_CALL_INFO, "AKB123", None))
        mock_connect.assert_not_called()


class TestIceServerKwargs:
    def test_extracts_from_sip_info_shape(self):
        sip_info = {
            "sipCallInfo": SIP_CALL_INFO,
            "iceServers": {
                "data": [
                    {"type": "stun", "domain": "relay.arlo.com", "port": "19302"},
                ]
            },
        }
        servers = ice_server_kwargs(sip_info)
        assert servers == [{"urls": "stun:relay.arlo.com:19302"}]

    def test_missing_ice_servers_is_empty(self):
        assert ice_server_kwargs({"sipCallInfo": SIP_CALL_INFO}) == []
