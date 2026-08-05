"""Tests for the SIP/WebRTC live-view protocol helpers and eligibility logic.

These target the pure protocol-framing functions in pyaarlo.webrtc (verified
by hand against a real captured Arlo session) and the eligibility/fallback
logic in pyaarlo.camera, using lightweight duck-typed fakes rather than a
full ArloCamera instance so the tests don't need real device/backend wiring.
"""
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from pyaarlo.camera import ArloCamera, _get_model_capabilities, _model_capabilities_cache
from pyaarlo.webrtc import (
    _build_ice_servers,
    _http_over_ws_message,
    _parse_http_over_ws_message,
    _rewritten_sip_call_info,
)


# ---------------------------------------------------------------------------
# pyaarlo.webrtc protocol helpers
# ---------------------------------------------------------------------------

def test_rewritten_sip_call_info_drops_and_rewrites_fields():
    original = {
        "calleeUri": "sip:AKB123_x@livestream-z1-prod.arlo.com:443",
        "id": "Conference_x_caller",
        "password": "secret",
        "domain": "livestream-z1-prod.arlo.com",
        "port": 443,
        "deviceId": "AKB123",
        "callId": "abc",
        "conferenceId": None,
    }
    rewritten = _rewritten_sip_call_info(original, "livestream-z1-prod.arlo.com:7443")
    assert rewritten == {
        "calleeUri": original["calleeUri"],
        "id": original["id"],
        "password": original["password"],
        "domain": "livestream-z1-prod.arlo.com:7443",
        "port": "7443",
    }
    # deviceId/callId/conferenceId must not leak into the wire message
    assert "deviceId" not in rewritten
    assert "callId" not in rewritten
    assert "conferenceId" not in rewritten


def test_http_over_ws_message_matches_captured_format():
    body = {"sipCallInfo": {"id": "x"}, "payload": {"sessionId": "sid"}}
    message = _http_over_ws_message(
        "POST /hmswebsocketproxy/initiateOffer", "livestream-z1-prod.arlo.com:7443", body
    )
    header, _, raw_body = message.partition("\r\n\r\n")
    lines = header.split("\r\n")
    assert lines[0] == "POST /hmswebsocketproxy/initiateOffer HTTP/1.1"
    assert "Host: livestream-z1-prod.arlo.com:7443" in lines
    assert "User-Agent: ArloWebRTC/1 CFNetwork/1329 Darwin/21.3.0" in lines
    assert "Content-Length: {}".format(len(json.dumps(body))) in lines
    assert json.loads(raw_body) == body


def test_parse_http_over_ws_message_success():
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "X-Powered-By: Express\r\n"
        "Content-Type: application/json\r\n"
        "\r\n"
        '{"data":{"payload":{"answer":{"format":"SDP","value":"v=0..."}}},'
        '"sessionId":"sid","success":true}'
    )
    parsed = _parse_http_over_ws_message(raw)
    assert parsed["success"] is True
    assert parsed["data"]["payload"]["answer"]["value"] == "v=0..."


def test_parse_http_over_ws_message_failure():
    raw = (
        "HTTP/1.1 200 OK\r\n\r\n"
        '{"data":{"payload":{"answer":{"format":"SDP","value":""}}},'
        '"success":false,"message":"Login Incorrect","code":-32001}'
    )
    parsed = _parse_http_over_ws_message(raw)
    assert parsed["success"] is False
    assert parsed["message"] == "Login Incorrect"


def test_build_ice_servers():
    servers = _build_ice_servers([
        {"type": "stun", "domain": "relay02-z1-prod.ar.arlo.com", "port": "19302"},
        {
            "type": "turn",
            "domain": "relay02-z1-prod.ar.arlo.com",
            "port": "443",
            "transport": "tcp",
            "username": "u",
            "credential": "c",
        },
    ])
    assert len(servers) == 2
    assert servers[0].urls == "stun:relay02-z1-prod.ar.arlo.com:19302"
    assert servers[1].urls == "turn:relay02-z1-prod.ar.arlo.com:443"
    assert servers[1].username == "u"
    assert servers[1].credential == "c"


def test_build_ice_servers_empty():
    assert _build_ice_servers(None) == []
    assert _build_ice_servers([]) == []


# ---------------------------------------------------------------------------
# _get_model_capabilities (public, unauthenticated capability document fetch)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_capabilities_cache():
    _model_capabilities_cache.clear()
    yield
    _model_capabilities_cache.clear()


def test_get_model_capabilities_caches_by_model(monkeypatch):
    calls = []

    def fake_http_get(url):
        calls.append(url)
        return json.dumps({"Capabilities": {"Streaming": {"SIPStreaming": {}}}}).encode()

    monkeypatch.setattr("pyaarlo.camera.http_get", fake_http_get)

    caps1 = _get_model_capabilities("VMC4070PA")
    caps2 = _get_model_capabilities("vmc4070pa")  # different case, same model
    assert caps1 == caps2
    assert caps1["Streaming"]["SIPStreaming"] == {}
    # only fetched once - second/lowercased call served from cache
    assert len(calls) == 1


def test_get_model_capabilities_handles_failure(monkeypatch):
    monkeypatch.setattr("pyaarlo.camera.http_get", lambda url: False)
    assert _get_model_capabilities("UNKNOWNMODEL") is None


def test_get_model_capabilities_none_model_id():
    assert _get_model_capabilities(None) is None
    assert _get_model_capabilities("") is None


# ---------------------------------------------------------------------------
# ArloCamera.supports_sip_webrtc_streaming() - duck-typed fakes, no full
# ArloCamera/backend wiring needed since the method only touches model_id/
# parent_id/device_id/base_station.
# ---------------------------------------------------------------------------

def _fake_camera(model_id, device_id, parent_id, base_station=None):
    return SimpleNamespace(
        model_id=model_id,
        device_id=device_id,
        parent_id=parent_id,
        base_station=base_station,
        supports_sip_webrtc_streaming=ArloCamera.supports_sip_webrtc_streaming,
    )


def _patch_capabilities(monkeypatch, table):
    """table: dict of model_id.lower() -> Capabilities dict (or None)."""
    def fake(model_id):
        return table.get((model_id or "").lower())

    monkeypatch.setattr("pyaarlo.camera._get_model_capabilities", fake)


def test_gateway_camera_eligible_when_sip_capability_present(monkeypatch):
    _patch_capabilities(monkeypatch, {
        "vmc4070pa": {"Streaming": {"SIPStreaming": {"protocol": "sip"}}},
    })
    cam = _fake_camera("VMC4070PA", "AKB1", "AKB1")  # own parent -> Gateway
    assert cam.supports_sip_webrtc_streaming(cam) is True


def test_gateway_camera_not_eligible_without_sip_capability(monkeypatch):
    _patch_capabilities(monkeypatch, {
        "vmc3030": {"Streaming": {"CloudStreaming": {}}},
    })
    cam = _fake_camera("VMC3030", "AKB1", "AKB1")
    assert cam.supports_sip_webrtc_streaming(cam) is False


def test_satellite_camera_needs_parent_sip_live_stream_flag(monkeypatch):
    _patch_capabilities(monkeypatch, {
        "vmc4070pb": {"Streaming": {"SIPStreaming": {"protocol": "sip"}}},
        "vmb5000": {"sipLiveStream": {"supported": True}},
    })
    base = SimpleNamespace(model_id="VMB5000")
    cam = _fake_camera("VMC4070PB", "CAM1", "BASE1", base_station=base)
    assert cam.supports_sip_webrtc_streaming(cam) is True


def test_satellite_camera_not_eligible_without_parent_flag(monkeypatch):
    _patch_capabilities(monkeypatch, {
        "vmc4070pb": {"Streaming": {"SIPStreaming": {"protocol": "sip"}}},
        "vmb5000": {},  # no sipLiveStream at all
    })
    base = SimpleNamespace(model_id="VMB5000")
    cam = _fake_camera("VMC4070PB", "CAM1", "BASE1", base_station=base)
    assert cam.supports_sip_webrtc_streaming(cam) is False


def test_satellite_camera_no_base_station_found(monkeypatch):
    _patch_capabilities(monkeypatch, {
        "vmc4070pb": {"Streaming": {"SIPStreaming": {"protocol": "sip"}}},
    })
    cam = _fake_camera("VMC4070PB", "CAM1", "BASE1", base_station=None)
    assert cam.supports_sip_webrtc_streaming(cam) is False


def test_unknown_model_capabilities_fetch_failed(monkeypatch):
    _patch_capabilities(monkeypatch, {})
    cam = _fake_camera("VMC3030", "AKB1", "AKB1")
    assert cam.supports_sip_webrtc_streaming(cam) is False


# ---------------------------------------------------------------------------
# _start_stream_with_webrtc_fallback() - falls back to RTSP-cloud on ANY
# failure of the WebRTC path, and doesn't even try it when ineligible or
# disabled via config.
# ---------------------------------------------------------------------------

def _fake_camera_for_fallback(eligible, disable_cfg, webrtc_raises=None, webrtc_url="tcp://127.0.0.1:1234"):
    cam = SimpleNamespace()
    cam._arlo = SimpleNamespace(cfg=SimpleNamespace(disable_sip_webrtc_streaming=disable_cfg))
    cam._lock = MagicMock()
    cam._lock.__enter__ = MagicMock(return_value=None)
    cam._lock.__exit__ = MagicMock(return_value=False)
    cam._local_users = set()
    cam._webrtc_session = None
    cam.supports_sip_webrtc_streaming = MagicMock(return_value=eligible)
    cam.debug = MagicMock()
    cam._start_stream = MagicMock(return_value="rtsps://fallback.example/stream")

    class FakeSession:
        def __init__(self, camera):
            pass

        def start(self, timeout=15):
            if webrtc_raises is not None:
                raise webrtc_raises
            return webrtc_url

    with patch("pyaarlo.webrtc.ArloWebRtcSession", FakeSession):
        return ArloCamera._start_stream_with_webrtc_fallback(cam, "arlo")


def test_fallback_not_attempted_when_ineligible():
    url = _fake_camera_for_fallback(eligible=False, disable_cfg=False)
    assert url == "rtsps://fallback.example/stream"


def test_fallback_not_attempted_when_disabled_by_config():
    url = _fake_camera_for_fallback(eligible=True, disable_cfg=True)
    assert url == "rtsps://fallback.example/stream"


def test_webrtc_used_when_eligible_and_succeeds():
    url = _fake_camera_for_fallback(eligible=True, disable_cfg=False)
    assert url == "tcp://127.0.0.1:1234"


def test_falls_back_to_rtsp_cloud_on_any_webrtc_failure():
    url = _fake_camera_for_fallback(
        eligible=True, disable_cfg=False, webrtc_raises=RuntimeError("ICE failed")
    )
    assert url == "rtsps://fallback.example/stream"
