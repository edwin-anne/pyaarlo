"""Tests for the SIP/WebRTC live-view protocol helpers and eligibility logic.

These target the pure protocol-framing functions in pyaarlo.webrtc (verified
by hand against a real captured Arlo session) and the eligibility/fallback
logic in pyaarlo.camera, using lightweight duck-typed fakes rather than a
full ArloCamera instance so the tests don't need real device/backend wiring.
"""
import json
import threading
import time
from types import MethodType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from pyaarlo.camera import ArloCamera, _get_model_capabilities, _model_capabilities_cache
from pyaarlo.webrtc import (
    ArloWebRtcSession,
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
    assert servers[1].urls == "turn:relay02-z1-prod.ar.arlo.com:443?transport=tcp"
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
    cam._webrtc_starting = False
    cam._stream_url = None
    cam._dump_activities = MagicMock()
    cam.supports_sip_webrtc_streaming = MagicMock(return_value=eligible)
    cam.debug = MagicMock()
    cam._start_stream = MagicMock(return_value="rtsps://fallback.example/stream")
    # Real lease methods (not stubs): _start_stream_with_webrtc_fallback now
    # calls these for real, and the lock is a no-op MagicMock, so binding the
    # actual ArloCamera implementation exercises the real acquire/release
    # logic without needing real threading.
    cam.begin_webrtc_attempt = MethodType(ArloCamera.begin_webrtc_attempt, cam)
    cam.end_webrtc_attempt = MethodType(ArloCamera.end_webrtc_attempt, cam)

    class FakeSession:
        def __init__(self, camera):
            pass

        def start(self, timeout=15):
            if webrtc_raises is not None:
                raise webrtc_raises
            return webrtc_url

        def stop(self):
            pass

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


# ---------------------------------------------------------------------------
# WebRTC stream lifetime/ref-counting.
# ---------------------------------------------------------------------------

def _fake_camera_for_stop(local_users, webrtc_session=None):
    cam = ArloCamera.__new__(ArloCamera)
    cam._lock = threading.Condition()
    cam._local_users = set(local_users)
    cam._remote_users = set()
    cam._user_requests = set()
    cam._webrtc_session = webrtc_session
    cam._stream_url = "tcp://127.0.0.1:1234" if webrtc_session is not None else "rtsps://legacy"
    cam._dump_activities = MagicMock()
    cam._stop_activity = MagicMock()
    return cam


def test_stop_stream_keeps_webrtc_alive_while_other_local_users_remain():
    session = MagicMock()
    cam = _fake_camera_for_stop({"streaming", "snapshot"}, session)

    ArloCamera._stop_stream(cam, "snapshot")

    assert cam._local_users == {"streaming"}
    assert cam._webrtc_session is session
    assert cam._stream_url == "tcp://127.0.0.1:1234"
    session.stop.assert_not_called()
    cam._stop_activity.assert_not_called()


def test_stop_stream_closes_webrtc_without_legacy_idle_when_last_user_stops():
    session = MagicMock()
    cam = _fake_camera_for_stop({"streaming"}, session)

    ArloCamera._stop_stream(cam, "streaming")

    assert cam._local_users == set()
    assert cam._webrtc_session is None
    assert cam._stream_url is None
    session.stop.assert_called_once_with()
    cam._stop_activity.assert_not_called()


def test_stop_stream_uses_legacy_idle_for_legacy_stream_when_last_user_stops():
    cam = _fake_camera_for_stop({"streaming"}, webrtc_session=None)

    ArloCamera._stop_stream(cam, "streaming")

    assert cam._local_users == set()
    cam._stop_activity.assert_called_once_with()


# ---------------------------------------------------------------------------
# Shared WebRTC attempt lease (begin_webrtc_attempt/end_webrtc_attempt),
# used by both the legacy aiortc path and hass-aarlo's native browser-relay
# path to keep two live-view negotiations from racing Arlo's API at once.
# ---------------------------------------------------------------------------

def _fake_camera_for_lease():
    cam = ArloCamera.__new__(ArloCamera)
    cam._lock = threading.Condition()
    cam._webrtc_starting = False
    cam._webrtc_session = None
    cam._stream_url = None
    return cam


def test_begin_webrtc_attempt_succeeds_when_free():
    cam = _fake_camera_for_lease()
    assert cam.begin_webrtc_attempt(timeout=5) is True
    assert cam._webrtc_starting is True


def test_end_webrtc_attempt_frees_the_lease():
    cam = _fake_camera_for_lease()
    cam.begin_webrtc_attempt(timeout=5)
    cam.end_webrtc_attempt()
    assert cam._webrtc_starting is False


def test_second_attempt_waits_then_succeeds_once_released():
    cam = _fake_camera_for_lease()
    assert cam.begin_webrtc_attempt(timeout=5) is True

    results = []

    def contender():
        results.append(cam.begin_webrtc_attempt(timeout=5))

    t = threading.Thread(target=contender)
    t.start()
    time.sleep(0.05)  # give the contender a chance to start waiting
    assert results == []  # still blocked - the lease is held
    cam.end_webrtc_attempt()
    t.join(timeout=5)

    assert results == [True]
    assert cam._webrtc_starting is True  # the contender now holds it


def test_second_attempt_times_out_if_never_released():
    cam = _fake_camera_for_lease()
    cam.begin_webrtc_attempt(timeout=5)

    start = time.monotonic()
    acquired = cam.begin_webrtc_attempt(timeout=0.2)
    elapsed = time.monotonic() - start

    assert acquired is False
    assert elapsed < 1  # bounded by the timeout, not left hanging
    # A timed-out attempt must not disturb the lease it failed to acquire.
    assert cam._webrtc_starting is True


def test_only_one_of_many_concurrent_attempts_holds_the_lease_at_once():
    cam = _fake_camera_for_lease()
    concurrent_holders = []
    lock = threading.Lock()

    def attempt():
        if cam.begin_webrtc_attempt(timeout=5):
            with lock:
                concurrent_holders.append(1)
                count = len(concurrent_holders)
            assert count == 1, "two threads held the lease at once"
            time.sleep(0.01)
            with lock:
                concurrent_holders.pop()
            cam.end_webrtc_attempt()

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert cam._webrtc_starting is False


def test_stop_alive_legacy_webrtc_session_tears_down_and_clears_refs():
    session = MagicMock()
    session.is_alive = True
    cam = _fake_camera_for_lease()
    cam._webrtc_session = session
    cam._stream_url = "tcp://127.0.0.1:1234"

    cam.stop_alive_legacy_webrtc_session()

    session.stop.assert_called_once_with()
    assert cam._webrtc_session is None
    assert cam._stream_url is None


def test_stop_alive_legacy_webrtc_session_noop_when_none():
    cam = _fake_camera_for_lease()
    cam.stop_alive_legacy_webrtc_session()  # no raise, nothing to stop


def test_webrtc_mpegts_recorder_muxes_video_only(monkeypatch):
    session = ArloWebRtcSession.__new__(ArloWebRtcSession)
    session._camera = SimpleNamespace(debug=MagicMock())
    session._recorder = MagicMock()
    session._recorder_started = False
    session._recorder_track_ids = set()
    session._discard_track_ids = set()
    session._discard_track_tasks = set()
    session._video_debug_track = None

    fake_discard_task = MagicMock()
    fake_discard_task.add_done_callback = MagicMock()

    def fake_ensure_future(coro):
        coro.close()
        return fake_discard_task

    monkeypatch.setattr("pyaarlo.webrtc.asyncio.ensure_future", fake_ensure_future)

    audio_track = SimpleNamespace(kind="audio")
    video_track = SimpleNamespace(kind="video")

    ArloWebRtcSession._add_recorder_track(session, audio_track)
    session._recorder.addTrack.assert_not_called()
    assert id(audio_track) in session._discard_track_ids

    ArloWebRtcSession._add_recorder_track(session, video_track)
    session._recorder.addTrack.assert_called_once()
    assert session._video_debug_track is not None
