"""Lightweight SIP/WebRTC signaling: relay only, no local media engine.

This is the negotiation half of webrtc.py's hmswebsocketproxy JSON-over-WS
dialect, with the local WebRTC media engine removed entirely. It exists for
callers (Home Assistant's native `Camera.async_handle_async_webrtc_offer`
provider pattern, matching how the `ring`/`nest` integrations work) where a
real browser's own RTCPeerConnection does the actual ICE/DTLS/SRTP/H264
work - this module's only job is to shuttle the browser's SDP offer to
Arlo's cloud and hand back Arlo's SDP answer, as plain JSON messages over a
WebSocket.

Deliberately no `aiortc`/`av` import anywhere in this module: unlike
webrtc.py's `ArloWebRtcSession`, nothing here ever holds a PeerConnection, so
there is nothing to decode, encode, or remux, and no local TCP relay to run
- that is the whole point of this module existing alongside webrtc.py rather
than instead of it (see camera.py's `_start_stream_with_webrtc_fallback` and
the Gateway/VMC4070-4072 models it remains the only option for).

No SDP text-surgery either (contrast webrtc.py's `_browser_match_offer`,
`_strip_unoffered_payload_types`, `_ensure_answer_mids`,
`_ensure_answer_directions`): that machinery exists purely to make aiortc's
offer/answer look like a real browser's. A real browser's offer already is
one, so none of it applies here.

Two things intentionally not implemented yet, because neither is confirmed
necessary for this dialect specifically (see pyaarlo's project plan for the
reasoning): a periodic keepalive, and trickled-ICE-candidate handling. Both
are open questions to settle with real traffic, not something to guess at.
"""

import asyncio
import uuid

import websockets

from .webrtc_common import (
    ARLO_WEBRTC_ACCEPT_LANGUAGE,
    ARLO_WEBRTC_WS_USER_AGENT,
    FAST_SIGNALING_TIMEOUT,
    build_ice_server_kwargs,
    domain_with_signaling_port,
    http_over_ws_message,
    initiate_offer_body,
    parse_http_over_ws_message,
    session_disconnected_body,
)

__all__ = [
    "WebRtcSignalingError",
    "async_negotiate_offer",
    "async_close_session",
    "ice_server_kwargs",
]


class WebRtcSignalingError(Exception):
    """Raised when Arlo's SIP/WebRTC signaling proxy rejects or can't be reached.

    A separate type from webrtc.WebRtcSessionError so this module's only
    pyaarlo-internal dependency stays webrtc_common/constant, not webrtc.py.
    """


async def _open_signaling_socket(domain_with_port):
    # The signaling server rejects the WS upgrade with HTTP 400 if no Origin
    # header is present (confirmed via a real my.arlo.com capture).
    return await websockets.connect(
        "wss://{}".format(domain_with_port),
        subprotocols=["sip"],
        origin="https://my.arlo.com",
        user_agent_header=ARLO_WEBRTC_WS_USER_AGENT,
        additional_headers={
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Accept-Language": ARLO_WEBRTC_ACCEPT_LANGUAGE,
        },
    )


async def async_negotiate_offer(sip_call_info, device_id, offer_sdp, arlo_session_id=None):
    """Send a browser's SDP offer to Arlo and return its SDP answer.

    :param sip_call_info: the `sipCallInfo` dict from `ArloCamera._get_sip_info()`.
    :param device_id: the camera's device id (fallback if sipCallInfo lacks one).
    :param offer_sdp: the offer exactly as the browser produced it - no rewriting.
    :param arlo_session_id: reuse an existing Arlo-side session id, or generate
        a fresh one if not given.
    :raises WebRtcSignalingError: on any transport failure, rejection, or a
        response missing an answer.
    """
    domain_with_port = domain_with_signaling_port(sip_call_info)
    session_id = arlo_session_id or str(uuid.uuid4())
    try:
        async with await _open_signaling_socket(domain_with_port) as ws:
            body = initiate_offer_body(
                sip_call_info, device_id, session_id, offer_sdp, domain_with_port
            )
            message = http_over_ws_message(
                "POST /hmswebsocketproxy/initiateOffer", domain_with_port, body
            )
            await ws.send(message)
            response = await asyncio.wait_for(ws.recv(), timeout=FAST_SIGNALING_TIMEOUT)
            parsed = parse_http_over_ws_message(response)
    except WebRtcSignalingError:
        raise
    except Exception as e:
        raise WebRtcSignalingError(
            "initiateOffer failed: {}: {}".format(type(e).__name__, e)
        ) from e

    if not parsed.get("success"):
        raise WebRtcSignalingError(parsed.get("message", "initiateOffer failed"))
    answer = (parsed.get("data") or {}).get("payload", {}).get("answer", {}).get("value")
    if not answer:
        raise WebRtcSignalingError("no answer SDP in initiateOffer response")
    return answer


async def async_close_session(sip_call_info, device_id, arlo_session_id):
    """Tell Arlo a live-view session is over.

    Best-effort: swallows every error, since teardown must never raise back
    into a caller (Home Assistant's `close_webrtc_session` is a synchronous
    `@callback` with nowhere useful to send an exception).
    """
    if sip_call_info is None or arlo_session_id is None:
        return
    try:
        domain_with_port = domain_with_signaling_port(sip_call_info)
        async with await _open_signaling_socket(domain_with_port) as ws:
            body = session_disconnected_body(
                sip_call_info, device_id, arlo_session_id, domain_with_port
            )
            message = http_over_ws_message(
                "POST /hmswebsocketproxy/sessionDisconnected", domain_with_port, body
            )
            await ws.send(message)
    except Exception:
        pass


def ice_server_kwargs(sip_info):
    """ICE server kwargs (`urls`/`username`/`credential` dicts) from a sipInfo response."""
    return build_ice_server_kwargs((sip_info.get("iceServers") or {}).get("data"))
