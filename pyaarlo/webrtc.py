"""SIP/WebRTC live-view client.

Implements the newer live-view path some Arlo cameras have started rolling
out (observed on my.arlo.com, protocol name internally still "sipCallInfo"
but the actual mechanism is a plain WebRTC offer/answer exchange tunneled as
pseudo-HTTP messages over a WebSocket - not raw SIP REGISTER/INVITE). This
sits alongside the existing RTSP-cloud path (camera.py's _start_stream()) and
is only used for cameras where ArloCamera.supports_sip_webrtc_streaming() is
true; callers are expected to fall back to the RTSP-cloud path on any
WebRtcSessionError, exactly like Arlo's own clients do.

The received audio/video is re-muxed (decode + re-encode, aiortc's
MediaRecorder does not support raw passthrough) into a local MPEG-TS stream
served over a plain TCP socket, so get_stream() can keep returning a simple
URL string (`tcp://127.0.0.1:{port}`) without any changes needed downstream
in hass-aarlo/HA.
"""

import asyncio
import json
import socket
import threading
import uuid

from aiortc import (
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.contrib.media import MediaRecorder
import websockets

from .constant import WEBRTC_SIGNALING_PORT

# These are hardcoded literals in Arlo's own web client (main-JY57BLPJ.js),
# confirmed inconsistent with the real browser's own User-Agent/Accept-Language -
# replicated verbatim out of caution rather than using our own values.
_ARLO_WEBRTC_USER_AGENT = "ArloWebRTC/1 CFNetwork/1329 Darwin/21.3.0"
_ARLO_WEBRTC_ACCEPT_LANGUAGE = "en-IN,en-GB;q=0.9,en;q=0.8"

_ICE_GATHERING_TIMEOUT = 5
_CONNECT_TIMEOUT = 10
_SIGNALING_TIMEOUT = 10


class WebRtcSessionError(Exception):
    """Raised when the SIP/WebRTC live-view session cannot be established.

    Callers should catch this and fall back to the existing RTSP-cloud path.
    """


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_ice_servers(ice_servers_data):
    servers = []
    for entry in ice_servers_data or []:
        kwargs = {"urls": "{}:{}:{}".format(entry.get("type"), entry.get("domain"), entry.get("port"))}
        if entry.get("username"):
            kwargs["username"] = entry["username"]
        if entry.get("credential"):
            kwargs["credential"] = entry["credential"]
        servers.append(RTCIceServer(**kwargs))
    return servers


def _rewritten_sip_call_info(sip_call_info, domain_with_port):
    """Arlo's own client rewrites domain/port to the signaling host:port and
    drops conferenceId/callId/deviceId before sending sipCallInfo back."""
    return {
        "calleeUri": sip_call_info["calleeUri"],
        "id": sip_call_info["id"],
        "password": sip_call_info["password"],
        "domain": domain_with_port,
        "port": str(WEBRTC_SIGNALING_PORT),
    }


def _http_over_ws_message(request_line, host, body_obj):
    """Build the pseudo-HTTP text frame hmswebsocketproxy expects."""
    body = json.dumps(body_obj)
    headers = (
        "{request_line} HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Content-Type: application/json\r\n"
        "Connection: keep-alive\r\n"
        "Accept: */*\r\n"
        "User-Agent: {ua}\r\n"
        "Content-Length: {length}\r\n"
        "Accept-Language: {lang}\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "\r\n"
    ).format(
        request_line=request_line,
        host=host,
        ua=_ARLO_WEBRTC_USER_AGENT,
        length=len(body),
        lang=_ARLO_WEBRTC_ACCEPT_LANGUAGE,
    )
    return headers + body


def _parse_http_over_ws_message(text):
    """Parse the pseudo-HTTP response hmswebsocketproxy sends back."""
    header_end = text.index("\r\n\r\n")
    return json.loads(text[header_end + 4:])


class ArloWebRtcSession:
    """One SIP/WebRTC live-view session for a single camera."""

    def __init__(self, camera):
        self._camera = camera
        self._pc = None
        self._recorder = None
        self._ws = None
        self._session_id = None
        self._sip_call_info = None
        self._loop = None
        self._thread = None
        self._port = None

    def start(self, timeout=15):
        """Start the session; blocks the calling thread until media is
        flowing or setup fails.

        Returns the local stream URL to hand back from get_stream(). Raises
        WebRtcSessionError on any failure.
        """
        sip_info = self._camera._get_sip_info()
        if not sip_info or not sip_info.get("sipCallInfo"):
            raise WebRtcSessionError("no sipInfo available")
        self._sip_call_info = sip_info["sipCallInfo"]
        ice_servers = _build_ice_servers((sip_info.get("iceServers") or {}).get("data"))

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name="ArloWebRtc-{}".format(self._camera.device_id),
            daemon=True,
        )
        self._thread.start()

        future = asyncio.run_coroutine_threadsafe(self._async_start(ice_servers), self._loop)
        try:
            return future.result(timeout=timeout)
        except Exception as e:
            self.stop()
            raise WebRtcSessionError(str(e)) from e

    def stop(self):
        """Tear down the session: sessionDisconnected, close peer connection,
        stop the local recorder, stop the background event loop."""
        if self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._async_stop(), self._loop).result(timeout=5)
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._loop = None
        self._thread = None

    async def _async_start(self, ice_servers):
        self._pc = RTCPeerConnection(RTCConfiguration(iceServers=ice_servers))
        self._pc.addTransceiver("audio")
        self._pc.addTransceiver("video", direction="recvonly")

        @self._pc.on("track")
        def on_track(track):
            if self._recorder is not None:
                self._recorder.addTrack(track)

        self._port = _find_free_port()
        self._recorder = MediaRecorder(
            "tcp://127.0.0.1:{}?listen=1".format(self._port), format="mpegts"
        )

        offer = await self._pc.createOffer()
        await self._pc.setLocalDescription(offer)
        await self._wait_ice_gathering_complete()

        self._session_id = str(uuid.uuid4())
        answer_sdp = await self._negotiate(self._pc.localDescription.sdp)
        await self._pc.setRemoteDescription(RTCSessionDescription(sdp=answer_sdp, type="answer"))
        await self._wait_connected()
        await self._recorder.start()

        return "tcp://127.0.0.1:{}".format(self._port)

    async def _wait_ice_gathering_complete(self):
        if self._pc.iceGatheringState == "complete":
            return
        done = asyncio.Event()

        @self._pc.on("icegatheringstatechange")
        def on_change():
            if self._pc.iceGatheringState == "complete":
                done.set()

        try:
            await asyncio.wait_for(done.wait(), timeout=_ICE_GATHERING_TIMEOUT)
        except asyncio.TimeoutError:
            # Match Arlo's own client: use whatever candidates were gathered
            # rather than failing outright.
            pass

    async def _wait_connected(self):
        if self._pc.connectionState == "connected":
            return
        done = asyncio.Event()

        @self._pc.on("connectionstatechange")
        def on_change():
            if self._pc.connectionState in ("connected", "failed", "closed"):
                done.set()

        await asyncio.wait_for(done.wait(), timeout=_CONNECT_TIMEOUT)
        if self._pc.connectionState != "connected":
            raise WebRtcSessionError(
                "WebRTC connection state failed: {}".format(self._pc.connectionState)
            )

    async def _negotiate(self, offer_sdp):
        domain = self._sip_call_info["domain"]
        domain_with_port = "{}:{}".format(domain, WEBRTC_SIGNALING_PORT)
        self._ws = await websockets.connect(
            "wss://{}".format(domain_with_port),
            subprotocols=["sip"],
            # The signaling server rejects the WS upgrade with HTTP 400 if no
            # Origin header is present (confirmed via a real my.arlo.com capture).
            origin="https://my.arlo.com",
        )
        body = {
            "sipCallInfo": _rewritten_sip_call_info(self._sip_call_info, domain_with_port),
            "payload": {
                "sessionId": self._session_id,
                "cameraId": self._sip_call_info.get("deviceId", self._camera.device_id),
                "offer": {"format": "SDP", "value": offer_sdp},
            },
        }
        message = _http_over_ws_message(
            "POST /hmswebsocketproxy/initiateOffer", domain_with_port, body
        )
        await self._ws.send(message)
        response = await asyncio.wait_for(self._ws.recv(), timeout=_SIGNALING_TIMEOUT)
        parsed = _parse_http_over_ws_message(response)
        if not parsed.get("success"):
            raise WebRtcSessionError(parsed.get("message", "initiateOffer failed"))
        answer = (parsed.get("data") or {}).get("payload", {}).get("answer", {}).get("value")
        if not answer:
            raise WebRtcSessionError("no answer SDP in initiateOffer response")
        return answer

    async def _async_stop(self):
        if self._ws is not None and self._sip_call_info is not None:
            try:
                domain = self._sip_call_info["domain"]
                domain_with_port = "{}:{}".format(domain, WEBRTC_SIGNALING_PORT)
                body = {
                    "sipCallInfo": _rewritten_sip_call_info(self._sip_call_info, domain_with_port),
                    "payload": {
                        "sessionId": self._session_id,
                        "cameraId": self._sip_call_info.get("deviceId", self._camera.device_id),
                    },
                }
                message = _http_over_ws_message(
                    "POST /hmswebsocketproxy/sessionDisconnected", domain_with_port, body
                )
                await self._ws.send(message)
            except Exception:
                pass
            try:
                await self._ws.close()
            except Exception:
                pass
        if self._recorder is not None:
            try:
                await self._recorder.stop()
            except Exception:
                pass
        if self._pc is not None:
            try:
                await self._pc.close()
            except Exception:
                pass
