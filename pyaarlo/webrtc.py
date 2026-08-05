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
import time
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
_TCP_ACCEPT_TIMEOUT = 120
_TCP_STARTUP_BUFFER_LIMIT = 4 * 1024 * 1024


class WebRtcSessionError(Exception):
    """Raised when the SIP/WebRTC live-view session cannot be established.

    Callers should catch this and fall back to the existing RTSP-cloud path.
    """


class _TcpSocketWriter:
    """Small write-only file object backed by a local TCP listener.

    PyAV/FFmpeg's tcp listen URL handling is not consistent across builds. This
    guarantees the advertised localhost port is listening before HA receives it.
    """

    def __init__(
        self,
        camera=None,
        host="127.0.0.1",
        port=0,
        accept_timeout=_TCP_ACCEPT_TIMEOUT,
        on_client=None,
    ):
        self._camera = camera
        self._host = host
        self._accept_timeout = accept_timeout
        self._on_client = on_client
        self._lock = threading.Condition()
        self._conns = []
        self._closed = False
        self._accept_error = None
        self._live_waiting = False
        self._startup_buffer = []
        self._startup_buffered = 0
        self._startup_chunks_dropped = 0
        self._startup_bytes_dropped = 0
        self._write_count = 0
        self._write_bytes = 0

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((host, port))
        self._server.listen(1)
        self._server.settimeout(1)
        self._port = self._server.getsockname()[1]
        self.name = self.url
        self.mode = "wb"

        self._thread = threading.Thread(
            target=self._accept_loop,
            name="ArloWebRtcTcp-{}".format(self._port),
            daemon=True,
        )
        self._thread.start()

    @property
    def port(self):
        return self._port

    @property
    def url(self):
        return "tcp://{}:{}".format(self._host, self._port)

    def writable(self):
        return True

    def readable(self):
        return False

    def seekable(self):
        return False

    @property
    def closed(self):
        return self._closed

    def tell(self):
        return 0

    def _accept_loop(self):
        while True:
            with self._lock:
                if self._closed:
                    return
            try:
                conn, _ = self._server.accept()
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except socket.timeout:
                continue
            except OSError as e:
                with self._lock:
                    if not self._closed:
                        self._accept_error = e
                        self._lock.notify_all()
                return

            with self._lock:
                if self._closed:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    return
                self._accept_error = None
                startup_buffer = self._startup_buffer
                startup_buffered = self._startup_buffered
                startup_chunks_dropped = self._startup_chunks_dropped
                startup_bytes_dropped = self._startup_bytes_dropped
                self._startup_buffer = []
                self._startup_buffered = 0
                self._startup_chunks_dropped = 0
                self._startup_bytes_dropped = 0
            try:
                for chunk in startup_buffer:
                    conn.sendall(chunk)
            except OSError:
                self._drop_connection(conn)
                continue
            with self._lock:
                if self._closed:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    return
                self._conns.append(conn)
                self._lock.notify_all()
            self._debug("SIP/WebRTC TCP client connected")
            if startup_buffer:
                self._debug(
                    "SIP/WebRTC TCP replayed startup buffer: {} chunks / {} bytes"
                    " (dropped {} chunks / {} bytes)".format(
                        len(startup_buffer),
                        startup_buffered,
                        startup_chunks_dropped,
                        startup_bytes_dropped,
                    )
                )
            if self._on_client is not None:
                self._on_client()

    def set_live_waiting(self):
        with self._lock:
            self._live_waiting = True

    def _debug(self, msg):
        if self._camera is not None:
            self._camera.debug(msg)

    def _wait_for_connection(self, deadline):
        with self._lock:
            while not self._conns:
                if self._closed:
                    raise BrokenPipeError("TCP stream is closed")
                if self._accept_error is not None:
                    raise BrokenPipeError(str(self._accept_error))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("no TCP consumer connected")
                self._lock.wait(timeout=min(remaining, 1))
            return list(self._conns)

    def _drop_connection(self, conn):
        with self._lock:
            if conn in self._conns:
                self._conns.remove(conn)
            self._lock.notify_all()
        try:
            conn.close()
        except Exception:
            pass

    def write(self, data):
        if not data:
            return 0

        data = bytes(data)
        deadline = time.monotonic() + self._accept_timeout
        while True:
            with self._lock:
                if not self._conns and not self._live_waiting:
                    self._startup_buffer.append(data)
                    self._startup_buffered += len(data)
                    while (
                        self._startup_buffered > _TCP_STARTUP_BUFFER_LIMIT
                        and self._startup_buffer
                    ):
                        dropped = self._startup_buffer.pop(0)
                        self._startup_buffered -= len(dropped)
                        self._startup_chunks_dropped += 1
                        self._startup_bytes_dropped += len(dropped)
                    return len(data)
            conns = self._wait_for_connection(deadline)
            sent = False
            for conn in conns:
                try:
                    conn.sendall(data)
                    sent = True
                except OSError:
                    self._debug("SIP/WebRTC TCP client disconnected during write")
                    self._drop_connection(conn)
            if sent:
                self._write_count += 1
                self._write_bytes += len(data)
                if self._write_count == 1:
                    self._debug(
                        "SIP/WebRTC TCP first write: {} bytes, prefix={}".format(
                            len(data), data[:16].hex()
                        )
                    )
                elif self._write_count in (10, 100):
                    self._debug(
                        "SIP/WebRTC TCP wrote {} chunks / {} bytes".format(
                            self._write_count, self._write_bytes
                        )
                    )
                return len(data)

    def flush(self):
        return None

    def close(self):
        with self._lock:
            self._closed = True
            conns = self._conns
            self._conns = []
            self._startup_buffer = []
            self._startup_buffered = 0
            self._startup_chunks_dropped = 0
            self._startup_bytes_dropped = 0
            self._lock.notify_all()
        for sock in conns + [self._server]:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass


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


def _media_section_mids(sdp):
    """Return the media section mids from an SDP, in m-line order."""
    mids = []
    current_mid = None
    in_media = False
    for line in sdp.splitlines():
        if line.startswith("m="):
            if in_media:
                mids.append(current_mid)
            in_media = True
            current_mid = None
        elif in_media and line.startswith("a=mid:"):
            current_mid = line.split(":", 1)[1]
    if in_media:
        mids.append(current_mid)
    return mids


def _ensure_answer_mids(answer_sdp, offer_sdp):
    """FreeSWITCH's answer omits a=mid, which browsers tolerate but aiortc
    requires in order to match answer media sections back to the offer."""
    offer_mids = _media_section_mids(offer_sdp)
    if not offer_mids or any(mid is None for mid in offer_mids):
        return answer_sdp

    lines = answer_sdp.splitlines()
    fixed = []
    media_index = -1
    media_has_mid = False
    pending_mid = None

    def flush_pending_mid():
        nonlocal pending_mid, media_has_mid
        if pending_mid is not None and not media_has_mid:
            fixed.append("a=mid:{}".format(pending_mid))
        pending_mid = None
        media_has_mid = False

    for line in lines:
        if line.startswith("m="):
            flush_pending_mid()
            media_index += 1
            pending_mid = (
                offer_mids[media_index] if media_index < len(offer_mids) else None
            )
            fixed.append(line)
            continue

        if line.startswith("a=mid:"):
            media_has_mid = True

        if pending_mid is not None and (
            line.startswith("a=rtpmap:")
            or line.startswith("a=send")
            or line.startswith("a=recv")
            or line.startswith("a=fingerprint:")
        ):
            flush_pending_mid()

        fixed.append(line)

    flush_pending_mid()
    return "\r\n".join(fixed) + "\r\n"


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
        self._tcp_writer = None
        self._recorder_started = False
        self._recorder_starting = False
        self._tracks = []
        self._video_track_ready = None

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
        self._video_track_ready = asyncio.Event()
        self._pc.addTransceiver("audio")
        self._pc.addTransceiver("video", direction="recvonly")

        @self._pc.on("track")
        def on_track(track):
            self._camera.debug("SIP/WebRTC received {} track".format(track.kind))
            self._tracks.append(track)
            if self._recorder is not None:
                self._recorder.addTrack(track)
            if track.kind == "video" and self._video_track_ready is not None:
                self._video_track_ready.set()

        self._tcp_writer = _TcpSocketWriter(
            camera=self._camera, on_client=self._start_recorder_from_client
        )
        self._port = self._tcp_writer.port
        self._camera.debug("SIP/WebRTC local TCP listener ready at {}".format(self._tcp_writer.url))
        self._recorder = MediaRecorder(self._tcp_writer, format="mpegts")

        offer = await self._pc.createOffer()
        await self._pc.setLocalDescription(offer)
        await self._wait_ice_gathering_complete()

        self._session_id = str(uuid.uuid4())
        answer_sdp = await self._negotiate(self._pc.localDescription.sdp)
        answer_sdp = _ensure_answer_mids(answer_sdp, self._pc.localDescription.sdp)
        await self._pc.setRemoteDescription(RTCSessionDescription(sdp=answer_sdp, type="answer"))
        await self._wait_connected()
        await self._wait_video_track_ready()
        await self._async_start_recorder()
        self._camera.debug(
            "SIP/WebRTC peer connection established; recorder is buffering for TCP client"
        )

        return self._tcp_writer.url

    def _start_recorder_from_client(self):
        if self._loop is None:
            return

        def schedule():
            if self._tcp_writer is not None:
                self._tcp_writer.set_live_waiting()
            asyncio.ensure_future(self._async_start_recorder())

        self._loop.call_soon_threadsafe(schedule)

    async def _async_start_recorder(self):
        if self._recorder_started or self._recorder_starting:
            return
        self._recorder_starting = True
        try:
            await self._recorder.start()
            self._recorder_started = True
            self._camera.debug("SIP/WebRTC recorder started at {}".format(self._tcp_writer.url))
        except Exception as e:
            self._camera.debug("SIP/WebRTC recorder start failed ({})".format(e))
        finally:
            self._recorder_starting = False

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

    async def _wait_video_track_ready(self):
        if any(track.kind == "video" for track in self._tracks):
            return
        if self._video_track_ready is None:
            return
        try:
            await asyncio.wait_for(self._video_track_ready.wait(), timeout=_CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            raise WebRtcSessionError("WebRTC video track was not received")

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
        if self._tcp_writer is not None:
            try:
                self._tcp_writer.close()
            except Exception:
                pass
