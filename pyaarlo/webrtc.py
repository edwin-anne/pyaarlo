"""SIP/WebRTC live-view client.

Implements the newer live-view path some Arlo cameras have started rolling
out (observed on my.arlo.com, protocol name internally still "sipCallInfo"
but the actual mechanism is a plain WebRTC offer/answer exchange tunneled as
pseudo-HTTP messages over a WebSocket - not raw SIP REGISTER/INVITE). This
sits alongside the existing RTSP-cloud path (camera.py's _start_stream()) and
is only used for cameras where ArloCamera.supports_sip_webrtc_streaming() is
true; callers are expected to fall back to the RTSP-cloud path on any
WebRtcSessionError, exactly like Arlo's own clients do.

Offers both an audio and a video transceiver, matching the SDP shape of
Arlo's own web player (my.arlo.com always offers "audio" sendrecv + "video"
recvonly, even with no local mic track). bundlePolicy is "balanced" (also
matching the web player); FreeSWITCH's answer never groups media under
a=group:BUNDLE regardless, so each leg ends up on its own independent
ICE/DTLS transport either way. Each leg is then waited on independently so
a slow/failing audio leg cannot block video, which is the leg that actually
matters here.

The received video is re-muxed (decode + re-encode, aiortc's MediaRecorder
does not support raw passthrough) into a local MPEG-TS stream served over a
plain TCP socket, so get_stream() can keep returning a simple URL string
(`tcp://127.0.0.1:{port}`) without any changes needed downstream in
hass-aarlo/HA.
"""

import asyncio
import fractions
import hashlib
import random
import re
import socket
import string
import threading
import time
import uuid

import av
from aiortc import (
    MediaStreamTrack,
    RTCBundlePolicy,
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.contrib.media import MediaRecorder
import websockets

from .constant import WEBRTC_SIGNALING_PORT
from .webrtc_common import (
    ARLO_WEBRTC_ACCEPT_LANGUAGE as _ARLO_WEBRTC_ACCEPT_LANGUAGE,
    ARLO_WEBRTC_WS_USER_AGENT as _ARLO_WEBRTC_WS_USER_AGENT,
    FAST_SIGNALING_TIMEOUT as _FAST_SIGNALING_TIMEOUT,
    SIGNALING_TIMEOUT as _SIGNALING_TIMEOUT,
    build_ice_server_kwargs as _build_ice_server_kwargs,
    domain_with_signaling_port as _domain_with_signaling_port,
    http_over_ws_message as _http_over_ws_message,
    initiate_offer_body as _initiate_offer_body,
    instant_message_body as _instant_message_body,
    parse_http_over_ws_message as _parse_http_over_ws_message,
    # Re-exported for tests/test_webrtc.py, which imports it from this module;
    # no longer called directly here now that the body builders wrap it.
    rewritten_sip_call_info as _rewritten_sip_call_info,
    session_disconnected_body as _session_disconnected_body,
)

_ICE_GATHERING_TIMEOUT = 5
_CONNECT_TIMEOUT = 10
# _SIGNALING_TIMEOUT/_FAST_SIGNALING_TIMEOUT: imported from webrtc_common above.
# The "fast" one bounds only the synchronous prefix's wait for the first
# signaling response (INVITE's 100 Trying, or initiateOffer's JSON reply) -
# kept much tighter so start() can return to Home Assistant well within its
# own 10s stream_source() budget; everything after that checkpoint runs in
# the background and can afford to be patient.
_KEEPALIVE_INTERVAL = 30
# Matches scryptedapp/arlo's generic WebRTC bridge (wrtc-to-rtsp.ts), which
# found empirically that a gateway-style backend like this one needs a
# recurring PLI (not just an initial one) to keep producing keyframes for a
# client that connects or reconnects mid-session.
_PLI_INTERVAL = 4
# How long to wait for the first decodable video frame before letting the
# recorder start with libx264's default size (see _prime_recorder_video_size).
# The camera only produces one once a keyframe lands, so this has to tolerate a
# couple of PLI rounds.
_VIDEO_FRAME_TIMEOUT = 15

# Toggle between the hmswebsocketproxy JSON-over-WS wrapper (matches
# my.arlo.com's own web player, confirmed working via a real capture) and
# real SIP INVITE/ACK/BYE signaling (matches scryptedapp/arlo's Go SIP
# client, also confirmed working in production). Both talk to the same
# domain/port/sipCallInfo; this only changes how the offer/answer exchange
# and keepalives are framed on the wire.
_USE_REAL_SIP = True
_TCP_ACCEPT_TIMEOUT = 120
_TCP_STARTUP_BUFFER_LIMIT = 4 * 1024 * 1024


class WebRtcSessionError(Exception):
    """Raised when the SIP/WebRTC live-view session cannot be established.

    Callers should catch this and fall back to the existing RTSP-cloud path.
    """


# ContentType(1) + ProtocolVersion(2) + epoch(2) + sequence_number(6) + length(2)
_DTLS_RECORD_HEADER_LENGTH = 13


def _patch_aiortc_dtls_record_framing():
    """Make aiortc emit DTLS on record boundaries instead of 1500-byte slices.

    aiortc's RTCDtlsTransport._write_ssl does a single `bio_read(1500)` and
    sends the result as one datagram. The BIO is a byte stream but the
    transport is a datagram one, so that both strands whatever is queued past
    the slice AND cuts in half the record straddling the 1500-byte boundary.
    The peer drops the truncated record, then drops the orphaned tail (its
    first byte is not a valid DTLS content type).

    It goes unnoticed with most peers because aiortc is usually the DTLS
    client, whose flights are small. Arlo's FreeSWITCH always answers
    a=setup:active, making *us* the server: our flight (ServerHello,
    Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone) runs
    to ~1.6kB and never lands intact. FreeSWITCH then retransmits its own
    flight forever, never finishes its handshake, never installs SRTP - so it
    sends cleartext RTCP and no media at all - while aiortc reports "DTLS
    handshake complete", because the peer's flight did arrive.

    Patched here rather than in site-packages so it survives reinstalling
    aiortc. Upstream-worthy; remove once aiortc frames its DTLS output."""
    from OpenSSL import SSL as _SSL
    from aiortc.rtcdtlstransport import RTCDtlsTransport

    if getattr(RTCDtlsTransport, "_arlo_dtls_framing_patched", False):
        return

    async def _send_datagram(self, data):
        await self.transport._send(data)
        self._RTCDtlsTransport__tx_bytes += len(data)
        self._RTCDtlsTransport__tx_packets += 1

    async def patched_write_ssl(self):
        buf = b""
        while True:
            try:
                chunk = self._ssl.bio_read(4096)
            except _SSL.Error:
                break
            if not chunk:
                break
            buf += chunk

        offset = 0
        while offset + _DTLS_RECORD_HEADER_LENGTH <= len(buf):
            length = int.from_bytes(
                buf[offset + 11 : offset + _DTLS_RECORD_HEADER_LENGTH], "big"
            )
            end = offset + _DTLS_RECORD_HEADER_LENGTH + length
            if end > len(buf):
                break
            await _send_datagram(self, buf[offset:end])
            offset = end

        if offset < len(buf):
            # Not record-aligned - send the remainder rather than drop it.
            await _send_datagram(self, buf[offset:])

    RTCDtlsTransport._write_ssl = patched_write_ssl
    RTCDtlsTransport._arlo_dtls_framing_patched = True


# aiortc sizes its video jitter buffer at 128 packets. A 1920x1072 keyframe
# from these cameras spans roughly 175 RTP packets, so the buffer wraps around
# mid-keyframe and evicts the packets it already holds; the depacketizer then
# sees a truncated NAL sequence and the decoder reports "No start code is
# found", freezing the picture until the next keyframe. Must be a power of 2.
_VIDEO_JITTER_CAPACITY = 1024


def _patch_aiortc_video_jitter_buffer():
    """Give the inbound video jitter buffer room for a whole keyframe.

    See _VIDEO_JITTER_CAPACITY. Substituting the class the receiver module
    looks up leaves aiortc's own logic untouched; only the floor on capacity
    for video changes."""
    import aiortc.rtcrtpreceiver as m

    if getattr(m, "_arlo_jitter_capacity_patched", False):
        return
    base = m.JitterBuffer

    class _ArloVideoJitterBuffer(base):
        def __init__(self, capacity, prefetch=0, is_video=False):
            if is_video and capacity < _VIDEO_JITTER_CAPACITY:
                capacity = _VIDEO_JITTER_CAPACITY
            super().__init__(capacity, prefetch=prefetch, is_video=is_video)

    m.JitterBuffer = _ArloVideoJitterBuffer
    m._arlo_jitter_capacity_patched = True


def _patch_aiortc_audio_marker_bit():
    """aiortc's RTCRtpSender sets packet.marker=1 whenever a payload is the
    last of its encoded frame's payload list. Encoded audio frames always
    have exactly one payload, so this makes aiortc mark *every* audio RTP
    packet - not just the first one of a talk spurt. scryptedapp/arlo's Go
    SIP client hits the exact same issue with pion and works around it
    explicitly ("packets we receive from ffmpeg all have the marker set,
    which seems to confuse arlo's backend. therefore, we only set the first
    packet's marker"). Patch RTCRtpSender so only the very first RTP packet
    an audio sender ever transmits carries the marker bit; video senders
    (multiple payloads per frame, correct marker semantics already) are
    untouched."""
    import aiortc.rtcrtpsender as m

    sender_cls = m.RTCRtpSender
    if getattr(sender_cls, "_arlo_audio_marker_patched", False):
        return
    original_run_rtp = sender_cls._run_rtp

    async def patched_run_rtp(self, codec):
        if self.kind != "audio":
            await original_run_rtp(self, codec)
            return

        self._RTCRtpSender__log_debug("- RTP started")
        self._RTCRtpSender__rtp_started.set()

        sequence_number = m.random_sequence_number()
        timestamp_origin = m.random32()
        first_packet_sent = False
        try:
            while True:
                if not self._RTCRtpSender__track:
                    await asyncio.sleep(0.02)
                    continue

                enc_frame = await self._next_encoded_frame(codec)
                if enc_frame is None:
                    continue

                timestamp = m.uint32_add(timestamp_origin, enc_frame.timestamp)

                for payload in enc_frame.payloads:
                    packet = m.RtpPacket(
                        payload_type=codec.payloadType,
                        sequence_number=sequence_number,
                        timestamp=timestamp,
                    )
                    packet.ssrc = self._ssrc
                    packet.payload = payload
                    packet.marker = 0 if first_packet_sent else 1
                    first_packet_sent = True

                    packet.extensions.abs_send_time = (
                        m.clock.current_ntp_time() >> 14
                    ) & 0x00FFFFFF
                    packet.extensions.mid = self._RTCRtpSender__mid
                    if enc_frame.audio_level is not None:
                        packet.extensions.audio_level = (False, -enc_frame.audio_level)

                    self._RTCRtpSender__log_debug("> %s", packet)
                    self._RTCRtpSender__rtp_history[
                        packet.sequence_number % m.RTP_HISTORY_SIZE
                    ] = packet
                    packet_bytes = packet.serialize(
                        self._RTCRtpSender__rtp_header_extensions_map
                    )
                    await self.transport._send_rtp(packet_bytes)

                    sequence_number = m.uint16_add(sequence_number, 1)
        except (asyncio.CancelledError, ConnectionError, m.MediaStreamError):
            pass
        except Exception:
            self._RTCRtpSender__log_warning(m.traceback.format_exc())

    sender_cls._run_rtp = patched_run_rtp
    sender_cls._arlo_audio_marker_patched = True


class _SilentAudioTrack(MediaStreamTrack):
    """A real (silent) local audio track for the audio transceiver.

    Without this, our "sendrecv" audio transceiver never actually transmits
    any RTP - only periodic RTCP Sender Reports with packet_count=0 - even
    though the SDP claims sendrecv. Arlo's own clients (both the web player
    and scryptedapp/arlo's Go SIP client) always attach a real local audio
    track/RTP source. Media relays commonly "learn" the client's address
    from inbound RTP before starting to forward media back (symmetric RTP),
    so a transceiver that only sends RTCP with no RTP may never get treated
    as a real, live leg."""

    kind = "audio"

    _SAMPLE_RATE = 48000
    _SAMPLES_PER_FRAME = 960  # 20ms at 48kHz

    def __init__(self):
        super().__init__()
        self._timestamp = 0

    async def recv(self):
        frame = av.AudioFrame(format="s16", layout="mono", samples=self._SAMPLES_PER_FRAME)
        for plane in frame.planes:
            plane.update(bytes(plane.buffer_size))
        frame.sample_rate = self._SAMPLE_RATE
        frame.pts = self._timestamp
        frame.time_base = fractions.Fraction(1, self._SAMPLE_RATE)
        self._timestamp += self._SAMPLES_PER_FRAME
        await asyncio.sleep(self._SAMPLES_PER_FRAME / self._SAMPLE_RATE)
        return frame


class _DebugMediaTrack:
    """Proxy a media track so we can see whether frames reach MediaRecorder."""

    def __init__(self, camera, track):
        self._camera = camera
        self._track = track
        self._frames = 0
        self._ended_logged = False
        self._pushback = None
        self.kind = track.kind

    @property
    def readyState(self):
        return self._track.readyState

    async def peek(self):
        """Pull one frame and keep it queued for the next recv().

        Lets the caller inspect the real picture size before the recorder opens
        its encoders, without dropping the frame - which for video is the
        keyframe the decoder needs."""
        if self._pushback is None:
            self._pushback = await self.recv()
        return self._pushback

    async def recv(self):
        if self._pushback is not None:
            frame, self._pushback = self._pushback, None
            return frame

        try:
            frame = await self._track.recv()
        except Exception as e:
            if not self._ended_logged:
                self._ended_logged = True
                self._camera.debug(
                    "SIP/WebRTC {} track recv ended/failed: {}({})".format(
                        self.kind, type(e).__name__, e
                    )
                )
            raise

        self._frames += 1
        if self._frames in (1, 10, 100):
            self._camera.debug(
                "SIP/WebRTC {} track frame {}: {}".format(
                    self.kind, self._frames, self._describe_frame(frame)
                )
            )
        return frame

    def stop(self):
        self._track.stop()

    def _describe_frame(self, frame):
        parts = [
            type(frame).__name__,
            "pts={}".format(getattr(frame, "pts", None)),
            "time_base={}".format(getattr(frame, "time_base", None)),
        ]
        width = getattr(frame, "width", None)
        height = getattr(frame, "height", None)
        if width is not None and height is not None:
            parts.append("size={}x{}".format(width, height))
        samples = getattr(frame, "samples", None)
        if samples is not None:
            parts.append("samples={}".format(samples))
        return ", ".join(parts)


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
    """aiortc-typed wrapper around webrtc_common's dependency-free normalization."""
    return [
        RTCIceServer(**kwargs)
        for kwargs in _build_ice_server_kwargs(ice_servers_data)
    ]


# Real SIP signaling (REGISTER-less INVITE/ACK/BYE/MESSAGE), as an
# alternative to the hmswebsocketproxy pseudo-HTTP wrapper above. Ported
# from scryptedapp/arlo's Go SIP client (bjia56/scrypted-arlo-go's sip.go,
# built on github.com/jart/gosip), which is a real, working implementation
# of this same live-view path. Header field VALUES are matched to what
# gosip's Msg.Append() serializes; header ORDER is not since SIP (unlike
# some strict HTTP servers) does not treat header order as significant.
_SIP_ALLOW = "ACK,CANCEL,INVITE,MESSAGE,BYE,OPTIONS,INFO,NOTIFY,REFER"
_SIP_USER_AGENT = "SIP.js/0.21.1"


def _sip_rand_string(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _sip_gen_branch():
    return "z9hG4bK" + "".join(random.choices(string.digits, k=7))


def _sip_gen_tag():
    return uuid.uuid4().hex[:12]


def _sip_gen_call_id():
    return str(uuid.uuid4())


def _sip_gen_rand_host():
    return _sip_rand_string(12) + ".invalid"


def _sip_from_header(caller_uri, tag):
    return '"WebRTC-UDP" <{}>;tag={}'.format(caller_uri, tag)


def _build_sip_invite(
    caller_uri,
    callee_uri,
    device_id,
    local_sdp,
    rand_host,
    branch,
    from_tag,
    call_id,
    contact_user,
    cseq,
    proxy_authorization=None,
):
    lines = [
        "INVITE {} SIP/2.0".format(callee_uri),
        "From: {}".format(_sip_from_header(caller_uri, from_tag)),
        "To: <{}>".format(callee_uri),
        "Via: SIP/2.0/WSS {};branch={}".format(rand_host, branch),
        "Contact: <sip:{}@{};transport=ws;ob>".format(contact_user, rand_host),
        "Call-ID: {}".format(call_id),
        "CSeq: {} INVITE".format(cseq),
        "User-Agent: {}".format(_SIP_USER_AGENT),
        "Max-Forwards: 70",
        "Allow: {}".format(_SIP_ALLOW),
        "Supported: outbound",
        "X-extension: {}; User-Agent: webrtc".format(device_id),
    ]
    if proxy_authorization:
        lines.append("Proxy-Authorization: {}".format(proxy_authorization))
    lines.append("Content-Type: application/sdp")
    lines.append("Content-Length: {}".format(len(local_sdp.encode("utf-8"))))
    return "\r\n".join(lines) + "\r\n\r\n" + local_sdp


def _build_sip_ack_or_bye(
    method,
    caller_uri,
    callee_uri,
    from_tag,
    to_header_value,
    call_id,
    cseq,
    rand_host,
    route_header_value=None,
):
    lines = [
        "{} {} SIP/2.0".format(method, callee_uri),
        "From: {}".format(_sip_from_header(caller_uri, from_tag)),
        "To: {}".format(to_header_value),
        "Via: SIP/2.0/WSS {};branch={}".format(rand_host, _sip_gen_branch()),
    ]
    if route_header_value:
        lines.append("Route: {}".format(route_header_value))
    lines += [
        "Call-ID: {}".format(call_id),
        "CSeq: {} {}".format(cseq, method),
        "User-Agent: {}".format(_SIP_USER_AGENT),
        "Max-Forwards: 70",
        "Supported: outbound",
        "Content-Length: 0",
    ]
    return "\r\n".join(lines) + "\r\n\r\n"


def _build_sip_message(
    caller_uri,
    callee_uri,
    from_tag,
    call_id,
    cseq,
    payload,
    to_header=None,
    route_header_value=None,
):
    """Build a SIP MESSAGE.

    Pass `to_header`/`route_header_value` (captured from the 200 OK that
    established the dialog, same as ACK/BYE use) to send it in-dialog on an
    established call - required for FreeSWITCH to associate it with the live
    call at all. Without them (to_header=None), this builds a standalone
    out-of-dialog MESSAGE."""
    body = payload
    to_header_value = to_header if to_header is not None else "<{}>".format(callee_uri)
    lines = [
        "MESSAGE {} SIP/2.0".format(callee_uri),
        "From: {}".format(_sip_from_header(caller_uri, from_tag)),
        "To: {}".format(to_header_value),
        "Via: SIP/2.0/WSS {};branch={}".format(_sip_gen_rand_host(), _sip_gen_branch()),
    ]
    if route_header_value:
        lines.append("Route: {}".format(route_header_value))
    lines += [
        "Call-ID: {}".format(call_id),
        "CSeq: {} MESSAGE".format(cseq),
        "User-Agent: {}".format(_SIP_USER_AGENT),
        "Max-Forwards: 70",
        "Supported: outbound",
        "Content-Type: text/plain",
        "Content-Length: {}".format(len(body.encode("utf-8"))),
    ]
    return "\r\n".join(lines) + "\r\n\r\n" + body


def _parse_sip_message(text):
    """Parse a SIP request/response into (start_line, headers, body).

    headers maps lowercased header name -> list of raw values (order
    preserved), since SIP allows repeated headers (e.g. Via)."""
    header_end = text.index("\r\n\r\n")
    head = text[:header_end]
    body = text[header_end + 4:]
    lines = head.split("\r\n")
    headers = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return lines[0], headers, body


def _sip_status_code(start_line):
    parts = start_line.split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("SIP/"):
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _sip_header(headers, name):
    values = headers.get(name.lower())
    return values[0] if values else None


def _sip_header_all(headers, name):
    """Join every instance of a header (SIP allows repeats either as
    separate lines or comma-separated on one line - normalize to the
    comma-separated form)."""
    values = headers.get(name.lower())
    return ", ".join(values) if values else None


def _sip_reverse_route(record_route_value):
    """Reverse a comma-separated Record-Route into a Route header value,
    per RFC 3261: the UAC's Route header is the Record-Route set reversed."""
    if not record_route_value:
        return None
    parts = [p.strip() for p in record_route_value.split(",")]
    return ", ".join(reversed(parts))


def _sip_digest_response(username, realm, password, method, uri, nonce, cnonce, nc):
    def md5(*parts):
        return hashlib.md5(":".join(parts).encode("utf-8")).hexdigest()

    ha1 = md5(username, realm, password)
    ha2 = md5(method, uri)
    return md5(ha1, nonce, nc, cnonce, "auth", ha2)


def _sip_parse_proxy_authenticate(header_value):
    """Parse a `Digest realm="...", nonce="...", ...` header into a dict."""
    if not header_value.startswith("Digest"):
        raise WebRtcSessionError(
            "unsupported Proxy-Authenticate scheme: {}".format(header_value)
        )
    params = {}
    for kv in header_value[len("Digest"):].split(","):
        kv = kv.strip()
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        params[k.strip()] = v.strip().strip('"')
    return params


def _media_section_ssrcs(sdp, kind):
    """Return SSRCs advertised in the selected media section."""
    ssrcs = []
    in_media = False
    for line in sdp.splitlines():
        if line.startswith("m="):
            parts = line.split()
            in_media = bool(parts and parts[0] == "m={}".format(kind))
            continue
        if not in_media or not line.startswith("a=ssrc:"):
            continue
        raw_ssrc = line.split(":", 1)[1].split(None, 1)[0]
        try:
            ssrc = int(raw_ssrc)
        except ValueError:
            continue
        if ssrc not in ssrcs:
            ssrcs.append(ssrc)
    return ssrcs


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


def _offered_payload_types(offer_sdp):
    """Return, in m-line order, the set of payload types each media section
    of the offer advertised."""
    result = []
    for line in offer_sdp.splitlines():
        if not line.startswith("m="):
            continue
        parts = line.split()
        result.append(set(parts[3:]))
    return result


def _strip_unoffered_payload_types(answer_sdp, offer_sdp):
    """Drop any payload type from the answer that wasn't in our own offer
    for that media section.

    Real SIP call handling (FreeSWITCH mod_sofia via a raw SIP INVITE, as
    opposed to the hmswebsocketproxy JSON wrapper) can answer with an extra
    codec we never offered (observed: "101 telephone-event/8000" added to
    the audio m-line even though our offer only listed opus/G722/PCMU/PCMA).
    aiortc silently fails to attach the RTCRtpReceiver for a media section
    whose negotiated codec set doesn't match what we offered - no "track"
    event fires - rather than raising, so this is easy to miss. JSEP
    requires the answer's payload types to be a subset of the offer's;
    enforce that ourselves since FreeSWITCH doesn't always."""
    offered = _offered_payload_types(offer_sdp)
    lines = answer_sdp.splitlines()
    fixed = []
    media_index = -1
    allowed_pts = set()
    for line in lines:
        if line.startswith("m="):
            media_index += 1
            allowed_pts = (
                offered[media_index] if media_index < len(offered) else None
            )
            if allowed_pts is None:
                fixed.append(line)
                continue
            parts = line.split()
            kept_pts = [pt for pt in parts[3:] if pt in allowed_pts]
            fixed.append(" ".join(parts[:3] + kept_pts))
            continue

        if allowed_pts is not None:
            match = re.match(r"a=(rtpmap|fmtp|rtcp-fb):(\d+)\b", line)
            if match and match.group(2) not in allowed_pts:
                continue

        fixed.append(line)

    return "\r\n".join(fixed) + "\r\n"


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


_DIRECTION_ATTRS = ("a=sendrecv", "a=recvonly", "a=sendonly", "a=inactive")
_DEFAULT_DIRECTION_BY_KIND = {"audio": "a=sendrecv", "video": "a=sendonly"}


def _ensure_answer_directions(answer_sdp):
    """Insert a default direction attribute into any media section that
    omits one entirely. Per SDP RFC the default is "sendrecv" and a
    spec-compliant parser must assume that, but aiortc doesn't reliably
    attach a receiver (no "track" event fires) for a section with no
    explicit direction. FreeSWITCH's raw-SIP answers (mod_sofia) have been
    observed to omit the audio section's direction entirely, unlike its
    hmswebsocketproxy-specific answers which always include it. Ported from
    scryptedapp/arlo's Go SIP client (sip.go's cleanSDP: needsAudioDirection
    /needsVideoDirection), which defaults audio to sendrecv and video to
    sendonly - the same defaults used here."""
    lines = answer_sdp.splitlines()
    fixed = []
    kind = None
    has_direction = False
    pending_insert_index = None

    def flush():
        if pending_insert_index is not None and not has_direction and kind in _DEFAULT_DIRECTION_BY_KIND:
            fixed.insert(pending_insert_index, _DEFAULT_DIRECTION_BY_KIND[kind])

    for line in lines:
        if line.startswith("m="):
            flush()
            kind = line.split()[0][2:] if line.startswith("m=") else None
            has_direction = False
            fixed.append(line)
            pending_insert_index = len(fixed)
            continue
        if line in _DIRECTION_ATTRS:
            has_direction = True
        fixed.append(line)

    flush()
    return "\r\n".join(fixed) + "\r\n"


_RTPMAP_RE = re.compile(r"a=rtpmap:(\d+) ([A-Za-z0-9\-]+)/")


def _is_private_ipv4(host):
    """True for addresses Arlo's media relay can never route back to: RFC1918,
    loopback, link-local and CGNAT."""
    try:
        parts = [int(p) for p in host.split(".")]
    except ValueError:
        return False
    if len(parts) != 4:
        return False
    a, b = parts[0], parts[1]
    return (
        a == 10
        or a == 127
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 169 and b == 254)
        or (a == 100 and 64 <= b <= 127)
    )


_CANDIDATE_RE = re.compile(
    r"^a=candidate:\S+ \d+ (\S+) (\d+) (\S+) (\d+) typ (\S+)(?:.* rport (\d+))?"
)


def _keep_candidate(line):
    """Reproduce the candidate set Arlo's own web player ends up sending.

    Chrome never puts a routable private address in an offer: its host
    candidates are mDNS `.local` names, and Arlo's client strips those (the
    same filter is spelled out in scryptedapp/arlo's ArloCamera.parse_sdp:
    drop candidates with more than one ':' - IPv6 - and any '.local'). What
    survives in the captured working session is exactly one thing per media
    section: the public server-reflexive candidate.

    aiortc has no mDNS support, so it advertises every local interface
    verbatim. On a Docker host that is eight 172.x.0.1 bridge gateways plus
    the LAN address, all at `host` priority 2130706431 - strictly above the
    real srflx candidates. FreeSWITCH picks its media destination from that
    list and streams to an address that goes nowhere, which is why ICE and
    DTLS both complete (those work off the source address of the packets we
    send) while inbound RTP stays at exactly zero.

    Dropping the private host candidates is not enough on its own either:
    Arlo's web player is configured with STUN only and no TURN, so a relay
    candidate is another shape it never sends. Keep public srflx only."""
    match = _CANDIDATE_RE.match(line)
    if match is None:
        return False
    transport, _priority, host, _port, typ, _rport = match.groups()
    if transport.lower() != "udp":
        return False
    if typ != "srflx":
        return False
    if ":" in host or ".local" in host:
        return False
    return not _is_private_ipv4(host)


def _browser_match_offer(offer_sdp):
    """Text-level surgery to make aiortc's offer look more like Arlo's own
    web player's (captured via rtcstats on a session confirmed to work):
    - a single sha-256 fingerprint per media section instead of aiortc's
      default sha-256/384/512.
    - a=extmap-allow-mixed at session level.
    - a=rtcp-rsize alongside a=rtcp-mux.
    - a=rtcp-fb transport-cc/ccm fir entries the browser advertises that
      aiortc doesn't.
    - a=ice-options:trickle, which the browser advertises.
    - keep only the public srflx ICE candidates (see _keep_candidate) and
      re-point each media section's m= port and c= line at the surviving
      default candidate, so the SDP stays self-consistent. FreeSWITCH answers
      488 "INCOMPATIBLE_DESTINATION" to a section with no candidate and a
      c=IN IP4 0.0.0.0, so the candidates cannot simply be dropped."""
    sections = _split_media_sections(offer_sdp.splitlines())
    fixed = []
    for index, section in enumerate(sections):
        fixed.extend(_browser_match_section(section, is_session=index == 0))
    return "\r\n".join(fixed) + "\r\n"


def _split_media_sections(lines):
    """Split SDP lines into [session, media0, media1, ...]."""
    sections = [[]]
    for line in lines:
        if line.startswith("m="):
            sections.append([])
        sections[-1].append(line)
    return sections


def _browser_match_section(lines, is_session):
    kept_candidates = [l for l in lines if _keep_candidate(l)]

    # aiortc points m=/c= at its default (first host) candidate. That
    # candidate is about to be dropped, so re-point them at the srflx
    # candidate derived from it - matched on rport, which is the base
    # candidate's port - falling back to whichever srflx survived.
    default_line = None
    default = None
    if kept_candidates:
        media_port = lines[0].split(" ")[1] if not is_session else None
        for candidate in kept_candidates:
            match = _CANDIDATE_RE.match(candidate)
            if match.group(6) == media_port:
                default_line, default = candidate, match
                break
        if default is None:
            default_line = kept_candidates[0]
            default = _CANDIDATE_RE.match(default_line)

    fixed = []
    seen_fingerprint = False
    for line in lines:
        # aiortc opens one socket per local interface, so every one of them
        # yields its own srflx candidate mapped through the same public IP.
        # The browser only ever offers one, and the extra ones are a liability
        # here: their NAT bindings are only kept alive while aioice is probing
        # them, so if FreeSWITCH latched onto a stale one the media would be
        # dropped upstream. Offer the default only.
        if line.startswith("a=candidate:"):
            if line != default_line:
                continue

        if default is not None and line.startswith("m="):
            parts = line.split(" ")
            parts[1] = default.group(4)
            line = " ".join(parts)

        if default is not None and line.startswith("c=IN IP"):
            fixed.append("c=IN IP4 {}".format(default.group(3)))
            continue

        if line.startswith("a=ice-pwd:"):
            fixed.append(line)
            fixed.append("a=ice-options:trickle")
            continue

        if line.startswith("a=group:BUNDLE"):
            fixed.append(line)
            fixed.append("a=extmap-allow-mixed")
            continue

        if not is_session and line.startswith("a=fingerprint:"):
            if seen_fingerprint:
                continue
            seen_fingerprint = True

        fixed.append(line)

        if line.startswith("a=rtcp-mux"):
            fixed.append("a=rtcp-rsize")
            continue

        match = _RTPMAP_RE.match(line)
        if match:
            pt, name = match.group(1), match.group(2).lower()
            if name == "opus":
                fixed.append("a=rtcp-fb:{} transport-cc".format(pt))
            elif name in ("vp8", "h264", "vp9", "av1"):
                fixed.append("a=rtcp-fb:{} transport-cc".format(pt))
                fixed.append("a=rtcp-fb:{} ccm fir".format(pt))

    return fixed



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
        self._recorder_track_ids = set()
        self._discard_track_ids = set()
        self._discard_track_tasks = set()
        self._recorder_debug_tasks = set()
        self._stats_task = None
        self._video_track_ready = None
        self._video_transceiver = None
        self._video_pli_task = None
        self._video_ssrcs = None
        # Wrapped inbound video track, used by the PLI loop to tell a stalled
        # stream from a healthy one (see _async_send_periodic_video_pli).
        self._video_debug_track = None
        self._keepalive_task = None
        # fast-return start() bookkeeping (see start()/_async_start())
        self._fast_ready = None
        self._start_error = None
        self._start_future = None
        # real-SIP signaling state (see _negotiate_sip)
        self._sip_rand_host = None
        self._sip_from_tag = None
        self._sip_call_id = None
        self._sip_cseq = None
        self._sip_caller_uri = None
        self._sip_callee_uri = None
        self._sip_to_header = None
        self._sip_route_header = None

    @property
    def is_alive(self):
        """Whether this session's peer connection is still usable.

        The peer connection can die in the background (ICE failure, consent
        timeout) without anything calling stop() - callers must check this
        before reusing a cached session/URL, otherwise a dead session's URL
        gets handed out forever after it fails once."""
        return self._pc is not None and self._pc.connectionState not in (
            "failed",
            "closed",
        )

    def _mark_fast_ready(self):
        """Thread-safe checkpoint: unblocks start() as soon as either the
        SIP/WebRTC signaling proxy has responded at all, or setup failed
        before reaching that point. threading.Event.set() is safe to call
        from any thread (unlike asyncio primitives), and this is invoked
        from the background loop's own thread."""
        if self._fast_ready is not None:
            self._fast_ready.set()

    def start(self, timeout=15):
        """Start the session: returns as soon as the local TCP listener
        exists and Arlo's SIP/WebRTC signaling proxy has responded at all
        (the "fast" checkpoint, fired from inside negotiate()) - the rest of
        the ICE/DTLS/track-ready handshake continues in the background on
        this session's own event loop. This keeps get_stream() well within
        Home Assistant's own ~10s stream_source() budget instead of blocking
        for the full 10-15s+ negotiation. A camera that flatly can't do
        SIP/WebRTC still fails synchronously here (see _async_start's first
        except block), so the RTSP-cloud fallback still triggers.

        Returns the local stream URL to hand back from get_stream(). Raises
        WebRtcSessionError on any failure.
        """
        sip_info = self._camera.get_sip_info()
        if not sip_info or not sip_info.get("sipCallInfo"):
            raise WebRtcSessionError("no sipInfo available")
        self._sip_call_info = sip_info["sipCallInfo"]
        ice_servers = _build_ice_servers((sip_info.get("iceServers") or {}).get("data"))

        self._fast_ready = threading.Event()
        self._start_error = None

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name="ArloWebRtc-{}".format(self._camera.device_id),
            daemon=True,
        )
        self._thread.start()

        self._start_future = asyncio.run_coroutine_threadsafe(
            self._async_start(ice_servers), self._loop
        )

        if not self._fast_ready.wait(timeout=timeout):
            self.stop()
            raise WebRtcSessionError("timed out waiting for SIP/WebRTC signaling to start")
        if self._start_error is not None:
            self.stop()
            raise WebRtcSessionError(str(self._start_error))
        return self._tcp_writer.url

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
        # Split into two stages so start() can return to its caller (Home
        # Assistant's stream_source(), bounded by HA's own ~10s timeout) as
        # soon as Arlo's SIP/WebRTC signaling proxy has responded at all,
        # instead of blocking for the entire 10-15s+ ICE/DTLS/track-ready
        # handshake. _mark_fast_ready() is called from inside negotiate()
        # (_negotiate_sip/_negotiate) the moment that first response arrives;
        # this outer try/except only covers the case where we fail *before*
        # that checkpoint (bad sipInfo, WS connect failure, immediate SIP
        # rejection) - such a failure must still unblock start() immediately
        # and raise synchronously so ArloCamera's RTSP-cloud fallback still
        # triggers exactly as it did before this change.
        try:
            # Disabled: this monkeypatch appears to silently break the audio
            # RTCRtpSender entirely (zero RTP sent at all - worse than the
            # marker=1-always issue it was meant to fix). Needs debugging
            # before re-enabling; see _patch_aiortc_audio_marker_bit's
            # docstring for the (still valid) rationale.
            # _patch_aiortc_audio_marker_bit()
            _patch_aiortc_dtls_record_framing()
            _patch_aiortc_video_jitter_buffer()
            self._pc = RTCPeerConnection(
                RTCConfiguration(
                    iceServers=ice_servers, bundlePolicy=RTCBundlePolicy.BALANCED
                )
            )
            self._video_track_ready = asyncio.Event()
            # Order matters: matches Arlo's web player, which always adds
            # "audio" before "video" (recvonly). Unlike the web player, we
            # attach a real (silent) local audio track rather than an empty
            # transceiver - see _SilentAudioTrack.
            self._pc.addTransceiver(_SilentAudioTrack(), direction="sendrecv")
            self._video_transceiver = self._pc.addTransceiver("video", direction="recvonly")

            @self._pc.on("iceconnectionstatechange")
            def on_ice_connection_state_change():
                self._camera.debug("SIP/WebRTC ICE state={}".format(self._pc.iceConnectionState))

            @self._pc.on("connectionstatechange")
            def on_connection_state_change():
                self._camera.debug(
                    "SIP/WebRTC connection state={}".format(self._pc.connectionState)
                )

            @self._pc.on("track")
            def on_track(track):
                self._camera.debug("SIP/WebRTC received {} track".format(track.kind))
                self._tracks.append(track)
                if self._recorder is not None:
                    self._add_recorder_track(track)
                if track.kind == "video" and self._video_track_ready is not None:
                    self._video_track_ready.set()

            self._tcp_writer = _TcpSocketWriter(
                camera=self._camera, on_client=self._start_recorder_from_client
            )
            self._port = self._tcp_writer.port
            self._camera.debug(
                "SIP/WebRTC local TCP listener ready at {}".format(self._tcp_writer.url)
            )
            self._recorder = MediaRecorder(self._tcp_writer, format="mpegts")

            offer = await self._pc.createOffer()
            await self._pc.setLocalDescription(offer)
            await self._wait_ice_gathering_complete()
            offer_sdp = _browser_match_offer(self._pc.localDescription.sdp)
            self._camera.debug(
                "SIP/WebRTC-DBG offer SDP:\n{}".format(offer_sdp)
            )

            self._session_id = str(uuid.uuid4())
            negotiate = self._negotiate_sip if _USE_REAL_SIP else self._negotiate
            answer_sdp = await negotiate(offer_sdp)
            self._camera.debug("SIP/WebRTC-DBG raw answer SDP:\n{}".format(answer_sdp))
        except Exception as e:
            self._start_error = e
            self._mark_fast_ready()
            raise

        # From here on, start() has already returned the TCP URL to its
        # caller (via the checkpoint fired inside negotiate() above) - a
        # failure here can no longer trigger the RTSP-cloud fallback, so
        # instead make sure it closes self._pc, so is_alive correctly
        # reports this session as dead for the *next* get_stream() call.
        try:
            answer_sdp = _strip_unoffered_payload_types(answer_sdp, offer_sdp)
            answer_sdp = _ensure_answer_directions(answer_sdp)
            self._camera.debug(
                "SIP/WebRTC-DBG payload-stripped/direction-fixed answer SDP:\n{}".format(answer_sdp)
            )
            answer_sdp = _ensure_answer_mids(answer_sdp, self._pc.localDescription.sdp)
            self._camera.debug(
                "SIP/WebRTC-DBG mid-fixed answer SDP:\n{}".format(answer_sdp)
            )
            video_ssrcs = _media_section_ssrcs(answer_sdp, "video")
            await self._pc.setRemoteDescription(RTCSessionDescription(sdp=answer_sdp, type="answer"))
            await self._wait_video_connected()
            await self._wait_video_track_ready()
            self._start_video_pli_task(video_ssrcs)
            await self._async_start_recorder()
            await self._send_keepalive("keepAlive")
            self._keepalive_task = asyncio.ensure_future(self._async_keepalive_loop())
            self._camera.debug(
                "SIP/WebRTC peer connection established; recorder is buffering for TCP client"
            )
            return self._tcp_writer.url
        except Exception as e:
            self._start_error = e
            self._camera.debug(
                "SIP/WebRTC background negotiation failed after URL was handed"
                " out ({})".format(e)
            )
            if self._pc is not None:
                try:
                    await self._pc.close()
                except Exception:
                    pass
            raise

    async def _send_instant_message(self, message_string):
        """Send hmswebsocketproxy's JSON-over-WS equivalent of a SIP MESSAGE.

        The 30s keepalive interval this is used for (_KEEPALIVE_INTERVAL) is
        NOT observed on Arlo's own web player for the camera-video path -
        main-JY57BLPJ.js's startKeepAlive()/SIP MESSAGE "keepAlive" every 30s
        belongs to a different feature (the two-way-audio SIP.js call path);
        the video WebRTCPlayer sends no keepalive of any kind. This is
        borrowed by analogy from scryptedapp/arlo's Go SIP client, which uses
        the same 30s interval successfully on this same live-view path over
        real SIP - not confirmed as necessary (or accepted) on the JSON-over-WS
        dialect specifically."""
        domain_with_port = _domain_with_signaling_port(self._sip_call_info)
        body = _instant_message_body(
            self._sip_call_info, self._session_id, message_string, domain_with_port
        )
        message = _http_over_ws_message(
            "POST /hmswebsocketproxy/instantMessage", domain_with_port, body
        )
        await self._ws.send(message)
        response = await asyncio.wait_for(self._ws.recv(), timeout=_SIGNALING_TIMEOUT)
        parsed = _parse_http_over_ws_message(response)
        self._camera.debug(
            "SIP/WebRTC instantMessage({}) response={}".format(message_string, parsed)
        )
        return parsed

    async def _send_keepalive(self, message_string):
        if _USE_REAL_SIP:
            return await self._send_sip_message(message_string)
        return await self._send_instant_message(message_string)

    async def _async_keepalive_loop(self):
        try:
            while True:
                await asyncio.sleep(_KEEPALIVE_INTERVAL)
                await self._send_keepalive("keepAlive")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._camera.debug(
                "SIP/WebRTC keepAlive failed ({}), stopping loop and closing session"
                " (call is presumed dead on the backend)".format(e)
            )
            if self._pc is not None:
                try:
                    await self._pc.close()
                except Exception:
                    pass

    def _start_recorder_from_client(self):
        if self._loop is None:
            return

        def schedule():
            if self._tcp_writer is not None:
                self._tcp_writer.set_live_waiting()
            asyncio.ensure_future(self._async_start_recorder())
            # A client that connects mid-session needs a fresh keyframe right
            # away rather than waiting for the next periodic PLI tick.
            asyncio.ensure_future(self._send_video_pli_once())

        self._loop.call_soon_threadsafe(schedule)

    def _add_recorder_track(self, track):
        track_id = id(track)
        if track_id in self._recorder_track_ids:
            return
        self._recorder_track_ids.add(track_id)
        if track.kind != "video":
            self._discard_unmuxed_track(track)
            return
        wrapped = _DebugMediaTrack(self._camera, track)
        self._video_debug_track = wrapped
        self._recorder.addTrack(wrapped)
        self._camera.debug("SIP/WebRTC recorder added {} track".format(track.kind))
        if self._recorder_started:
            # Safety net for a track that still shows up after the recorder is
            # running: MediaRecorder.start() is idempotent and only spawns
            # reader tasks for contexts that have none, so re-running it is
            # what attaches this one. Without it the track is silently never
            # read.
            asyncio.ensure_future(self._async_attach_late_track())

    async def _async_attach_late_track(self):
        try:
            await self._recorder.start()
            self._attach_recorder_task_debug()
        except Exception as e:
            self._camera.debug(
                "SIP/WebRTC could not attach late recorder track ({})".format(e)
            )

    def _discard_unmuxed_track(self, track):
        track_id = id(track)
        if track_id in self._discard_track_ids:
            return
        self._discard_track_ids.add(track_id)
        task = asyncio.ensure_future(self._async_discard_track(track))
        self._discard_track_tasks.add(task)
        task.add_done_callback(self._discard_track_done)
        self._camera.debug(
            "SIP/WebRTC consuming {} track without muxing it to Home Assistant".format(
                track.kind
            )
        )

    async def _async_discard_track(self, track):
        wrapped = _DebugMediaTrack(self._camera, track)
        try:
            while True:
                await wrapped.recv()
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    def _discard_track_done(self, task):
        self._discard_track_tasks.discard(task)
        if task.cancelled():
            return
        try:
            task.exception()
        except Exception:
            pass

    async def _async_start_recorder(self):
        if self._recorder_started or self._recorder_starting:
            return
        self._recorder_starting = True
        try:
            # MediaRecorder.start() only spawns a reader task per track it
            # already knows about, and it is this call - not track arrival -
            # that a connecting TCP client triggers. Since start() now hands
            # the URL to Home Assistant at the "100 Trying" checkpoint, its
            # ffmpeg routinely connects several seconds before
            # setRemoteDescription creates the tracks; starting here would
            # leave both tracks unread forever, so nothing would ever be muxed
            # and ffmpeg would sit on a silent socket until its 30s probe
            # timeout. Wait for the tracks first.
            await self._wait_video_track_ready()
            await self._prime_recorder_video_size()
            await self._recorder.start()
            self._attach_recorder_task_debug()
            if self._stats_task is None:
                self._stats_task = asyncio.ensure_future(self._async_log_media_stats())
            self._recorder_started = True
            self._camera.debug("SIP/WebRTC recorder started at {}".format(self._tcp_writer.url))
        except Exception as e:
            self._camera.debug("SIP/WebRTC recorder start failed ({})".format(e))
        finally:
            self._recorder_starting = False

    async def _prime_recorder_video_size(self):
        """Pin the recorder's H264 encoder to the camera's real picture size.

        aiortc's MediaRecorder only adopts the output size when it encodes its
        first video frame (contrib/media.py, MediaRecorder.__run_track). That is
        too late here: the audio track yields a frame within ~20ms while the
        first decodable video frame has to wait for a keyframe, so the first
        mux() - and with it avformat_write_header(), which opens every stream's
        encoder - happens while the video stream is still on libx264's 640x480
        default. The encoder then stays at 640x480 for the whole session and
        encodes the top-left 640x480 crop of each 1920x1072 frame, which is
        exactly what a viewer sees: the picture stuck in the corner.

        Peek one frame first (it stays queued for the recorder, see
        _DebugMediaTrack.peek) and size the stream from it."""
        tracks = getattr(self._recorder, "_MediaRecorder__tracks", {})
        for track, context in list(tracks.items()):
            if getattr(track, "kind", None) != "video":
                continue
            stream = getattr(context, "stream", None)
            if stream is None or not hasattr(track, "peek"):
                continue
            try:
                frame = await asyncio.wait_for(
                    track.peek(), timeout=_VIDEO_FRAME_TIMEOUT
                )
            except asyncio.TimeoutError:
                self._camera.debug(
                    "SIP/WebRTC no video frame within {}s, recorder keeps the"
                    " default encoder size".format(_VIDEO_FRAME_TIMEOUT)
                )
                continue
            except Exception as e:
                self._camera.debug(
                    "SIP/WebRTC could not peek a video frame ({})".format(e)
                )
                continue

            width = getattr(frame, "width", None)
            height = getattr(frame, "height", None)
            if not width or not height:
                continue
            stream.width = width
            stream.height = height
            self._camera.debug(
                "SIP/WebRTC recorder video size pinned to {}x{}".format(width, height)
            )

    def _attach_recorder_task_debug(self):
        tracks = getattr(self._recorder, "_MediaRecorder__tracks", {})
        for track, context in list(tracks.items()):
            task = getattr(context, "task", None)
            if task is None or task in self._recorder_debug_tasks:
                continue
            self._recorder_debug_tasks.add(task)
            kind = getattr(track, "kind", "unknown")
            task.add_done_callback(
                lambda done_task, task_kind=kind: self._recorder_task_done(
                    task_kind, done_task
                )
            )

    def _recorder_task_done(self, kind, task):
        if task.cancelled():
            self._camera.debug("SIP/WebRTC recorder {} task cancelled".format(kind))
            return
        try:
            exc = task.exception()
        except Exception as e:
            self._camera.debug(
                "SIP/WebRTC recorder {} task exception lookup failed ({})".format(kind, e)
            )
            return
        if exc is not None:
            self._camera.debug(
                "SIP/WebRTC recorder {} task failed: {}({})".format(
                    kind, type(exc).__name__, exc
                )
            )
        else:
            self._camera.debug("SIP/WebRTC recorder {} task ended".format(kind))

    async def _async_log_media_stats(self):
        last = None
        for _ in range(12):
            await asyncio.sleep(5)
            if self._pc is None:
                return
            try:
                stats = await self._pc.getStats()
            except Exception as e:
                self._camera.debug("SIP/WebRTC stats failed ({})".format(e))
                return
            lines = []
            for report in stats.values():
                report_type = getattr(report, "type", None)
                if report_type in ("inbound-rtp", "outbound-rtp"):
                    kind = (
                        getattr(report, "kind", None)
                        or getattr(report, "mediaType", None)
                        or "unknown"
                    )
                    if report_type == "inbound-rtp":
                        lines.append(
                            "in {} packets={} bytes={} frames={}".format(
                                kind,
                                getattr(report, "packetsReceived", None),
                                getattr(report, "bytesReceived", None),
                                getattr(report, "framesDecoded", None),
                            )
                        )
                    else:
                        lines.append(
                            "out {} packets={} bytes={}".format(
                                kind,
                                getattr(report, "packetsSent", None),
                                getattr(report, "bytesSent", None),
                            )
                        )
                elif report_type == "transport":
                    lines.append(
                        "transport dtls={} sent={}/{} recv={}/{}".format(
                            getattr(report, "dtlsState", None),
                            getattr(report, "packetsSent", None),
                            getattr(report, "bytesSent", None),
                            getattr(report, "packetsReceived", None),
                            getattr(report, "bytesReceived", None),
                        )
                    )
            current = "; ".join(sorted(lines)) if lines else "no RTP/transport stats"
            if current != last:
                self._camera.debug("SIP/WebRTC RTP stats: {}".format(current))
                last = current

    def _start_video_pli_task(self, video_ssrcs):
        if self._video_pli_task is not None:
            return
        if not video_ssrcs:
            self._camera.debug("SIP/WebRTC answer did not advertise video SSRCs for PLI")
            return
        self._camera.debug(
            "SIP/WebRTC answer video SSRCs for PLI: {}".format(
                ",".join(str(ssrc) for ssrc in video_ssrcs)
            )
        )
        self._video_ssrcs = video_ssrcs
        self._video_pli_task = asyncio.ensure_future(
            self._async_send_periodic_video_pli(video_ssrcs)
        )

    async def _send_video_pli_once(self, video_ssrcs=None):
        """Send a single PLI round for the given (or last known) SSRCs.

        Matches scryptedapp/arlo's generic WebRTC bridge (wrtc-to-rtsp.ts),
        which found this gateway-style backend only reliably emits a fresh
        IDR in response to PLI, not just once at call setup - so this is
        also called whenever a new TCP consumer connects, to guarantee it
        gets a decodable frame promptly instead of waiting for the next
        periodic tick."""
        ssrcs = video_ssrcs if video_ssrcs is not None else self._video_ssrcs
        if not ssrcs or self._pc is None or self._pc.connectionState in ("failed", "closed"):
            return
        receiver = getattr(self._video_transceiver, "receiver", None)
        send_pli = getattr(receiver, "_send_rtcp_pli", None)
        if send_pli is None:
            self._camera.debug("SIP/WebRTC video receiver cannot send PLI")
            return
        try:
            for ssrc in ssrcs:
                await send_pli(ssrc)
        except Exception as e:
            self._camera.debug("SIP/WebRTC video PLI failed ({})".format(e))

    async def _async_send_periodic_video_pli(self, video_ssrcs):
        """Ask for a keyframe only while the video is actually stalled.

        An unconditional PLI every few seconds is what gets a stalled session
        going, but once frames are flowing it is actively harmful: each PLI
        forces a fresh 1920x1072 IDR, and FreeSWITCH's answer offers no plain
        `nack` (only `ccm fir`/`nack pli`), so nothing retransmits the packets
        those bursts drop. The result is a decode failure every couple of
        seconds and a picture that freezes until the next keyframe. Only poke
        the camera when no new frame has arrived since the last tick."""
        try:
            attempt = 0
            last_frames = -1
            while True:
                if self._pc is None or self._pc.connectionState in ("failed", "closed"):
                    return
                frames = getattr(self._video_debug_track, "_frames", 0)
                if frames == last_frames:
                    attempt += 1
                    await self._send_video_pli_once(video_ssrcs)
                    if attempt in (1, 5) or attempt % 30 == 0:
                        self._camera.debug(
                            "SIP/WebRTC video stalled at {} frames, sent PLI"
                            " (attempt {})".format(frames, attempt)
                        )
                last_frames = frames
                await asyncio.sleep(_PLI_INTERVAL)
        except asyncio.CancelledError:
            raise

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

    async def _wait_video_connected(self):
        """Wait on the video leg's own DTLS transport rather than the
        aggregate RTCPeerConnection.connectionState, so a slow/failing audio
        leg (bundlePolicy=BALANCED gives it its own independent transport)
        cannot block video, which is the leg that actually matters here."""
        transport = self._video_transceiver.receiver.transport
        if transport.state == "connected":
            return
        done = asyncio.Event()

        @transport.on("statechange")
        def on_change():
            if transport.state in ("connected", "failed", "closed"):
                done.set()

        await asyncio.wait_for(done.wait(), timeout=_CONNECT_TIMEOUT)
        if transport.state != "connected":
            raise WebRtcSessionError(
                "WebRTC video transport failed: {}".format(transport.state)
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
        domain_with_port = _domain_with_signaling_port(self._sip_call_info)
        self._ws = await websockets.connect(
            "wss://{}".format(domain_with_port),
            subprotocols=["sip"],
            # The signaling server rejects the WS upgrade with HTTP 400 if no
            # Origin header is present (confirmed via a real my.arlo.com capture).
            origin="https://my.arlo.com",
            user_agent_header=_ARLO_WEBRTC_WS_USER_AGENT,
            additional_headers={
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Accept-Language": _ARLO_WEBRTC_ACCEPT_LANGUAGE,
            },
        )
        body = _initiate_offer_body(
            self._sip_call_info, self._camera.device_id, self._session_id,
            offer_sdp, domain_with_port,
        )
        message = _http_over_ws_message(
            "POST /hmswebsocketproxy/initiateOffer", domain_with_port, body
        )
        await self._ws.send(message)
        response = await asyncio.wait_for(self._ws.recv(), timeout=_FAST_SIGNALING_TIMEOUT)
        parsed = _parse_http_over_ws_message(response)
        if not parsed.get("success"):
            raise WebRtcSessionError(parsed.get("message", "initiateOffer failed"))
        # Fast checkpoint: the proxy responded at all, so unblock start() -
        # everything from here on runs in _async_start's backgrounded tail.
        self._mark_fast_ready()
        answer = (parsed.get("data") or {}).get("payload", {}).get("answer", {}).get("value")
        if not answer:
            raise WebRtcSessionError("no answer SDP in initiateOffer response")
        return answer

    async def _sip_recv_debug(self, label, timeout=_SIGNALING_TIMEOUT):
        response = await asyncio.wait_for(self._ws.recv(), timeout=timeout)
        self._camera.debug("SIP/WebRTC-DBG SIP {}:\n{}".format(label, response))
        return _parse_sip_message(response)

    async def _negotiate_sip(self, offer_sdp):
        domain = self._sip_call_info["domain"]
        domain_with_port = "{}:{}".format(domain, WEBRTC_SIGNALING_PORT)
        self._ws = await websockets.connect(
            "wss://{}".format(domain_with_port),
            subprotocols=["sip"],
            origin="https://my.arlo.com",
            user_agent_header=_ARLO_WEBRTC_WS_USER_AGENT,
            additional_headers={
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Accept-Language": _ARLO_WEBRTC_ACCEPT_LANGUAGE,
            },
        )

        device_id = self._sip_call_info.get("deviceId", self._camera.device_id)
        self._sip_caller_uri = "sip:{}@{}:{}".format(
            self._sip_call_info["id"], domain, WEBRTC_SIGNALING_PORT
        )
        self._sip_callee_uri = self._sip_call_info["calleeUri"]
        self._sip_rand_host = _sip_gen_rand_host()
        self._sip_from_tag = _sip_gen_tag()
        self._sip_call_id = _sip_gen_call_id()
        self._sip_cseq = 1
        contact_user = _sip_rand_string(8)

        invite = _build_sip_invite(
            self._sip_caller_uri,
            self._sip_callee_uri,
            device_id,
            offer_sdp,
            self._sip_rand_host,
            _sip_gen_branch(),
            self._sip_from_tag,
            self._sip_call_id,
            contact_user,
            self._sip_cseq,
        )
        self._camera.debug("SIP/WebRTC-DBG SIP INVITE:\n{}".format(invite))
        await self._ws.send(invite)

        start_line, _headers, _body = await self._sip_recv_debug(
            "response (expect 100)", timeout=_FAST_SIGNALING_TIMEOUT
        )
        if _sip_status_code(start_line) != 100:
            raise WebRtcSessionError("expected 100 Trying, got: {}".format(start_line))
        # Fast checkpoint: Arlo's signaling proxy is responding at all, so
        # unblock start() - the 407 challenge/200 OK/ACK below and
        # everything after it runs in _async_start's backgrounded tail.
        self._mark_fast_ready()

        start_line, headers, body = await self._sip_recv_debug("response (expect 200/407)")
        status = _sip_status_code(start_line)

        if status == 407:
            auth_params = _sip_parse_proxy_authenticate(
                _sip_header(headers, "proxy-authenticate")
            )
            cnonce = _sip_rand_string(12)
            nc = "00000001"
            response_digest = _sip_digest_response(
                self._sip_call_info["id"],
                auth_params["realm"],
                self._sip_call_info["password"],
                "INVITE",
                self._sip_callee_uri,
                auth_params["nonce"],
                cnonce,
                nc,
            )
            proxy_authorization = (
                'Digest username="{}", realm="{}", nonce="{}", uri="{}", '
                'response="{}", algorithm=MD5, qop=auth, nc={}, cnonce="{}"'
            ).format(
                self._sip_call_info["id"],
                auth_params["realm"],
                auth_params["nonce"],
                self._sip_callee_uri,
                response_digest,
                nc,
                cnonce,
            )

            # RFC 3261: non-2xx responses to INVITE must be ACKed.
            ack = _build_sip_ack_or_bye(
                "ACK",
                self._sip_caller_uri,
                self._sip_callee_uri,
                self._sip_from_tag,
                _sip_header(headers, "to"),
                self._sip_call_id,
                self._sip_cseq,
                self._sip_rand_host,
            )
            await self._ws.send(ack)

            self._sip_cseq += 1
            invite = _build_sip_invite(
                self._sip_caller_uri,
                self._sip_callee_uri,
                device_id,
                offer_sdp,
                self._sip_rand_host,
                _sip_gen_branch(),
                self._sip_from_tag,
                self._sip_call_id,
                contact_user,
                self._sip_cseq,
                proxy_authorization=proxy_authorization,
            )
            self._camera.debug("SIP/WebRTC-DBG SIP INVITE (with auth):\n{}".format(invite))
            await self._ws.send(invite)

            start_line, _headers, _body = await self._sip_recv_debug("response (expect 100)")
            if _sip_status_code(start_line) != 100:
                raise WebRtcSessionError("expected 100 Trying, got: {}".format(start_line))

            start_line, headers, body = await self._sip_recv_debug("response (expect 200)")
            status = _sip_status_code(start_line)

        if status != 200:
            raise WebRtcSessionError("SIP INVITE failed: {}".format(start_line))

        content_type = _sip_header(headers, "content-type") or ""
        if "sdp" not in content_type.lower():
            raise WebRtcSessionError(
                "unexpected SIP response content type: {}".format(content_type)
            )

        self._sip_to_header = _sip_header(headers, "to")
        self._sip_route_header = _sip_reverse_route(
            _sip_header_all(headers, "record-route")
        )

        ack = _build_sip_ack_or_bye(
            "ACK",
            self._sip_caller_uri,
            self._sip_callee_uri,
            self._sip_from_tag,
            self._sip_to_header,
            self._sip_call_id,
            self._sip_cseq,
            self._sip_rand_host,
            route_header_value=self._sip_route_header,
        )
        await self._ws.send(ack)

        return body

    async def _send_sip_message(self, payload):
        """Send an in-dialog SIP MESSAGE on the live call.

        Must reuse the actual INVITE dialog's From-tag/Call-ID and increment
        the shared CSeq (exactly like _send_sip_bye already does) - a fresh
        tag/call-id per message is an out-of-dialog transaction FreeSWITCH
        cannot associate with the live call, so it does nothing to keep the
        call alive. This was the actual bug behind sessions dying on their
        own after a few minutes despite "successful" keepalive responses."""
        self._sip_cseq += 1
        message = _build_sip_message(
            self._sip_caller_uri,
            self._sip_callee_uri,
            self._sip_from_tag,
            self._sip_call_id,
            self._sip_cseq,
            payload,
            to_header=self._sip_to_header,
            route_header_value=self._sip_route_header,
        )
        await self._ws.send(message)
        start_line, _headers, _body = await self._sip_recv_debug(
            "MESSAGE({}) response".format(payload)
        )
        status = _sip_status_code(start_line)
        if status is None or status >= 300:
            raise WebRtcSessionError(
                "SIP MESSAGE({}) rejected: {}".format(payload, start_line)
            )
        return status

    async def _send_sip_bye(self):
        self._sip_cseq += 1
        bye = _build_sip_ack_or_bye(
            "BYE",
            self._sip_caller_uri,
            self._sip_callee_uri,
            self._sip_from_tag,
            self._sip_to_header,
            self._sip_call_id,
            self._sip_cseq,
            self._sip_rand_host,
            route_header_value=self._sip_route_header,
        )
        await self._ws.send(bye)

    async def _async_stop(self):
        # If start() already returned (fast checkpoint fired) while
        # _async_start's backgrounded tail is still negotiating, cancel it so
        # it doesn't keep running/logging after this session has been torn
        # down - mirrors the explicit-cancel pattern used below for
        # _stats_task/_video_pli_task/_keepalive_task.
        if self._start_future is not None:
            self._start_future.cancel()
        if self._ws is not None and self._sip_call_info is not None:
            try:
                if _USE_REAL_SIP and self._sip_to_header is not None:
                    await self._send_sip_bye()
                elif not _USE_REAL_SIP:
                    domain_with_port = _domain_with_signaling_port(self._sip_call_info)
                    body = _session_disconnected_body(
                        self._sip_call_info, self._camera.device_id, self._session_id,
                        domain_with_port,
                    )
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
        for task in list(self._discard_track_tasks):
            task.cancel()
        self._discard_track_tasks.clear()
        if self._stats_task is not None:
            self._stats_task.cancel()
            self._stats_task = None
        if self._video_pli_task is not None:
            self._video_pli_task.cancel()
            self._video_pli_task = None
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            self._keepalive_task = None
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
