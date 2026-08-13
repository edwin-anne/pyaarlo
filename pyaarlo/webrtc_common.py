"""Shared pieces of Arlo's SIP/WebRTC signaling that don't depend on aiortc.

Split out of webrtc.py so a lightweight signaling-only client (see
webrtc_signaling.py) can reuse the exact wire framing without dragging in
aiortc/av, which only exist to run a local WebRTC media engine - something a
signaling-only client, which hands the actual PeerConnection to a real
browser, never needs.

Everything here is either a literal constant reverse-engineered from a real
my.arlo.com capture, or pure data transformation - no network I/O, no aiortc
types.
"""

import json

from .constant import WEBRTC_SIGNALING_PORT

# These are hardcoded literals in Arlo's own web client (main-JY57BLPJ.js),
# confirmed inconsistent with the real browser's own User-Agent/Accept-Language -
# replicated verbatim out of caution rather than using our own values.
ARLO_WEBRTC_USER_AGENT = "ArloWebRTC/1 CFNetwork/1329 Darwin/21.3.0"
ARLO_WEBRTC_ACCEPT_LANGUAGE = "en-IN,en-GB;q=0.9,en;q=0.8"

# The pseudo-HTTP messages tunneled *inside* the WebSocket use the literals
# above, but the WebSocket upgrade request itself is made by the real
# browser and carries its own User-Agent/Accept-Language (confirmed via a
# real my.arlo.com capture) - not the ArloWebRTC one. websockets' own
# default User-Agent ("Python/x.y websockets/z") is an obvious tell that
# this isn't a real client, so replicate a browser-like one here too.
ARLO_WEBRTC_WS_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"
    " Chrome/128.0.0.0 Safari/537.36"
)

SIGNALING_TIMEOUT = 10
# Bounds only the synchronous prefix's wait for the first signaling response -
# kept much tighter than SIGNALING_TIMEOUT so callers with their own upstream
# deadline (e.g. Home Assistant's ~10s stream_source()/WebRTC-offer budget)
# can return well within it; everything after that checkpoint can afford to
# be patient.
FAST_SIGNALING_TIMEOUT = 5


def http_over_ws_message(request_line, host, body_obj):
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
        ua=ARLO_WEBRTC_USER_AGENT,
        length=len(body),
        lang=ARLO_WEBRTC_ACCEPT_LANGUAGE,
    )
    return headers + body


def parse_http_over_ws_message(text):
    """Parse the pseudo-HTTP response hmswebsocketproxy sends back."""
    header_end = text.index("\r\n\r\n")
    return json.loads(text[header_end + 4:])


def rewritten_sip_call_info(sip_call_info, domain_with_port):
    """Arlo's own client rewrites domain/port to the signaling host:port and
    drops conferenceId/callId/deviceId before sending sipCallInfo back."""
    return {
        "calleeUri": sip_call_info["calleeUri"],
        "id": sip_call_info["id"],
        "password": sip_call_info["password"],
        "domain": domain_with_port,
        "port": str(WEBRTC_SIGNALING_PORT),
    }


def domain_with_signaling_port(sip_call_info):
    return "{}:{}".format(sip_call_info["domain"], WEBRTC_SIGNALING_PORT)


def build_ice_server_kwargs(ice_servers_data):
    """Normalize Arlo's iceServers.data payload into RTCIceServer kwargs.

    Returns plain dicts ({"urls": ..., "username": ..., "credential": ...})
    rather than an aiortc/webrtc_models type, so this stays usable by callers
    that don't want either dependency - each wraps the result in whatever
    ICE-server type it actually needs.
    """
    servers = []
    for entry in ice_servers_data or []:
        server_type = entry.get("type")
        domain = entry.get("domain")
        port = entry.get("port")
        if not server_type or not domain or not port:
            continue

        url = "{}:{}:{}".format(server_type, domain, port)
        transport = entry.get("transport")
        if server_type in ("turn", "turns") and transport:
            # Both aiortc and browsers default TURN URLs without ?transport=
            # to UDP. Arlo gives separate TCP/UDP TURN entries, so keep that
            # distinction.
            url = "{}?transport={}".format(url, transport)

        kwargs = {"urls": url}
        if entry.get("username"):
            kwargs["username"] = entry["username"]
        if entry.get("credential"):
            kwargs["credential"] = entry["credential"]
        servers.append(kwargs)
    return servers


def initiate_offer_body(sip_call_info, device_id, session_id, offer_sdp, domain_with_port):
    return {
        "sipCallInfo": rewritten_sip_call_info(sip_call_info, domain_with_port),
        "payload": {
            "sessionId": session_id,
            "cameraId": sip_call_info.get("deviceId", device_id),
            "offer": {"format": "SDP", "value": offer_sdp},
        },
    }


def instant_message_body(sip_call_info, session_id, message_string, domain_with_port):
    return {
        "sipCallInfo": rewritten_sip_call_info(sip_call_info, domain_with_port),
        "payload": {
            "sessionId": session_id,
            "MessageString": message_string,
        },
    }


def session_disconnected_body(sip_call_info, device_id, session_id, domain_with_port):
    return {
        "sipCallInfo": rewritten_sip_call_info(sip_call_info, domain_with_port),
        "payload": {
            "sessionId": session_id,
            "cameraId": sip_call_info.get("deviceId", device_id),
        },
    }
