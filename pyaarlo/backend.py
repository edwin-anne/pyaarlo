from __future__ import annotations

import json
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
    AUTH_UNTRUSTED_ERRORS,
    AUTH_FINISH_PATH,
    AUTH_GET_FACTORID,
    AUTH_GET_FACTORS,
    AUTH_PATH,
    AUTH_START_PAIRING,
    AUTH_START_PATH,
    AUTH_VALIDATE_PATH,
    DEFAULT_RESOURCES,
    DEVICES_PATH,
    LOGOUT_PATH,
    MQTT_HOST,
    MQTT_PATH,
    MQTT_URL_KEY,
    NOTIFY_PATH,
    ORIGIN_HOST,
    REFERER_HOST,
    RELOGIN_BACKOFF_BASE,
    RELOGIN_BACKOFF_MAX,
    SESSION_PATH,
    SUBSCRIBE_PATH,
    TFA_CONSOLE_SOURCE,
    TFA_IMAP_SOURCE,
    TFA_PUSH_DENIED_ERROR,
    TFA_PUSH_SOURCE,
    TFA_PUSH_TYPE,
    TFA_REST_API_SOURCE,
    TFA_SOURCES,
    TOKEN_MIN_SECONDS_LEFT,
    TRANSID_PREFIX,
    USER_AGENTS,
)
from .sseclient import SSEClient
from .tfa import Arlo2FAConsole, Arlo2FAImap, Arlo2FARestAPI
from .util import now_strftime, seconds_until, time_to_arlotime, to_b64


class AuthResult(IntEnum):
    CAN_RETRY = -1,
    SUCCESS = 0,
    FAILED = 1


class LoginStep(IntEnum):
    """Where an interactive `login_*` call has left the login.

    `SUCCESS` - logged in, nothing more to do.
    `NEEDS_FACTOR` - call `login_choose_factor()` with one of `login_factors`.
    `AWAITING_PUSH` - call `login_poll_push()` again after `tfa_push_poll`
      seconds, until it stops returning this.
    `AWAITING_CODE` - call `login_submit_code()` with the code the user typed.
    `FAILED` - could not log in, see `last_error`.
    """
    FAILED = 0
    SUCCESS = 1
    NEEDS_FACTOR = 2
    AWAITING_PUSH = 3
    AWAITING_CODE = 4


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

    # State for an interactive login in progress, driven by the `login_*`
    # methods rather than the classic blocking `_login()`.
    _login_factors: list | None = None
    _login_factor: dict | None = None
    _login_factor_auth_code: str | None = None
    _login_headers: dict | None = None
    _login_push_deadline: float | None = None

    def __init__(self, arlo, auto_login=True):

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
        self._load_cookies()
        if auto_login:
            self._logged_in = self._login()
            if not self._logged_in:
                self.debug("failed to log in")
                return
        else:
            # Caller drives the login themselves through the `login_*`
            # methods, e.g. an interactive setup flow that needs to show the
            # user their 2FA factors before picking one.
            self._logged_in = False

    def _set_token(self, token):
        """Set the token, keeping the base64 flavour the auth API wants in step."""
        self._token = token
        self._token64 = to_b64(token) if token is not None else None

    def _load_session(self):
        self._user_id = None
        self._web_id = None
        self._sub_id = None
        self._set_token(None)
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
                        self._set_token(session_info["token"])
                        self._expires_in = session_info["expires_in"]
                        if "browser_auth_code" in session_info:
                            self._browser_auth_code = session_info["browser_auth_code"]
                        if "device_id" in session_info:
                            self._user_device_id = session_info["device_id"]
                        self.debug(f"loadv{version}:session_info={ArloBackEnd._session_info}")
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
                    self.debug(f"savev2:session_info={ArloBackEnd._session_info}")
        except Exception as e:
            self._arlo.warning("session file not written" + str(e))

    def _save_cookies(self):
        if self._cookies is not None:
            self.debug(f"saving-cookies={self._cookies}")
            self._cookies.save(ignore_discard=True)

    def _load_cookies(self):
        self._cookies = LWPCookieJar(self._arlo.cfg.cookies_file)
        try:
            # Must match the ignore_discard we save with. Arlo's browser trust
            # cookie has no expiry, so loading without this reads it back as
            # nothing and we get asked for a 2FA code on every restart.
            self._cookies.load(ignore_discard=True)
        except FileNotFoundError:
            self.debug("no cookie file yet")
        except Exception as e:
            self._arlo.warning(f"cookie file not read: {e}")
        self.debug(f"loading cookies={self._cookies}")

    def _transaction_id(self):
        return 'FE!' + str(uuid.uuid4())

    def _build_url(self, url, tid):
        sep = "&" if "?" in url else "?"
        now = time_to_arlotime()
        return f"{url}{sep}eventId={tid}&time={now}"

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
                        return 200, r
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
                    return 200, None
        except Exception as e:
            self._arlo.warning("request-error={}".format(type(e).__name__))
            return 500, None

        try:
            if "application/json" in r.headers["Content-Type"]:
                body = r.json()
            else:
                body = r.text
            self.vdebug("request-body=\n{}".format(pprint.pformat(body)))
        except Exception as e:
            self._arlo.warning("body-error={}".format(type(e).__name__))
            self._arlo.debug(f"request-text={r.text}")
            return 500, None

        self.vdebug("request-end={}".format(r.status_code))
        if r.status_code != 200:
            return r.status_code, None

        if raw:
            return 200, body

        # New auth style and TFA helper
        if "meta" in body:
            if body["meta"]["code"] == 200:
                return 200, body["data"]
            else:
                # don't warn on untrusted errors, they just mean we need to log in
                if body["meta"]["error"] not in AUTH_UNTRUSTED_ERRORS:
                    self._arlo.warning("error in new response=" + str(body))
                return int(body["meta"]["code"]), body["meta"]["message"]

        # Original response type
        elif "success" in body:
            if body["success"]:
                if "data" in body:
                    return 200, body["data"]
                # success, but no data so fake empty data
                return 200, {}
            else:
                self._arlo.warning("error in response=" + str(body))

        return 500, None

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
        code, body = self._request_tuple(path=path, method=method, params=params, headers=headers,
                                         stream=stream, raw=raw, timeout=timeout, host=host, authpost=authpost, cookies=cookies)
        return body

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
        self.debug("re-logging in")

        while not self._stop_thread:

            # say we're starting
            if self._dump_file is not None:
                with open(self._dump_file, "a") as dump:
                    time_stamp = now_strftime("%Y-%m-%d %H:%M:%S.%f")
                    dump.write("{}: {}\n".format(time_stamp, "event_thread start"))

            # login again if not first iteration, this will also create a new session.
            # Back off on consecutive failures so a persistent auth problem doesn't
            # turn into a tight retry loop against Arlo's (Cloudflare-fronted) login
            # endpoint - that's what trips Cloudflare's 429 rate limiting.
            retry_wait = RELOGIN_BACKOFF_BASE
            while not self._logged_in and not self._stop_thread:
                with self._lock:
                    self._lock.wait(retry_wait)
                if self._stop_thread:
                    break
                self.debug("re-logging in")
                self._logged_in = self._login()
                if not self._logged_in:
                    retry_wait = min(retry_wait * 2, RELOGIN_BACKOFF_MAX)

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
                # Logged out? MQTT will log back in until stopped.
                self._arlo.warning("logged out? did you log in from elsewhere?")
                return

            # pass on to general handler
            self._event_handle_response(response)

        except json.decoder.JSONDecodeError as e:
            self.debug("reopening: json error " + str(e))

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
        """Return the 2FA handler we're using, or `None` if it isn't configured."""
        tfa_source = self._arlo.cfg.tfa_source
        if tfa_source == TFA_CONSOLE_SOURCE:
            return Arlo2FAConsole(self._arlo)
        elif tfa_source == TFA_IMAP_SOURCE:
            return Arlo2FAImap(self._arlo)
        elif tfa_source == TFA_REST_API_SOURCE:
            return Arlo2FARestAPI(self._arlo)
        elif tfa_source == TFA_PUSH_SOURCE:
            # Push has no handler, Arlo asks the phone app directly and we just
            # wait for the user to tap approve.
            return TFA_PUSH_SOURCE
        self._arlo.error(
            "unknown tfa_source '{}', expected one of: {}".format(
                tfa_source, ", ".join(TFA_SOURCES)
            )
        )
        return None

    @staticmethod
    def _describe_factor(factor):
        """One line description of a 2FA factor, for logs and listings."""
        return "{}/{} ({})".format(
            factor.get("factorType", "?"),
            factor.get("displayName") or factor.get("factorNickname") or "?",
            factor.get("factorId", "?"),
        )

    def _get_factors(self, headers=None):
        """Return the 2FA factors Arlo has on file, or `None` if we can't read them.

        Needs a token - either a part authenticated one from the middle of a
        login, or a full one once we're in.
        """
        if headers is None:
            headers = self._auth_headers()
            headers["Authorization"] = self._token64
        code, body = self.auth_get_tuple(
            AUTH_GET_FACTORS + "?data = {}".format(int(time.time())), {}, headers
        )
        if code != 200:
            self._arlo.error(f"2fa: unable to read the factor list: {code} - {body}")
            return None
        return body.get("items", [])

    def _select_factor(self, factors):
        """Pick the 2FA factor Arlo should send the code to.

        `tfa_factor_id` wins outright. It names one exact factor, which is the
        only reliable way to choose when an account has several of the same
        type - two phones, or a work and a home email. Without it we fall back
        to matching on `tfa_type` and then `tfa_nickname`.
        """
        known = ", ".join(self._describe_factor(f) for f in factors)

        wanted_id = self._arlo.cfg.tfa_factor_id
        if wanted_id is not None:
            for factor in factors:
                if factor.get("factorId") == wanted_id:
                    self.debug(f"2fa: using {self._describe_factor(factor)}")
                    return factor
            self._arlo.error(
                f"2fa: no factor with id {wanted_id}, this account has: {known}"
            )
            return None

        wanted_type = self._arlo.cfg.tfa_type
        of_type = [
            f for f in factors if f.get("factorType", "").lower() == wanted_type
        ]
        if not of_type:
            self._arlo.error(
                f"2fa: no {wanted_type} factor, this account has: {known}"
            )
            return None

        nickname = self._arlo.cfg.tfa_nickname
        for factor in of_type:
            if factor.get("factorNickname") == nickname:
                self.debug(f"2fa: using {self._describe_factor(factor)}")
                return factor

        if len(of_type) > 1:
            self._arlo.warning(
                f"2fa: no {wanted_type} factor nicknamed '{nickname}', falling back "
                f"to {self._describe_factor(of_type[0])} - set tfa_factor_id to choose"
            )
        self.debug(f"2fa: using {self._describe_factor(of_type[0])}")
        return of_type[0]

    def tfa_factors(self):
        """Return the 2FA factors configured on the account.

        Each entry carries at least `factorId`, `factorType`, `factorRole` and
        `factorNickname`. Feed a `factorId` back in as `tfa_factor_id` to pin
        the login to that one factor.
        """
        return self._get_factors()

    def _update_auth_info(self, body):
        if "accessToken" in body:
            body = body["accessToken"]
        self._set_token(body["token"])
        self._user_id = body["userId"]
        self._web_id = self._user_id + "_web"
        self._sub_id = "subscriptions/" + self._web_id
        self._expires_in = body["expiresIn"]
        if "browserAuthCode" in body:
            self.debug("browser auth code: {}".format(body["browserAuthCode"]))
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
            "User-Agent": self._user_agent,
            "X-Service-Version": "3",
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

    def _auth_trusted_browser(self, factor_id, headers):
        """Finish a login on a browser Arlo already trusts.

        No code and no waiting: startAuth on the BROWSER factor answers with a
        full token straight away.
        """
        self.debug("browser is trusted, finishing without 2fa")
        payload = {
            "factorId": factor_id,
            "factorType": "BROWSER",
            "userId": self._user_id
        }
        self._options = self.auth_options(AUTH_START_PATH, headers)
        code, body = self.auth_post(AUTH_START_PATH, payload, headers)
        if code != 200:
            self._arlo.error(f"login failed: quick start failed: {code} - {body}")
            return AuthResult.FAILED, None
        return AuthResult.SUCCESS, body

    def _start_factor_auth(self, factor, headers, factor_type="BROWSER"):
        """POST startAuth for one factor - shared by the OTP and push flows,
        and by the resumable `login_choose_factor()`.

        `factor_type` is what push sends: an empty string rather than
        `BROWSER`, matching what the Arlo apps do.
        """
        payload = {
            "factorId": factor["factorId"],
            "factorType": factor_type,
            "userId": self._user_id
        }
        self._options = self.auth_options(AUTH_START_PATH, headers)
        code, body = self.auth_post(AUTH_START_PATH, payload, headers)
        if code != 200:
            self._arlo.error(f"login failed: start failed: {code} - {body}")
            return AuthResult.CAN_RETRY, None
        return AuthResult.SUCCESS, body["factorAuthCode"]

    def _finish_factor_auth(self, factor_auth_code, headers, otp=None):
        """POST finishAuth for a typed code - shared by `_auth_with_otp()`
        and the resumable `login_submit_code()`.
        """
        payload = {"factorAuthCode": factor_auth_code, "isBrowserTrusted": True}
        if otp is not None:
            payload["otp"] = otp
        code, body = self.auth_post(AUTH_FINISH_PATH, payload, headers)
        if code != 200:
            self._arlo.error(f"login failed: finish failed: {code} - {body}")
            return AuthResult.FAILED, None
        return AuthResult.SUCCESS, body

    def _check_push_auth(self, factor_auth_code, headers):
        """One non-blocking finishAuth check for a push login - shared by
        `_auth_with_push()`'s wait loop and the resumable `login_poll_push()`.

        `AuthResult.CAN_RETRY` means "not yet, keep polling". `FAILED` means
        denied. `SUCCESS` carries the finished auth body.
        """
        # Ask raw, so we can read the error number under the meta block and
        # tell a denial from a "not yet".
        code, body = self.auth_post(
            AUTH_FINISH_PATH, {
                "factorAuthCode": factor_auth_code,
                "isBrowserTrusted": True
            },
            headers, raw=True,
        )
        meta = (body or {}).get("meta", {})

        if code == 200 and meta.get("code") == 200:
            return AuthResult.SUCCESS, body.get("data", {})
        if meta.get("error") == TFA_PUSH_DENIED_ERROR:
            return AuthResult.FAILED, None
        return AuthResult.CAN_RETRY, None

    def _auth_with_otp(self, factor, headers):
        """Have Arlo send a code, then read it back from the configured source."""
        tfa = self._get_tfa()
        if tfa is None:
            return AuthResult.FAILED, None
        if tfa == TFA_PUSH_SOURCE:
            self._arlo.error(
                "login failed: tfa_source is 'push' but {} cannot be approved "
                "from the phone app, pick a PUSH factor or another "
                "tfa_source".format(self._describe_factor(factor))
            )
            return AuthResult.FAILED, None

        # Snapshot the source before Arlo sends anything, so imap can tell the
        # new mail from the old.
        if not tfa.start():
            self._arlo.error("login failed: 2fa: startup failed")
            return AuthResult.FAILED, None

        self.debug(f"starting auth with {self._describe_factor(factor)}")
        result, factor_auth_code = self._start_factor_auth(factor, headers)
        if result != AuthResult.SUCCESS:
            tfa.stop()
            return result, None

        otp = tfa.get()
        tfa.stop()
        if otp is None:
            self._arlo.error("login failed: 2fa: code retrieval failed")
            return AuthResult.CAN_RETRY, None

        self.debug("finishing auth")
        return self._finish_factor_auth(factor_auth_code, headers, otp=otp)

    def _auth_with_push(self, factor, headers):
        """Wait for the user to approve the login in the Arlo phone app.

        There is no code to type. Arlo pushes a prompt to the phone and we poll
        finishAuth until it is approved, denied, or we run out of patience.
        """
        self.debug(f"starting push auth with {self._describe_factor(factor)}")
        result, factor_auth_code = self._start_factor_auth(factor, headers, factor_type="")
        if result != AuthResult.SUCCESS:
            return result, None

        timeout = self._arlo.cfg.tfa_push_timeout
        poll = self._arlo.cfg.tfa_push_poll
        name = factor.get("displayName") or factor.get("factorNickname") or "your phone"
        self._arlo.info(
            f"2fa: approve the login on {name}, waiting up to {timeout}s"
        )

        deadline = time.monotonic() + timeout
        while True:
            result, body = self._check_push_auth(factor_auth_code, headers)

            if result == AuthResult.SUCCESS:
                self.debug("push approved")
                return result, body

            if result == AuthResult.FAILED:
                self._arlo.error("login failed: 2fa: the push was denied")
                return result, None

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._arlo.error(
                    f"login failed: 2fa: nobody answered the push within {timeout}s"
                )
                return AuthResult.FAILED, None
            time.sleep(min(poll, remaining))

    def _signin(self, headers) -> tuple[AuthResult, dict | None]:
        """POST username/password, retrying a couple of times on a Cloudflare
        hiccup. Shared by `_auth()` and the resumable `login_start()`.
        """
        # Handle 1015 error
        attempt = 0
        code = 0
        body = None
        while attempt < 3:
            attempt += 1
            self.debug("login attempt #{}".format(attempt))
            self._options = self.auth_options(AUTH_PATH, headers)

            code, body = self.auth_post(
                AUTH_PATH,
                {
                    "email": self._arlo.cfg.username,
                    "password": to_b64(self._arlo.cfg.password),
                    "language": "en",
                    "EnvSource": "prod",
                },
                headers,
            )
            if code == 200 or code == 401:
                break
            time.sleep(3)

        if body is None:
            self._arlo.error(f"login failed: {code} - possible cloudflare issue")
            return AuthResult.CAN_RETRY, None
        if code != 200:
            self._arlo.error(f"login failed: {code} - {body}")
            return AuthResult.FAILED, None
        return AuthResult.SUCCESS, body

    def _check_trusted_browser(self, headers):
        """Ask Arlo if this browser is already paired.

        Returns `(True, factor_id)` if it is - `_auth_trusted_browser` can
        finish the login without bothering the user. Returns `(False,
        factors)` if not, with the account's 2FA factor list (`None` on
        error). Shared by `_auth()` and the resumable `login_start()`.
        """
        self.debug("getting tfa choices")
        self._options = self.auth_options(AUTH_GET_FACTORID, headers)

        # Is this browser already trusted? If it is Arlo hands us a BROWSER
        # factor and we can finish without bothering the user at all.
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
            return True, body["factorId"]

        self._needs_pairing = True
        return False, self._get_factors(headers)

    def _auth(self) -> AuthResult:
        headers = self._auth_headers()

        result, body = self._signin(headers)
        if result != AuthResult.SUCCESS:
            return result

        # save new login information
        self._update_auth_info(body)

        # Looks like we need 2FA. So, request a code be sent to our email address.
        if not body["authCompleted"]:
            self.debug("need 2FA...")

            headers["Authorization"] = self._token64

            trusted, data = self._check_trusted_browser(headers)
            if trusted:
                result, body = self._auth_trusted_browser(data, headers)
            else:
                factors = data
                if not factors:
                    self._arlo.error("login failed: 2fa: no secondary choices available")
                    return AuthResult.FAILED

                factor = self._select_factor(factors)
                if factor is None:
                    return AuthResult.FAILED

                # Which flow to run is decided by the factor, not by the config.
                # A PUSH factor has no code to type, so asking a code source for
                # one would just hang until it gave up.
                if factor.get("factorType", "").upper() == TFA_PUSH_TYPE:
                    result, body = self._auth_with_push(factor, headers)
                else:
                    result, body = self._auth_with_otp(factor, headers)

            if result != AuthResult.SUCCESS:
                return result

            # save new login information
            self._update_auth_info(body)

        return AuthResult.SUCCESS

    def _finish_login(self, body) -> bool:
        """Finish an interactive login: record the token, validate it, pair
        the browser if needed, and persist both to disk.

        Used by the resumable `login_*` API once a factor's auth body comes
        back - mirrors what `_authenticate()` does inline for the classic
        blocking login path.
        """
        self._update_auth_info(body)
        if not (self._validate() and self._pair_auth_code()):
            return False
        self._logged_in = True
        self._save_session()
        return True

    def login_start(self) -> LoginStep:
        """Begin an interactive login: reuse a saved session if we still can,
        else sign in with the password and see whether 2FA is needed.

        Returns `SUCCESS` if nothing more is needed (a resumed session, or an
        already-trusted browser), `NEEDS_FACTOR` if the caller must pick one
        of `login_factors` and call `login_choose_factor()`, or `FAILED`
        (see `last_error`).
        """
        self._user_agent = self.user_agent(self._arlo.cfg.user_agent)
        if self._session is None:
            self._create_session()

        if self._resume_session():
            return LoginStep.SUCCESS

        headers = self._auth_headers()
        result, body = self._signin(headers)
        if result != AuthResult.SUCCESS:
            return LoginStep.FAILED

        self._update_auth_info(body)

        if body["authCompleted"]:
            return LoginStep.SUCCESS if self._finish_login(body) else LoginStep.FAILED

        headers["Authorization"] = self._token64
        trusted, data = self._check_trusted_browser(headers)
        if trusted:
            result, body = self._auth_trusted_browser(data, headers)
            if result != AuthResult.SUCCESS:
                return LoginStep.FAILED
            return LoginStep.SUCCESS if self._finish_login(body) else LoginStep.FAILED

        factors = data
        if not factors:
            self._arlo.error("login failed: 2fa: no secondary choices available")
            return LoginStep.FAILED

        self._login_factors = factors
        return LoginStep.NEEDS_FACTOR

    @property
    def login_factors(self):
        """The 2FA factors offered after `login_start()` returns `NEEDS_FACTOR`."""
        return self._login_factors

    def login_choose_factor(self, factor_id) -> LoginStep:
        """Start auth with one of the factors from `login_factors`.

        Returns `AWAITING_PUSH` if the caller should now poll
        `login_poll_push()`, `AWAITING_CODE` if it should collect a typed
        code and call `login_submit_code()`, or `FAILED`.
        """
        factors = self._login_factors or []
        factor = next((f for f in factors if f.get("factorId") == factor_id), None)
        if factor is None:
            known = ", ".join(self._describe_factor(f) for f in factors)
            self._arlo.error(f"2fa: no factor with id {factor_id}, this account has: {known}")
            return LoginStep.FAILED

        headers = self._auth_headers()
        headers["Authorization"] = self._token64
        self._login_headers = headers
        self._login_factor = factor

        if factor.get("factorType", "").upper() == TFA_PUSH_TYPE:
            result, factor_auth_code = self._start_factor_auth(factor, headers, factor_type="")
            if result != AuthResult.SUCCESS:
                return LoginStep.FAILED
            self._login_factor_auth_code = factor_auth_code
            timeout = self._arlo.cfg.tfa_push_timeout
            self._login_push_deadline = time.monotonic() + timeout
            name = factor.get("displayName") or factor.get("factorNickname") or "your phone"
            self._arlo.info(f"2fa: approve the login on {name}, waiting up to {timeout}s")
            return LoginStep.AWAITING_PUSH

        result, factor_auth_code = self._start_factor_auth(factor, headers)
        if result != AuthResult.SUCCESS:
            return LoginStep.FAILED
        self._login_factor_auth_code = factor_auth_code
        return LoginStep.AWAITING_CODE

    def login_poll_push(self) -> LoginStep:
        """One non-blocking check of a push login started with
        `login_choose_factor()`. Call again after `tfa_push_poll` seconds
        while it keeps returning `AWAITING_PUSH`.
        """
        result, body = self._check_push_auth(self._login_factor_auth_code, self._login_headers)

        if result == AuthResult.SUCCESS:
            return LoginStep.SUCCESS if self._finish_login(body) else LoginStep.FAILED

        if result == AuthResult.FAILED:
            self._arlo.error("login failed: 2fa: the push was denied")
            return LoginStep.FAILED

        if time.monotonic() >= self._login_push_deadline:
            timeout = self._arlo.cfg.tfa_push_timeout
            self._arlo.error(f"login failed: 2fa: nobody answered the push within {timeout}s")
            return LoginStep.FAILED

        return LoginStep.AWAITING_PUSH

    def login_submit_code(self, otp) -> LoginStep:
        """Finish an EMAIL/SMS login with the code the user typed in,
        started with `login_choose_factor()`.
        """
        result, body = self._finish_factor_auth(self._login_factor_auth_code, self._login_headers, otp=otp)
        if result != AuthResult.SUCCESS:
            return LoginStep.FAILED
        return LoginStep.SUCCESS if self._finish_login(body) else LoginStep.FAILED

    def _validate(self):
        headers = self._auth_headers()
        headers["Authorization"] = self._token64

        # Validate it! The auth API answers a rejected token with http 200 and
        # an error in the `meta` block, so we have to look at the code rather
        # than just check we got a body back.
        code, body = self.auth_get_tuple(
            AUTH_VALIDATE_PATH + "?data = {}".format(int(time.time())), {}, headers
        )
        if code != 200:
            self._arlo.error(f"token validation failed: {code} - {body}")
            return False
        return True

    def _pair_auth_code(self):
        headers = self._auth_headers()
        headers["Authorization"] = self._token64

        if not self._needs_pairing:
            self._arlo.debug("no pairing required")
            self._save_cookies()
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
        code, body = self.auth_post(AUTH_START_PAIRING, payload, headers, cookies=self._cookies)
        self._save_cookies()

        if code != 200:
            self._arlo.error(f"pairing: failed: {code} - {body}")
            return False

        self._arlo.debug("pairing succeeded")
        return True

    def _v2_session(self):
        v2_session = self.get(SESSION_PATH)
        if v2_session is None:
            self._arlo.error("session start failed")
            return False
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
            self._session = cffi_requests.Session(impersonate=self._arlo.cfg.curl_cffi_impersonate)
        else:
            import cloudscraper
            self._session = cloudscraper.create_scraper(
                disableCloudflareV1=True,
                ecdhCurve=curve,
                debug=False,
            )
        if self._cookies is not None:
            self._session.cookies = self._cookies

    def _resume_session(self):
        """Try to carry on with the token we saved last time.

        This is what the web app does when you reload the page: it keeps the
        token in local storage and only revalidates it. Reusing it saves a
        password POST on every restart and, more to the point, on every event
        stream reconnect - and it is that stream of password posts that upsets
        CloudFlare.

        Arlo tokens only last a couple of hours, so this helps within that
        window rather than across days. That is still most reconnects.
        """
        if not self._arlo.cfg.reuse_session:
            return False
        if self._token is None or self._user_id is None:
            self.debug("no saved token to resume")
            return False

        left = seconds_until(self._expires_in)
        if left < TOKEN_MIN_SECONDS_LEFT:
            self.debug(f"saved token expires in {left:.0f}s, logging in again")
            return False

        if not self._validate():
            self.debug("saved token rejected, logging in again")
            return False

        self.debug(f"resumed saved session, token good for another {left:.0f}s")
        self._needs_pairing = False
        self._save_cookies()
        return True

    def _authenticate(self) -> AuthResult:
        """Get us a usable token, reusing the saved one when we still can."""
        if self._resume_session():
            return AuthResult.SUCCESS

        result = self._auth()
        if result != AuthResult.SUCCESS:
            return result
        if not (self._validate() and self._pair_auth_code()):
            # Worth another go on a different CloudFlare curve.
            return AuthResult.CAN_RETRY
        return AuthResult.SUCCESS

    def _login(self):

        # pickup user configured user agent
        self._user_agent = self.user_agent(self._arlo.cfg.user_agent)

        success = AuthResult.FAILED
        if self._arlo.cfg.http_backend == "curl_cffi":
            self._create_session()
            success = self._authenticate()
        else:
            for curve in self._arlo.cfg.ecdh_curves:
                self.debug(f"CloudFlare curve set to: {curve}")
                self._create_session(curve=curve)

                # Try to authenticate. We retry if it was a cloud flare
                # error or we failed to get the 2FA code.
                success = self._authenticate()
                if success != AuthResult.CAN_RETRY:
                    break
                self.debug("login failed, trying another ecdh_curve")

        if success != AuthResult.SUCCESS:
            return False

        # save session in case we updated it
        self._save_session()

        # update sessions headers
        headers = self._headers()
        self._session.headers.update(headers)

        # Grab a session. Needed for new session and used to check existing
        # session. (May not really be needed for existing but will fail faster.)
        if not self._v2_session():
            return False
        return True

    def _notify(self, base, body, trans_id=None):
        if trans_id is None:
            trans_id = self.gen_trans_id()

        body["to"] = base.device_id
        if "from" not in body:
            body["from"] = self._web_id
        body["transId"] = trans_id

        response = self.post(
            NOTIFY_PATH + base.device_id, body, headers={"xcloudId": base.xcloud_id}
        )

        if response is None:
            return None
        else:
            return trans_id

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
            except KeyError as _e:
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
            return self._request(
                path, "GET", params, headers, stream, raw, timeout, host, cookies=cookies
            )
        else:
            self.vdebug("get sent")
            self._arlo.bg.run(
                self._request, path=path, method="GET", params=params, headers=headers,
                stream=stream, raw=raw, timeout=timeout, host=host, cookies=cookies
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
            return self._request(
                path, "PUT", params, headers, False, raw, timeout, cookies=cookies
            )
        else:
            self.vdebug("put sent")
            self._arlo.bg.run(
                self._request, path=path, method="PUT", params=params, headers=headers,
                raw=raw, timeout=timeout, cookies=cookies
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
            self._request(path, "POST", params, headers, False, raw, timeout)
            return self._wait_for_transaction(tid, timeout)
        if wait_for == "response":
            self.vdebug("post+response running")
            return self._request(path, "POST", params, headers, False, raw, timeout)
        else:
            self.vdebug("post sent")
            self._arlo.bg.run(
                self._request, path=path, method="POST", params=params, headers=headers,
                raw=raw, timeout=timeout
            )

    def auth_post(self, path, params=None, headers=None, raw=False, timeout=None, cookies=None):
        return self._request_tuple(
            path, "POST", params, headers, False, raw, timeout, self._arlo.cfg.auth_host, authpost=True, cookies=cookies
        )

    def auth_get_tuple(self, path, params=None, headers=None, timeout=None, cookies=None):
        """Auth host GET that reports the status code as well as the body.

        The auth API signals failure inside a `meta` block on an http 200, so
        callers that care about success need the code, not just the body.
        """
        return self._request_tuple(
            path, "GET", params, headers, False, False, timeout,
            self._arlo.cfg.auth_host, authpost=True, cookies=cookies
        )

    def auth_get(
        self, path, params=None, headers=None, stream=False, raw=False, timeout=None, cookies=None
    ):
        return self._request(
            path, "GET", params, headers, stream, raw, timeout, self._arlo.cfg.auth_host, authpost=True, cookies=cookies
        )

    def auth_options(
        self, path, headers=None, timeout=None
     ):
        return self._request(
            path, "OPTIONS", None, headers, False, False, timeout, self._arlo.cfg.auth_host, authpost=True
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
