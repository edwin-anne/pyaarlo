"""Arlo API error codes and what to do about them.

Arlo replies to almost every request with HTTP 200 and an envelope of the form::

    {"meta": {"code": 400, "error": 9276, "message": "..."}, "data": ...}

so the HTTP status alone says very little: the real outcome is ``meta.code``
(HTTP-like) plus ``meta.error`` (an Arlo-specific numeric code). Historically
this library only recognised one of those numeric codes, which meant every
failure was treated identically - "it failed, retry the exact same thing" -
and a permanently dead session looked the same as a momentary blip.

The code groups below are taken from the official web client
(``my.arlo.com``), where ``ConstantsService`` carries the table and
``CamSdkApiService.onResponseSuccess`` applies it. The important insight from
that client is that it distinguishes only a handful of *behaviours*, and has no
blind HTTP retry at all: it is purely reactive, dropping the token and
returning to login when the server says the session is gone. That is the model
mirrored here, so callers should branch on the :class:`ErrorAction` rather than
on individual codes.
"""

from enum import Enum, auto
from typing import Any, NamedTuple, Optional


class ErrorAction(Enum):
    """What a caller should do about a response.

    Branch on this, not on the numeric codes: the same condition reaches us
    under several different codes depending on the endpoint.
    """

    OK = auto()
    """The request succeeded."""

    RETRY = auto()
    """Transient. Retry the same request, with backoff."""

    REAUTH = auto()
    """The session is dead server-side. Discard the saved session and log in
    again from scratch. Retrying the request as-is can never succeed."""

    AUTH_PENDING = auto()
    """Two-step authentication has not been completed yet. NOT a hard failure:
    the caller is expected to carry on with (or restart) the 2FA flow. Treating
    this as an error breaks the PUSH factor, which reports it while waiting."""

    FATAL = auto()
    """Permanent. Credentials are wrong, expired, or the account is locked.
    Never retry - retrying makes a lockout worse - surface it to the user."""

    OTP_RETRY = auto()
    """The one-time code was wrong, expired, or exhausted. A fresh code is
    needed; reusing the current one cannot work."""

    DEVICE_OFFLINE = auto()
    """The device (typically a base station) is unreachable. Nothing to do with
    authentication: stop polling that device instead of retrying."""

    REJECTED = auto()
    """The user actively denied the authentication request."""


# --- Session is gone server-side -------------------------------------------
# ERROR_CODES_SESSION_EXPIRE in the web client, which logs straight out on
# these. 9328 additionally means "you must re-enter your password on all
# signed-in devices", so the saved token is worthless.
SESSION_EXPIRED = frozenset({9002, 9022, 9025, 9328})

# --- Two-step authentication not finished ----------------------------------
# The web client swallows these as successes rather than failing the call.
#   9233/9276 "Please complete two-step authentication ... and then try again"
#   9278      "There is another pending authentication request"
#   9306      generic, swallowed
#   9307      "MFA is limited for the region"
# 9233 in particular is load-bearing for the PUSH factor: finishAuth returns it
# for as long as the push notification is unanswered, and the web client simply
# keeps polling every 5s. Do not classify these as failures.
AUTH_PENDING = frozenset({9233, 9276, 9278, 9306, 9307})

# --- Permanent, do not retry ------------------------------------------------
#   9001 invalid email address        9004 authentication failed for credentials
#   9015 password not correct         9016 account not found
#   9019 email and password do not match
#   9058 invalid email address        9340 password expired
# Retrying any of these can never succeed: the credentials themselves need to
# change, which is why hass-aarlo turns this into a "Reconfigure" card rather
# than an automatic retry.
FATAL_AUTH = frozenset({9001, 9004, 9015, 9016, 9019, 9058, 9340})

# --- Temporary lockout, retry after it expires -------------------------------
#   9017 account locked (5 minutes)
# Not permanent like the codes above - the account unlocks itself - so this is
# RETRY, not FATAL: FATAL sends the user to a "Reconfigure" card even though
# nothing about their credentials is wrong, and RETRY lets Home Assistant's own
# ConfigEntryNotReady backoff recover unattended once the 5 minutes pass.
# Callers that blind-retry immediately (a handful of login attempts a few
# seconds apart, before this classification is even visible) still need to
# special-case 9017 themselves: retrying *at all* during the lockout window
# keeps extending it, which RETRY's normal backoff is too slow to prevent on
# its own for the first few seconds.
ACCOUNT_LOCKED = frozenset({9017})

# --- A new one-time code is required ---------------------------------------
#   9234/9301 code retry limit exceeded, resend and try again
#   9236      incorrect code          9237 code expired
#   9238      authentication request timed out
#   9243      code is required
OTP_ERRORS = frozenset({9234, 9236, 9237, 9238, 9243, 9301})

# --- The user said no -------------------------------------------------------
REJECTED = frozenset({9239})

# --- Transient / unknown-but-worth-retrying ---------------------------------
#   0 request timed out, 9000/9029/9241/9316/9334 generic "something went wrong"
TRANSIENT = frozenset({0, 9000, 9029, 9241, 9316, 9334})

# --- Device unreachable (a different namespace entirely) --------------------
# These arrive on base-station notify calls, not auth calls. The web client's
# GatewayPollingService marks the gateway and all its children unavailable and
# stops polling it rather than retrying.
DEVICE_OFFLINE = frozenset({2059, 2222})

# --- Untrusted browser ------------------------------------------------------
# Empirically Arlo returns 9204 on the auth endpoints to mean "this browser is
# not trusted, complete a login" - which is why this library has always treated
# it as an expected, non-noisy step of logging in. Note that the official code
# table maps 9204 to "New email already exists": Arlo reuses numeric codes
# across endpoints, so this one is deliberately interpreted in the auth
# context, where it is the only meaning that makes sense.
UNTRUSTED = frozenset({9204})

# Codes that are an expected part of logging in, so they should not be logged
# as warnings. The web client likewise swallows AUTH_PENDING silently.
QUIET = AUTH_PENDING | UNTRUSTED


# Messages taken from the official client's ERROR_STRINGS, so that what we log
# matches what a user would have seen in the web UI for the same code.
MESSAGES = {
    0: "Your request timed out.",
    1134: "Invalid image.",
    2059: "Base station is not responding.",
    2222: "Base station is not responding.",
    9000: "Something went wrong. Try again.",
    9001: "Invalid email address.",
    9002: "Your session expired. Please login to continue.",
    9004: "Authentication failed for current credentials.",
    9013: "Account already exists.",
    9015: "Password not correct.",
    9016: "Account not found.",
    9017: "Due to multiple attempts account is locked. Please try again after 5 minutes.",
    9019: "Email and password does not match.",
    9022: "Session expired. Sign in again.",
    9025: "Session expired. Sign in again.",
    9029: "An error has occurred. Please try again.",
    9058: "Invalid email address.",
    9072: "Invalid phone number.",
    9204: "Browser is not trusted, a full login is required.",
    9233: "Please complete two-step authentication successfully and then try again.",
    9234: "Code retry limit exceeded. Resend the code and try again.",
    9236: "Incorrect code. Please try again.",
    9237: "Code expired, please resend code.",
    9238: "Authentication request timed-out. Try again.",
    9239: "Your authentication request has been rejected.",
    9241: "Something went wrong. Try again.",
    9243: "Please enter the code.",
    9261: "Invalid phone number.",
    9262: "Either number is not valid or region is not supported.",
    9263: "Two-factor authentication for this account is already completed.",
    9264: "Verification method already exists.",
    9271: "Device limit reached, remove a device then try again.",
    9276: "Please complete two-step authentication successfully and then try again.",
    9278: "There is another pending authentication request.",
    9285: "Email is already confirmed.",
    9286: "New password matches one of the passwords you have used before.",
    9301: "Code retry limit exceeded. Resend the code and try again.",
    9303: "Application was removed from your device. Try another verification method.",
    9304: "Application was removed from your device. Try another verification method.",
    9305: "Application was removed from your device. Try another verification method.",
    9306: "Something went wrong. Try again.",
    9307: "MFA is limited for the region.",
    9310: "Our services are not supported in your country.",
    9316: "Something went wrong. Try again.",
    9328: "Re-login required. You must re-enter your password on all signed in devices.",
    9334: "Something went wrong. Try again.",
    9340: "Password expired.",
    9361: "Something went wrong. Try again.",
}


def message_for(arlo_error, default=None):
    """Return the human-readable message for an Arlo error code."""
    return MESSAGES.get(arlo_error, default)


def classify(http_code, arlo_error=None):
    """Map a response onto the action a caller should take.

    :param http_code: ``meta.code`` when the envelope carried one, otherwise
        the HTTP status. Our own transport failures arrive here as 500.
    :param arlo_error: ``meta.error`` if the envelope carried one.
    :returns: the :class:`ErrorAction` to take.

    The Arlo code wins when both are present: it is far more specific than the
    HTTP-ish code, which is frequently a flat 400 for wildly different causes -
    a dead session and an unfinished 2FA enrolment both arrive as 400.
    """
    if arlo_error is not None:
        if arlo_error in SESSION_EXPIRED:
            return ErrorAction.REAUTH
        if arlo_error in AUTH_PENDING:
            return ErrorAction.AUTH_PENDING
        if arlo_error in ACCOUNT_LOCKED:
            return ErrorAction.RETRY
        if arlo_error in FATAL_AUTH:
            return ErrorAction.FATAL
        if arlo_error in OTP_ERRORS:
            return ErrorAction.OTP_RETRY
        if arlo_error in REJECTED:
            return ErrorAction.REJECTED
        if arlo_error in DEVICE_OFFLINE:
            return ErrorAction.DEVICE_OFFLINE
        if arlo_error in UNTRUSTED:
            return ErrorAction.REAUTH
        if arlo_error in TRANSIENT:
            return ErrorAction.RETRY
        # An unknown Arlo code. Retry rather than give up: unknown codes are
        # more often a new transient condition than a new permanent one, and a
        # wrong FATAL would leave the integration dead until a restart.
        return ErrorAction.RETRY

    if http_code == 200:
        return ErrorAction.OK
    if http_code == 401:
        # The web client's only interceptor: drop the token, tear down the
        # event stream and go back to login. No silent retry.
        return ErrorAction.REAUTH
    if http_code == 403:
        # Arlo uses 403 for a token that is present but no longer accepted.
        return ErrorAction.REAUTH
    if http_code == 429:
        # Rate limited, very often Cloudflare rather than Arlo itself.
        return ErrorAction.RETRY
    return ErrorAction.RETRY


def is_permanent(action):
    """Whether retrying can never help, so retries should stop entirely."""
    return action in (ErrorAction.FATAL, ErrorAction.REJECTED)


def describe(http_code, arlo_error=None, message=None):
    """Build a log line that keeps every piece of diagnostic information.

    Existing log lines such as ``session start failed`` and ``failed to set
    mode.`` name only the symptom, so an expired token, a revision conflict and
    a socket timeout all read identically. Use this so the code survives into
    the log.
    """
    action = classify(http_code, arlo_error)
    parts = [f"code={http_code}"]
    if arlo_error is not None:
        parts.append(f"error={arlo_error}")
    parts.append(f"action={action.name}")
    text = message or message_for(arlo_error)
    if text:
        parts.append(f"message={text}")
    return ",".join(parts)


class ArloResponse(NamedTuple):
    """Everything a response told us, instead of only part of it.

    The library's public ``get``/``put``/``post`` return the body alone, which
    is why a dead token used to be indistinguishable from an empty result. This
    keeps the code and the classification alongside the body so callers that
    need to react can, while the simple accessors stay unchanged.
    """

    code: int
    """``meta.code`` when the envelope carried one, else the HTTP status."""

    body: Any
    """The payload (``meta.data``), or the error message on failure."""

    arlo_error: Optional[int] = None
    """``meta.error``, when present."""

    message: Optional[str] = None
    """``meta.message``, or our own description of a transport failure."""

    action: ErrorAction = ErrorAction.OK

    @property
    def ok(self):
        return self.action is ErrorAction.OK

    def describe(self):
        return describe(self.code, self.arlo_error, self.message)


class ArloApiError(Exception):
    """An Arlo API call failed, carrying enough detail to decide what to do.

    Replaces raising bare strings, which forced callers to either guess or give
    up. ``action`` is the field to branch on.
    """

    def __init__(self, http_code, arlo_error=None, message=None, action=None):
        self.http_code = http_code
        self.arlo_error = arlo_error
        self.message = message or message_for(arlo_error)
        self.action = action if action is not None else classify(http_code, arlo_error)
        super().__init__(describe(http_code, arlo_error, message))

    @property
    def is_permanent(self):
        return is_permanent(self.action)
