"""Interactive, resumable Arlo login.

For callers - typically a setup UI - that want to list an account's 2FA
factors and let the user pick one, rather than committing to a `tfa_source`/
`tfa_type` up front the way `PyArlo` does.
"""

import logging
import os

from .backend import ArloBackEnd, LoginStep
from .cfg import ArloCfg


_LOGGER = logging.getLogger("pyaarlo")


class _InlineBackground:
    """Stand-in for `ArloBackground` that runs jobs inline, with no thread.

    The login-only code path never actually queues background work - the
    `auth_*` calls it uses go straight through - but `ArloBackEnd` expects
    `arlo.bg` to exist.
    """

    @staticmethod
    def run(bg_cb, **kwargs):
        return bg_cb(**kwargs)


class ArloLogin:
    """A standalone, resumable Arlo login.

    Unlike `PyArlo`, building one does not log in, refresh devices, or start
    any background threads - it only gets as far as a session. Meant for
    interactive setup flows that need to show the user their real 2FA
    factors and let them choose:

    ```python
    login = ArloLogin(username=USER, password=PASS, storage_dir=DIR)
    step = login.start()
    if step == LoginStep.NEEDS_FACTOR:
        factor_id = ...  # let the user pick one of login.factors
        step = login.choose_factor(factor_id)
    if step == LoginStep.AWAITING_PUSH:
        while step == LoginStep.AWAITING_PUSH:
            time.sleep(login.cfg.tfa_push_poll)
            step = login.poll_push()
    elif step == LoginStep.AWAITING_CODE:
        step = login.submit_code(otp)
    ```

    A `SUCCESS` step means the session and cookies are saved to
    `storage_dir`. A later `PyArlo(storage_dir=DIR, ...)` picks them up
    without asking for the password or a 2FA code again, as long as
    `reuse_session` stays on and the token hasn't expired.
    """

    def __init__(self, **kwargs):
        self._last_error = None
        self._last_warning = None
        self._cfg = ArloCfg(self, **kwargs)
        self._bg = _InlineBackground()

        # `PyArlo` creates this on the way up; a caller building `ArloLogin`
        # standalone (e.g. a setup flow, before `storage_dir` has ever been
        # touched) needs the same thing or the first cookie/session save
        # fails outright.
        if self._cfg.save_state or self._cfg.dump or self._cfg.save_session:
            try:
                if not os.path.exists(self._cfg.storage_dir):
                    os.mkdir(self._cfg.storage_dir)
            except Exception:
                self.warning(f"Problem creating {self._cfg.storage_dir}")

        self._be = ArloBackEnd(self, auto_login=False)

    @property
    def cfg(self):
        return self._cfg

    @property
    def bg(self):
        return self._bg

    @property
    def factors(self):
        """The 2FA factors offered after `start()` returns `NEEDS_FACTOR`.

        Each entry carries at least `factorId`, `factorType`, `factorRole`
        and `factorNickname`.
        """
        return self._be.login_factors

    @property
    def last_error(self):
        """The last reported error, if any."""
        return self._last_error

    @property
    def last_warning(self):
        """The last reported warning, if any."""
        return self._last_warning

    def start(self) -> LoginStep:
        """Reuse a saved session if possible, else sign in with the password
        and see whether 2FA is needed. See `LoginStep` for what to do next.
        """
        return self._be.login_start()

    def choose_factor(self, factor_id) -> LoginStep:
        """Start auth with one of the factors from `factors`."""
        return self._be.login_choose_factor(factor_id)

    def poll_push(self) -> LoginStep:
        """One non-blocking check of a push login started with `choose_factor()`."""
        return self._be.login_poll_push()

    def submit_code(self, otp) -> LoginStep:
        """Finish an EMAIL/SMS login with the code the user typed in."""
        return self._be.login_submit_code(otp)

    def error(self, msg):
        self._last_error = msg
        _LOGGER.error(msg)

    def warning(self, msg):
        self._last_warning = msg
        _LOGGER.warning(msg)

    def info(self, msg):
        _LOGGER.info(msg)

    def debug(self, msg):
        _LOGGER.debug(msg)

    def vdebug(self, msg):
        if self._cfg.verbose:
            _LOGGER.debug(msg)
