import logging
from pyaarlo.cfg import ArloCfg


_LOGGER = logging.getLogger("pyaarlo")


class Background(object):
    """Stand in for ArloBackground that runs jobs inline.

    Deliberately mirrors the real `run(bg_cb, **kwargs)` signature, so a caller
    that passes positional arguments blows up here the same way it would in
    production instead of quietly passing the test.
    """

    def __init__(self):
        self.jobs = []

    def run(self, bg_cb, **kwargs):
        self.jobs.append((bg_cb, kwargs))
        return bg_cb(**kwargs)


class PyArlo(object):

    def __init__(self, **kwargs):
        """Constructor for the PyArlo object."""
        self._last_error = None
        self._last_warning = None
        self._cfg = ArloCfg(self, **kwargs)
        self._bg = Background()

    @property
    def cfg(self):
        return self._cfg

    @property
    def bg(self):
        return self._bg

    def error(self, msg):
        self._last_error = msg
        _LOGGER.error(msg)

    @property
    def last_error(self):
        """Return the last reported error."""
        return self._last_error

    @property
    def last_warning(self):
        """Return the last reported warning."""
        return self._last_warning

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
