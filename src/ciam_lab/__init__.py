"""Personal customer identity lab. Synthetic users only."""

import warnings

_warn = warnings.warn


def _quiet_authlib(message, category=None, stacklevel=1, source=None):
    """Authlib forces its own deprecation warnings on. Keep the lab output readable."""
    if isinstance(message, Warning) and type(message).__name__ == "AuthlibDeprecationWarning":
        return None
    if getattr(category, "__name__", "") == "AuthlibDeprecationWarning":
        return None
    return _warn(message, category=category, stacklevel=stacklevel, source=source)


warnings.warn = _quiet_authlib

__version__ = "1.0.0"
