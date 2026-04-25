"""HTTP helpers for ClawSentry CLI gateway calls."""

from __future__ import annotations

import urllib.parse
import urllib.request
from typing import Any

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_loopback_gateway_url(url: str) -> bool:
    """Return True for the explicitly supported local Gateway hosts."""

    parsed = urllib.parse.urlparse(url)
    return (parsed.hostname or "").lower() in _LOOPBACK_HOSTS


def _request_url(request_or_url: urllib.request.Request | str) -> str:
    if isinstance(request_or_url, urllib.request.Request):
        return request_or_url.full_url
    return str(request_or_url)


def urlopen_gateway(
    request_or_url: urllib.request.Request | str,
    *,
    timeout: float | int | None = None,
) -> Any:
    """Open a Gateway URL, bypassing proxy env only for loopback hosts.

    Corporate shells often export ``HTTP_PROXY`` / ``ALL_PROXY``. Python's
    default urllib opener honors those variables, which can incorrectly route
    local Gateway calls through a remote proxy. For explicit loopback hosts,
    use a per-call opener with ``ProxyHandler({})``. Non-loopback hosts keep
    urllib's default behavior so enterprise proxy semantics are unchanged.
    """

    url = _request_url(request_or_url)
    opener = (
        urllib.request.build_opener(urllib.request.ProxyHandler({}))
        if is_loopback_gateway_url(url)
        else None
    )
    open_fn = opener.open if opener is not None else urllib.request.urlopen
    if timeout is None:
        return open_fn(request_or_url)
    return open_fn(request_or_url, timeout=timeout)
