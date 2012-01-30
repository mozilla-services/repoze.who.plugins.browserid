# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Helper functions for repoze.who.plugins.browserid.

"""

from urlparse import urlparse


def check_url_origin(origin, url):
    """Check that the origin of the given URL matches the expected value.

    This function allows you to check whether a URL comes from the same origin
    as some canonical URL, which is useful for enforcing various same-origin
    security checks::

        >>> check_url_origin("http://mysite.com", "http://mysite.com/test1")
        True
        >>> check_url_origin("http://mysite.com", "http://evil.com/test1")
        False

    """
    origin_p = urlparse(origin)
    url_p = urlparse(url)
    # They must use the same protocol.
    if origin_p.scheme != url_p.scheme:
        return False
    # They must be at the same host.
    if origin_p.hostname != url_p.hostname:
        return False
    # They must be on the same port, taking standard ports into account.
    STANDARD_PORTS = {"http": 80, "https": 443}
    if origin_p.port:
        origin_port = origin_p.port
    else:
        origin_port = STANDARD_PORTS.get(origin_p.scheme, None)
    if url_p.port:
        url_port = url_p.port
    else:
        url_port = STANDARD_PORTS.get(url_p.scheme, None)
    if origin_port != url_port:
        return False
    # OK, looks good.
    return True


def str2bool(value):
    """Convert a text string value to a boolean True or False."""
    lvalue = value.lower()
    if lvalue in ("1", "yes", "on", "true"):
        return True
    if lvalue in ("0", "no", "off", "false"):
        return False
    raise ValueError("Not a boolean value: %r" % (value,))
