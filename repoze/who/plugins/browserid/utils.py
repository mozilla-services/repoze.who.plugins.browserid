# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is repoze.who.plugins.browserid
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (rkelly@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""

Helper functions for repoze.who.plugins.browserid.

"""

from urlparse import urlparse

import vep.utils


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


def parse_assertion(assertion):
    """Parse interesting information out of a BrowserID assertion.

    This function decodes and parses the given BrowserID assertion, returning
    a dict with the following items:

       * principal:  the asserted identity, eg: {"email": "test@example.com"}
       * audience:   the audience to whom it is asserted

    This does *not* verify the assertion at all, it is merely a way to see
    the information that is being asserted.  If the assertion is malformed
    then ValueError will be raised.
    """
    info = {}
    # Decode the bundled-assertion envelope.
    try:
        data = vep.utils.decode_json_bytes(assertion)
        certificates = data["certificates"]
        assertion = data["assertion"]
        # Get the asserted principal out of the certificate chain.
        info["principal"] = parse_jwt(certificates[0])["principal"]
        # Get the audience out of the assertion token.
        info["audience"] = parse_jwt(assertion)["aud"]
    except (TypeError, KeyError), e:
        raise ValueError(str(e))
    return info


def parse_jwt(token):
    """Parse a JWT to get the contained information.

    This function parses a JSON Web Token and returns the contained dict of
    information.  It does not validate the signature.
    """
    payload = token.split(".")[1]
    return vep.utils.decode_json_bytes(payload)


def str2bool(value):
    """Convert a text string value to a boolean True or False."""
    lvalue = value.lower()
    if lvalue in ("1", "yes", "on", "true"):
        return True
    if lvalue in ("0", "no", "off", "false"):
        return False
    raise ValueError("Not a boolean value: %r" % (value,))
