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

import os
import ssl
import time
import json
import base64
import socket
import httplib
import urllib2
from urlparse import urlparse
from fnmatch import fnmatch


BROWSERID_VERIFIER_URL = "https://browserid.org/verify"


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


def verify_assertion(assertion, audience, verifier_url=None, urlopen=None):
    """Verify the given BrowserID assertion.

    This function submits the given assertion and audience to the BrowserID
    verifier service.  If valid then it returns the dict of identity info
    from the assertion; if invalid then None is returned.

    Eventually this might learn how to do local verification.
    """
    if verifier_url is None:
        verifier_url = BROWSERID_VERIFIER_URL
    if urlopen is None:
        urlopen = secure_urlopen
    # Encode the data into x-www-form-urlencoded.
    post_data = {"assertion": assertion, "audience": audience}
    post_data = "&".join("%s=%s" % item for item in post_data.items())
    # Post it to the verifier.
    try:
        resp = urlopen(verifier_url, post_data)
        try:
            info = resp.info()
        except AttributeError:
            info = {}
        content_length = info.get("Content-Length")
        if content_length is None:
            data = resp.read()
        else:
            data = resp.read(int(content_length))
        data = json.loads(data)
    except (ValueError, IOError):
        return None
    # Did it come back clean?
    if data.get('status') != "okay":
        return None
    if data.get('audience') != audience:
        return None
    return data


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
        data = json.loads(decode_urlb64(assertion))
        certificates = data["certificates"]
        assertion = data["assertion"]
        # Get the asserted principal out of the certificate chain.
        info["principal"] = parse_jwt(certificates[0])["principal"]
        # Get the audience out of the assertion token.
        info["audience"] = parse_jwt(assertion)["aud"]
    except (TypeError, KeyError), e:
        raise ValueError(e.message)
    return info


def parse_jwt(token):
    """Parse a JWT to get the contained information.

    This function parses a JSON Web Token and returns the contained dict of
    information.  It does not validate the signature.
    """
    payload = token.split(".")[1]
    return json.loads(decode_urlb64(payload))


def decode_urlb64(value):
    """Decode BrowserID's base64 encoding format.

    BrowserID likes to strip padding characters off of base64-encoded strings,
    meaning we can't use the stdlib routines to decode them directly.  This
    is a simple wrapper that adds the padding back in.
    """
    if isinstance(value, unicode):
        value = value.encode("ascii")
    pad = len(value) % 4
    if pad == 2:
        value += "=="
    elif pad == 3:
        value += "="
    elif pad != 0:
        raise ValueError("incorrect b64 encoding")
    return base64.urlsafe_b64decode(value)


def str2bool(value):
    """Convert a text string value to a boolean True or False."""
    lvalue = value.lower()
    if lvalue in ("1", "yes", "on", "true"):
        return True
    if lvalue in ("0", "no", "off", "false"):
        return False
    raise ValueError("Not a boolean value: %r" % (value,))


# When using secure_urlopen we search for the platform default ca-cert file.
# This is done on-demand and the result cached in this global variable.
DEFAULT_CACERT_FILE = None
POSSIBLE_CACERT_FILES = ["/etc/ssl/certs/ca-certificates.crt",
                         "/etc/ssl/certs/ca-bundle.crt",
                         "/etc/ssl/ca-bundle.pem",
                         "/etc/pki/tls/certs/ca-bundle.crt"]

_OPENER_CACHE = {}


def secure_urlopen(url, data=None, timeout=None, ca_certs=None):
    """More secure replacement for urllib2.urlopen.

    This function provides an alternative to urllib2.urlopen which does
    basic validation and verification of HTTPS server certificates.
    """
    global DEFAULT_CACERT_FILE
    # Try to find platform default ca-cert file if none was specified.
    if ca_certs is None:
        ca_certs = DEFAULT_CACERT_FILE
        if ca_certs is None:
            for filenm in POSSIBLE_CACERT_FILES:
                if os.path.exists(filenm):
                    ca_certs = DEFAULT_CACERT_FILE = filenm
                    break
            if ca_certs is None:
                err = "could not locate default ca_certs file"
                raise RuntimeError(err)
    # Use a cached opener if possible.
    try:
        opener = _OPENER_CACHE[ca_certs]
    except KeyError:
        opener = urllib2.build_opener(ValidatingHTTPSHandler(ca_certs))
        _OPENER_CACHE[ca_certs] = opener
    return opener.open(url, data, timeout)


class ValidatingHTTPSHandler(urllib2.HTTPSHandler):
    """A urllib2 HTTPS handler that validates server certificates.

    This class provides a urllib2-compatible opener that will validate
    the HTTPS server certificate against the requested hostname before
    proceeding with the connection.

    It's mostly a wrapper around ValidatingHTTPSConnection, which is where
    all the fun really happens.
    """

    def __init__(self, ca_certs):
        urllib2.HTTPSHandler.__init__(self)
        self.ca_certs = ca_certs

    def https_open(self, req):
        return self.do_open(self._get_connection, req)

    def _get_connection(self, host, timeout):
        return ValidatingHTTPSConnection(host, timeout=timeout,
                                         ca_certs=self.ca_certs)


class ValidatingHTTPSConnection(httplib.HTTPSConnection):
    """HTTPSConnection that validates the server certificate.

    This class adds some SSL certificate-checking to httplib.  It's not
    robust and it's not complete, it's just enough to verify the certificate
    of the browserid.org verifier server.  Hopefully it will also work with
    other verifier URLs you might like to use.

    The connector also restricts SSL to version 3 in order to avoid
    downgrading the connection to an insecure older version.

    It doesn't do revocation checks.  It should.  But I've no idea how.

    The code uses implementations hints provided by:

        http://www.heikkitoivonen.net/blog/2008/10/14/ssl-in-python-26/

    """

    def __init__(self, *args, **kwds):
        self.ca_certs = kwds.pop("ca_certs", None)
        if self.ca_certs is None:
            raise TypeError("missing keyword argument: ca_certs")
        httplib.HTTPSConnection.__init__(self, *args, **kwds)

    def connect(self):
        addr = (self.host, self.port)
        sock = socket.create_connection(addr, self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=self.ca_certs)
        cert = self.sock.getpeercert()
        self._validate_certificate(cert)

    def _validate_certificate(self, cert):
        now = time.time()
        # Refuse to connect if there's no certificate.
        if cert is None:
            err = "no SSL certificate for %s" % (self.host,)
            raise socket.error(err)
        # Refuse to connect if the certificate has expired.
        if "notAfter" in cert:
            if ssl.cert_time_to_seconds(cert["notAfter"]) < now:
                err = "expired SSL certificate for %s" % (self.host,)
                raise socket.error(err)
        # Refuse to connect if the certificate is missing subject data.
        if "subject" not in cert:
            err = "malformed SSL certificate for %s" % (self.host,)
            raise socket.error(err)
        # Try to match the certificate to the requested host.
        if not self._validate_certificate_hostname(cert):
            err = "invalid SSL certificate for %s" % (self.host,)
            raise socket.error(err)

    def _validate_certificate_hostname(self, cert):
        for rdn in cert["subject"]:
            for name, value in rdn:
                if name == "commonName":
                    if value == self.host:
                        return True
                    elif fnmatch(self.host, value):
                        return True
                    # Ugh.
                    # It seems https://browserid.org uses the certificate for
                    # https://www.browserid.org, but redirects us away from
                    # that domain.  Apparently this is OK..?
                    elif value == "www." + self.host:
                        return True
        return False
