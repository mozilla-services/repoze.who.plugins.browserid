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
# The Original Code is Cornice (Sagrada)
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (ryan@rfk.id.au)
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
import re
import ssl
import time
import socket
import httplib
import urllib2
from fnmatch import fnmatch


# Regular expression matching a single param in the HTTP_AUTHORIZATION header.
# This is basically <name>=<value> where <value> can be an unquoted token,
# an empty quoted string, or a quoted string where the ending quote is *not*
# preceded by a backslash.
_AUTH_PARAM_RE = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
_AUTH_PARAM_RE = re.compile(r"^\s*" + _AUTH_PARAM_RE + r"\s*$")

# Regular expression matching an unescaped quote character.
_UNESC_QUOTE_RE = r'(^")|([^\\]")'
_UNESC_QUOTE_RE = re.compile(_UNESC_QUOTE_RE)

# Regular expression matching a backslash-escaped characer.
_ESCAPED_CHAR = re.compile(r"\\.")


def parse_auth_header(value):
    """Parse an authorization header string into an identity dict.

    This function can be used to parse the value from an Authorization
    header into a dict of its constituent parameters.  The auth scheme
    name will be included under the key "scheme", and any other auth
    params will appear as keys in the dictionary.

    For example, given the following auth header value:

        'BrowserID realm="www.example.com" assertion="abcdef"

    This function will return the following dict:

        {"scheme": "BrowseriD",
          realm: "www.example.com",
         "assertion": "abcdef"}

    """
    scheme, kvpairs_str = value.split(None, 1)
    # Split the parameters string into individual key=value pairs.
    # In the simple case we can just split by commas to get each pair.
    # Unfortunately this will break if one of the values contains a comma.
    # So if we find a component that isn't a well-formed key=value pair,
    # then we stitch bits back onto the end of it until it is.
    kvpairs = []
    if kvpairs_str:
        for kvpair in kvpairs_str.split(","):
            if not kvpairs or _AUTH_PARAM_RE.match(kvpairs[-1]):
                kvpairs.append(kvpair)
            else:
                kvpairs[-1] = kvpairs[-1] + "," + kvpair
        if not _AUTH_PARAM_RE.match(kvpairs[-1]):
            raise ValueError('Malformed auth parameters')
    # Now we can just split by the equal-sign to get each key and value.
    params = {"scheme": scheme}
    for kvpair in kvpairs:
        (key, value) = kvpair.strip().split("=", 1)
        # For quoted strings, remove quotes and backslash-escapes.
        if value.startswith('"'):
            value = value[1:-1]
            if _UNESC_QUOTE_RE.search(value):
                raise ValueError("Unescaped quote in quoted-string")
            value = _ESCAPED_CHAR.sub(lambda m: m.group(0)[1], value)
        params[key] = value
    return params


# When using secure_urlopen we search for the platform default ca-cert file.
# This is done on-demand and the result cached in this global variable.
DEFAULT_CACERT_FILE = None
POSSIBLE_CACERT_FILES = ["/etc/ssl/certs/ca-certificates.crt",
                         "/etc/ssl/certs/ca-bundle.crt"]

_OPENER_CACHE = {}


def secure_urlopen(url, data=None, ca_certs=None):
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
    return opener.open(url, data)


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
            raise httplib.HTTPException(err)
        # Refuse to connect if the certificate has expired.
        if "notAfter" in cert:
            if ssl.cert_time_to_seconds(cert["notAfter"]) < now:
                err = "expired SSL certificate for %s" % (self.host,)
                raise httplib.HTTPException(err)
        # Refuse to connect if the certificate is missing subject data.
        if "subject" not in cert:
            err = "malformed SSL certificate for %s" % (self.host,)
            raise httplib.HTTPException(err)
        # Try to match the certificate to the requested host.
        if not self._validate_certificate_hostname(cert):
            err = "invalid SSL certificate for %s" % (self.host,)
            raise httplib.HTTPException(err)

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
