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

import unittest
import urlparse
import tempfile
from StringIO import StringIO

from zope.interface.verify import verifyClass
from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger

from repoze.who.plugins.browserid import BrowserIDPlugin, make_plugin
from repoze.who.plugins.browserid import DEFAULT_CHALLENGE_BODY
from repoze.who.plugins.browserid.utils import secure_urlopen


def make_environ(**kwds):
    environ = {}
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = "http"
    environ["SERVER_NAME"] = "localhost"
    environ["SERVER_PORT"] = "80"
    environ["REQUEST_METHOD"] = "GET"
    environ["SCRIPT_NAME"] = ""
    environ["PATH_INFO"] = "/"
    environ.update(kwds)
    return environ


def get_response(app, environ):
    output = []
    def start_response(status, headers, exc_info=None): # NOQA
        output.append(status + "\r\n")
        for name, value in headers:
            output.append("%s: %s\r\n" % (name, value))
        output.append("\r\n")
    for chunk in app(environ, start_response):
        output.append(chunk)
    return "".join(output)


def urlopen_valid(url, post_data):
    """Fake urlopen for testing purposes.

    This function provides the required urlopen interface, but always returns
    a JSON response indicating the posted assertion is valid.
    """
    params = urlparse.parse_qs(post_data)
    data = '{ "status": "okay", "audience": "%s", "email": "%s" }'
    return StringIO(data % (params["audience"][0], params["assertion"][0]))


def urlopen_invalid(url, post_data):
    """Fake urlopen for testing purposes.

    This function provides the required urlopen interface, but always returns
    a JSON response indicating the posted assertion is invalid.
    """
    return StringIO('{ "status": "error" }')



CHALLENGE_BODY = "CHALLENGE HO!"


class TestBrowserIDPlugin(unittest.TestCase):
    """Testcases for the main BrowserIDPlugin class."""

    def test_implements(self):
        verifyClass(IIdentifier, BrowserIDPlugin)
        verifyClass(IAuthenticator, BrowserIDPlugin)
        verifyClass(IChallenger, BrowserIDPlugin)

    def test_make_plugin(self):
        # Test that everything can be set explicitly.
        plugin = make_plugin(
            postback_url="test_postback",
            came_from_field="u_waz_ere",
            challenge_body="repoze.who.plugins.browserid.tests:CHALLENGE_BODY",
            rememberer_name="remembermesoftly",
            verifier_url="http://invalid.org",
            urlopen="repoze.who.plugins.browserid.tests:urlopen_valid")
        self.assertEquals(plugin.postback_url, "test_postback")
        self.assertEquals(plugin.came_from_field, "u_waz_ere")
        self.assertEquals(plugin.challenge_body, "CHALLENGE HO!")
        self.assertEquals(plugin.rememberer_name, "remembermesoftly")
        self.assertEquals(plugin.verifier_url, "http://invalid.org")
        self.failUnless(plugin.urlopen is urlopen_valid)
        # Test that everything gets a sensible default.
        plugin = make_plugin()
        self.assertEquals(plugin.postback_url,
                          "/repoze.who.plugins.browserid.postback")
        self.assertEquals(plugin.came_from_field, "came_from")
        self.assertEquals(plugin.challenge_body, DEFAULT_CHALLENGE_BODY)
        self.assertEquals(plugin.rememberer_name, None)
        self.assertEquals(plugin.verifier_url, "https://browserid.org/verify")
        self.failUnless(plugin.urlopen is secure_urlopen)
        # Test that challenge body can be read from a file.
        with tempfile.NamedTemporaryFile() as f:
            f.write("CHALLENGE IN A FILE!")
            f.flush()
            plugin = make_plugin(challenge_body=f.name)
            self.assertEquals(plugin.challenge_body, "CHALLENGE IN A FILE!")

    def test_identify_with_no_credentials(self):
        plugin = BrowserIDPlugin()
        environ = make_environ()
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_identify_with_authz_header(self):
        plugin = BrowserIDPlugin()
        authz = "BrowserID test@example.com"
        environ = make_environ(HTTP_AUTHORIZATION=authz)
        identity = plugin.identify(environ)
        self.assertEquals(identity["browserid.assertion"], "test@example.com")

    def test_identify_with_invalid_authz_header(self):
        plugin = BrowserIDPlugin()
        authz = "SomeOtherScheme test@example.com"
        environ = make_environ(HTTP_AUTHORIZATION=authz)
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_identify_with_GET_vars(self):
        plugin = BrowserIDPlugin()
        qs = "browserid.assertion=test@example.com"
        environ = make_environ(QUERY_STRING=qs)
        identity = plugin.identify(environ)
        self.assertEquals(identity["browserid.assertion"], "test@example.com")

    def test_identify_with_POST_vars(self):
        plugin = BrowserIDPlugin()
        body = "browserid.assertion=test@example.com"
        environ = make_environ(REQUEST_METHOD="POST",
                               CONTENT_LENGTH=len(body))
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        # This fails since we're not at the postback url.
        self.assertEquals(identity, None)
        # This works since we're at the postback url.
        environ = make_environ(REQUEST_METHOD="POST",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        self.assertEquals(identity["browserid.assertion"], "test@example.com")

    def test_auth_with_no_assertion(self):
        plugin = BrowserIDPlugin(urlopen=urlopen_valid)
        environ = make_environ(HTTP_HOST="localhost")
        identity = {"some other thing": "not browserid"}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)

    def test_auth_with_no_audience(self):
        plugin = BrowserIDPlugin(urlopen=urlopen_valid)
        environ = make_environ()
        identity = {"browserid.assertion": "test@example.com"}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)

    def test_auth_with_good_assertion(self):
        plugin = BrowserIDPlugin(urlopen=urlopen_valid)
        environ = make_environ(HTTP_HOST="localhost")
        identity = {"browserid.assertion": "test@example.com"}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, "test@example.com")

    def test_auth_with_bad_assertion(self):
        plugin = BrowserIDPlugin(urlopen=urlopen_invalid)
        environ = make_environ(HTTP_HOST="localhost")
        identity = {"browserid.assertion": "test@example.com"}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)

