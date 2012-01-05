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

import unittest2
import tempfile
import base64
import json
import urllib2
from StringIO import StringIO

from zope.interface import implements
from zope.interface.verify import verifyClass

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.config import WhoConfig
from repoze.who.api import APIFactory
from repoze.who.middleware import PluggableAuthenticationMiddleware

from webtest import TestApp

from vep.utils import get_assertion_info

from repoze.who.plugins.browserid import (BrowserIDPlugin,
                                          make_plugin,
                                          DEFAULT_CHALLENGE_BODY,
                                          _ENVKEY_ERROR_MESSAGE)


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


def make_fake_jwt(payload):
    """Make a fake JWT for testing purposes."""
    payload = base64.urlsafe_b64encode(json.dumps(payload))
    return ".".join(("FAKE", payload, "FAKE"))


def make_fake_assertion(email, audience="http://localhost"):
    """Make a fake, unsigned assertion for testing purposes."""
    certificates = [make_fake_jwt({"principal": {"email": email}})]
    assertion = make_fake_jwt({"aud": audience})
    bundle = json.dumps({"certificates": certificates, "assertion": assertion})
    return base64.urlsafe_b64encode(bundle).rstrip("=")


class DummyRememberer(object):
    """Simple rememberer plugin for testing purposes."""

    implements(IIdentifier)

    def identify(self, environ):
        return None

    def remember(self, environ, identity):
        return [("X-Dummy-Remember", identity["repoze.who.userid"])]

    def forget(self, environ, identity):
        return [("X-Dummy-Remember", "")]


class DummyVerifierValid(object):
    """Dummy verifier class that thinks everything is valid."""

    def verify(self, assertion, audience=None):
        info = get_assertion_info(assertion)
        return {"status": "okay",
                "audience": info["audience"],
                "email": info["principal"]["email"]}


class DummyVerifierInvalid(object):
    """Dummy verifier class that thinks everything is invalid."""

    def verify(self, assertion, audience=None):
        raise ValueError("Invalid BrowserID assertion")


WHO_CONFIG = """
[plugin:browserid]
use = repoze.who.plugins.browserid:make_plugin
audiences = http://localhost
verifier = repoze.who.plugins.browserid.tests.test_plugin:DummyVerifierValid
rememberer_name = dummy

[plugin:dummy]
use = repoze.who.plugins.browserid.tests.test_plugin:DummyRememberer

[identifiers]
plugins = browserid dummy

[authenticators]
plugins = browserid

[challengers]
plugins = browserid

[general]
challenge_decider = repoze.who.classifiers:default_challenge_decider
request_classifier = repoze.who.classifiers:default_request_classifier
"""


CHALLENGE_BODY = "CHALLENGE HO!"


class TestBrowserIDPlugin(unittest2.TestCase):
    """Testcases for the main BrowserIDPlugin class."""

    def _make_api_factory(self):
        parser = WhoConfig("")
        parser.parse(WHO_CONFIG)
        return APIFactory(parser.identifiers,
                          parser.authenticators,
                          parser.challengers,
                          parser.mdproviders,
                          parser.request_classifier,
                          parser.challenge_decider)

    def _make_wsgi_app(self):
        parser = WhoConfig("")
        parser.parse(WHO_CONFIG)

        def application(environ, start_response):
            start_response("401 Unauthorized", [])
            return [""]

        return PluggableAuthenticationMiddleware(application,
                                 parser.identifiers,
                                 parser.authenticators,
                                 parser.challengers,
                                 parser.mdproviders,
                                 parser.request_classifier,
                                 parser.challenge_decider)

    def test_implements(self):
        verifyClass(IIdentifier, BrowserIDPlugin)
        verifyClass(IAuthenticator, BrowserIDPlugin)
        verifyClass(IChallenger, BrowserIDPlugin)

    def test_make_plugin(self):
        # Test that everything can be set explicitly.
        def ref(name):
            return "repoze.who.plugins.browserid.tests.test_plugin:" + name
        plugin = make_plugin(
            audiences="example.com",
            rememberer_name="remember_me_softly",
            postback_url="test_postback",
            assertion_field="da_assertion_baby",
            came_from_field="u_waz_ere",
            csrf_field="for_your_protection",
            csrf_cookie_name="monster",
            challenge_body=ref("CHALLENGE_BODY"),
            verifier="vep:RemoteVerifier",
            verifier_urlopen="urllib2:urlopen",
            check_https="no",
            check_referer="on")
        self.assertEquals(plugin.audiences, ["example.com"])
        self.assertEquals(plugin.rememberer_name, "remember_me_softly")
        self.assertEquals(plugin.postback_url, "test_postback")
        self.assertEquals(plugin.assertion_field, "da_assertion_baby")
        self.assertEquals(plugin.came_from_field, "u_waz_ere")
        self.assertEquals(plugin.csrf_field, "for_your_protection")
        self.assertEquals(plugin.csrf_cookie_name, "monster")
        self.assertEquals(plugin.challenge_body, "CHALLENGE HO!")
        self.assertEquals(plugin.verifier.urlopen, urllib2.urlopen)
        self.assertEquals(plugin.check_https, False)
        self.assertEquals(plugin.check_referer, True)
        # Test that everything gets a sensible default.
        plugin = make_plugin("siteone sitetwo")
        self.assertEquals(plugin.audiences, ["siteone", "sitetwo"])
        self.assertEquals(plugin.rememberer_name, None)
        self.assertEquals(plugin.postback_url,
                          "/repoze.who.plugins.browserid.postback")
        self.assertEquals(plugin.assertion_field, "assertion")
        self.assertEquals(plugin.came_from_field, "came_from")
        self.assertEquals(plugin.csrf_field, "csrf_token")
        self.assertEquals(plugin.csrf_cookie_name, "browserid_csrf_token")
        self.assertEquals(plugin.challenge_body, DEFAULT_CHALLENGE_BODY)
        self.assertEquals(plugin.verifier.__class__.__name__, "RemoteVerifier")
        self.assertEquals(plugin.check_https, None)
        self.assertEquals(plugin.check_referer, None)
        # Test that challenge body can be read from a file.
        with tempfile.NamedTemporaryFile() as f:
            f.write("CHALLENGE IN A FILE!")
            f.flush()
            plugin = make_plugin("www.mysite.com", challenge_body=f.name)
            self.assertEquals(plugin.challenge_body, "CHALLENGE IN A FILE!")
        # Test that empty audiences string goes to None.
        plugin = make_plugin("")
        self.assertEquals(plugin.audiences, None)

    def test_identify_with_no_credentials(self):
        plugin = BrowserIDPlugin(None)
        environ = make_environ()
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_identify_with_POST_vars(self):
        plugin = BrowserIDPlugin(["localhost"])
        assertion = make_fake_assertion("test@example.com")
        body = "assertion=%s&csrf_token=123456" % (assertion,)
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body))
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        # This fails since we're not at the postback url.
        self.assertEquals(identity, None)
        # This works since we're at the postback url.
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        self.assertEquals(identity["browserid.assertion"], assertion)

    def test_identify_with_GET_vars(self):
        plugin = BrowserIDPlugin(["localhost"])
        assertion = make_fake_assertion("test@example.com")
        query_string = "/?assertion=%s&csrf_token=123456" % (assertion,)
        environ = make_environ(REQUEST_METHOD="GET",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               PATH_INFO=plugin.postback_url,
                               QUERY_STRING=query_string)
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_identify_with_no_assertion(self):
        plugin = BrowserIDPlugin(["localhost"])
        body = "csrf_token=123456"
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "No BrowserID assertion found")

    def test_identify_with_required_https(self):
        plugin = BrowserIDPlugin(["localhost"], check_https=True,
                                                check_referer=False)
        assertion = make_fake_assertion("test@example.com")
        body = "assertion=%s&csrf_token=123456" % (assertion,)
        # This one fails due to not being over https.
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "Login requests must use a secure connection")
        # This one still works OK.
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        environ["wsgi.url_scheme"] = "https"
        identity = plugin.identify(environ)
        self.assertEquals(identity["browserid.assertion"], assertion)

    def test_identify_with_malformed_assertion(self):
        plugin = BrowserIDPlugin(["localhost"])
        body = "assertion=%s&csrf_token=123456" % ("JUNK",)
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "Malformed BrowserID assertion")

    def test_identify_with_bad_csrf(self):
        plugin = BrowserIDPlugin(None)
        assertion = make_fake_assertion("test@example.com")
        body = "assertion=%s&csrf_token=987654" % (assertion,)
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_identify_with_missing_csrf(self):
        plugin = BrowserIDPlugin(None)
        assertion = make_fake_assertion("test@example.com")
        body = "assertion=%s&csrf_token=987654" % (assertion,)
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_identify_with_invalid_referer(self):
        plugin = BrowserIDPlugin(["localhost"])
        assertion = make_fake_assertion("test@example.com")
        body = "assertion=%s&csrf_token=123456" % (assertion,)
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               HTTP_REFERER="http://evil.com/attackpage",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        # By default we don't check referer for http connections.
        environ["wsgi.url_scheme"] = "http"
        identity = plugin.identify(environ)
        self.assertEquals(identity["browserid.assertion"], assertion)
        # But we do check them for https connections.
        environ["wsgi.url_scheme"] = "https"
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_identify_with_missing_referer(self):
        plugin = BrowserIDPlugin(["localhost"])
        assertion = make_fake_assertion("test@example.com")
        body = "assertion=%s&csrf_token=123456" % (assertion,)
        environ = make_environ(REQUEST_METHOD="POST",
                               HTTP_COOKIE="browserid_csrf_token=123456",
                               CONTENT_LENGTH=len(body),
                               PATH_INFO=plugin.postback_url)
        environ["wsgi.input"] = StringIO(body)
        # By default we don't check referer for http connections.
        environ["wsgi.url_scheme"] = "http"
        identity = plugin.identify(environ)
        self.assertEquals(identity["browserid.assertion"], assertion)
        # But we do check them for https connections.
        environ["wsgi.url_scheme"] = "https"
        identity = plugin.identify(environ)
        self.assertEquals(identity, None)

    def test_auth_with_no_assertion(self):
        plugin = BrowserIDPlugin(None, verifier=DummyVerifierValid())
        environ = make_environ()
        identity = {"some other thing": "not browserid"}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "No BrowserID assertion found")

    def test_auth_with_mismatched_audience(self):
        plugin = BrowserIDPlugin(None, verifier=DummyVerifierValid())
        environ = make_environ(HTTP_HOST="GOOD")
        assertion = make_fake_assertion("test@example.com", "BAD")
        identity = {"browserid.assertion": assertion}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "The audience \"BAD\" is not recognised")

    def test_auth_with_unrecognised_audience(self):
        plugin = BrowserIDPlugin(["GOOD"], verifier=DummyVerifierValid())
        environ = make_environ(HTTP_HOST="BAD")
        assertion = make_fake_assertion("test@example.com", "BAD")
        identity = {"browserid.assertion": assertion}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "The audience \"BAD\" is not recognised")

    def test_auth_with_good_assertion(self):
        plugin = BrowserIDPlugin(["localhost"], verifier=DummyVerifierValid())
        environ = make_environ()
        assertion = make_fake_assertion("test@example.com")
        identity = {"browserid.assertion": assertion}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, "test@example.com")

    def test_auth_with_invalid_assertion(self):
        plugin = BrowserIDPlugin(["localhost"],
                                 verifier=DummyVerifierInvalid())
        environ = make_environ()
        assertion = make_fake_assertion("test@example.com")
        identity = {"browserid.assertion": assertion}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "Invalid BrowserID assertion")

    def test_auth_with_malformed_assertion(self):
        plugin = BrowserIDPlugin(["localhost"], verifier=DummyVerifierValid())
        environ = make_environ()
        identity = {"browserid.assertion": "JUNK"}
        userid = plugin.authenticate(environ, identity)
        self.assertEquals(userid, None)
        self.assertEquals(environ[_ENVKEY_ERROR_MESSAGE],
                          "Malformed BrowserID assertion")

    def test_login_and_logout(self):
        api_factory = self._make_api_factory()
        environ = make_environ(HTTP_HOST="localhost")
        api = api_factory(environ)
        assertion = make_fake_assertion("test@example.com")
        identity = {"browserid.assertion": assertion}
        identity, headers = api.login(identity)
        self.assertEquals(identity["repoze.who.userid"], "test@example.com")
        self.assertEquals(headers[0][0], "X-Dummy-Remember")
        self.assertEquals(headers[0][1], "test@example.com")
        headers = api.logout()
        self.assertEquals(headers[0][0], "X-Dummy-Remember")
        self.assertEquals(headers[0][1], "")

    def test_challenge_and_response(self):
        app = TestApp(self._make_wsgi_app())
        plugin = app.app.api_factory.identifiers[0][1]
        # With no credentials, we get the challenge page.
        r = app.get("/", status=401)
        self.failUnless("POST" in r.body)
        self.failUnless(plugin.postback_url in r.body)
        # With good credentials, we get a redirect.
        assertion = make_fake_assertion("test@example.com")
        credentials = {"assertion": assertion}
        credentials["csrf_token"] = r.cookies_set["browserid_csrf_token"]
        r = app.post(plugin.postback_url, credentials, status=302)
        self.assertEquals(r.headers["X-Dummy-Remember"], "test@example.com")
        # With invalid credentials, we get the login page
        plugin.verifier = DummyVerifierInvalid()
        r = app.post(plugin.postback_url, credentials, status=401)
        self.failIf("X-Dummy-Remember" in r.headers)

    def test_challenge_gets_secure_cookie_over_https(self):
        app = TestApp(self._make_wsgi_app())
        plugin = app.app.api_factory.identifiers[0][1]
        # With no credentials, we get the challenge page.
        extra_environ = {"HTTP_HOST": "localhost", "wsgi.url_scheme": "https"}
        r = app.get("/", status=401, extra_environ=extra_environ)
        self.failUnless("POST" in r.body)
        self.failUnless(plugin.postback_url in r.body)
        self.failUnless("Secure" in r.headers['Set-Cookie'])
