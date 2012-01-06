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

A repoze.who plugin for authentication via BrowserID:

    https://browserid.org/

"""

__ver_major__ = 0
__ver_minor__ = 3
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


import os
import re
import fnmatch
from urlparse import urlparse, urljoin

from zope.interface import implements

from webob import Request, Response

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.api import get_api
from repoze.who.utils import resolveDotted

import vep
import vep.utils

from repoze.who.plugins.browserid.utils import str2bool, check_url_origin
                                                


# We store error messages in the WSGI environ under this key.
# It's needed to tunnel messages between identify() and challenge() calls.
_ENVKEY_ERROR_MESSAGE = "repoze.who.plugins.browserid.error_message"


class BrowserIDPlugin(object):
    """A repoze.who plugin for authentication via BrowserID.

    This plugin provides a repoze.who IIdentifier/IAuthenticator/IChallenger
    implementing the Verified Email Protocol as defined by Mozilla's
    BrowserID project:

        https://browserid.org/

    When used as an IIdentifier, it will process POST requests to a configured
    URL as attempts to log in using BrowserID.  The identity extracted from
    such requests will contain the key "browserid.assertion" giving the
    (unverified) identity assertion.

    When used as an IAuthenticator, it will verifiy an extracted BrowserID
    assertion using the PyVEP client library.  If valid then the asseted email
    address is returned as the userid.

    When used as an IChallenger, it will send a HTML page with the necessary
    embedded javascript to trigger a BrowserID prompt and POST the assertion
    back to the server for checking.
    """

    implements(IIdentifier, IChallenger, IAuthenticator)

    def __init__(self, audiences, rememberer_name=None, postback_url=None,
                 assertion_field=None, came_from_field=None, csrf_field=None,
                 csrf_cookie_name=None, challenge_body=None, verifier=None,
                 check_https=None, check_referer=None):
        if postback_url is None:
            postback_url = "/repoze.who.plugins.browserid.postback"
        if assertion_field is None:
            assertion_field = "assertion"
        if came_from_field is None:
            came_from_field = "came_from"
        if csrf_field is None:
            csrf_field = "csrf_token"
        if csrf_cookie_name is None:
            csrf_cookie_name = "browserid_csrf_token"
        if challenge_body is None:
            challenge_body = DEFAULT_CHALLENGE_BODY
        if verifier is None:
            verifier = vep.RemoteVerifier()
        self.audiences = audiences
        if audiences:
            audience_patterns = map(self._compile_audience_pattern, audiences)
            self._audience_patterns = audience_patterns
        self.rememberer_name = rememberer_name
        self.postback_url = postback_url
        self.postback_path = urlparse(postback_url).path
        self.assertion_field = assertion_field
        self.came_from_field = came_from_field
        self.csrf_field = csrf_field
        self.csrf_cookie_name = csrf_cookie_name
        self.challenge_body = challenge_body
        self.verifier = verifier
        self.check_https = check_https
        self.check_referer = check_referer

    def identify(self, environ):
        """Extract BrowserID credentials from the request.

        This method checks whether the request is to the configured postback
        URL, and if so extracts a BrowserID assertion from the POST data.
        The returned identity then maps the key "browserid.assertion" to the
        unverified assertion string.

        This method is also responsible for CSRF protection.  If the request
        does not contain the necessary CSRF tokens then no identity will be
        returned.
        """
        request = Request(environ)
        # If we're not at the postback url then don't process the login.
        if request.path != self.postback_path:
            return None
        if request.method != "POST":
            environ[_ENVKEY_ERROR_MESSAGE] = "Login requests must use POST"
            self._rechallenge_at_postback(request)
            return None
        # Check that connection is as secure as required.
        if self.check_https:
            if request.environ["wsgi.url_scheme"] != "https":
                msg = "Login requests must use a secure connection"
                environ[_ENVKEY_ERROR_MESSAGE] = msg
                self._rechallenge_at_postback(request)
                return None
        # If this might be a CSRF attack, fail out.
        if not self._check_csrf_token(request):
            environ[_ENVKEY_ERROR_MESSAGE] = "Invalid or missing CSRF token"
            self._rechallenge_at_postback(request)
            return None
        # Find the assertion in the POST vars.
        assertion = request.POST.get(self.assertion_field)
        if assertion is None:
            environ[_ENVKEY_ERROR_MESSAGE] = "No BrowserID assertion found"
            self._rechallenge_at_postback(request)
            return None
        # Parse out the audience, which also checks well-formedness.
        try:
            audience = vep.utils.get_assertion_info(assertion)["audience"]
        except (ValueError, KeyError):
            environ[_ENVKEY_ERROR_MESSAGE] = "Malformed BrowserID assertion"
            self._rechallenge_at_postback(request)
            return None
        # Check that the referer header matches the audience.
        if not self._check_referer_header(request, audience):
            msg = "Invalid or missing Referer header."
            self._rechallenge_at_postback(request)
            environ[_ENVKEY_ERROR_MESSAGE] = msg
            return None
        # That's all we need for an identity.
        identity = {"browserid.assertion": assertion,
                    "browserid.audience": audience}
        return identity

    def remember(self, environ, identity):
        """Remember the authenticated identity.

        BrowserID has no builtin mechanism for persistent logins.  This
        method simply delegates to another IIdentifier plugin if configured.
        """
        headers = []
        api = get_api(environ)
        if self.rememberer_name is not None and api is not None:
            plugin = api.name_registry[self.rememberer_name]
            i_headers = plugin.remember(environ, identity)
            if i_headers is not None:
                headers.extend(i_headers)
        return headers

    def forget(self, environ, identity):
        """Forget the authenticated identity.

        BrowserID has no builtin mechanism for persistent logins.  This
        method simply delegates to another IIdentifier plugin if configured.
        """
        headers = []
        api = get_api(environ)
        if self.rememberer_name is not None and api is not None:
            plugin = api.name_registry[self.rememberer_name]
            i_headers = plugin.forget(environ, identity)
            if i_headers is not None:
                headers.extend(i_headers)
        return headers

    def challenge(self, environ, status, app_headers=(), forget_headers=()):
        """Challenge for BrowserID credentials.

        The challenge app will send a HTML page with embedded javascript
        to walk the user through the BrowserID login process.  Once complete
        it will post the obtained BrowserID assertion to the configured
        postback URL.
        """
        def challenge_app(environ, start_response):
            request = Request(environ)
            headers = list(forget_headers)
            # See if we have an error message from a failed login.
            error_message = environ.get(_ENVKEY_ERROR_MESSAGE,
                                        "Please sign in using BrowserID")
            # Get the postback url as a full URL including host and scheme.
            postback_url = urljoin(request.host_url, self.postback_url)
            postback_url_p = urlparse(postback_url)
            # Preserve the "came_from" variable across page loads.
            request_url = urljoin(request.host_url, request.path)
            came_from = request.params.get("came_from", request_url)
            # Send a random CSRF token in a cookie.
            # Try to limit things so it's only sent to the postback url.
            csrf_token = os.urandom(16).encode("hex")
            cookie = "%s=%s; HttpOnly" % (self.csrf_cookie_name, csrf_token)
            cookie += "; Domain=" + postback_url_p.hostname
            cookie += "; Path=" + postback_url_p.path
            if postback_url_p.scheme == "https":
                cookie += "; Secure"
            headers.append(('Set-Cookie', cookie))
            # Interpolate various request data into the challenge body.
            challenge_vars = {}
            challenge_vars["postback_url"] = postback_url
            challenge_vars["assertion_field"] = self.assertion_field
            challenge_vars["came_from_field"] = self.came_from_field
            challenge_vars["csrf_field"] = self.csrf_field
            challenge_vars["came_from"] = came_from
            challenge_vars["request_url"] = request_url
            challenge_vars["request_method"] = environ.get("REQUEST_METHOD")
            challenge_vars["csrf_token"] = csrf_token
            challenge_vars["error_message"] = error_message
            challenge_body = self.challenge_body % challenge_vars
            # Send the challenge page as text/html.
            headers.append(("Content-Type", "text/html"))
            start_response(status, headers)
            return [challenge_body]
        return challenge_app

    def authenticate(self, environ, identity):
        """Authenticate and extract identity from a BrowserID assertion.

        This method verifies a BrowserID assertion and uses the contained
        email as the authenticated userid of the user.

        This method also handles the logic for the postback url.  If the user
        is not authenicated then a new challenge gets issued; if they are
        authenticated then they get redirected to their final destination.
        """
        request = Request(environ)
        # Is this a BrowserID identity?
        assertion = identity.get("browserid.assertion")
        if assertion is None:
            environ[_ENVKEY_ERROR_MESSAGE] = "No BrowserID assertion found"
            self._rechallenge_at_postback(request)
            return None
        # Get the audience, using cache in identity if given.
        audience = identity.get("browserid.audience")
        if audience is None:
            try:
                audience = vep.utils.get_assertion_info(assertion)["audience"]
                identity["browserid.audience"] = audience
            except (ValueError, KeyError):
                msg = "Malformed BrowserID assertion"
                environ[_ENVKEY_ERROR_MESSAGE] = msg
                self._rechallenge_at_postback(request)
                return None
        # Check that the audience matches one of the expected values.
        if not self._check_audience(request, audience):
            msg = "The audience \"%s\" is not recognised" % (audience,)
            environ[_ENVKEY_ERROR_MESSAGE] = msg
            self._rechallenge_at_postback(request)
            return None
        # Verify the assertion and extract data into the identity.
        try:
            data = self.verifier.verify(assertion)
        except Exception:
            msg = "Invalid BrowserID assertion"
            environ[_ENVKEY_ERROR_MESSAGE] = msg
            self._rechallenge_at_postback(request)
            return None
        # Success!
        userid = identity["email"] = data["email"]
        self._redirect_from_postback(request, identity)
        return userid

    def _check_csrf_token(self, request):
        """Check if the request has a valid CSRF-protection token.

        When CSRF protection is enabled, any incoming login attempts much
        provide a matching token in two places: the cookie headers and the
        request parameters.  This is the "session-independent nonce" technique
        described by Barth et. al.
        """
        if self.csrf_cookie_name and self.csrf_field:
            csrf_token = request.cookies.get(self.csrf_cookie_name, None)
            if not csrf_token:
                return False
            if csrf_token != request.params.get(self.csrf_field, None):
                return False
        return True

    def _check_referer_header(self, request, audience):
        """Check if the request has a referer that matches the audience.

        If the "check_referer" setting is True, this method checks that the
        incoming request has a HTTP Referer header from the same origin as the
        assertion audience.  This ensures some measure of protection against
        CSRF attacks, as the attacker would need to spoof the Referer header
        in order to execute an unauthorized login request.

        By default this check is only performed for secure connections; the
        referer header is often missing and easily spoofable on insecure
        connections so it's usually not worth it.
        """
        check_referer = self.check_referer
        if check_referer is None:
            check_referer = (request.environ["wsgi.url_scheme"] == "https")
        if check_referer:
            if request.referer is None:
                return False
            referer = urljoin(request.host_url, request.referer)
            if not check_url_origin(audience, referer):
                return False
        return True

    def _check_audience(self, request, audience):
        """Check that the audience is valid according to our configuration.

        This function uses the configured list of valid audience patterns to
        verify the given audience.  If no audience values have been configured
        then it matches against the Host header from the request.
        """
        if not self.audiences:
            return audience == request.host_url
        for audience_pattern in self._audience_patterns:
            if audience_pattern.match(audience):
                return True
        return False

    def _compile_audience_pattern(self, pattern):
        """Compile a glob-style audience pattern into a regular expression."""
        re_pattern = fnmatch.translate(pattern)
        if "://" not in pattern:
            re_pattern = "[a-z]+://" + re_pattern
        return re.compile(re_pattern)

    def _rechallenge_at_postback(self, request):
        """Re-issue a failed auth challenge at the postback url."""
        if request.path == self.postback_path:
            challenge_app = self.challenge(request.environ, "401 Unauthorized")
            request.environ["repoze.who.application"] = challenge_app

    def _redirect_from_postback(self, request, identity):
        """Redirect from the postback URL after a successful authentication."""
        if request.path == self.postback_path:
            came_from = request.params.get(self.came_from_field)
            if came_from is None:
                came_from = "/"
            response = Response()
            response.status = 302
            response.location = came_from
            request.environ["repoze.who.application"] = response


def make_plugin(audiences, rememberer_name=None, postback_url=None,
                assertion_field=None, came_from_field=None, csrf_field=None,
                csrf_cookie_name=None, challenge_body=None, verifier=None,
                check_https=None, check_referer=None, **kwds):
    """Make a BrowserIDPlugin using values from a .ini config file.

    This is a helper function for loading a BrowserIDPlugin via the
    repoze.who .ini config file system. It converts its arguments from
    strings to the appropriate type then passes them on to the plugin.
    """
    if not audiences:
        audiences = None
    elif isinstance(audiences, basestring):
        audiences = audiences.split()
    if isinstance(challenge_body, basestring):
        try:
            challenge_body = resolveDotted(challenge_body)
        except (ValueError, ImportError):
            with open(challenge_body, "rb") as f:
                challenge_body = f.read()
    if isinstance(verifier, basestring):
        verifier = resolveDotted(verifier)
        if callable(verifier):
            verifier_kwds = {}
            for key, value in kwds.iteritems():
                if key == "verifier_urlopen":
                    value = resolveDotted(value)
                if key.startswith("verifier_"):
                    verifier_kwds[key[len("verifier_"):]] = value
            verifier = verifier(**verifier_kwds)
    if isinstance(check_https, basestring):
        check_https = str2bool(check_https)
    if isinstance(check_referer, basestring):
        check_referer = str2bool(check_referer)
    plugin = BrowserIDPlugin(audiences, rememberer_name, postback_url,
                             assertion_field, came_from_field, csrf_field,
                             csrf_cookie_name, challenge_body, verifier,
                             check_https, check_referer)
    return plugin


# This is the default HTML + JavaScript that gets returned
# for a BrowserID login challenge.
DEFAULT_CHALLENGE_BODY = """
<html>
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.6.4/jquery.min.js"
        type="text/javascript"></script>
<script src="https://browserid.org/include.js"
        type="text/javascript"></script>
</head>
<body>
<h1>Authentication Required</h1>
<noscript>
This page requires authentication via BrowserID.
Unfortunately your browser does not support JavaScript which is required
for BrowserID login.
</noscript>
<script type="text/javascript">
$(function() {
    // Generate login button in script, so it only appears if
    // we're actually capable of doing it.
    //
    $("<h3>%(error_message)s</h3>" +
      "<img src='https://browserid.org/i/sign_in_blue.png' id='signin'" +
      "     alt='sign-in button' />").appendTo($("body"));

    // Fire up the BrowserID callback when clicked.
    //
    $("#signin").click(function() {
        navigator.id.getVerifiedEmail(function(assertion) {
            if (assertion) {
                var $form = $("<form method=POST "+
                              "      action='%(postback_url)s'>" +
                              "  <input type='hidden' " +
                              "         name='%(assertion_field)s' " +
                              "         value='" + assertion + "' />" +
                              "  <input type='hidden' " +
                              "         name='%(came_from_field)s' "+
                              "         value='%(came_from)s' />" +
                              "  <input type='hidden' " +
                              "         name='%(csrf_field)s' "+
                              "         value='%(csrf_token)s' />" +
                              "</form>").appendTo($("body"));
                $form.submit();
            }
        });
    });
});
</script>
</body>
"""
