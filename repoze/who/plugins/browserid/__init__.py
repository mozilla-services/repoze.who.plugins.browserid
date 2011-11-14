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

import json
import urlparse
import wsgiref.util

from zope.interface import implements

from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger
from repoze.who.utils import resolveDotted

from repoze.who.plugins.browserid.utils import (parse_auth_header,
                                                secure_urlopen)


class BrowserIDPlugin(object):
    """A repoze.who plugin for authentication via BrowserID.

    This plugin provides a repoze.who IIdentifier/IAuthenticator/IChallenger
    implementing the Verified Email Protocol as defined by Mozilla's
    BrowserID project:

        https://browserid.org/

    When used as an IIdentifier, it will extract a BrowserID assertion from
    the query-string, POST body or HTTP Authorization header.  The returned
    identity will contain the assertion under the key "browserid.assertion".

    When used as an IAuthenticator, it will verifiy a BrowserID assertion
    by POSTing it to the browserid.org verifier service.  If successfully
    verified, the asserted email address is returned as the userid.

    When used as an IChallenger, it will send a HTML page with the necessary
    embedded javascript to trigger a BrowserID prompt and send the assertion
    back to the server.

    When talking to the remote verifier service, this class does strict SSL
    certificate checking by default.  You can customize the process by
    providing a "urlopen" callback that has the same interface as the function
    of that name from urllib2.
    """

    implements(IIdentifier, IChallenger, IAuthenticator)

    def __init__(self, postback_url=None, verifier_url=None, urlopen=None,
                 challenge_body=None):
        if verifier_url is None:
            verifier_url = "https://browserid.org/verify"
        if urlopen is None:
            urlopen = secure_urlopen
        if challenge_body is None:
            challenge_body = DEFAULT_CHALLENGE_BODY
        self.postback_url = postback_url
        self.verifier_url = verifier_url
        self.urlopen = urlopen
        self.challenge_body = challenge_body

    def identify(self, environ):
        """Extract BrowserID credentials from the request.

        This method extracts a BrowserID assertion from the request, either
        from the query-string or the HTTP Authorization header.  If found,
        the returned identity will contain a single key "browserid.assertion"
        containing the (unverified) assertion.
        """
        # We need to find a BrowserID assertion.
        assertion = None
        # It might be in the query string,
        qs = environ.get("QUERY_STRING", "")
        if qs:
            assertion = urlparse.parse_qs(qs).get("browserid.assertion")
        # It might be in an HTTP-Auth header.
        if assertion is None:
            authz = environ.get("HTTP_AUTHORIZATION")
            if authz is not None:
                try:
                    params = parse_auth_header(authz)
                    if params["scheme"].lower() == "browserid":
                        assertion = params.get("assertion")
                except ValueError:
                    pass
        # If found, that's all we need for the identity.
        if assertion is None:
            return None
        identity = {}
        identity["browserid.assertion"] = assertion
        return identity

    def remember(self, environ, identity):
        """Remember the authenticated identity.

        This is a no-op for BrowserID since it has no builtin mechanism
        for persistent logins.  You should combine this plugin e.g. a
        signed-cookie plugin to achieve such functionality.
        """
        return []

    def forget(self, environ, identity):
        """Forget the authenticated identity.

        This is a no-op for BrowserID since it has no builtin mechanism
        for persistent logins.  You should combine this plugin e.g. a
        signed-cookie plugin to achieve such functionality.
        """
        return []

    def challenge(self, environ, status, app_headers, forget_headers):
        """Challenge for BrowserID credentials.

        The challenge app will send a HTML page with embedded javascript
        to walk the user through the BrowserID login process.  Once complete
        it will post the obtained BrowserID assertion to the configured
        postback URL.
        """
        def challenge_app(environ, start_response):
            headers = list(forget_headers)
            # Always include a WWW-Authenticate BrowserID challenge,
            # to accomodate any non-browser clients that can't do JS.
            realm = environ.get("HTTP_HOST", "")
            challenge = "BrowserID realm=\"%s\"" % (realm,)
            headers.append(('WWW-Authenticate', challenge))
            # Interpolate various request data into the challenge body.
            challenge_vars = {}
            challenge_vars["request_method"] = environ.get("REQUEST_METHOD")
            challenge_vars["request_uri"] = wsgiref.util.request_uri(environ)
            if self.postback_url is not None:
                challenge_vars["postback_url"] = self.postback_url
            else:
                challenge_vars["postback_url"] = challenge_vars["request_uri"]
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
        """
        # Is this a BrowserID identity?
        assertion = identity.get("browserid.assertion")
        if assertion is None:
            return None
        # The audience should be the submitted host.
        # Fail out if it's wrong to prevent replay attacks.
        audience = environ.get('HTTP_HOST')
        if audience is None:
            return None
        # Verify the assertion and extract data into the identity.
        data = self._verify_assertion(assertion, audience)
        if data is None:
            return None
        identity["browserid.audience"] = audience
        userid = identity["email"] = data["email"]
        # Success!
        return userid

    def _verify_assertion(self, assertion, audience):
        """Verify the given BrowserID assertion/audience pair.

        This method verifies the signatures in the given BrowserID assertion,
        checks that is intended for the specified audience, and returns a
        dict giving the information contained in the assertion.

        Currently this POSTs the assertion to an external verifier service.
        """
        # Encode the data into x-www-form-urlencoded.
        post_data = {"assertion": assertion, "audience": audience}
        post_data = "&".join("%s=%s" % item for item in post_data.items())
        # Post it to the verifier.
        try:
            resp = self.urlopen(self.verifier_url, post_data)
            content_length = resp.info().get("Content-Length")
            if content_length is None:
                data = resp.read()
            else:
                data = resp.read(int(content_length))
        except IOError:
            return None
        # Did it come back clean?
        data = json.loads(data)
        if data.get('status') != "okay":
            return None
        if data.get('audience') != audience:
            return None
        return data


def make_plugin(postback_url=None, verifier_url=None, urlopen=None,
                challenge_body=None):
    """Make a BrowserIDPlugin using values from a .ini config file.

    This is a helper function for loading a BrowserIDPlugin via the
    repoze.who .ini config file system. It converts its arguments from
    strings to the appropriate type then passes them on to the plugin.
    """
    if isinstance(challenge_body, basestring):
        with open(challenge_body, "rb") as f:
            challenge_body = f.read()
    if isinstance(urlopen, basestring):
        urlopen = resolveDotted(urlopen)
        if urlopen is not None:
            assert callable(urlopen)
    plugin = BrowserIDPlugin(postback_url, verifier_url, urlopen,
                             challenge_body)
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
    $("<h3>Please sign in using BrowserID</h3>" +
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
                              "         name='browserid.assertion' " +
                              "         value='" + assertion + "' />" +
                              "  <input type='hidden' name='came_from' "+
                              "         value='%(request_uri)s' />" +
                              "</form>").appendTo($("body"));
                $form.submit();
            }
        });
    });
});
</script>
</body>
"""
