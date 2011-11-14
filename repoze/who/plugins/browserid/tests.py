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

from zope.interface.verify import verifyClass
from repoze.who.interfaces import IIdentifier, IAuthenticator, IChallenger

from repoze.who.plugins.browserid import BrowserIDPlugin


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


class TestBrowserIDPlugin(unittest.TestCase):
    """Testcases for the main BrowserIDPlugin class."""

    def test_implements(self):
        verifyClass(IIdentifier, BrowserIDPlugin)
        verifyClass(IAuthenticator, BrowserIDPlugin)
        verifyClass(IChallenger, BrowserIDPlugin)
