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

import os
import unittest2
import threading
import socket
import ssl
import urllib2
import json
import base64

from repoze.who.plugins.browserid.utils import (check_url_origin,
                                                parse_assertion,
                                                str2bool)


class TestUtils(unittest2.TestCase):

    def test_check_url_origin(self):
        self.assertTrue(check_url_origin("http://one.com",
                                         "http://one.com/ha/ha/ha"))
        self.assertTrue(check_url_origin("http://one.com",
                                         "http://one.com:80/ho/ho/ho"))
        self.assertFalse(check_url_origin("http://one.com",
                                          "https://evil.com/i/hack/you"))
        self.assertFalse(check_url_origin("http://one.com",
                                          "https://one.com/he/he#he"))
        self.assertTrue(check_url_origin("https://one.com:443/blah",
                                         "https://one.com/he/he#he"))
        self.assertTrue(check_url_origin("https://one.com:123",
                                          "https://one.com:123/he/he#he"))
        self.assertFalse(check_url_origin("https://one.com:123",
                                          "https://one.com:456/he/he#he"))

    def test_parse_assertion(self):
        assertion = """
        eyJjZXJ0aWZpY2F0ZXMiOlsiZXlKaGJHY2lPaUpTVXpFeU9DSjkuZXlKcGMzTWlPaUppY
        205M2MyVnlhV1F1YjNKbklpd2laWGh3SWpveE16SXhPVFF4T1Rnek1EVXdMQ0p3ZFdKc2
        FXTXRhMlY1SWpwN0ltRnNaMjl5YVhSb2JTSTZJbEpUSWl3aWJpSTZJamd4TmpreE5UQTB
        OVGswTkRVek5EVTFPREF4TlRreU5Ea3hNemsyTkRFNE56RTJNVFUwTkRNNE5EWXdPREl6
        TXpBMU1USXlPRGN3TURRNE56TTFNREk1TURrek16a3lNRFkzTURFMU1qQTBORGd6TWpVM
        U56WXdOREE1TnpFeU9EYzNNVGswT1RVek1UQXdNVFEyTkRVek56TTJOakU0TlRVek5EY3
        hNakkxT0RreU16TTFPRFV4TWpZNU1EQXdOREF5TVRrMk9ERTBNRGtpTENKbElqb2lOalU
        xTXpjaWZTd2ljSEpwYm1OcGNHRnNJanA3SW1WdFlXbHNJam9pY25saGJrQnlabXN1YVdR
        dVlYVWlmWDAua19oaEtYMFRCVnUyX2szbV9uRDVOVWJfTktwX19PLTY1MW1CRUl3S1NZZ
        GlOenQwQm9WRkNEVEVueEhQTWJCVjJaejk0WDgtLVRjVXJidEV0MWV1S1dWdjMtNTFUOU 
        xBZnV6SEhfekNCUXJVbmxkMVpXSmpBM185ZEhQeTMwZzRMSU9YZTJWWmd0T1Nva3MyZFE
        4ZDNvazlSUTJQME5ERzB1MDBnN3lGejE4Il0sImFzc2VydGlvbiI6ImV5SmhiR2NpT2lK
        U1V6WTBJbjAuZXlKbGVIQWlPakV6TWpFNU1qazBOelU0TWprc0ltRjFaQ0k2SW1oMGRIQ
        TZMeTl0ZVdaaGRtOXlhWFJsWW1WbGNpNXZjbWNpZlEuQWhnS2Q0eXM0S3FnSGJYcUNSS3
        hHdlluVmFJOUwtb2hYSHk0SVBVWDltXzI0TWdfYlU2aGRIMTNTNnFnQy1vSHBpS3BfTGl
        6cDRGRjlUclBjNjBTRXcifQ
        """.replace(" ", "").replace("\n", "").strip()
        data = parse_assertion(assertion)
        self.assertEquals(data["principal"]["email"], "ryan@rfk.id.au")
        self.assertEquals(data["audience"], "http://myfavoritebeer.org")
        self.assertRaises(ValueError, parse_assertion, "JUNK")
        self.assertRaises(ValueError, parse_assertion, "X")
        self.assertRaises(ValueError, parse_assertion, "\x00\x01\x02")
        bad_assertion = json.dumps({"fake": "assertion"})
        bad_assertion = base64.urlsafe_b64encode(bad_assertion)
        self.assertRaises(ValueError, parse_assertion, bad_assertion)

    def test_str2bool(self):
        self.assertTrue(str2bool("TRUE"))
        self.assertTrue(str2bool("trUe"))
        self.assertTrue(str2bool("on"))
        self.assertTrue(str2bool("yes"))
        self.assertTrue(str2bool("1"))
        self.assertFalse(str2bool("FALSE"))
        self.assertFalse(str2bool("fAlSe"))
        self.assertFalse(str2bool("ofF"))
        self.assertFalse(str2bool("no"))
        self.assertFalse(str2bool("0"))
        self.assertRaises(ValueError, str2bool, "42")
        self.assertRaises(ValueError, str2bool, "kumquat")
