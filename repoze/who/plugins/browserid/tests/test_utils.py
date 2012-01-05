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
import json
import base64

from repoze.who.plugins.browserid.utils import check_url_origin, str2bool
                                                


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
