# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

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
