#
# Copyright Red Hat, Inc. 2012
#
# This work is licensed under the terms of the GNU GPL, version 2 or later.
# See the COPYING file in the top-level directory.
#

"""
Unit tests for building query strings with bin/bugzilla
"""

from __future__ import print_function

import os
import tempfile
import unittest

import pytest

import bugzilla
import tests
from bugzilla.backendxmlrpc import BackendXMLRPC


class MiscCLI(unittest.TestCase):
    """
    Test miscellaneous CLI bits to get build out our code coverage
    """
    maxDiff = None

    def testHelp(self):
        out = tests.clicomm("bugzilla --help", None)
        assert len(out.splitlines()) > 18

    def testCmdHelp(self):
        out = tests.clicomm("bugzilla query --help", None)
        assert len(out.splitlines()) > 40

    def testVersion(self):
        out = tests.clicomm("bugzilla --version", None)
        assert len(out.splitlines()) >= 2

    def testPositionalArgs(self):
        # Make sure cli correctly rejects ambiguous positional args
        out = tests.clicomm("bugzilla login --xbadarg foo",
                None, expectfail=True)
        assert "unrecognized arguments: --xbadarg" in out

        out = tests.clicomm("bugzilla modify 123456 --foobar --status NEW",
                None, expectfail=True)
        assert "unrecognized arguments: --foobar" in out


class MiscAPI(unittest.TestCase):
    """
    Test miscellaneous API bits
    """
    def testUserAgent(self):
        b3 = tests.make_bz("3.0.0")
        assert "python-bugzilla" in b3.backend.user_agent

    def test_fixurl(self):
        assert (BackendXMLRPC.fix_url("example.com") ==
            "https://example.com/xmlrpc.cgi")
        assert (BackendXMLRPC.fix_url("example.com/xmlrpc.cgi") ==
            "https://example.com/xmlrpc.cgi")
        assert (BackendXMLRPC.fix_url("http://example.com/somepath.cgi") ==
            "http://example.com/somepath.cgi")

    def testCookies(self):
        cookiesbad = os.path.join(os.getcwd(), "tests/data/cookies-bad.txt")
        cookieslwp = os.path.join(os.getcwd(), "tests/data/cookies-lwp.txt")
        cookiesmoz = os.path.join(os.getcwd(), "tests/data/cookies-moz.txt")

        # We used to convert LWP cookies, but it shouldn't matter anymore,
        # so verify they fail at least
        with pytest.raises(bugzilla.BugzillaError):
            tests.make_bz("3.0.0", cookiefile=cookieslwp)

        with pytest.raises(bugzilla.BugzillaError):
            tests.make_bz("3.0.0", cookiefile=cookiesbad)

        # Mozilla should 'just work'
        tests.make_bz("3.0.0", cookiefile=cookiesmoz)

    def test_readconfig(self):
        # Testing for bugzillarc handling
        bzapi = tests.make_bz("4.4.0", rhbz=True)
        bzapi.backend.url = "example.com"
        temp = tempfile.NamedTemporaryFile(mode="w")

        content = """
[example.com]
foo=1
user=test1
password=test2"""
        temp.write(content)
        temp.flush()
        bzapi.backend.readconfig(temp.name)
        assert bzapi.backend.user == "test1"
        assert bzapi.backend.password == "test2"
        assert bzapi.backend.api_key is None

        bzapi.backend.url = "foo.example.com"
        bzapi.backend.user = None
        bzapi.backend.readconfig(temp.name)
        assert bzapi.backend.user is None

        content = """
[foo.example.com]
user=test3
password=test4
api_key=123abc
"""
        temp.write(content)
        temp.flush()
        bzapi.backend.readconfig(temp.name)
        assert bzapi.backend.user == "test3"
        assert bzapi.backend.password == "test4"
        assert bzapi.backend.api_key == "123abc"

        bzapi.backend.url = "bugzilla.redhat.com"
        bzapi.backend.user = None
        bzapi.backend.password = None
        bzapi.backend.api_key = None
        bzapi.backend.readconfig(temp.name)
        assert bzapi.backend.user is None
        assert bzapi.backend.password is None
        assert bzapi.backend.api_key is None


    def testPostTranslation(self):
        def _testPostCompare(bz, indict, outexpect):
            outdict = indict.copy()
            bz.post_translation({}, outdict)
            assert outdict == outexpect

            # Make sure multiple calls don't change anything
            bz.post_translation({}, outdict)
            assert outdict == outexpect

        bug3 = tests.make_bz("3.4.0")
        rhbz = tests.make_bz("4.4.0", rhbz=True)

        test1 = {
            "component": ["comp1"],
            "version": ["ver1", "ver2"],

            'flags': [{
                'is_active': 1,
                'name': 'qe_test_coverage',
                'setter': 'pm-rhel@redhat.com',
                'status': '?',
            }, {
                'is_active': 1,
                'name': 'rhel-6.4.0',
                'setter': 'pm-rhel@redhat.com',
                'status': '+',
            }],

            'alias': ["FOO", "BAR"],
            'blocks': [782183, 840699, 923128],
            'keywords': ['Security'],
            'groups': ['redhat'],
        }

        out_simple = test1.copy()
        out_simple["components"] = out_simple["component"]
        out_simple["component"] = out_simple["components"][0]
        out_simple["versions"] = out_simple["version"]
        out_simple["version"] = out_simple["versions"][0]

        _testPostCompare(bug3, test1, test1)
        _testPostCompare(rhbz, test1, out_simple)
