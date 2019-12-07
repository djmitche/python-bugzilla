# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
# the full text of the license.

import os
import sys
import logging

# pylint: disable=import-error,no-name-in-module,ungrouped-imports
if sys.version_info[0] >= 3:
    from collections.abc import Mapping
    from configparser import ConfigParser
    from http.cookiejar import LoadError, MozillaCookieJar
    from urllib.parse import urlparse, urlunparse, parse_qsl
    from xmlrpc.client import Binary, Fault
else:
    from collections import Mapping
    from ConfigParser import SafeConfigParser as ConfigParser
    from cookielib import LoadError, MozillaCookieJar
    from urlparse import urlparse, urlunparse, parse_qsl
    from xmlrpclib import Binary, Fault
# pylint: enable=import-error,no-name-in-module,ungrouped-imports

from ._rc import _open_bugzillarc, DEFAULT_CONFIGPATHS
from .transport import BugzillaError, _BugzillaServerProxy, _RequestsTransport
from .apiversion import __version__

log = logging.getLogger(__name__)

class BackendXMLRPC(object):
    def __init__(
        self,
        url=-1,
        user=None,
        password=None,
        cookiefile=-1,
        sslverify=True,
        tokenfile=-1,
        use_creds=True,
        api_key=None,
        cert=None,
        configpaths=-1,
        basic_auth=False,
    ):
        """
        :param url: The bugzilla instance URL, which we will connect
            to immediately. Most users will want to specify this at
            __init__ time, but you can defer connecting by passing
            url=None and calling connect(URL) manually
        :param user: optional username to connect with
        :param password: optional password for the connecting user
        :param cert: optional certificate file for client side certificate
            authentication
        :param cookiefile: Location to cache the login session cookies so you
            don't have to keep specifying username/password. Bugzilla 5+ will
            use tokens instead of cookies.
            If -1, use the default path. If None, don't use or save
            any cookiefile.
        :param sslverify: Set this to False to skip SSL hostname and CA
            validation checks, like out of date certificate
        :param tokenfile: Location to cache the API login token so youi
            don't have to keep specifying username/password.
            If -1, use the default path. If None, don't use
            or save any tokenfile.
        :param use_creds: If False, this disables cookiefile, tokenfile,
            and any bugzillarc reading. This overwrites any tokenfile
            or cookiefile settings
        :param sslverify: Maps to 'requests' sslverify parameter. Set to
            False to disable SSL verification, but it can also be a path
            to file or directory for custom certs.
        :param api_key: A bugzilla5+ API key
        :param basic_auth: Use headers with HTTP Basic authentication
        """

        if url == -1:
            raise TypeError("Specify a valid bugzilla url, or pass url=None")

        # Settings the user might want to tweak
        self.user = user or ""
        self.password = password or ""
        self.api_key = api_key
        self.cert = cert or ""
        self.url = ""

        self._proxy = None
        self._transport = None
        self._cookiejar = None
        self._sslverify = sslverify
        self._use_creds = use_creds
        if not self._use_creds:
            cookiefile = None
            tokenfile = None
            configpaths = []

        if cookiefile == -1:
            cookiefile = _default_cache_location("bugzillacookies")
        if tokenfile == -1:
            tokenfile = _default_cache_location("bugzillatoken")
        if configpaths == -1:
            configpaths = DEFAULT_CONFIGPATHS[:]

        log.debug("Using tokenfile=%s", tokenfile)
        self.cookiefile = cookiefile
        self.tokenfile = tokenfile
        self.configpath = configpaths
        self._basic_auth = basic_auth

        if url:
            self.connect(url)

    @staticmethod
    def fix_url(url):
        """
        Turn passed url into a bugzilla XMLRPC web url
        """
        scheme, netloc, path, params, query, fragment = urlparse(url)
        if not scheme:
            log.debug('No scheme given for url, assuming https')
            scheme = 'https'

        if path and not netloc:
            netloc = path.split("/", 1)[0]
            path = "/".join(path.split("/")[1:]) or None

        if not path:
            log.debug('No path given for url, assuming /xmlrpc.cgi')
            path = 'xmlrpc.cgi'

        newurl = urlunparse((scheme, netloc, path, params, query, fragment))
        if newurl != url:
            log.debug("Generated fixed URL: %s", newurl)
        return newurl

    def connect(self, url=None):
        """
        Connect to the bugzilla instance with the given url. This is
        called by __init__ if a URL is passed. Or it can be called manually
        at any time with a passed URL.

        This will also read any available config files (see readconfig()),
        which may set 'user' and 'password', and others.

        If 'user' and 'password' are both set, we'll run login(). Otherwise
        you'll have to login() yourself before some methods will work.
        """
        if self._transport:
            self.disconnect()

        if url is None and self.url:
            url = self.url
        url = self.fix_url(url)

        self._transport = _RequestsTransport(
            url, self._cookiejar, sslverify=self._sslverify, cert=self.cert
        )
        self._transport.user_agent = self.user_agent
        self._proxy = _BugzillaServerProxy(url, self.tokenfile, self._transport)

        self.url = url
        # we've changed URLs - reload config
        self.readconfig(overwrite=False)

        if self.user and self.password:
            log.info("user and password present - doing login()")
            self.login()

        if self.api_key:
            log.debug("using API key")
            self._proxy.use_api_key(self.api_key)

        version = self._proxy.Bugzilla.version()["version"]
        log.debug("Bugzilla version string: %s", version)
        self._set_bz_version(version)

    def _set_bz_version(self, version):
        try:
            self.bz_ver_major, self.bz_ver_minor = [
                int(i) for i in version.split(".")[0:2]]
        except Exception:
            log.debug("version doesn't match expected format X.Y.Z, "
                    "assuming 5.0", exc_info=True)
            self.bz_ver_major = 5
            self.bz_ver_minor = 0

    def _get_user_agent(self):
        return 'python-bugzilla/%s' % __version__
    user_agent = property(_get_user_agent)

    def disconnect(self):
        """
        Disconnect from the given bugzilla instance.
        """
        self._proxy = None
        self._transport = None
        self._cache = _BugzillaAPICache()

    def _login(self, user, password, restrict_login=None):
        """
        Backend login method for Bugzilla3
        """
        if self._basic_auth:
            self._transport.set_basic_auth(user, password)

        payload = {'login': user, 'password': password}
        if restrict_login:
            payload['restrict_login'] = True

        return self._proxy.User.login(payload)

    def login(self, user=None, password=None, restrict_login=None):
        """
        Attempt to log in using the given username and password. Subsequent
        method calls will use this username and password. Returns False if
        login fails, otherwise returns some kind of login info - typically
        either a numeric userid, or a dict of user info.

        If user is not set, the value of Bugzilla.user will be used. If *that*
        is not set, ValueError will be raised. If login fails, BugzillaError
        will be raised.

        The login session can be restricted to current user IP address
        with restrict_login argument. (Bugzilla 4.4+)

        This method will be called implicitly at the end of connect() if user
        and password are both set. So under most circumstances you won't need
        to call this yourself.
        """
        if self.api_key:
            raise ValueError("cannot login when using an API key")

        if user:
            self.user = user
        if password:
            self.password = password

        if not self.user:
            raise ValueError("missing username")
        if not self.password:
            raise ValueError("missing password")

        if restrict_login:
            log.info("logging in with restrict_login=True")

        try:
            ret = self._login(self.user, self.password, restrict_login)
            self.password = ''
            log.info("login successful for user=%s", self.user)
            return ret
        except Fault as e:
            raise BugzillaError("Login failed: %s" % str(e.faultString))

    def interactive_login(self, user=None, password=None, force=False,
                          restrict_login=None, use_api_key=False):
        """
        Helper method to handle login for this bugzilla instance.

        :param user: bugzilla username. If not specified, prompt for it.
        :param password: bugzilla password. If not specified, prompt for it.
        :param force: Unused
        :param restrict_login: restricts session to IP address
        :param use_api_key: If True, prompt for an api_key instead
        """
        ignore = force
        log.debug('Calling interactive_login')

        if use_api_key:
            sys.stdout.write('API Key: ')
            sys.stdout.flush()
            api_key = sys.stdin.readline().strip()

            self.disconnect()
            self.api_key = api_key

            log.info('Checking API key... ')
            self.connect()

            if not self.logged_in:
                raise BugzillaError("Login with API_KEY failed")
            log.info('API Key accepted')

            if self._use_creds:
                _save_api_key(self.url, self.api_key)
            else:
                log.info("API Key won't be updated because use_creds=False")
            return

        if not user:
            sys.stdout.write('Bugzilla Username: ')
            sys.stdout.flush()
            user = sys.stdin.readline().strip()
        if not password:
            password = getpass.getpass('Bugzilla Password: ')

        log.info('Logging in... ')
        self.login(user, password, restrict_login)
        log.info('Authorization cookie received.')

    def _logout(self):
        """
        Backend login method for Bugzilla3
        """
        return self._proxy.User.logout()

    def logout(self):
        """
        Log out of bugzilla. Drops server connection and user info, and
        destroys authentication cookies.
        """
        self._logout()
        self.disconnect()
        self.user = ''
        self.password = ''

    #############################
    # Login/connection handling #
    #############################

    def readconfig(self, configpath=None, overwrite=True):
        """
        :param configpath: Optional bugzillarc path to read, instead of
            the default list.

        This function is called automatically from Bugzilla connect(), which
        is called at __init__ if a URL is passed. Calling it manually is
        just for passing in a non-standard configpath.

        The locations for the bugzillarc file are preferred in this order:

            ~/.config/python-bugzilla/bugzillarc
            ~/.bugzillarc
            /etc/bugzillarc

        It has content like:
          [bugzilla.yoursite.com]
          user = username
          password = password
        Or
          [bugzilla.yoursite.com]
          api_key = key

        The file can have multiple sections for different bugzilla instances.
        A 'url' field in the [DEFAULT] section can be used to set a default
        URL for the bugzilla command line tool.

        Be sure to set appropriate permissions on bugzillarc if you choose to
        store your password in it!

        :param overwrite: If True, bugzillarc will clobber any already
            set self.user/password/api_key/cert value.
        """
        cfg = _open_bugzillarc(configpath or self.configpath)
        if not cfg:
            return

        section = ""
        log.debug("bugzillarc: Searching for config section matching %s",
            self.url)

        urlhost = _parse_hostname(self.url)
        for sectionhost in sorted(cfg.sections()):
            # If the section is just a hostname, make it match
            # If the section has a / in it, do a substring match
            if "/" not in sectionhost:
                if sectionhost == urlhost:
                    section = sectionhost
            elif sectionhost in self.url:
                section = sectionhost
            if section:
                log.debug("bugzillarc: Found matching section: %s", section)
                break

        if not section:
            log.debug("bugzillarc: No section found")
            return

        for key, val in cfg.items(section):
            if key == "api_key" and (overwrite or not self.api_key):
                log.debug("bugzillarc: setting api_key")
                self.api_key = val
            elif key == "user" and (overwrite or not self.user):
                log.debug("bugzillarc: setting user=%s", val)
                self.user = val
            elif key == "password" and (overwrite or not self.password):
                log.debug("bugzillarc: setting password")
                self.password = val
            elif key == "cert" and not (overwrite or not self.cert):
                log.debug("bugzillarc: setting cert")
                self.cert = val
            else:
                log.debug("bugzillarc: unknown key=%s", key)

    ###################
    # Cookie handling #
    ###################

    def _getcookiefile(self):
        """
        cookiefile is the file that bugzilla session cookies are loaded
        and saved from.
        """
        return self._cookiejar.filename

    def _delcookiefile(self):
        self._cookiejar = None

    def _setcookiefile(self, cookiefile):
        if (self._cookiejar and cookiefile == self._cookiejar.filename):
            return

        if self._proxy is not None:
            raise RuntimeError("Can't set cookies with an open connection, "
                               "disconnect() first.")

        log.debug("Using cookiefile=%s", cookiefile)
        self._cookiejar = _build_cookiejar(cookiefile)

    cookiefile = property(_getcookiefile, _setcookiefile, _delcookiefile)

def _default_location(filename, kind):
    """
    Determine default location for filename, like 'bugzillacookies'. If
    old style ~/.bugzillacookies exists, we use that, otherwise we
    use ~/.cache/python-bugzilla/bugzillacookies.
    Same for bugzillatoken and bugzillarc
    """
    homepath = os.path.expanduser("~/.%s" % filename)
    xdgpath = os.path.expanduser("~/.%s/python-bugzilla/%s" % (kind, filename))
    if os.path.exists(xdgpath):
        return xdgpath
    if os.path.exists(homepath):
        return homepath

    if not os.path.exists(os.path.dirname(xdgpath)):
        os.makedirs(os.path.dirname(xdgpath), 0o700)
    return xdgpath


def _default_cache_location(filename):
    return _default_location(filename, 'cache')


def _default_config_location(filename):
    return _default_location(filename, 'config')


def _build_cookiejar(cookiefile):
    cj = MozillaCookieJar(cookiefile)
    if cookiefile is None:
        return cj
    if not os.path.exists(cookiefile):
        # Make sure a new file has correct permissions
        open(cookiefile, 'a').close()
        os.chmod(cookiefile, 0o600)
        cj.save()
        return cj

    try:
        cj.load()
        return cj
    except LoadError:
        raise BugzillaError("cookiefile=%s not in Mozilla format" %
                            cookiefile)


def _save_api_key(url, api_key):
    """
    Save the API_KEY in the config file.

    If tokenfile and cookiefile are undefined, it means that the
    API was called with --no-cache-credentials and no change will be
    made
    """
    config_filename = _default_config_location('bugzillarc')
    section = _parse_hostname(url)

    cfg = ConfigParser()
    cfg.read(config_filename)

    if section not in cfg.sections():
        cfg.add_section(section)

    cfg[section]['api_key'] = api_key.strip()

    with open(config_filename, 'w') as configfile:
        cfg.write(configfile)

    log.info("API key written to %s", config_filename)
    print("API key written to %s" % config_filename)


def _parse_hostname(url):
    # If http://example.com is passed, netloc=example.com path=""
    # If just example.com is passed, netloc="" path=example.com
    parsedbits = urlparse(url)
    return parsedbits.netloc or parsedbits.path
