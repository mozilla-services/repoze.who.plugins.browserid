============================
repoze.who.plugins.browserid
============================

This is repoze.who plugin for authentication via Mozilla's BrowserID project:

    https://browserid.org/

It supports verification of BrowserID assertions using the PyVEP client
library.  Currently PyVEP defaults to posting assertions to the browserid.org
verifier servive, but it also has preliminary support for verifying assertions
locally.  As the protocol becomes more stable then local verification will
become the default.

Configuration of the plugin can be done from the standard repoze.who config
file like so::

    [plugin:browserid]
    use = repoze.who.plugins.browserid:make_plugin
    audiences = www.mysite.com
    rememberer_name = authtkt

    [plugin:authtkt]
    use = repoze.who.plugins.auth_tkt:make_plugin
    secret = My Special Secret

    [identifiers]
    plugins = authtkt browserid

    [authenticators]
    plugins = authtkt browserid

    [challengers]
    plugins = browserid
    
Note that we have paired the BrowserID plugin with the standard AuthTkt plugin
so that it can remember the user's login across requests.


Customization
=============

The following settings can be specified in the configuration file to customize
the behaviour of the plugin:

  :audiences:   A space-separated list of acceptable hostnames or glob patterns
                for the BrowserID assertion audience.  Any assertion whose
                audience does not match an item in the list will be rejected.

                You must specify a value for this setting, since it is integral
                to the security of BrowserID.  See the Security Notes section
                below for more details.

  :rememberer_name:   The name of another repoze.who plugin which should be
                      called to remember/forget the authentication.  This 
                      would typically be a signed-cookie implementation such
                      as the built-in auth_tkt plugin.  If unspecificed or 
                      None then authentication will not be remembered.

  :postback_url:   The URL to which BrowserID credentials should be sent
                   for validation.  The default value is hopefully conflict
                   free: /repoze.who.plugins.browserid.postback.

  :assertion_field:   The name of the POST form field in which to find the
                      BrowserID assertion.  The default value is "assertion".

  :came_from_field:   The name of the POST form field in which to find the
                      referring page, to which the user will be redirected
                      after processing their login.  The default value is
                      "came_from".

  :csrf_field:   The name of the POST form field in which to find the CSRF
                 protection token.  The default value is "csrf_token".  If
                 set to the empty string then CSRF checking is disabled.

  :csrf_cookie_name:   The name of the cookie in which to set and find the
                       CSRF protection token.  The default cookie name is
                       "browserid_csrf_token".  If set to the empty string
                       then CSRF checking is disabled.

  :challenge_body:   The location at which to find the HTML for the login
                     page, either as a dotted python reference or a filename.
                     The contained HTML may use python string interpolation
                     syntax to include details of the challenge, e.g. use
                     %(csrf_token)s to include the CSRF token.

  :verifier:   The PyVEP Verifier object to use for checking assertions, or
               the dotted python name of such an object.  The default value
               is vep.RemoteVerifier() which should be suitable for most
               purposes.

  :check_https:   Boolean indicating whether to reject login attempts over
                  enencrypted connections.  The default value is False.

  :check_referer:   Boolean indicating whether to reject login attempts where
                    the referer header does not match the expected audience.
                    The default is to perform this check for secure connections
                    only.


Security Notes
==============

CSRF Protection
---------------

This plugin attempts to provide some basic protection against login-CSRF 
attacks as described by Barth et. al. in "Robust Defenses for Cross-Site
Request Forgery":

    http://seclab.stanford.edu/websec/csrf/csrf.pdf

In the terminology of the above paper, it combines a session-independent
nonce with strict referer checking for secure connections.  You can tweak
the protection by adjusting the "csrf_cookie_name", "check_referer" and
"check_https" settings.


Audience Checking
-----------------

BrowserID uses the notion of an "audience" to protect against stolen logins.
The audience ties a BrowserID assertion to a specific host, so that an 
attacker can't collect assertions on one site and then use them to log in to
another.

This plugin performs strict audience checking by default.  You must provide
a list of acceptable audience string when creating the plugin, and they should
be specific to your application.  For example, if your application serves
requests on three different hostnames http://mysite.com, http://www.mysite.com
and http://uploads.mysite.com, you might provide::

    [plugin:browserid]
    use = repoze.who.plugins.browserid:make_plugin
    audiences = mysite.com *.mysite.com

If your application does strict checking of the HTTP Host header, then you can
instruct the plugin to use the Host header as the audience by leaving the list
blank::

    [plugin:browserid]
    use = repoze.who.plugins.browserid:make_plugin
    audiences =

This is not the default behaviour since it may be insecure on some systems.
