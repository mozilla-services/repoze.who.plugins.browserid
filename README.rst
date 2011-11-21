============================
repoze.who.plugins.browserid
============================

This is repoze.who plugin for authentication via Mozilla's BrowserID project:

    https://browserid.org/

It currently supports verification of BrowserID assertions by posting them 
to the browserid.org verifier services.  As the protocol becomes more stable
it will grow the ability to verify assertions locally.

Configuration of the plugin can be done from the standard repoze.who config
file like so::

    [plugin:browserid]
    use = repoze.who.plugins.browserid:make_plugin
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


TODO: fill this in.


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
"check_secure" settings.


Audience Checking
-----------------

BrowserID uses the notion of an "audience" to protect against stolen logins.
The audience ties a BrowserID assertion to a specific host, so that an 
attacker can't collect assertions on one site and use them to log in to
another.

This plugin performs strict audience checking by default.  You can provide
a specific audience string when creating the plugin, but there is no option to
disable these checks.
