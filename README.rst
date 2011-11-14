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

