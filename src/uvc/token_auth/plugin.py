# -*- coding: utf-8 -*-

import grok
import uvcsite.plugins
from zope.component import queryUtility
from zope.authentication.interfaces import IAuthentication
from zope.pluggableauth.interfaces import IAuthenticatorPlugin

from uvcsite.plugins import flags as statuses
from uvc.token_auth.components import TokenAuthenticator, TokenCredentials
from uvc.token_auth import create_rsa_pair


class TokenAuthenticationPlugin(uvcsite.plugins.Plugin):
    grok.name('uvc.token_auth')

    title = u"Token authentication"
    description = u"Bearer token authentication capabilities"
    fa_icon = 'user-lock'

    @property
    def status(self):
        sm = grok.getApplication().getSiteManager()
        pau = queryUtility(IAuthentication)

        cred_name = grok.name.bind().get(TokenCredentials)
        auth_name = grok.name.bind().get(TokenAuthenticator)

        pau_has_auth = auth_name in pau.authenticatorPlugins
        pau_has_cred = cred_name in pau.credentialsPlugins
        sm_has_auth = auth_name in sm
        
        if (pau_has_auth and pau_has_cred and sm_has_auth):
            return uvcsite.plugins.INSTALLED

        if (pau_has_auth or pau_has_cred or sm_has_auth):
            return uvcsite.plugins.INCONSISTANT

        return uvcsite.plugins.NOT_INSTALLED

    @uvcsite.plugins.plugin_action(
        'Install', _for=(statuses.NOT_INSTALLED, statuses.INCONSISTANT))
    def install(site):        
        sm = site.getSiteManager()
        pau = sm.queryUtility(IAuthentication)

        cred_name = grok.name.bind().get(TokenCredentials)
        auth_name = grok.name.bind().get(TokenAuthenticator)

        # Check if the utility already exists
        if auth_name not in sm:
            # Generate the keys, persist and register the utility
            utility = TokenAuthenticator()
            utility.private_key, utility.public_key = create_rsa_pair()
            sm[auth_name] = utility
            sm.registerUtility(
                utility, provided=IAuthenticatorPlugin, name=auth_name)

        # Add a PAU entry
        if auth_name not in pau:
            pau.authenticatorPlugins = pau.authenticatorPlugins + (auth_name,)

        # Add a PAU entry
        if cred_name not in pau:
            pau.credentialsPlugins = pau.credentialsPlugins + (cred_name,)

        return uvcsite.plugins.PluginResult(
            value=u'Token authentication installed with success',
            type=uvcsite.plugins.STATUS_MESSAGE,
            redirect=True)

    @uvcsite.plugins.plugin_action(
        'Uninstall', _for=(statuses.INSTALLED, statuses.INCONSISTANT))
    def uninstall(site):
        sm = site.getSiteManager()
        pau = sm.queryUtility(IAuthentication)

        cred_name = grok.name.bind().get(TokenCredentials)
        auth_name = grok.name.bind().get(TokenAuthenticator)

        # Check if the utility already exists
        if auth_name in sm:
            utility = sm[auth_name]
            sm.unregisterUtility(
                utility, provided=IAuthenticatorPlugin, name=auth_name)
            del sm[auth_name]

        # Remove PAU entry
        pau.authenticatorPlugins = tuple((
            name for name in pau.authenticatorPlugins
            if name != auth_name))

        # Remove PAU entry
        pau.credentialsPlugins = tuple((
            name for name in pau.credentialsPlugins
            if name != cred_name))

        return uvcsite.plugins.PluginResult(
            value=u'Token authentication uninstalled with success',
            type=uvcsite.plugins.STATUS_MESSAGE,
            redirect=True)

    @uvcsite.plugins.plugin_action(
        'Show details', _for=uvcsite.plugins.INSTALLED)
    def details(site):
        sm = site.getSiteManager()
        auth_name = grok.name.bind().get(TokenAuthenticator)
        plugin = sm[auth_name]
        return uvcsite.plugins.PluginResult(
            value={
                'Private key': plugin._private_key,
                'Public key': plugin._public_key,
                'Time to live': plugin.TTL,
            },
            type=uvcsite.plugins.STRUCTURE,
            redirect=False)

    @uvcsite.plugins.plugin_action(
        'Test token generation', _for=uvcsite.plugins.INSTALLED)
    def test_token(site):
        sm = site.getSiteManager()
        auth_name = grok.name.bind().get(TokenAuthenticator)
        plugin = sm[auth_name]
        token = plugin.make_token()        
        return uvcsite.plugins.PluginResult(
            value={
                'url encoded token': token
            },
            type=uvcsite.plugins.STRUCTURE,
            redirect=False)
