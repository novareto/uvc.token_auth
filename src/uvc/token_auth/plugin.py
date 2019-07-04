# -*- coding: utf-8 -*-

import grok
import uvcsite.plugins.components
import uvcsite.plugins.subplugins
from zope.component import queryUtility
from zope.authentication.interfaces import IAuthentication
from zope.pluggableauth.interfaces import IAuthenticatorPlugin

from uvcsite.plugins.flags import States
from uvc.token_auth.components import TokenAuthenticator, TokenCredentials
from uvc.token_auth import create_rsa_pair


def token_auth():
    utility = TokenAuthenticator()
    utility.private_key, utility.public_key = create_rsa_pair()
    return utility


class TokenAuthenticationPlugin(uvcsite.plugins.components.ComplexPlugin):
    grok.name('jwt.auth')

    title = u"Token authentication"
    description = u"Bearer token authentication capabilities"
    fa_icon = 'user-lock'

    subplugins = (
        uvcsite.plugins.subplugins.PAUComponent(
            token_auth, 'authenticator', name='token_auth'),
        uvcsite.plugins.subplugins.PAUComponent(
            TokenCredentials, 'credentials'),
    )

    @staticmethod
    def generate_token(site=None, **args):
        if site is None:
            site = grok.getApplication()
        sm = site.getSiteManager()
        auth_name = grok.name.bind().get(TokenAuthenticator)
        plugin = sm[auth_name]
        token = plugin.make_token(**args)
        return token

    @uvcsite.plugins.components.plugin_action(
        'Install', States.NOT_INSTALLED)
    def install(self, site):
        return self.dispatch('install', site)

    @uvcsite.plugins.components.plugin_action(
        'Uninstall', States.INSTALLED, States.INCONSISTANT)
    def uninstall(self, site):
        return self.dispatch('uninstall', site)

    @uvcsite.plugins.components.plugin_action(
        'Show details', States.INSTALLED)
    def details(self, site):
        plugin = self.subplugins[0].get(site)
        return uvcsite.plugins.components.Result(
            uvcsite.plugins.flags.ResultTypes.JSON,
            value={
                'Private key': str(plugin._private_key),
                'Public key': str(plugin._public_key),
                'Time to live': str(plugin.TTL),
            },
            redirect=False)
    
    @uvcsite.plugins.components.plugin_action(
        'Test token generation', States.INSTALLED)
    def test_token(self, site, **args):
        token = self.generate_token(site=site, test='test')    
        return uvcsite.plugins.components.Result(
            uvcsite.plugins.flags.ResultTypes.JSON,
            value={
                'token': token
            },
            redirect=False)
