# -*- coding: utf-8 -*-

import base64
import grok
import json
import time
import urllib

from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
from zope.interface import implementer
from zope.pluggableauth import interfaces
from zope.pluggableauth.factories import PrincipalInfo
from zope.publisher.interfaces.http import IHTTPRequest
from zope.cachedescriptors.property import CachedProperty


@implementer(interfaces.ICredentialsPlugin)
class TokenCredentials(grok.GlobalUtility):
    grok.name("token_creds")

    def extractCredentials(self, request):
        if not IHTTPRequest.providedBy(request):
            return None

        # this is an access token in the URL  ?access_token=...
        if not hasattr(request, 'form'):
            return None
        access_token = (request.form.get('access_token', None) or
                        request.form.get('form.field.access_token', None))
        if access_token is not None:
            return {'access_token': access_token}
        return None

    def challenge(self, request):
        return True

    def logout(self, request):
        # We might want to expire the cookie, if the token came
        # from a cookie, but it's not yet the case.
        return False


@implementer(interfaces.IAuthenticatorPlugin)
class TokenAuthenticator(grok.LocalUtility):
    grok.name('token_auth')

    prefix = 'token.principals.'
    _private_key = None
    _public_key = None
    TTL = dict(days=10, hours=0, minutes=0)
    
    @CachedProperty
    def private_key(self):
        return RSA.importKey(self._private_key)

    @private_key.setter
    def private_key(self, value):
        self._private_key = value

    @CachedProperty
    def public_key(self):
        return RSA.importKey(self._public_key)

    @public_key.setter
    def public_key(self, value):
        self._public_key = value

    def make_token(self):
        ts = int(time.mktime((
            datetime.now() + timedelta(**self.TTL)).timetuple()
        ))
        token = json.dumps({
            'timestamp': ts,
            'id': 'servicetelefon',
        })
        encrypted = self.public_key.encrypt(token, 32)
        access_token = urllib.quote_plus(base64.b64encode(encrypted[0]))
        return access_token

    def authenticateCredentials(self, credentials):
        if not credentials:
            return
        access_token = credentials.get('access_token')
        if access_token is None:
            return
        try:
            token = base64.b64decode(access_token)
            decrypted = self.private_key.decrypt((token,))
            data = json.loads(decrypted)
        except TypeError:
            return None
        except Exception as exc:
            print exc  # log this nasty error
            return None

        now = int(time.time())

        if now > data['timestamp']:
            # expired
            return None

        authenticated = dict(
                id=data['id'] + '-0',
                title='Token generated',
                description='Token generated',
                login=data['id'] + '-0')
        return PrincipalInfo(**authenticated)

    def principalInfo(self, id):
        """we don´t need this method"""
        if id.startswith('uvc.'):
            return PrincipalInfo(id, id, id, id)
