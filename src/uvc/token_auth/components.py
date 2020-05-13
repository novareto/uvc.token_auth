import base64
import grok
import json
import time

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from datetime import datetime, timedelta
from zope.interface import implementer
from zope.pluggableauth import interfaces
from zope.pluggableauth.factories import PrincipalInfo
from zope.publisher.interfaces.http import IHTTPRequest


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

    @property
    def private_key(self):
        return RSA.importKey(self._private_key)

    @private_key.setter
    def private_key(self, value):
        self._private_key = value

    @property
    def public_key(self):
        return RSA.importKey(self._public_key)

    @public_key.setter
    def public_key(self, value):
        self._public_key = value

    def make_token(self, **data):
        ts = int(time.mktime((
            datetime.now() + timedelta(**self.TTL)).timetuple()
        ))
        # We override the reserved keys 'timestamp' and 'id'.
        data['timestamp'] = ts
        data['id'] = 'uvcsite.jwt'
        token = json.dumps(data)
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted = cipher_rsa.encrypt(token.encode('utf-8'))
        access_token = quote(base64.b64encode(encrypted))
        return access_token

    def authenticateCredentials(self, credentials):
        if not credentials:
            return
        access_token = credentials.get('access_token')
        if access_token is None:
            return
        try:
            token = base64.b64decode(access_token)
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            decrypted = cipher_rsa.decrypt(token)
            data = json.loads(decrypted)
        except TypeError:
            return None
        except Exception as exc:
            # log this nasty error
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
        """we don't need this method"""
        if id.startswith('uvc.'):
            return PrincipalInfo(id, id, id, id)
