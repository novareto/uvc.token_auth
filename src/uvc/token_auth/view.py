# -*- coding: utf-8 -*-

import grok
import json
import uvcsite
from .plugin import TokenAuthenticationPlugin
import zope.security.interfaces
from zope.authentication.interfaces import IUnauthenticatedPrincipal


class QueryToken(grok.View):
    grok.context(TokenAuthenticationPlugin)
    grok.require('zope.Public')
    grok.name('token')

    def render(self):
        principal = self.request.principal
        if IUnauthenticatedPrincipal.providedBy(principal):
            self.request.response.setStatus(401)
            return "Unauthorized: unidentified users can't get tokens.\n"
        token = self.context.generate_token(**{'principal': principal.id})
        self.request.response.setHeader('Content-Type', 'application/json')
        self.request.response.setHeader('Access-Control-Allow-Origin', '*')
        return json.dumps({'token': token})
