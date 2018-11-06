# -*- coding: utf-8 -*-

from Crypto.PublicKey import RSA

def create_rsa_pair(size=2048):
    key = RSA.generate(size)
    pubkey = key.publickey()
    return key.exportKey('PEM'), pubkey.exportKey('PEM')


__all__ = ('create_rsa_pair')
