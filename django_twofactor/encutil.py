"""
Kind of based on the encryption bits detailed in
http://djangosnippets.org/snippets/1095/
"""

from hashlib import sha256
from django.conf import settings
from django.utils.encoding import smart_bytes, force_bytes
from binascii import hexlify, unhexlify
import string

# Get best AES implementation we can.
try:
    from Crypto.Cipher import AES
except ImportError:
    from django_twofactor import pyaes as AES

BLOCK_SIZE = AES.block_size

# Get best `random` implementation we can.
import random
try:
    random = random.SystemRandom()
except:
    pass

def _gen_salt(length=16):
    return ''.join([random.choice(string.ascii_letters + string.digits) for i in range(length)])

def _get_key(salt):
    """ Combines `settings.SECRET_KEY` with a salt. """
    if not salt: salt = ""
    
    return sha256(force_bytes(settings.SECRET_KEY) + force_bytes(salt)).digest()

def encrypt(data, salt):
    cipher = AES.new(_get_key(salt), mode=AES.MODE_ECB)
    value = smart_bytes(data)

    padding  = BLOCK_SIZE - len(value) % BLOCK_SIZE
    if padding and padding < BLOCK_SIZE:
        value += b"\0" + ''.join([random.choice(string.printable) for index in range(padding-1)]).encode('ascii')
    return hexlify(cipher.encrypt(value)).decode('ascii')

def decrypt(encrypted_data, salt):
    cipher = AES.new(_get_key(salt), mode=AES.MODE_ECB)

    # Note: this doesn't return the correct raw data if it has a null character
    # ("\x00") somewhere. Correct way would be
    #return cipher.decrypt(unhexlify(smart_bytes(encrypted_data))).rsplit('\0', 1)[0]
    # However, fixing this would render some existing tokens unusable.
    return cipher.decrypt(unhexlify(smart_bytes(encrypted_data))).split(b'\0')[0]
