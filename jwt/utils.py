import base64
import json
from Crypto.PublicKey import RSA
from Crypto import Random

def base64url_decode(input):
    input += '=' * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input)
def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace('=', '')

def to_json(a): return json.dumps(a)
def from_json(a): return json.loads(a)
def to_base64(a): return base64url_encode(a)
def from_base64(a): return base64url_decode(a)
def encode(a): return to_base64(to_json(a))
def decode(a): return from_json(from_base64(a))
def rsa_key(keystr):
    return RSA.importKey(keystr)
