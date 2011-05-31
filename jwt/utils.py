import base64
import json

def base64url_decode(input):
    input += '=' * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input)
def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace('=', '')

def to_json(*a): return __multi(json.dumps, *a)
def from_json(*a): return __multi(json.loads, *a)
def to_base64(*a): return __multi(base64url_encode, *a)
def from_base64(*a): return __multi(base64url_decode, *a)
def __multi(fn, *a):
    if len(a) == 1: return fn(a[0])
    return [fn(arg) for arg in a]
