import Crypto
import hmac
import hashlib
import utils

class DecodeError(Exception): pass
class InvalidHeaderError(Exception): pass

def not_implemented(msg):
    def f(*a): raise NotImplementedError(msg)
    return f

reserved_params = [
    'alg', # REQUIRED, signing algo, see signing_methods
    'typ', # OPTIONAL, type of signed content
    'jku', # OPTIONAL, JSON Key URL. See http://self-issued.info/docs/draft-jones-json-web-key.html
    'kid', # OPTIONAL, key id, hint for which key to use.
    'x5u', # OPTIONAL, x.509 URL pointing to certificate or certificate chain
    'x5t', # OPTIONAL, x.509 certificate thumbprint
]

signing_methods = {
    # HMAC
    'HS256': lambda msg, key: hmac.new(key, msg, hashlib.sha256).digest(),
    'HS384': lambda msg, key: hmac.new(key, msg, hashlib.sha384).digest(),
    'HS512': lambda msg, key: hmac.new(key, msg, hashlib.sha512).digest(),
    # RSA
    'RS256': not_implemented('RSA not yet implemented'),
    'RS384': not_implemented('RSA not yet implemented'),
    'RS512': not_implemented('RSA not yet implemented'),
    # ECDSA
    'ES256': not_implemented('ECDSA not yet implemented'),
    'ES384': not_implemented('ECDSA not yet implemented'),
    'ES512': not_implemented('ECDSA not yet implemented'),
}

def validate_header(header):
    # TODO: allow for arbitrary contraints, based on this requirement:
    #    5. The JWS Header Input MUST be validated to only include params and
    #    values whose syntax and semantics are both understood and supported
    if u'alg' not in header:
        raise InvalidHeaderError('JWS Header Input must have alg parameter')
    if header['alg'] not in signing_methods:
        raise InvalidHeaderError('%s algorithm not supported.' % header['alg'])

def sign(raw_header, raw_payload, **kwargs):
    validate_header(raw_header)
    
    header_input, payload_input = map(utils.encode, [raw_header, raw_payload])
    signing_input = "%s.%s" % (header_input, payload_input)
    crypto_method = signing_methods[raw_header['alg']]
    crypto_output = crypto_method(signing_input, kwargs.get('key', ''))
    return utils.base64url_encode(crypto_output)

def verify(header_input, payload_input, crypto_output):
    pass
