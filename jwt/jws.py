import re
import utils

# Exceptions
class DecodeError(Exception): pass
class InvalidHeaderError(Exception): pass
class SignatureError(Exception): pass
class MissingAlgorithmError(Exception): pass

# Signing algorithms
class SigningAlgorithm(object):
    def __init__(self, bits):
        import hashlib
        if int(bits) not in (256, 384, 512):
            raise NotImplementedError("%s only implements 256, 384 and 512 bit algorithms (given %s)" % self.__class__, bits)
        self.hasher = getattr(hashlib, 'sha%d' % int(bits))
        
class HMAC(SigningAlgorithm):
    import hmac
    def sign(self, msg, key):
        return self.hmac.new(key, msg, self.hasher).digest()
    
    def verify(self, msg, crypto, key):
        if not self.sign(msg, key) == crypto:
            raise SignatureError("Could not validate signature")


class RSA(SigningAlgorithm): pass
class ECDSA(SigningAlgorithm): pass

# Main class
class JWS(object):
    reserved_params = [
        'alg', # REQUIRED, signing algo, see signing_methods
        'typ', # OPTIONAL, type of signed content
        'jku', # OPTIONAL, JSON Key URL. See http://self-issued.info/docs/draft-jones-json-web-key.html
        'kid', # OPTIONAL, key id, hint for which key to use.
        'x5u', # OPTIONAL, x.509 URL pointing to certificate or certificate chain
        'x5t', # OPTIONAL, x.509 certificate thumbprint
    ]
    
    def __init__(self, header={}, payload={}):
        self.algorithms = [
            (r'^HS(256|384|512)$', HMAC),
            (r'^RS(256|384|512)$', RSA),
            (r'^ES(256|384|512)$', HMAC),
        ]
        self.__algorithm = None
        if header:  self.set_header(header)
        if payload: self.set_payload(payload)
    
    def set_header(self, header):
        """
        Verify and set the header. Also calls set_algorithm when it finds an
        alg property and ensures that the algorithm is implemented.
        """
        if u'alg' not in header:
            raise InvalidHeaderError('JWS Header Input must have alg parameter')
        try:
            self.set_algorithm(header['alg'])
        except NotImplementedError, e:
            raise InvalidHeaderError('%s algorithm not implemented.' % header['alg'])
        self.__header = header

    def set_payload(self, payload):
        self.__payload = payload
    
    def set_algorithm(self, algo):
        """
        Verify and set the signing/verifying algorithm. Looks up regex mapping
        from self.algorithms to determine which algorithm class to use.
        """
        for (regex, cls) in self.algorithms:
            match = re.match(regex, algo)
            if match:
                self.__algorithm = cls(match.groups()[0])
                return 
        raise NotImplementedError("Could not find algorithm defined for %s" % algo)

    def sign(self, *args, **kwargs):
        if not self.__algorithm:
            raise MissingAlgorithmError("Could not find algorithm. Make sure to call set_header() before trying to sign anything")
        return self.__algorithm.sign(self.signing_input(), *args, **kwargs)
    
    def verify(self, *args, **kwargs):
        if not self.__algorithm:
            raise MissingAlgorithmError("Could not find algorithm. Make sure to call set_header() before trying to verify anything")
        return self.__algorithm.verify(self.signing_input(), *args, **kwargs)
    
    def signing_input(self):
        header_input, payload_input = map(utils.encode, [self.__header, self.__payload])
        return "%s.%s" % (header_input, payload_input)
    
        
def not_implemented(msg):
    def f(*a): raise NotImplementedError(msg)
    return f

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
    # TODO: allow for user-defined contraints, based on this requirement:
    #    5. The JWS Header Input MUST be validated to only include params and
    #    values whose syntax and semantics are both understood and supported
    if u'alg' not in header:
        raise InvalidHeaderError('JWS Header Input must have alg parameter')
    if header['alg'] not in signing_methods:
        raise InvalidHeaderError('%s algorithm not supported.' % header['alg'])

def sign(raw_header, raw_payload, key):
    validate_header(raw_header)
    
    header_input, payload_input = map(utils.encode, [raw_header, raw_payload])
    signing_input = "%s.%s" % (header_input, payload_input)
    crypto_method = signing_methods[raw_header['alg']]
    crypto_output = crypto_method(signing_input, key)
    return utils.base64url_encode(crypto_output)

def verify(header_input, payload_input, crypto_output, key):
    header, payload = map(utils.decode, [header_input, payload_input])
    validate_header(header)
    
    if sign(header, payload, key) != crypto_output:
        raise SignatureError('Signature could not be verified')
    
