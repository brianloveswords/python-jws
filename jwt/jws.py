import re
import utils

# Exceptions
class DecodeError(Exception): pass
class InvalidHeaderError(Exception): pass
class SignatureError(Exception): pass
class MissingAlgorithmError(Exception): pass

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
            (r'^ES(256|384|512)$', ECDSA),
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
        self.set_algorithm(header['alg'])
        self.__header = header

    def set_payload(self, payload):
        """For symmetry"""
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
        """
        Calls the sign method on the algorithm instance determined from the
        header with signing input, generated from header and payload, and any
        additional algorithm-specific parameters.

        Returns the resulting signature as a base64url encoded string.
        """
        if not self.__algorithm:
            raise MissingAlgorithmError("Could not find algorithm. Make sure to call set_header() before trying to sign anything")
        crypto = self.__algorithm.sign(self.signing_input(), *args, **kwargs)
        return utils.base64url_encode(crypto)

    def verify(self, crypto_output, *args, **kwargs):
        """
        Calls the verify method on the algorithm instance determined from the
        header with signing input, generated from header and payload, the
        signature to verify, and any additional algorithm-specific parameters.
        """
        if not self.__algorithm:
            raise MissingAlgorithmError("Could not find algorithm. Make sure to call set_header() before trying to verify anything")
        crypto = utils.base64url_decode(crypto_output)
        return self.__algorithm.verify(self.signing_input(), crypto, *args, **kwargs)

    def signing_input(self):
        """
        Generates the signing input by json + base64url encoding the header
        and the payload, then concatenating the results with a '.' character.
        """
        header_input, payload_input = map(utils.encode, [self.__header, self.__payload])
        return "%s.%s" % (header_input, payload_input)



import hashlib

##############
# public api #
##############
def sign(header, payload, algos=None):
    pass
def verify(header, payload, signature, algos=None):
    pass

####################
# semi-private api #
####################

# algorithm routing
class RouteMissingError(Exception): pass
class RouteEndpointError(Exception): pass

def _algorithm_router(name):
    return _algorithm_resolve(*_algorithm_find(name))

def _algorithm_find(name):
    assert _DEFAULT_ALGORITHMS
    for (route, endpoint) in _DEFAULT_ALGORITHMS:
        match = re.match(route, name)
        if match:
            return (endpoint, match)
    raise RouteMissingError('endpoint matching %s could not be found' % name)
    
def _algorithm_resolve(endpoint, match):
    if callable(endpoint):
        # send result back through
        return _algorithm_resolve(endpoint(**match.groupdict()), match)
    
    # get the sign and verify methods from dict or obj
    try:
        crypt = { 'sign': endpoint['sign'], 'verify': endpoint['verify'] }
    except TypeError:
        try:
            crypt = { 'sign': endpoint.sign, 'verify': endpoint.verify }
        except AttributeError, e:
            raise RouteEndpointError('route enpoint must have sign, verify as attributes or items of dict')
    # verify callability
    try:
        assert callable(crypt['sign'])
        assert callable(crypt['verify'])
    except AssertionError, e:
        raise RouteEndpointError('sign, verify of endpoint must be callable')
    return crypt

import algos
def _hmac():      return algos.HMAC(bits)
def _rsa(bits):   return algos.RSA(bits)
def _ecdsa(bits): return algos.ECDSA(bits)
           

# route endpoints can either be:
#   * a callable thing that takes the match dict from the regexp
#     - needs to generate a dict or object with 'sign' and 'verify'
#       as items or attributes
#   * a dict or object in the style described above
_DEFAULT_ALGORITHMS = (
    (r'^HS(?P<bits>256|384|512)$', _hmac),
    (r'^RS(?P<bits>256|384|512)$', _rsa),
    (r'^ES(?P<bits>256|384|512)$', _ecdsa),
)

