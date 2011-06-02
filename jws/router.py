import re

# algorithm routing
class RouteMissingError(Exception): pass
class RouteEndpointError(Exception): pass
def route(name):
    return resolve(*find(name))

def find(name):
    assert DEFAULT_ALGORITHMS
    algorithms = CUSTOM_ALGORITHMS + list(DEFAULT_ALGORITHMS)
    for (route, endpoint) in algorithms:
        match = re.match(route, name)
        if match:
            return (endpoint, match)
    raise RouteMissingError('endpoint matching %s could not be found' % name)
    
def resolve(endpoint, match):
    if callable(endpoint):
        # send result back through
        return resolve(endpoint(**match.groupdict()), match)
    
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
DEFAULT_ALGORITHMS = (
    (r'^HS(?P<bits>256|384|512)$', algos.HMAC),
    (r'^RS(?P<bits>256|384|512)$', algos.RSA),
    (r'^ES(?P<bits>256|384|512)$', algos.ECDSA),
)
CUSTOM_ALGORITHMS = []
