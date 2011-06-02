import router
class ParameterBase(object):
    def __init__(self, name, value):
        self.name = name
        self.value = self.clean(value)
    def sign(self): return self.value
    def verify(self): return self.value
    def clean(self, value): return value

class GenericString(ParameterBase):
    def clean(self, value):
        return str(value)

class SignNotImplemented(ParameterBase):
    def sign(self):
        raise "Header Paramter %s not implemented in the context of signing" % self.name

class VerifyNotImplemented(ParameterBase):
    def verify(self):
        raise "Header Paramter %s not implemented in the context of verifying" % self.name

class NotImplemented(ParameterBase):
    def clean(self):
        raise "Header Paramter %s not implemented" % self.name

class Algorithm(ParameterBase):
    def clean(self, value):
        self.methods = router.route(value)
    def sign(self):
        return self.methods['sign']
    def verify(self):
        return self.methods['verify']

DEFAULT_HEADER_ACTIONS = {
    # REQUIRED, signing algo, see signing_methods
    'alg': Algorithm,
    # OPTIONAL, type of signed content         
    'typ': GenericString,
    # OPTIONAL, JSON Key URL. See http://self-issued.info/docs/draft-jones-json-web-key.html
    'jku': VerifyNotImplemented,
     # OPTIONAL, key id, hint for which key to use.    
    'kid': VerifyNotImplemented,
    # OPTIONAL, x.509 URL pointing to certificate or certificate chain
    'x5u': VerifyNotImplemented,
    # OPTIONAL, x.509 certificate thumbprint    
    'x5t': VerifyNotImplemented,
}

def process(header, step):
    results = {}
    for param in header:
        cls = DEFAULT_HEADER_ACTIONS.get(param, NotImplemented)
        inst = cls(param, header[param])
        proc = getattr(inst, step)
        results[param] = proc()
    return results

