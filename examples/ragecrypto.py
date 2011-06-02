import jws
from jws.algos import AlgorithmBase, SignatureError

class FXUY(AlgorithmBase):
    # initializer gets variables from algo router
    # named groups in the regexp get sent here.
    def __init__(self, fval, uval):
        self.x = len(fval)
        self.y = len(uval)

    # straightforward, just return the signature
    def sign(self, msg, key):
        return 'srs' * self.x + key + 'bzns' * self.y + msg
 
    # verify should only return if the signature is valid.
    # otherwise raise a SignatureError
    def verify(self, msg, sig, key):
        if sig != self.sign(msg, key):
            raise SignatureError('nope')
        return True

# algos.CUSTOM is a list that holds custom algorithms.
# the format is [(routing_regex, algorithm_class)...]
#
# values from the 'alg' key in headers are run through each algorithm
# routing_regex, stopping on the first one that matches. algos in the CUSTOM
# list take precedence over the defaults -- note that this means you can add
# override any default algorithms by defining a custom algorithm with a
# routing_regex that matches one of the defaults.
jws.algos.CUSTOM = [
    # a regular expression with two named matching groups.
    # named groups will be sent to the class constructor
    (r'^(?P<fval>f+)(?P<uval>u+)$',  FXUY),
]

## now this will be the algorithm discovered for any of the following headers:
# will sign with FXUY(fval=3, uval=3).sign
jws.sign({'alg': 'fffuuu'}, {'claim':'rad'}, 'key')

# will sign with FXUY(fval=1, uval=8).sign
jws.sign({'alg': 'fuuuuuuuu'}, {'claim':'rad'}, 'key')

# will sign with FXUY(fval=7, uval=12).sign
jws.sign({'alg': 'fffffffuuuuuuuuuuu'}, {'claim':'rad'}, 'key')
