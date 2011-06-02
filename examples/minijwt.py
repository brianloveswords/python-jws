import jws
def to_jwt(claim, algo, key):
    header = {'typ': 'JWT', 'alg': algo}
    return "%s.%s.%s" % [
        jws.utils.encode(header),
        jws.utils.encode(claim),
        jws.sign(header, claim, key)
    ]
def from_jwt(jwt, key):
    (header, claim, sig) = jwt.split('.')
    header = jws.utils.decode(header)
    claim = jws.utils.decode(claim)
    jws.verify(header, claim, sig, key)
    return claim

