import jws
def to_jwt(claim, algo, key):
    header = {'typ': 'JWT', 'alg': algo}
    return '.'.join([
        jws.utils.encode(header),
        jws.utils.encode(claim),
        jws.sign(header, claim, key)
    ])
def from_jwt(jwt, key):
    "Returns the decoded claim on success, or throws exception on error"
    (header, claim, sig) = jwt.split('.')
    header = jws.utils.from_base64(header)
    claim = jws.utils.from_base64(claim)
    jws.verify(header, claim, sig, key, is_json=True)
    return jws.utils.from_json(claim)

