from datetime import datetime
from utils import (base64url_encode as b64encode, base64url_decode as b64decode)

class AlgorithmError(Exception): pass

class JWK(object):
    @classmethod
    def to_real_key(klass, webkey):
        return getattr(klass, 'to_%s' % webkey['algorithm'])(webkey)

    @classmethod
    def to_ECDSA(klass, webkey):
        import ecdsa
        curves = {
            'P-256': ecdsa.NIST256p,
            'P-384': ecdsa.NIST384p,
            'P-521': ecdsa.NIST521p,
        }

        x = long(b64decode(webkey['x']))
        y = long(b64decode(webkey['y']))
        curve = curves[webkey['curve']]

        # the method ``from_public_point()`` takes an instance of
        # ellipticcurve.Point instance, which must be generated from an
        # instance of CurveFp, long x, and long y.
        point = ecdsa.ellipticcurve.Point(curve.curve, x, y)
        return ecdsa.VerifyingKey.from_public_point(point, curve)

    @classmethod
    def to_RSA(klass, webkey):
        from Crypto.PublicKey import RSA
        exp = long(b64decode(webkey['exponent']))
        mod = long(b64decode(webkey['modulus']))
        return RSA.construct((exp, mod,))

    @classmethod
    def from_real_key(klass, keyobj):
        from ecdsa.keys import VerifyingKey as ECDSAKey
        from Crypto.PublicKey.RSA import _RSAobj as RSAKey

        # keyed by actual class. will use value to generate a method call
        known_types = { ECDSAKey: 'ECDSA', RSAKey: 'RSA', }

        try:
            keytype = known_types[keyobj.__class__]
        except KeyError, e:
            raise AlgorithmError("I don't know how to deal with this type of key: %s" % keyobj.__class__)
        return getattr(klass, 'from_%s' % keytype)(keyobj)

    @classmethod
    def from_ECDSA(klass, keyobj):
        point = keyobj.pubkey.point
        curve = 'P-%s' % keyobj.curve.name[4:7] # e.g. NIST256p, we only want the 256
        return {
            'algorithm': 'ECDSA',
            'curve': curve,
            'x': b64encode(str(point.x())),
            'y': b64encode(str(point.y())),
            'keyid': datetime.now().isoformat(),
        }

    @classmethod
    def from_RSA(klass, keyobj):
        return {
            'algorithm': 'RSA',
            'modulus': b64encode(str(keyobj.e)),
            'exponent': b64encode(str(keyobj.n)),
            'keyid': datetime.now().isoformat(),
        }
