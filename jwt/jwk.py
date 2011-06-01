from datetime import datetime
from utils import (base64url_encode as b64encode, base64url_decode as b64decode)

class AlgorithmError(Exception): pass

class JWK(object):
    @classmethod
    def to_real_key(klass, webkey_entry):
        return getattr(klass, 'to_%s' % webkey_entry['algorithm'])(webkey_entry)
    
    @classmethod
    def to_ECDSA(klass, webkey_entry):
        import ecdsa
        curves = {
            'P-256': ecdsa.NIST256p,
            'P-384': ecdsa.NIST384p,
            'P-521': ecdsa.NIST521p,
        }
        x = long(b64decode(webkey_entry['x']))
        y = long(b64decode(webkey_entry['y']))
        curve = curves[webkey_entry['curve']]
        point = ecdsa.ellipticcurve.Point(curve.curve, x, y)
        return ecdsa.VerifyingKey.from_public_point(point, curve)
        
    @classmethod
    def from_real_key(klass, keyobj):
        from ecdsa.keys import VerifyingKey as ECDSAKey
        from Crypto.PublicKey.RSA import _RSAobj as RSAKey
        
        # keyed by real class
        known_types = {
            ECDSAKey: 'ECDSA', RSAKey: 'RSA',
        }
        try:
            keytype = known_types[keyobj.__class__]
        except KeyError, e:
            raise AlgorithmError("I don't know how to deal with this type of key: %s" % keyobj.__class__)
        return getattr(klass, 'from_%s' % keytype)(keyobj)
        
    @classmethod
    def from_ECDSA(klass, keyobj):
        point = keyobj.pubkey.point
        curve = 'P-%s' % keyobj.curve.name[4:7] # e.g. NIST256p, we only want the 256
        x, y = point.x(), point.y()
        return {
            'algorithm': 'ECDSA',
            'curve': curve,
            'x': b64encode(str(point.x())),
            'y': b64encode(str(point.y())),
            'keyid': datetime.now().isoformat(),
        }
    
    @classmethod
    def from_RSA(klass, keyobj):
        raise NotImplementedError("Not yet implemented")

