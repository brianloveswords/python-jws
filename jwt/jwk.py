from datetime import datetime
from ecdsa.keys import VerifyingKey as ECDSAKey
from Crypto.PublicKey.RSA import _RSAobj as RSAKey
import utils

class AlgorithmError(Exception): pass

class JWK(object):
    known_types = {
        ECDSAKey: 'ECDSA',
        RSAKey: 'RSA',
    }
    @classmethod
    def from_key(klass, keyobj):
        try:
            keytype = klass.known_types[keyobj.__class__]
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
            'x': utils.base64url_encode(str(point.x())),
            'y': utils.base64url_encode(str(point.y())),
            'keyid': datetime.now().isoformat(),
        }
    
    @classmethod
    def from_RSA(klass, keyobj):
        print 'rsa'

