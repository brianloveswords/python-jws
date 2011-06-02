class SignatureError(Exception): pass
class AlgorithmBase(object):
    """Base for algorithm support classes."""
    supported_bits = (256, 384, 512)
    def __init__(self, bits):
        """
        Determine if the algorithm supports the requested bit depth and set up
        matching hash method from ``hashlib`` if necessary.
        """
        self.bits = int(bits)
        if self.bits not in self.supported_bits:
            raise NotImplementedError("%s implements %s bit algorithms (given %d)" %
                                      (self.__class__, ', '.join(self.supported_bits), self.bits))
        if not getattr(self, 'hasher', None):
            import hashlib
            self.hasher = getattr(hashlib, 'sha%d' % self.bits)

class HMAC(AlgorithmBase):
    """
    Support for HMAC signing.
    """
    def sign(self, msg, key):
        import hmac
        utfkey = unicode(key).encode('utf8')
        return hmac.new(utfkey, msg, self.hasher).digest()

    def verify(self, msg, crypto, key):
        if not self.sign(msg, key) == crypto:
            raise SignatureError("Could not validate signature")
        return True

class RSA(AlgorithmBase):
    """
    Support for RSA signing.

    The ``Crypto`` package is required. However...

    NOTE: THIS ALGORITHM IS CRIPPLED AND INCOMPLETE

    Section 7.2 of the specification (found at
    http://self-issued.info/docs/draft-jones-json-web-signature.html)
    describes the algorithm for creating a JWS with RSA. It is mandatory to
    use RSASSA-PKCS1-V1_5-SIGN and either SHA256, 385 or 512.

    Problem 1: The Crypto library doesn't currently support PKCS1-V1_5. There
    is a fork that does have support:

    https://github.com/Legrandin/pycrypto/tree/pkcs1

    Problem 2: The PKCS signing method requires a Crypto.Hash class.
    Crypto.Hash doesn't yet have support anything above SHA256.

    Bottom line, you should probably use ECDSA instead.
    """
    supported_bits = (256,)

    def sign(self, msg, key):
        """
        Signs a message with an RSA PrivateKey and hash method
        """
        import Crypto.Signature.PKCS1_v1_5 as PKCS
        import Crypto.Hash.SHA256 as SHA256
        import Crypto.PublicKey.RSA as RSA

        hashm = SHA256.new()
        hashm.update(msg)
        private_key = RSA.importKey(key)
        return PKCS.sign(hashm, private_key)

    def verify(self, msg, crypto, key):
        """
        Verifies a message using RSA cryptographic signature and key.

        ``crypto`` is the cryptographic signature
        ``key`` is the verifying key. Can be a real key object or a string.
        """
        import Crypto.Signature.PKCS1_v1_5 as PKCS
        import Crypto.Hash.SHA256 as SHA256
        import Crypto.PublicKey.RSA as RSA

        hashm = SHA256.new()
        hashm.update(msg)
        private_key = key
        if not isinstance(key, RSA._RSAobj):
            private_key = RSA.importKey(key)
        if not PKCS.verify(hashm, private_key, crypto):
            raise SignatureError("Could not validate signature")
        return True

class ECDSA(AlgorithmBase):
    """
    Support for ECDSA signing. This is the preferred algorithm for private/public key
    verification.

    The ``ecdsa`` package is required. ``pip install ecdsa``
    """
    bits_to_curve = {
        256: 'NIST256p',
        384: 'NIST384p',
        512: 'NIST521p',
    }
    def sign(self, msg, key):
        """
        Signs a message with an ECDSA SigningKey and hash method matching the
        bit depth of curve algorithm.
        """
        import ecdsa
        ##  assume the signing key is already a real key
        # curve = getattr(ecdsa, self.bits_to_curve[self.bits])
        # signing_key = ecdsa.SigningKey.from_string(key, curve=curve)
        return key.sign(msg, hashfunc=self.hasher)

    def verify(self, msg, crypto, key):
        """
        Verifies a message using ECDSA cryptographic signature and key.

        ``crypto`` is the cryptographic signature
        ``key`` is the verifying key. Can be a real key object or a string.
        """
        import ecdsa
        curve = getattr(ecdsa, self.bits_to_curve[self.bits])
        vk = key
        if not isinstance(vk, ecdsa.VerifyingKey):
            vk = ecdsa.VerifyingKey.from_string(key, curve=curve)
        try:
            vk.verify(crypto, msg, hashfunc=self.hasher)
        except ecdsa.BadSignatureError:
            raise SignatureError("Could not validate signature")
        except AssertionError:
            raise SignatureError("Could not validate signature")
        return True

