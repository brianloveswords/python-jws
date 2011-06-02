import unittest
import jws 
import ecdsa
import hashlib

class TestJWS_ecdsa(unittest.TestCase):
    sk256 = ecdsa.SigningKey.generate(ecdsa.NIST256p)
    sk384 = ecdsa.SigningKey.generate(ecdsa.NIST384p)
    sk512 = ecdsa.SigningKey.generate(ecdsa.NIST521p) # yes, 521

    hasher256 = hashlib.sha256
    hasher384 = hashlib.sha384
    hasher512 = hashlib.sha512
    
    def setUp(self):
        self.payload = {
            'whine': {'luke': 'But I was going into Tosche station to pick up some power converters!'},
            'rebuttal': {'owen': "You can waste time with your friends when you're done with your chores."},
        }
    
    def test_valid_ecdsa256_encode(self):
        header = {'alg': 'ES256'}
        sig = jws.sign(header, self.payload, self.sk256)
        self.assertTrue(len(sig) > 0)
        
        # should not raise exception
        jws.verify(header, self.payload, sig, self.sk256)
        
    def test_invalid_ecdsa256_encode(self):
        pass
        
