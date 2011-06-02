import unittest
import jws 
import ecdsa
import hashlib

class TestJWS_utilities(unittest.TestCase):
    def test_default_algorithm_finding(self):
        names = [('ES256', jws.algos.ECDSA), ('ES384', jws.algos.ECDSA), ('ES512', jws.algos.ECDSA),
                 ('RS256', jws.algos.RSA),   ('RS384', jws.algos.RSA),   ('RS512', jws.algos.RSA),
                 ('HS256', jws.algos.HMAC),  ('HS384', jws.algos.HMAC),  ('HS512', jws.algos.HMAC)]
                
        map(lambda (name, fn): self.assertIn(fn, jws._algorithm_find(name)), names)
    
    def test_bad_algorithm_route(self):
        self.assertRaises(jws.RouteMissingError, jws._algorithm_router, 'f7u12')

    def test_algorithm_resolve(self):
        resolved = jws._algorithm_resolve(*jws._algorithm_find('ES256'))
        self.assertTrue(callable(resolved['sign']))
        self.assertTrue(callable(resolved['verify']))

class TestJWS_ecdsa(unittest.TestCase):
    sk256 = ecdsa.SigningKey.generate(ecdsa.NIST256p)
    # sk384 = ecdsa.SigningKey.generate(ecdsa.NIST384p)
    # sk512 = ecdsa.SigningKey.generate(ecdsa.NIST521p) # yes, 521

    hasher256 = hashlib.sha256
    # hasher384 = hashlib.sha384
    # hasher512 = hashlib.sha512
    
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
        
