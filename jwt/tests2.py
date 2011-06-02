import unittest
import jws 
import ecdsa
import hashlib

class TestJWS_utilities(unittest.TestCase):
    def test_default_algorithm_finding(self):
        names = [('ES256', jws._ecdsa), ('ES384', jws._ecdsa), ('ES512', jws._ecdsa),
                 ('RS256', jws._rsa),   ('RS384', jws._rsa),   ('RS512', jws._rsa),
                 ('HS256', jws._hmac),  ('HS384', jws._hmac),  ('HS512', jws._hmac),]
        map(lambda (name, fn): self.assertIn(fn, jws._algorithm_find(name)), names)
    
    def test_bad_algorithm_route(self):
        self.assertRaises(jws.RouteError, jws._algorithm_router, 'f7u12')


# class TestJWS_ecdsa(unittest.TestCase):
#     sk256 = ecdsa.SigningKey.generate(ecdsa.NIST256p)
#     sk384 = ecdsa.SigningKey.generate(ecdsa.NIST384p)
#     sk512 = ecdsa.SigningKey.generate(ecdsa.NIST521p) # yes, 521

#     hasher256 = hashlib.sha256
#     hasher384 = hashlib.sha384
#     hasher512 = hashlib.sha512
    
#     def setUp(self):
#         self.payload = {
#             'whine': {'luke': 'But I was going into Tosche station to pick up some power converters!'},
#             'rebuttal': {'owen': "You can waste time with your friends when you're done with your chores."},
#         }
    
#     def test_valid_ecdsa256_encode(self):
#         header = {'alg': 'ES256'}
#         sig = jws.sign(header, self.payload, self.sk256)
#         self.assertTrue(len(sig) > 0)
        
#         # should not raise exception
#         jws.verify(header, self.payload, sig, self.sk256)
        
#     def test_invalid_ecdsa256_encode(self):
#         pass
        
