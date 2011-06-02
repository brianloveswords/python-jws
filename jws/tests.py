import unittest
import jws 
import ecdsa
import hashlib

class TestJWS_helpers(unittest.TestCase):
    def test_default_algorithm_finding(self):
        names = [('ES256', jws.algos.ECDSA), ('ES384', jws.algos.ECDSA), ('ES512', jws.algos.ECDSA),
                 ('RS256', jws.algos.RSA),   ('RS384', jws.algos.RSA),   ('RS512', jws.algos.RSA),
                 ('HS256', jws.algos.HMAC),  ('HS384', jws.algos.HMAC),  ('HS512', jws.algos.HMAC)]
                
        map(lambda (name, fn): self.assertIn(fn, jws.router.find(name)), names)
    
    def test_bad_algorithm_route(self):
        self.assertRaises(jws.router.RouteMissingError, jws.router.route, 'f7u12')

    def test_algorithm_resolve(self):
        resolved = jws.router.resolve(*jws.router.find('ES256'))
        self.assertTrue(callable(resolved['sign']))
        self.assertTrue(callable(resolved['verify']))

    def test_header_algo_find(self):
        header = {'alg': 'ES256'}
        processed = jws.header.process(header, 'sign')
        self.assertIn('alg', processed)
        self.assertTrue(callable(processed['alg']))
        
        # make sure algo can actually sign
        sk256 = ecdsa.SigningKey.generate(ecdsa.NIST256p)
        found = processed['alg']
        self.assertTrue(found('what', sk256))

    def test_header_algo_missing(self):
        header = {'alg': 'f7u12'}
        self.assertRaises(jws.header.AlgorithmNotImplemented, jws.header.process, header, 'sign')
    
    def test_header_param_not_implemented(self):
        header = {'something': "i don't understand"}
        self.assertRaises(jws.header.ParameterNotUnderstood, jws.header.process, header, 'sign')


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
        jws.verify(header, self.payload, sig, self.sk256.get_verifying_key())
        
    def test_invalid_ecdsa256_encode(self):
        pass
        
