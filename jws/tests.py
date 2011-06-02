import unittest
import jws 
import ecdsa
import hashlib

class TestJWS_helpers(unittest.TestCase):
    def test_default_algorithm_finding(self):
        names = [('ES256', jws.algos.ECDSA), ('ES384', jws.algos.ECDSA), ('ES512', jws.algos.ECDSA),
                 ('RS256', jws.algos.RSA),   ('RS384', jws.algos.RSA),   ('RS512', jws.algos.RSA),
                 ('HS256', jws.algos.HMAC),  ('HS384', jws.algos.HMAC),  ('HS512', jws.algos.HMAC)]
                
        map(lambda (name, fn): self.assertIn(fn, jws.algos.find(name)), names)
    
    def test_bad_algorithm_route(self):
        self.assertRaises(jws.algos.RouteMissingError, jws.algos.route, 'f7u12')

    def test_algorithm_resolve(self):
        resolved = jws.algos.resolve(*jws.algos.find('ES256'))
        self.assertTrue(callable(resolved['sign']))
        self.assertTrue(callable(resolved['verify']))

    def test_header_algo_find(self):
        data = {'header': {'alg': 'ES256'}}
        jws.header.process(data, 'sign')
        self.assertIn('signer', data)
        self.assertTrue(callable(data['signer']))
        
        # make sure algo can actually sign
        sk256 = ecdsa.SigningKey.generate(ecdsa.NIST256p)
        found = data['signer']
        self.assertTrue(found('what', sk256))

    def test_header_algo_missing(self):
        header = {'alg': 'f7u12'}
        self.assertRaises(jws.header.AlgorithmNotImplemented, jws.header.process, {'header':header}, 'sign')
    
    def test_header_param_not_implemented(self):
        header = {'something': "i don't understand"}
        self.assertRaises(jws.header.ParameterNotUnderstood, jws.header.process, {'header':header}, 'sign')

    def test_custom_header_handler(self):
        header = {'changekey':'somethingelse'}
        class ChangeKey(jws.header.HeaderBase):
            def sign(self): self.data['key'] = self.value
        jws.header.KNOWN_HEADERS.update({'changekey': ChangeKey})
        data = {'header': header}
        jws.header.process(data, 'sign')
        self.assertEqual(data['key'], 'somethingelse')
        

class TestJWS_ecdsa(unittest.TestCase):
    sk256 = ecdsa.SigningKey.generate(ecdsa.NIST256p)
    sk384 = ecdsa.SigningKey.generate(ecdsa.NIST384p)
    sk512 = ecdsa.SigningKey.generate(ecdsa.NIST521p) # yes, 521
    
    def setUp(self):
        self.payload = {
            'whine': {'luke': 'But I was going into Tosche station to pick up some power converters!'},
            'rebuttal': {'owen': "You can waste time with your friends when you're done with your chores."},
        }
    
    def test_valid_ecdsa256(self):
        key = self.sk256
        header = {'alg': 'ES256'}
        sig = jws.sign(header, self.payload, key)
        self.assertTrue(len(sig) > 0)
        self.assertTrue(jws.verify(header, self.payload, sig, key.get_verifying_key()))
    
    def test_valid_ecdsa384(self):
        key = self.sk384
        header = {'alg': 'ES384'}
        sig = jws.sign(header, self.payload, key)
        self.assertTrue(len(sig) > 0)
        self.assertTrue(jws.verify(header, self.payload, sig, key.get_verifying_key()))
    
    def test_valid_ecdsa512(self):
        key = self.sk512
        header = {'alg': 'ES512'}
        sig = jws.sign(header, self.payload, key)
        self.assertTrue(len(sig) > 0)
        self.assertTrue(jws.verify(header, self.payload, sig, key.get_verifying_key()))
        
    def test_invalid_ecdsa_decode(self):
        header = {'alg': 'ES256'}
        sig = jws.sign(header, self.payload, self.sk256)
        vk = self.sk256.get_verifying_key()
        badkey = self.sk384.get_verifying_key()
        self.assertRaises(jws.algos.SignatureError, jws.verify, header, self.payload, 'not a good sig', vk)
        self.assertRaises(jws.algos.SignatureError, jws.verify, header, {'bad':1}, sig, vk)
        self.assertRaises(jws.algos.SignatureError, jws.verify, header, {'bad':1}, sig, badkey)

        
