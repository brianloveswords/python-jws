import unittest
import time
from jwt import jws, utils
import jwt

class TestJWT(unittest.TestCase):

    def setUp(self):
        self.payload = {"iss": "jeff", "exp": int(time.time()), "claim": "insanity"}

    def test_encode_decode(self):
        secret = 'secret'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)
    
    def test_bad_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        self.assertRaises(jwt.DecodeError, jwt.decode, jwt_message, bad_secret)
    
    def test_decodes_valid_jwt(self):
        example_payload = {"hello": "world"}
        example_secret = "secret"
        example_jwt = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        decoded_payload = jwt.decode(example_jwt, example_secret)
        self.assertEqual(decoded_payload, example_payload)
    
    def test_allow_skip_verification(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        decoded_payload = jwt.decode(jwt_message, verify=False)
        self.assertEqual(decoded_payload, self.payload)
    
    def test_no_secret(self):
        right_secret = 'foo'
        bad_secret = 'bar'
        jwt_message = jwt.encode(self.payload, right_secret)
        self.assertRaises(jwt.DecodeError, jwt.decode, jwt_message)
    
    def test_invalid_crypto_alg(self):
        self.assertRaises(NotImplementedError, jwt.encode, self.payload, "secret", "HS1024")
    
    def test_unicode_secret(self):
        secret = u'\xc2'
        jwt_message = jwt.encode(self.payload, secret)
        decoded_payload = jwt.decode(jwt_message, secret)
        self.assertEqual(decoded_payload, self.payload)

class TestJWS(unittest.TestCase):
    # STEPS TO CREATE:
    # 1. Create the payload content to be encoded as the
    #    Decoded JWS Payload Input
    # 2. base64url encode the Decoded JWS Payload Input. This encoding becomes
    #    the JWS Payload Input
    # 3. Create a JSON object containing set of desired header params.
    # 4. Translate this JSON object's Unicode code points into UTF-8
    # 5. base64url encode the UTF-8 repr. of this JSON object without padding.
    #    This becomes JWS Header Input.
    # 6. Compute the JWS Crypto Output using algo. from header.
    #    JWS Signing Input is: ({JWS Header Input}.{JWS Payload Input})
    def setUp(self):
        self.payload = {'arbitrary': 'data', 'anything': 'at-all'}
    
    def test_validate_header(self):
        valid_header = {'alg': 'HS512'}
        u_valid_header = {u'\u0061lg': 'ES384'}
        invalid_header = {'missing_alg': True}
        invalid_algo_header = {'alg': 'ROT13'}

        self.assertRaises(jws.InvalidHeaderError, jws.validate_header, invalid_header)
        self.assertRaises(jws.InvalidHeaderError, jws.validate_header, invalid_algo_header)
        
        # should not raise exceptions
        jws.validate_header(valid_header)
        jws.validate_header(u_valid_header)
        
                         
    def test_sign_with_hmac(self):
        header = {'alg': 'HS256'}
        crypto_output = jws.sign(header, self.payload, 'suprsecret')
         
        header_input = utils.encode(header)
        payload_input = utils.encode(self.payload)
        
        bad_header = utils.encode({'alg':'HS512'})
        bad_payload = utils.encode({'droids':'looking for other ones'})
        bad_crypto = jws.sign(header, bad_payload, 'suprsecret')
        
        # invalid key
        self.assertRaises(jws.SignatureError, jws.verify, header_input, payload_input, crypto_output, 'notsecret')
        # bad header
        self.assertRaises(jws.SignatureError, jws.verify, bad_header, payload_input, crypto_output, 'suprsecret')
        # invalid payload
        self.assertRaises(jws.SignatureError, jws.verify, header_input, bad_payload, crypto_output, 'suprsecret')
        # invalid crypto
        self.assertRaises(jws.SignatureError, jws.verify, header_input, payload_input, bad_crypto, 'suprsecret')
        
        # valid, shouldn't raise anything
        try: 
            jws.verify(header_input, payload_input, crypto_output, 'suprsecret')
        except jws.SignatureError, e:
            self.assertTrue(False, "Valid signature should not raise SignatureError")
    
    
    def test_sign_with_rsa(self):
        header = {'alg': 'RS256'}
        jws.validate_header(header)
        pass
    
    def test_sign_with_ecdsa(self):
        header = {'alg': 'ES384'}
        jws.validate_header(header)
        pass
    
    # STEPS TO VALIDATE:
    # 1. The JWS Payload Input MUST be successfully base64url decoded
    # 2. The JWS Header Input MUST be successfully base64url decoded
    # 3. The Decoded JWS Header Input MUST be completely valid JSON
    # 4. The JWS Crypto Output MUST be successfully base64url decoded
    # 5. The JWS Header Input MUST be validated to only include params and
    #    values whose syntax and semantics are both understood and supported
    # 6. The JWS Crypto Output MUST be successfully validated against the
    #    JWS Header Input and JWS Payload Input in the manner defined for the
    #    algo being used which MUST be accurately represented by the value of
    #    the `alg` header parameter which MUST be present.
    pass

if __name__ == '__main__':
    unittest.main()
