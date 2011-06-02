python-jws
=====
A Python implementation of [JSON Web Signatures draft 02](http://self-issued.info/docs/draft-jones-json-web-signature.html)

Installing
----------
    $ git://github.com/brianlovesdata/python-jws.git
    $ python setup.py install



Algorithms
---------- 
The JWS spec reserves several algorithms for cryptographic signing. Out of the 9, this library currently supports 7:

* HS256 – HMAC using SHA-256 hash algorithm
* HS384 – HMAC using SHA-384 hash algorithm
* HS512 – HMAC using SHA-512 hash algorithm
* RS256 – RSA using SHA-256 hash algorithm
* ES256 – ECDSA using P-256 curve and SHA-256 hash algorithm
* ES384 – ECDSA using P-384 curve and SHA-384 hash algorithm
* ES512 – ECDSA using P-521 curve and SHA-512 hash algorithm

There is also a mechanism for extending functionality by adding your own
algorithms without cracking open the whole codebase. See the advanced usage
section for an example.

Usage
-----
Let's check out some examples.    
    
    >>> import jws
    >>> header  = { 'alg': 'HS256' }
    >>> payload = { 'claim': 'JSON is the raddest.', 'iss': 'brianb' }
    >>> signature = jws.sign(header, payload, 'secret')
    >>> jws.verify(header, payload, signature, 'secret')
    True
    >>> jws.verify(header, payload, signature, 'badbadbad')
    Traceback (most recent call last):
    ...
    jws.exceptions.SignatureError: Could not validate signature    

Now with a real key!
    
    >>> import ecdsa
    >>> sk256 = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
    >>> vk = sk256.get_verifying_key()
    >>> header = { 'alg': 'ES256' }
    >>> sig = jws.sign(header, payload, sk256)
    >>> jws.verify(header, payload, sig, vk)
    True

Advanced Usage
--------------
Make this file    
    
    # file: sillycrypto.py
    import jws
    from jws.algos import AlgorithmBase, SignatureError
    class FXUY(AlgorithmBase):
        def __init__(self, x, y):
            self.x = int(x)
            self.y = int(y)
        def sign(self, msg, key):
            return 'verysecure' * self.x + key * self.y

        def verify(self, msg, sig, key):
            if sig != self.sign(msg, key):
                raise SignatureError('nope')
            return True

    jws.algos.CUSTOM = [
        (r'^F(?P<x>\d)U(?P<y>\d{2})$',  FXUY),
    ]

And in an interpreter:
    
    >>> import jws
    >>> header = { 'alg': 'F7U12' }
    >>> payload = { 'claim': 'wutt' }
    >>> sig = jws.sign(header, payload, '<trollface>')
    Traceback (most recent call last):
      ....
    jws.exceptions.AlgorithmNotImplemented: "F7U12" not implemented.
    >>> 
    >>> import sillycrypto
    >>> sig = jws.sign(header, payload, '<trollface>')
    >>> jws.verify(header, payload, sig, '<trollface>')
    True
    >>> jws.verify(header, payload, sig, 'y u no verify?')
    Traceback (most recent call last):
    ....
    jws.exceptions.SignatureError: nope


Other Stuff
---------

Check out
https://github.com/brianlovesdata/python-jws/blob/master/examples/minijwt.py
for a 14-line implemention of JWT.

Tests
-----

use nosetests

License
-------

MIT
