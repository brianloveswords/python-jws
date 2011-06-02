python-jws
=====
A Python implementation of [JSON Web Signatures draft 02](http://self-issued.info/docs/draft-jones-json-web-signature.html)

Installing
----------
dunno.

Usage
-----

this will be rather long

Algorithms
----------

The JWS spec supports several algorithms for cryptographic signing. This library currently supports:

* HS256 – HMAC using SHA-256 hash algorithm
* HS384 – HMAC using SHA-384 hash algorithm
* HS512 – HMAC using SHA-512 hash algorithm
* RS256 – RSA using SHA-256 hash algorithm
* ES256 – ECDSA using P-256 curve and SHA-256 hash algorithm
* ES384 – ECDSA using P-384 curve and SHA-384 hash algorithm
* ES512 – ECDSA using P-521 curve and SHA-512 hash algorithm

Tests
-----

use nosetests

License
-------

MIT
