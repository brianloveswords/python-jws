import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "jws",
    version = "0.1.2",
    author = "Brian J Brennan",
    author_email = "brian@nyhacker.org",
    description = ("JSON Web Signatures implementation in Python"),
    license = "MIT",
    keywords = "jws json web security signing",
    url = "http://github.com/brianlovesdata/python-jws",
    packages=['jws'],
    extras_require={
        'rsa': ['pycrypto>=2.6.1, <3.0.0'],
        'ecdsa': ['ecdsa>=0.13.0, <0.14.0'],
    },
    long_description=read('README.rst'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
    ],
)
