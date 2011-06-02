import utils

# local 
import algos
import header
import router

class MissingKey(Exception): pass
##############
# public api #
##############
def sign(head, payload, key=None):
    results = header.process(head, 'sign')
    signer = results['alg']
    return signer(_signing_input(head, payload), key)
    

def verify(head, payload, signature, key=None):
    results = header.process(head, 'verify')
    if not key:
        if 'jku' in results:
            key = results['jku']
        elif 'x5u' in results:
            key = results['x5u']
        else:
            raise MissingKey("Key was not passed as a param and a key could not be found from the header")
    
    verifier = results['alg']
    return verifier(_signing_input(head, payload), signature, key)
    
####################
# semi-private api #
####################
def _signing_input(head, payload):
    head_input, payload_input = map(utils.encode, [head, payload])
    return "%s.%s" % (head_input, payload_input)

