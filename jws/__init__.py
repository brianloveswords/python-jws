import utils

# local 
import algos
import header
import router

class MissingKey(Exception): pass
class MissingSigner(Exception): pass
class MissingVerifier(Exception): pass
##############
# public api #
##############
def sign(head, payload, key=None):
    data = {
        'key': key,
        'header': head,
        'payload': payload,
        'signer': None
    }
    # TODO: re-evaluate whether to pass ``data`` by reference, or to copy and reassign
    header.process(data, 'sign')
    if not data['key']:
        raise MissingKey("Key was not passed as a param and a key could not be found from the header")
    if not data['signer']:
        raise MissingSigner("Header was processed, but no algorithm was found to sign the message")
    signer = data['signer']
    return signer(_signing_input(head, payload), key)
    

def verify(head, payload, signature, key=None):
    data = {
        'key': key,
        'header': head,
        'payload': payload,
        'verifier': None
    }
    # TODO: re-evaluate whether to pass ``data`` by reference, or to copy and reassign
    header.process(data, 'verify')
    if not data['key']:
        raise MissingKey("Key was not passed as a param and a key could not be found from the header")
    if not data['verifier']:
        raise MissingVerifier("Header was processed, but no algorithm was found to sign the message")
    verifier = data['verifier']
    return verifier(_signing_input(head, payload), signature, key)
    
####################
# semi-private api #
####################
def _signing_input(head, payload):
    head_input, payload_input = map(utils.encode, [head, payload])
    return "%s.%s" % (head_input, payload_input)

