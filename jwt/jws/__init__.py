import utils

# local 
import algos
import header
import router

##############
# public api #
##############
def sign(head, payload, algos=None):
    print header.DEFAULT_HEADER_ACTIONS

def verify(head, payload, signature, algos=None):
    print header.DEFAULT_HEADER_ACTIONS

####################
# semi-private api #
####################
# header stuff

def _signing_input(header, payload):
    """
    Generates the signing input by json + base64url encoding the header
    and the payload, then concatenating the results with a '.' character.
    """
    header_input, payload_input = map(utils.encode, [header, payload])
    return "%s.%s" % (header_input, payload_input)

