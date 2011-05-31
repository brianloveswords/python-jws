import base64

def base64url_decode(input):
    input += '=' * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input)

def base64url_encode(input):
    return base64.urlsafe_b64encode(input).replace('=', '')
