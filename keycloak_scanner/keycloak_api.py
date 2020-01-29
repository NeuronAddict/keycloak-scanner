from keycloak_scanner.request import Request


class KeyCloakApi:

    def __init__(self, well_known):
        self.well_known = well_known
        
    def get_token(self, client_id, client_secret, username, password):
        r = Request.request().post(self.well_known['token_endpoint'],
                                  data={
                                      'client_id': client_id,
                                      'username': username,
                                      'password': password,
                                      'grant_type': 'password',
                                      'client_secret': client_secret
                                  })
        r.raise_for_status()
        res = r.json()
        return res['access_token'], res['refresh_token']

    def refresh(self, client, refresh_token):
        data = {'refresh_token': refresh_token, 'grant_type': 'refresh_token', 'client_id': client}
        r = Request.request().post(self.well_known['token_endpoint'], data=data)
        r.raise_for_status()
        res = r.json()
        return res['access_token'], res['refresh_token']