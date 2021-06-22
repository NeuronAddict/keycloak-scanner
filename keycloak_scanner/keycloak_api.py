from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scan_base.session_holder import SessionHolder
from keycloak_scanner.scan_base.types import Client


class FailedAuthException(Exception):
    pass


class KeyCloakApi(PrintLogger, SessionHolder):

    def __init__(self, well_known: dict, **kwargs):
        self.well_known = well_known
        super().__init__(**kwargs)

    def get_token(self, client_id: str, client_secret: str, username: str, password: str, grant_type='password'):
        r = super().session().post(self.well_known['token_endpoint'],
                              data={
                                  'client_id': client_id,
                                  'username': username,
                                  'password': password,
                                  'grant_type': grant_type,
                                  'client_secret': client_secret
                              })

        super().verbose(r.text)
        r.raise_for_status()
        res = r.json()
        return res['access_token'], res['refresh_token']

    def refresh(self, client, refresh_token):

        data = {'refresh_token': refresh_token, 'grant_type': 'refresh_token', 'client_id': client}
        r = super().session().post(self.well_known['token_endpoint'], data=data)
        r.raise_for_status()
        res = r.json()
        return res['access_token'], res['refresh_token']

    def auth(self, client: Client, username: str, password: str, redirect_uri: str = None, auth_headers=None) -> requests.Response:

        if auth_headers is None:
            auth_headers = {}
        session = super().session()

        url = self.well_known['authorization_endpoint']

        params = {'response_type': 'code',
                  'client_id': client.name,
                  'code_challenge_method': 'S256',
                  'code_challenge': 'W59JjmjRrRjxwZVd1SZW-zfqGilWDldy2gUAMPX8EuE',
                  'redirect_uri': redirect_uri
                  }

        r = session.get(url, params=params) # TODO : add custom headers

        r.raise_for_status()

        soup = BeautifulSoup(r.text, 'html.parser')

        try:
            link = soup.find('form').attrs['action']
            o = urlparse(link)
            q = parse_qs(o.query)

            auth_params = {'client_id': client.name}

            for param in ['session_code', 'execution', 'tab_id']:
                if param in q:
                    auth_params[param] = q[param]

            auth_data = {"username": username, "password": password}

            return session.post(link, headers=auth_headers, data=auth_data, params=auth_params, allow_redirects=False)

        except Exception as e:
            raise FailedAuthException(e)

