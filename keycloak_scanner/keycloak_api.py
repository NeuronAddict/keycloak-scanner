from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scanners.session_holder import SessionHolder


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

    def auth(self, client: Client, username: str, password: str, redirect_uri: str = None) -> requests.Response:

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
        link = soup.find('form').attrs['action']
        o = urlparse(link)
        q = parse_qs(o.query)

        auth_params = {'session_code': q['session_code'],
                       'execution': q['execution'],
                       'client_id': client.name,
                       'tab_id': q['tab_id']
                       }

        auth_headers = {"Connection": "close", "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                        "Origin": url,
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                        "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                        "Sec-Fetch-Dest": "document",
                        "Referer": url,
                        "Accept-Encoding": "gzip, deflate", "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"}

        auth_data = {"username": username, "password": password}

        return session.post(link, headers=auth_headers, data=auth_data, params=auth_params, allow_redirects=False)

        # if r.status_code == 302:
        #     redirect = r.headers['Location']
        #     if redirect_uri in redirect:
        #         print(f'[+] find login for user {username}')
        #         return Result.SUCCESS
        #     else:
        #         print(f'[?] unconfirmed login for username {username} ({redirect})')
        #         return Result.UNCONFIRMED
        # else:
        #     if r.status_code == 200:
        #         return Result.INVALID_CREDENTIALS
        #     else:
        #         print(f'[-] Got error for username {username}. HTTP status: {r.status_code}')
        #         return Result.ERROR