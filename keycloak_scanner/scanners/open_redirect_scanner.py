from typing import List, Dict

from keycloak_scanner.custom_logging import find
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need, Need3

URL_PATTERN = '{}/auth/realms/{}/{}'


class WellKnown:

    def __init__(self, json: dict):
        self.json = json

    def __getitem__(self, key) -> dict:
        return self.json[key]


Realms = List[str]

Clients = List[str]


class OpenRedirect:

    def __init__(self):
        self.results: Dict[str, bool] = {}

    def find(self, realm: str, value: bool):
        self.results[realm] = value


class OpenRedirectScanner(Need3[WellKnown, Realms, Clients], Scanner[OpenRedirect]):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, well_known: WellKnown, realms: Realms, clients: Clients, **kwargs) -> OpenRedirect:

        ret = OpenRedirect()

        for realm in realms:
            if 'code' not in well_known['response_types_supported']:
                super().verbose('code not in supported response types, can\' test redirect_uri for realm {}'.format(realm))
            else:
                url = well_known['authorization_endpoint']

                for client in clients:

                    r = super().session().get(url, params={
                        'response_type': 'code',
                        'client_id': client,
                        'redirect_uri': 'https://devops-devsecops.org/auth/{}/{}/'.format(realm, client)
                    })

                    if r.status_code == 200:
                        find('OpenRedirection', 'Open redirection for realm {} and clientid {}'.format(realm, client))
                        ret.find(f'{realm}-{client}', True)
                    else:
                        ret.find(f'{realm}-{client}', False)

        return ret
