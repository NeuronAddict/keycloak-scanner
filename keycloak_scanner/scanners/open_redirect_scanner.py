from typing import Dict

from keycloak_scanner.custom_logging import find
from keycloak_scanner.scanners.clients_scanner import Clients
from keycloak_scanner.scanners.realm_scanner import Realms
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need3
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict

URL_PATTERN = '{}/auth/realms/{}/{}'


class OpenRedirect:

    def __init__(self):
        self.results: Dict[str, bool] = {}

    def find(self, realm: str, value: bool):
        self.results[realm] = value


class OpenRedirectScanner(Need3[WellKnownDict, Realms, Clients], Scanner[OpenRedirect]):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, well_known_dict: WellKnownDict, realms: Realms, clients: Clients, **kwargs) -> OpenRedirect:

        ret = OpenRedirect()

        for realm in realms:
            if 'code' not in well_known_dict[realm.name].json['response_types_supported']:
                super().verbose(f'code not in supported response types, can\' test redirect_uri for realm {realm.name}')
            else:
                url = well_known_dict[realm.name].json['authorization_endpoint']

                for client in clients:

                    r = super().session().get(url, params={
                        'response_type': 'code',
                        'client_id': client,
                        'redirect_uri': f'https://devops-devsecops.org/auth/{realm.name}/{client.name}/'
                    })

                    if r.status_code == 200:
                        find('OpenRedirection', f'Open redirection for realm {realm.name} and clientid {client.name}')
                        ret.find(f'{realm.name}-{client.name}', True)
                    else:
                        ret.find(f'{realm.name}-{client.name}', False)

        return ret
