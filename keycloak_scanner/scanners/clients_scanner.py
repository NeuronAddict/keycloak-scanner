from typing import List

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.realm_scanner import Realms
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need2
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict

URL_PATTERN = '{}/auth/realms/{}/{}'


class Client:

    def __init__(self, name: str, url: str, auth_endpoint: str = None):
        self.name = name
        self.url = url
        self.auth_endpoint = auth_endpoint

    def __repr__(self):
        return f"Client('{self.name}', '{self.url}', '{self.auth_endpoint}')"

    def __eq__(self, other):
        if isinstance(other, Client):
            return self.name == other.name and self.url == other.url and self.auth_endpoint == other.auth_endpoint
        return NotImplemented


class Clients(List[Client]):
    pass


class ClientScanner(Need2[Realms, WellKnownDict], Scanner[Clients]):

    def __init__(self, clients: List[str], **kwargs):
        self.clients = clients
        super().__init__(**kwargs)

    def perform(self, realms: Realms, well_known_dict: WellKnownDict, **kwargs) -> (Clients, VulnFlag):

        result: Clients = Clients()

        for realm in realms:
            for client_name in self.clients:
                url = URL_PATTERN.format(super().base_url(), realm.name, client_name)

                try:
                    r = super().session().get(url)
                    r.raise_for_status()

                except Exception as e:
                    super().info('f [ClientScanner]: {e}')
                    url = None

                try:

                    auth_url = well_known_dict[realm.name].json['authorization_endpoint']

                    r = super().session().get(auth_url, params={'client_id': client_name}, allow_redirects=False)
                    if r.status_code == 302:
                        super().info('Find a client for realm {}: {}'.format(realm.name, client_name))
                        result.append(Client(name=client_name, url=url, auth_endpoint=auth_url))
                    else:
                        super().verbose('client {} seems to not exists'.format(client_name))

                except KeyError as e:
                    print(f'realm {realm.name}\'s wellknown doesn\t existsor do not have "authorization_endpoint". ({well_known_dict})')
                    auth_url = None

                result.append(Client(name=client_name, auth_endpoint=auth_url, url=url))

        return result, VulnFlag(False)
