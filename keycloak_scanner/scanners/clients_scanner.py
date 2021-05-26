from typing import List

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need2
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict




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

    def has_endpoint(self, realm: Realm, client_name: str) -> str:
        url = f'{super().base_url()}/auth/realms/{realm.name}/{client_name}'

        try:
            r = super().session().get(url)
            r.raise_for_status()
            super().info('Find a client for realm {}: {}'.format(realm.name, client_name))
            return url
        except Exception as e:
            super().info(f'[ClientScanner]: {e}')


    def perform(self, realms: Realms, well_known_dict: WellKnownDict, **kwargs) -> (Clients, VulnFlag):

        result: Clients = Clients()

        for realm in realms:
            for client_name in self.clients:

                url = self.has_endpoint(realm, client_name)

                # TODO: auth endpoint in other scanner ?
                auth_url = self.has_auth_endpoint(client_name, realm, well_known_dict)

                if auth_url is not None or url is not None:
                    result.append(Client(name=client_name, auth_endpoint=auth_url, url=url))

        return result, VulnFlag(False)

    def has_auth_endpoint(self, client_name, realm, well_known_dict) -> str:
        try:

            auth_url = well_known_dict[realm.name].json['authorization_endpoint']

            r = super().session().get(auth_url, params={'client_id': client_name}, allow_redirects=False)
            # TODO : is code 400 always an existing client ?
            if r.status_code == 302 or r.status_code == 400:
                super().info('Find a client auth endpoint for realm {}: {}'.format(realm.name, client_name))
            else:
                auth_url = None

        except KeyError as e:
            print(
                f'realm {realm.name}\'s wellknown doesn\'t exists or do not have "authorization_endpoint". ({well_known_dict})')
            print(e)
            auth_url = None
        return auth_url
