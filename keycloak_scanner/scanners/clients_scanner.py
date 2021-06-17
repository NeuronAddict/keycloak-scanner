from typing import List

from requests import HTTPError

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.types import Realm, WellKnown, clientType, Client, ClientConfig


class ClientScanner(Scanner[Client]):

    def __init__(self, clients: List[str], **kwargs):
        self.clients = clients
        super().__init__(result_type=clientType, **kwargs)

    def has_endpoint(self, realm: Realm, client_name: str) -> str:
        url = f'{super().base_url()}/auth/realms/{realm.name}/{client_name}'

        try:
            r = super().session().get(url)
            r.raise_for_status()
            super().info('Find a client for realm {}: {}'.format(realm.name, client_name))
            return url
        except Exception as e:
            super().info(f'[ClientScanner]: {e}')

    def perform(self, realm: Realm, well_known: WellKnown, **kwargs) -> (List[Client], VulnFlag):

        result: List[Client] = []

        for client_name in self.clients:

            url = self.has_endpoint(realm, client_name)

            # TODO: auth endpoint in other scanner ?
            auth_url = self.has_auth_endpoint(client_name, realm, well_known)

            registration = self.get_registration(client_name, realm)

            if auth_url is not None or url is not None or registration is not None:
                result.append(Client(name=client_name, auth_endpoint=auth_url, url=url, client_registration=registration))

        return result, VulnFlag(False)

    def get_registration(self, client_name, realm: Realm) -> ClientConfig:
        url = f'{super().base_url()}/realms/{realm.name}/clients-registrations/default/{client_name}'

        try:
            r = super().session().get(url)
            r.raise_for_status()
            if r.status_code == 200:
                return ClientConfig(client_name, url, r.json())
        except HTTPError as e:
            super().verbose(str(e))
        except ValueError as e:
            super().warn(f'{url} is not json but status is 200. It\'s weird. {e}')

    def has_auth_endpoint(self, client_name: str, realm: Realm, well_known: WellKnown) -> str:
        try:

            auth_url = well_known.json['authorization_endpoint']

            r = super().session().get(auth_url, params={'client_id': client_name}, allow_redirects=False)
            # TODO : is code 400 always an existing client ?
            if r.status_code == 302 or r.status_code == 400:
                super().info('Find a client auth endpoint for realm {}: {}'.format(realm.name, client_name))
            else:
                auth_url = None

        except KeyError as e:
            print(
                f'realm {realm.name}\'s wellknown doesn\'t exists or do not have "authorization_endpoint". ({well_known})')
            print(e)
            auth_url = None
        return auth_url
