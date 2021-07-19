from typing import List, Set

from requests import HTTPError

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import Realm, Client, ClientConfig
from keycloak_scanner.scan_base.wrap import WrapperTypes


class ClientScanner(Scanner[Client]):

    def __init__(self, clients: List[str], **kwargs):
        self.clients = clients
        super().__init__(result_type=WrapperTypes.CLIENT_TYPE, needs=[WrapperTypes.REALM_TYPE], **kwargs)

    def has_endpoint(self, realm: Realm, client_name: str) -> str:
        url = f'{super().base_url()}/auth/realms/{realm.name}/{client_name}'

        try:
            r = super().session().get(url)
            r.raise_for_status()
            super().info('Find a client for realm {}: {}'.format(realm.name, client_name))
            return url
        except Exception as e:
            super().info(f'[ClientScanner]: {e}')

    def perform(self, realm: Realm, **kwargs) -> (Set[Client], VulnFlag):

        result: Set[Client] = set()

        for client_name in self.clients:

            url = self.has_endpoint(realm, client_name)

            registration = self.get_registration(client_name, realm)

            if url is not None or registration is not None or self.has_auth_endpoint(client_name, realm):
                result.add(Client(name=client_name, url=url, client_registration=registration))

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


    def has_auth_endpoint(self, client_name: str, realm: Realm) -> bool:
        try:

            well_known = realm.get_well_known(self.base_url(), self.session())
            url = well_known.json['authorization_endpoint']
            r = super().session().get(url,
                                      params={'client_id': client_name}, allow_redirects=False)

            # TODO : is code 400 always an existing client ?
            if r.status_code == 302 or r.status_code == 400:
                super().find(self.name(), f'Find a client auth endpoint for realm {realm.name} and client {client_name}: {url}')
                return True

        except KeyError as e:
            print(
                f'realm {realm.name}\'s wellknown doesn\'t exists or do not have "authorization_endpoint".')
            print(e)
        return False