from typing import List, Set

from requests import HTTPError

from keycloak_scanner.keycloak_api import KeyCloakApi, FailedAuthException
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scanners.realm_scanner import Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.types import Credential
from keycloak_scanner.scanners.well_known_scanner import WellKnown
from keycloak_scanner.scanners.wrap import WrapperTypes


class LoginScanner(Scanner[Credential]):

    def __init__(self, username: str, password: str, **kwargs):
        self.username = username
        self.password = password
        super().__init__(result_type=WrapperTypes.CREDENTIAL_TYPE,
                         needs=[WrapperTypes.REALM_TYPE, WrapperTypes.CLIENT_TYPE, WrapperTypes.WELL_KNOWN_TYPE],
                         **kwargs)

    def perform(self, realm: Realm, client: Client, well_known: WellKnown, **kwargs) \
            -> (List[Credential], VulnFlag):

        results: Set[Credential] = set()

        # TODO : this condition in weird
        if well_known.realm == realm:

            for grant_type in well_known.allowed_grants():
                self.try_token(client, grant_type, realm, well_known, results)

            self.try_form_auth(client, realm, well_known, results)

        return results, VulnFlag(False)

    def try_form_auth(self, client: Client, realm: Realm, well_known: WellKnown, results: Set[Credential]):

        kapi = KeyCloakApi(well_known.json, verbose=super().is_verbose(),
                           session_provider=super().session)
        try:
            r = kapi.auth(client, self.username, self.password)

            if r.status_code == 302:
                results.add(Credential(realm, client, self.username, self.password))

                super().find(self.name(), f'Form login work for {self.username} on realm {realm.name}, '
                                          f'client {client.name}, ({r.headers.get("Location", "<unable to get header>")})')
        except HTTPError as e:
            super().verbose(f'HTTP error when login : {e}')
        except FailedAuthException as e:
            super().verbose(f'auth process fail : {e}')

    def try_token(self, client: Client, grant_type: str, realm: Realm, well_known: WellKnown, results: Set[Credential]):

        kapi = KeyCloakApi(well_known.json, verbose=super().is_verbose(),
                           session_provider=super().session)

        # TODO : get client secret
        try:

            access_token, refresh_token = kapi.get_token(client.name, '', self.username, self.password,
                                                         grant_type=grant_type)

            super().find(self.name(), f'Can login with username {self.username} on realm {realm.name}, '
                                      f'client {client.name}, grant_type: {grant_type}')
            super().verbose(f'access_token: {access_token}, refresh_token: {refresh_token}, '
                            f'password: {self.password}')

            results.add(Credential(realm, client, self.username, self.password))

        except HTTPError as e:
            super().verbose(f'HTTP error when login : {e}')
