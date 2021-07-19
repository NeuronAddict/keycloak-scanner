from typing import Set

from requests import HTTPError

from keycloak_scanner.keycloak_api import KeyCloakApi, FailedAuthException
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.clients_scanner import Client
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import Credential, WellKnown, Realm, Username, Password
from keycloak_scanner.scan_base.wrap import WrapperTypes


class LoginScanner(Scanner[Credential]):

    def __init__(self, **kwargs):
        super().__init__(result_type=WrapperTypes.CREDENTIAL_TYPE,
                         needs=[WrapperTypes.USERNAME_TYPE, WrapperTypes.PASSWORD_TYPE,
                                WrapperTypes.REALM_TYPE, WrapperTypes.CLIENT_TYPE],
                         **kwargs)

    def perform(self, username: Username, password: Password, realm: Realm, client: Client, **kwargs) \
            -> (Set[Credential], VulnFlag):

        results: Set[Credential] = set()

        well_known = realm.get_well_known(super().base_url(), super().session())

        for grant_type in well_known.allowed_grants():
            self.try_token(client, grant_type, realm, well_known, results, username, password)

        self.try_form_auth(client, realm, well_known, results, username, password)

        return results, VulnFlag(False)

    def try_form_auth(self, client: Client, realm: Realm, well_known: WellKnown, results: Set[Credential],
                      username: Username, password: Password):

        kapi = KeyCloakApi(well_known.json, verbose=super().is_verbose(),
                           session_provider=super().session)
        try:
            r = kapi.auth(client, username, password)

            if r.status_code == 302:
                results.add(Credential(realm, client, username, password))

                super().find(self.name(), f'Form login work for {username} on realm {realm.name}, '
                                          f'client {client.name}, ({r.headers.get("Location", "<unable to get header>")})')
        except HTTPError as e:
            super().verbose(f'HTTP error when login : {e}')
        except FailedAuthException as e:
            super().verbose(f'auth process fail : {e}')

    def try_token(self, client: Client, grant_type: str, realm: Realm, well_known: WellKnown, results: Set[Credential],
                  username: Username, password: Password):

        kapi = KeyCloakApi(well_known.json, verbose=super().is_verbose(),
                           session_provider=super().session)

        # TODO : get client secret
        try:

            access_token, refresh_token = kapi.get_token(client.name, '', username, password,
                                                         grant_type=grant_type)

            super().find(self.name(), f'Can login with username {username} on realm {realm.name}, '
                                      f'client {client.name}, grant_type: {grant_type}')
            super().verbose(f'access_token: {access_token}, refresh_token: {refresh_token}, '
                            f'password: {password}')

            results.add(Credential(realm, client, username, password))

        except HTTPError as e:
            super().verbose(f'HTTP error when login : {e}')
