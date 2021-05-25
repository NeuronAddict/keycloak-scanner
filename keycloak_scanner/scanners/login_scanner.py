from typing import Dict

import requests
from requests import HTTPError

from keycloak_scanner.keycloak_api import KeyCloakApi, FailedAuthException
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.clients_scanner import Clients, Client
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need3
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict


class Credential:

    def __init__(self, realm: Realm, client: Client, username: str, password: str):
        self.realm = realm
        self.client = client
        self.username = username
        self.password = password

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.realm)}, {repr(self.client)}, {repr(self.username)}, {repr(self.password)})"

    def __eq__(self, other):
        if isinstance(other, Credential):
            return self.realm == other.realm and self.client == other.client and self.username == other.username \
                   and self.password == other.password
        return NotImplemented


class CredentialDict(Dict[str, Credential]):
    pass


class LoginScanner(Need3[Realms, Clients, WellKnownDict], Scanner[CredentialDict]):

    def __init__(self, username: str, password: str, **kwargs):
        self.username = username
        self.password = password
        super().__init__(**kwargs)

    def perform(self, realms: Realms, clients: Clients, well_known_dict: WellKnownDict, **kwargs) \
            -> (CredentialDict, VulnFlag):

        results = CredentialDict()

        for realm in realms:

            for client in clients:

                well_known = well_known_dict[realm.name]

                for grant_type in well_known.allowed_grants():
                    self.try_token(client, grant_type, realm, results, well_known)

                self.try_form_auth(client, realm, results, well_known)

        return results, VulnFlag(False)

    def try_form_auth(self, client, realm, results, well_known):

        kapi = KeyCloakApi(well_known.json, verbose=super().is_verbose(),
                           session_provider=super().session)
        try:
            r = kapi.auth(client, self.username, self.password)

            if r.status_code == 302:
                results[f'{realm.name}-{client.name}'] = Credential(realm, client, self.username, self.password)

                super().find(self.name(), f'Form login work for {self.username} on realm {realm.name}, '
                                          f'client {client.name}, ({r.headers.get("Location", "<unable to get header>")})')
        except HTTPError as e:
            super().verbose(f'HTTP error when login : {e}')
        except FailedAuthException as e:
            super().verbose(f'auth process fail : {e}')

    def try_token(self, client, grant_type, realm, results, well_known):

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

            results[f'{realm.name}-{client.name}'] = Credential(realm, client, self.username, self.password)

        except HTTPError as e:
            super().verbose(f'HTTP error when login : {e}')
