from typing import Dict

import requests
from requests import HTTPError

from keycloak_scanner.keycloak_api import KeyCloakApi
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

    def perform(self, realms: Realms, clients: Clients, well_known_dict: WellKnownDict, **kwargs) -> CredentialDict:

        results = CredentialDict()

        for realm in realms:

            for client in clients:

                session = super().session()
                kapi = KeyCloakApi(session, well_known_dict[realm.name].json)

                # TODO : get client secret
                try:
                    access_token, refresh_token = kapi.get_token(client.name, '', self.username, self.password)

                    super().find(self.name(), f'Can login with username {self.username} on realm {realm.name}, '
                                              f'client {client.name}')
                    super().verbose(f'access_token: {access_token}, refresh_token: {refresh_token}, '
                                    f'password: {self.password}')

                    results[f'{realm.name}-{client.name}'] = Credential(realm, client, self.username, self.password)

                except HTTPError as e:
                    super().warn(f'HTTP error when login : {e}')

        return results
