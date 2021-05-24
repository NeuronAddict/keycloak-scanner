from typing import Dict

from keycloak_scanner.jwt_attack import change_to_none
from keycloak_scanner.keycloak_api import KeyCloakApi
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.clients_scanner import Clients
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need4
from keycloak_scanner.scanners.security_console_scanner import SecurityConsoleResults
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict


class NoneSignResult:

    def __init__(self, realm: Realm, is_vulnerable: bool):
        self.realm = realm
        self.is_vulnerable = is_vulnerable

    def __repr__(self):
        return f'NoneSignResult({repr(self.realm)}, {self.is_vulnerable})'

    def __eq__(self, other):
        if isinstance(other, NoneSignResult):
            return self.realm == other.realm and self.is_vulnerable == other.is_vulnerable
        return NotImplemented


class NoneSignResults(Dict[str, NoneSignResult]):
    pass


class NoneSignScanner(Need4[Realms, Clients, WellKnownDict, SecurityConsoleResults], Scanner[NoneSignResults]):

    def __init__(self, username: str = None, password: str = None, **kwars):
        self.username = username
        self.password = password
        super().__init__(**kwars)

    def perform(self, realms: Realms, clients: Clients, well_known_dict: WellKnownDict,
                security_console_results: SecurityConsoleResults, **kwargs) -> (NoneSignResults, VulnFlag):

        results = NoneSignResults()

        vf = VulnFlag()

        for realm in realms:

            is_vulnerable = False

            api = KeyCloakApi(super().session(), well_known_dict[realm.name].json)

            if realm.name in security_console_results and security_console_results[realm.name].secret:
                client_secret = security_console_results[realm.name].secret

                for client in clients:
                    if self.username is not None:
                        if self.password is not None:
                            is_vulnerable = self.test_none(api, client, client_secret, self.username, self.password)
                            vf.set_vuln()
                        else:
                            is_vulnerable = self.test_none(api, client, client_secret, self.username, self.username)
                            vf.set_vuln()
                    else:
                        super().info('No none scan, provide credentials to test jwt none signature')
            else:
                super().verbose(f'No secret for realm {realm.name}')

            results[realm.name] = NoneSignResult(realm, is_vulnerable)

        return results, vf

    def test_none(self, api, client, client_secret, username, password):

        try:

            access_token, refresh_token = api.get_token(client, client_secret, username, password)
            super().info(
                'Got token via password method. access_token:{}, refresh_token:{}'.format(access_token, refresh_token))
            none_refresh_token = change_to_none(refresh_token)

            try:
                access_token, refresh_token = api.refresh(client, none_refresh_token)
                super().find('NoneSign',
                             f'Refresh work with none. access_token:{access_token}, refresh_token:{refresh_token}')
                return True

            except Exception as e:
                super().verbose('None refresh token fail : {}'.format(e))

        except Exception as e:
            raise e

        return False
