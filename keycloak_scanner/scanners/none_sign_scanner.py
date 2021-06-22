from typing import Set

from keycloak_scanner.jwt_attack import change_to_none
from keycloak_scanner.keycloak_api import KeyCloakApi
from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import NoneSign, Client, WellKnown, SecurityConsole, Realm
from keycloak_scanner.scan_base.wrap import WrapperTypes


class NoneSignScanner(Scanner[NoneSign]):

    def __init__(self, username: str = None, password: str = None, **kwargs):
        # TODO : use credentials from events
        self.username = username
        self.password = password
        super().__init__(result_type=WrapperTypes.NONE_SIGN,
                         needs=[WrapperTypes.REALM_TYPE, WrapperTypes.CLIENT_TYPE, WrapperTypes.WELL_KNOWN_TYPE, WrapperTypes.SECURITY_CONSOLE],
                         **kwargs)

    def perform(self, realm: Realm, client: Client, well_known: WellKnown,
                security_console: SecurityConsole, **kwargs) -> (Set[NoneSign], VulnFlag):

        # TODO : make secret type + use credentials

        vf = VulnFlag()

        api = KeyCloakApi(well_known=well_known.json, session_provider=super().session, verbose=super().is_verbose())

        if well_known.realm == realm and security_console.secret:

            if self.username is not None:

                password = self.password
                if self.password is None:
                    password = self.username

                if self.test_none(api, client, security_console.secret, self.username, password):
                    return {NoneSign(realm)}, vf

            else:
                super().info('No none scan, provide credentials to test jwt none signature')
        else:
            super().verbose(f'No secret for realm {realm.name}')

        return set(), vf

    def test_none(self, api, client, client_secret, username, password):

        try:

            access_token, refresh_token = api.get_token(client.name, client_secret, username, password)
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
