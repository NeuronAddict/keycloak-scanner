from keycloak_scanner.custom_logging import find
from keycloak_scanner.jwt_attack import change_to_none
from keycloak_scanner.keycloak_api import KeyCloakApi
from keycloak_scanner.scanners.scanner import Scanner


class NoneSignScanner(Scanner):

    def __init__(self, username: str = None, password: str = None, **kwars):
        self.username = username
        self.password = password
        super().__init__(**kwars)

    def perform(self, scan_properties):

        realms = scan_properties['realms'].keys()

        for realm in realms:
            clients = scan_properties['clients'][realm]
            well_known = scan_properties['wellknowns'][realm]

            api = KeyCloakApi(super().session(), well_known)

            if 'security-admin-console' in scan_properties and realm in scan_properties['security-admin-console'] \
                    and 'secret' in scan_properties['security-admin-console'][realm]:

                client_secret = scan_properties['security-admin-console'][realm]['secret']

                for client in clients:
                    if self.username is not None:
                        if self.password is not None:
                            self.test_none(api, client, client_secret, self.username, self.password)
                        else:
                            self.test_none(api, client, client_secret, self.username, self.username)
                    else:
                        super().info('No none scan, provide credentials to test jwt none signature')
            else:
                super().verbose('No secret for realm {}'.format(realm))

    def test_none(self, api, client, client_secret, username, password):
        try:
            access_token, refresh_token = api.get_token(client, client_secret, username, password)
            super().info(
                'Got token via password method. access_token:{}, refresh_token:{}'.format(access_token, refresh_token))
            none_refresh_token = change_to_none(refresh_token)
            try:
                access_token, refresh_token = api.refresh(client, none_refresh_token)
                find('NoneSign',
                     'Refresh work with none. access_token:{}, refresh_token:{}'.format(access_token, refresh_token))
            except Exception as e:
                super().verbose('None refresh token fail : {}'.format(e))
        except Exception as e:
            raise e
