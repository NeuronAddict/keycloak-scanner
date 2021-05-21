from keycloak_scanner.custom_logging import verbose, info, find
from keycloak_scanner.jwt_attack import change_to_none
from keycloak_scanner.keycloak_api import KeyCloakApi
from keycloak_scanner.scan import Scan


def test_none(api, client, client_secret, username, password):
    try:
        access_token, refresh_token = api.get_token(client, client_secret, username, password)
        info('Got token via password method. access_token:{}, refresh_token:{}'.format(access_token, refresh_token))
        none_refresh_token = change_to_none(refresh_token)
        try:
            access_token, refresh_token = api.refresh(client, none_refresh_token)
            find('NoneSign', 'Refresh work with none. access_token:{}, refresh_token:{}'.format(access_token, refresh_token))
        except Exception as e:
            verbose('None refresh token fail : {}'.format(e))
    except Exception as e:
        verbose(e)


class NoneSignScan(Scan):

    def perform(self, launch_properties, scan_properties):

        realms = scan_properties['realms'].keys()

        for realm in realms:
            clients = scan_properties['clients'][realm]
            well_known = scan_properties['wellknowns'][realm]

            api = KeyCloakApi(self.session, well_known)

            if 'security-admin-console' not in scan_properties \
                    or realm not in scan_properties['security-admin-console'] \
                    or 'secret' not in scan_properties['security-admin-console'][realm]:
                verbose('No secret for realm {}'.format(realm))
                continue

            client_secret = scan_properties['security-admin-console'][realm]['secret']

            for client in clients:
                if 'username' in launch_properties:
                    username = launch_properties['username']
                    if 'password' in launch_properties:
                        password = launch_properties['password']
                        test_none(api, client, client_secret, username, password)
                    else:
                        test_none(api, client, client_secret, username, username)
                else:
                    info('No none scan, provide credentials to test jwt none signature')
