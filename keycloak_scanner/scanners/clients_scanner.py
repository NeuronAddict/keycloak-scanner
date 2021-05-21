from keycloak_scanner.constants import DEFAULT_CLIENTS
from keycloak_scanner.custom_logging import verbose, info
from keycloak_scanner.properties import add_list
from keycloak_scanner.scanners.scanner import Scanner

URL_PATTERN = '{}/auth/realms/{}/{}'


class ClientScanner(Scanner):

    def perform(self, launch_properties, scan_properties):

        base_url = launch_properties['base_url']
        realms = scan_properties['realms'].keys()
        clients = DEFAULT_CLIENTS + launch_properties['clients']

        scan_properties['clients'] = {}

        for realm in realms:
            for client in clients:
                url = URL_PATTERN.format(base_url, realm, client)
                r = self.session.get(url)

                if r.status_code != 200:
                    url = scan_properties['wellknowns'][realm]['authorization_endpoint']
                    r = self.session.get(url, params={'client_id': client}, allow_redirects=False)
                    if r.status_code == 302:
                        info('Find a client for realm {}: {}'.format(realm, client))
                        add_list(scan_properties['clients'], realm, client)
                    else:
                        verbose('client {} seems to not exists'.format(client))
                else:
                    info('Find a client for realm {}: {} ({})'.format(realm, client, url))
                    add_list(scan_properties['clients'], realm, client)
