from typing import List

from keycloak_scanner.custom_logging import verbose, info
from keycloak_scanner.properties import add_list
from keycloak_scanner.scanners.scanner import Scanner

URL_PATTERN = '{}/auth/realms/{}/{}'


class ClientScanner(Scanner):

    def __init__(self, clients: List[str], **kwargs):
        self.clients = clients
        super().__init__(**kwargs)

    def perform(self, scan_properties):

        realms = scan_properties['realms'].keys()

        scan_properties['clients'] = {}

        for realm in realms:
            for client in self.clients:
                url = URL_PATTERN.format(super().base_url(), realm, client)
                r = super().session().get(url)

                if r.status_code != 200:
                    url = scan_properties['wellknowns'][realm]['authorization_endpoint']
                    r = super().session().get(url, params={'client_id': client}, allow_redirects=False)
                    if r.status_code == 302:
                        info('Find a client for realm {}: {}'.format(realm, client))
                        add_list(scan_properties['clients'], realm, client)
                    else:
                        verbose('client {} seems to not exists'.format(client))
                else:
                    info('Find a client for realm {}: {} ({})'.format(realm, client, url))
                    add_list(scan_properties['clients'], realm, client)
