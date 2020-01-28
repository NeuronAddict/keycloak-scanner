import requests

from constants import DEFAULT_CLIENTS
from custom_logging import error, find, info
from openid_scanner.properties import add_list
from openid_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}/{}'


class ClientScan(Scan):

    def perform(self, launch_properties, scan_properties):

        base_url = launch_properties['base_url']
        realms = scan_properties['realms'].keys()
        clients = DEFAULT_CLIENTS + launch_properties['clients']

        scan_properties['clients'] = {}

        for realm in realms:
            for client in clients:
                url = URL_PATTERN.format(base_url, realm, client)
                r = requests.get(url)

                if r.status_code != 200:
                    url = scan_properties['wellknowns'][realm]['authorization_endpoint']
                    r = requests.get(url, params={'client_id': client}, allow_redirects=False)
                    if r.status_code == 302:
                        info('Find a client for realm {}: {}'.format(realm, client))
                        add_list(scan_properties['clients'], realm, client)
                    else:
                        error('client {} seems to not exists'.format(client))
                else:
                    info('Find a client for realm {}: {} ({})'.format(realm, client, url))
                    add_list(scan_properties['clients'], realm, client)
