import requests
from termcolor import colored

from constants import DEFAULT_CLIENTS
from custom_logging import error, find
from openid_scanner.properties import add_kv, add_list
from openid_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}/{}'


class ClientScan(Scan):

    def perform(self, launch_properties, scan_properties):

        base_url = launch_properties['base_url']
        realms = scan_properties['realms'].keys()
        clients = DEFAULT_CLIENTS + launch_properties['clients']
        for realm in realms:
            for client in clients:
                url = URL_PATTERN.format(base_url, realm, client)
                r = requests.get(url)

                if r.status_code != 200:
                    url = scan_properties['wellknowns'][realm]['authorization_endpoint']
                    r = requests.get(url, params={'client_id': client}, allow_redirects=False)
                    if r.status_code == 302:
                        find('Find a client for realm {}: {}'.format(realm, client))
                        add_kv(scan_properties, 'clients', realm, client)
                    else:
                        error('client {} seems to not exists'.format(client))
                else:
                    find('Find a client for realm {}: {} ({})'.format(realm, client, url))
                    add_kv(scan_properties, 'clients', realm, client)
