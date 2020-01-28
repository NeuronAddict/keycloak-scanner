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
        realms = map(lambda x: list(x.keys())[0], scan_properties['realms'])
        clients = DEFAULT_CLIENTS + launch_properties['clients']
        for realm in realms:
            for client in clients:
                url = URL_PATTERN.format(base_url, realm, client)
                r = requests.get(url)

                if r.status_code != 200:
                    error('Bad status code for realm {} and client {} {}: {}'.format(realm, client, url, r.status_code))
                else:
                    find('Find a client for realm {}: {} ({})'.format(realm, client, url))
                    add_list(scan_properties, 'clients', client)
