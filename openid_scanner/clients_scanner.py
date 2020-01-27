import requests
from termcolor import colored

from openid_scanner.properties import add_kv
from openid_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}/{}'


class ClientScan(Scan):

    def perform(self, launch_properties, scan_properties):

        base_url = launch_properties['base_url']
        realms = map(lambda x: list(x.keys())[0], scan_properties['realms'])

        for realm in realms:

            # noinspection DuplicatedCode
            url = URL_PATTERN.format(base_url, realm)

            r = requests.get(url)
            if r.status_code != 200:
                print(colored('[*] Bad status code for realm {} {}: {}'.format(realm, url, r.status_code), 'gray'))
            else:
                print(colored('[+] Find a well known for realm {} {}: {}'.format(realm, url, r.status_code), 'red'))
                add_kv(scan_properties, 'wellknowns', realm, r.json())
