import requests
from termcolor import colored

from properties import add_list, add_kv
from scan import Scan

URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'


class WellKnownScan(Scan):

    def perform(self, launch_properties, scan_properties):
        realms = list(scan_properties['realms'].keys())
        for realm in realms:
            base_url = launch_properties['base_url']
            url = URL_PATTERN.format(base_url, realm)
            r = requests.get(url)
            if r.status_code != 200:
                print(colored('[*] Bad status code for realm {} {}: {}'.format(realm, url, r.status_code), 'gray'))
            else:
                print(colored('[+] Find a well known for realm {} {}: {}'.format(realm, url, r.status_code), 'red'))
                add_kv(scan_properties, 'wellknowns', realm, r.json())
