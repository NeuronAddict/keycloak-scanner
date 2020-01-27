import requests
from termcolor import colored

from constants import DEFAULT_REALMS
from properties import add_kv
from scan import Scan

URL_PATTERN = '{}/auth/realms/{}'

class RealmScanner(Scan):

    def perform(self, launch_properties, scan_properties):
        realms = launch_properties['realms']
        for realm in DEFAULT_REALMS + realms:
            base_url = launch_properties['base_url']
            url = URL_PATTERN.format(base_url, realm)
            r = requests.get(url)
            if r.status_code != 200:
                print(colored('[-] Bad status code for realm {} {}: {}'.format(realm, url, r.status_code), 'red'))
            else:
                print(colored('[+] Find a well known for realm {} {}: {}'.format(realm, url, r.status_code), 'green'))
                add_kv(scan_properties, 'realms', realm, r.json())
