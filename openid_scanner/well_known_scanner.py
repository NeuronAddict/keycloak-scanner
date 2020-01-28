import requests
from termcolor import colored

from custom_logging import find, error
from openid_scanner.properties import add_kv
from openid_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'


class WellKnownScan(Scan):

    def perform(self, launch_properties, scan_properties):
        realms = map(lambda x: list(x.keys())[0], scan_properties['realms'])
        for realm in realms:
            base_url = launch_properties['base_url']
            url = URL_PATTERN.format(base_url, realm)
            r = requests.get(url)
            if r.status_code != 200:
                error('Bad status code for realm {} {}: {}'.format(realm, url, r.status_code))
            else:
                find('Find a well known for realm {} {}'.format(realm, url))
                add_kv(scan_properties, 'wellknowns', realm, r.json())
