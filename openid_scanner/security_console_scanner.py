import requests
from termcolor import colored

from custom_logging import find, error
from properties import add_list, add_kv
from scan import Scan

URL_PATTERN = '{}/auth/realms/{}/clients-registrations/default/security-admin-console'


class SecurityConsoleScan(Scan):

    def perform(self, launch_properties, scan_properties):

        base_url = launch_properties['base_url']
        realms = list(scan_properties['realms'].keys())
        for realm in realms:
            url = URL_PATTERN.format(base_url, realm)
            r = requests.get(url)
            if r.status_code != 200:
                error('Bad status code for {}: {}'.format(url, r.status_code))
            else:
                find('Find a security-admin-console {}: {}'.format(url, r.status_code))
                add_kv(scan_properties, 'security-admin-console', realm, r.json())
                if 'secret' in scan_properties['security-admin-console'][realm]:
                    find('Find secret for realm {} : {}'
                         .format(realm, scan_properties['security-admin-console'][realm]['secret']))

