import requests

from custom_logging import error, find, info
from openid_scanner.constants import DEFAULT_REALMS
from openid_scanner.properties import add_kv
from openid_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}'


class RealmScanner(Scan):

    def perform(self, launch_properties, scan_properties):
        realms = launch_properties['realms']
        for realm in DEFAULT_REALMS + realms:
            base_url = launch_properties['base_url']
            url = URL_PATTERN.format(base_url, realm)
            r = requests.get(url)
            if r.status_code != 200:
                error('Bad status code for realm {} {}: {}'.format(realm, url, r.status_code))
            else:
                find('Find realm {} ({})'.format(realm, url))
                add_kv(scan_properties, 'realms', realm, r.json())
                if 'public_key' in scan_properties['realms'][realm]:
                    info('Public key for realm {} : {}'
                         .format(realm, scan_properties['realms'][realm]['public_key']))
