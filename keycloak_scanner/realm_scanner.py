from keycloak_scanner.custom_logging import verbose, info
from keycloak_scanner.constants import DEFAULT_REALMS
from keycloak_scanner.properties import add_kv
from keycloak_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}'


class RealmScanner(Scan):

    def perform(self, launch_properties, scan_properties):
        realms = launch_properties['realms']
        for realm in DEFAULT_REALMS + realms:
            base_url = launch_properties['base_url']
            url = URL_PATTERN.format(base_url, realm)
            r = self.session.get(url)
            if r.status_code != 200:
                verbose('Bad status code for realm {} {}: {}'.format(realm, url, r.status_code))
            else:
                info('Find realm {} ({})'.format(realm, url))
                add_kv(scan_properties, 'realms', realm, r.json())
                if 'public_key' in scan_properties['realms'][realm]:
                    info('Public key for realm {} : {}'
                         .format(realm, scan_properties['realms'][realm]['public_key']))
