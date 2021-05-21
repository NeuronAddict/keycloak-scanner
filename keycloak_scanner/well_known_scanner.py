from keycloak_scanner.custom_logging import verbose, info
from keycloak_scanner.properties import add_kv
from keycloak_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'


class WellKnownScan(Scan):

    def perform(self, launch_properties, scan_properties):
        realms = scan_properties['realms'].keys()
        for realm in realms:
            base_url = launch_properties['base_url']
            url = URL_PATTERN.format(base_url, realm)
            r = self.session.get(url)
            if r.status_code != 200:
                verbose('Bad status code for realm {} {}: {}'.format(realm, url, r.status_code))
            else:
                info('Find a well known for realm {} {}'.format(realm, url))
                add_kv(scan_properties, 'wellknowns', realm, r.json())
