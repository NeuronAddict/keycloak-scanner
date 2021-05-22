from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.properties import add_kv
from keycloak_scanner.scanners.scanner import Scanner

URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'


class WellKnownScanner(Scanner, PrintLogger):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, scan_properties):
        realms = scan_properties['realms'].keys()
        for realm in realms:

            url = URL_PATTERN.format(super().base_url(), realm)
            r = super().session().get(url)
            if r.status_code != 200:
                super().verbose('Bad status code for realm {} {}: {}'.format(realm, url, r.status_code))
            else:
                super().info('Find a well known for realm {} {}'.format(realm, url))
                add_kv(scan_properties, 'wellknowns', realm, r.json())
