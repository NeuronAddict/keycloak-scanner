from keycloak_scanner.custom_logging import find
from keycloak_scanner.properties import add_kv
from keycloak_scanner.scanners.scanner import Scanner

URL_PATTERN = '{}/auth/realms/{}/clients-registrations/default/security-admin-console'


class SecurityConsoleScanner(Scanner):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, scan_properties):

        realms = list(scan_properties['realms'].keys())
        for realm in realms:
            url = URL_PATTERN.format(super().base_url(), realm)
            r = super().session().get(url)
            if r.status_code != 200:
                super().verbose('Bad status code for {}: {}'.format(url, r.status_code))
            else:
                find('SecurityAdminConsole', 'Find a security-admin-console {}: {}'.format(url, r.status_code))
                add_kv(scan_properties, 'security-admin-console', realm, r.json())
                if 'secret' in scan_properties['security-admin-console'][realm]:
                    find('ClientSecret', 'Find secret for realm {} : {}'
                         .format(realm, scan_properties['security-admin-console'][realm]['secret']))

