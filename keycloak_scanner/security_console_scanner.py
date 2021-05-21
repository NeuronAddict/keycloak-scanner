from .custom_logging import find, verbose
from .properties import add_kv
from .scan import Scan

URL_PATTERN = '{}/auth/realms/{}/clients-registrations/default/security-admin-console'


class SecurityConsoleScan(Scan):

    def perform(self, launch_properties, scan_properties):

        base_url = launch_properties['base_url']
        realms = list(scan_properties['realms'].keys())
        for realm in realms:
            url = URL_PATTERN.format(base_url, realm)
            r = self.session.get(url)
            if r.status_code != 200:
                verbose('Bad status code for {}: {}'.format(url, r.status_code))
            else:
                find('SecurityAdminConsole', 'Find a security-admin-console {}: {}'.format(url, r.status_code))
                add_kv(scan_properties, 'security-admin-console', realm, r.json())
                if 'secret' in scan_properties['security-admin-console'][realm]:
                    find('ClientSecret', 'Find secret for realm {} : {}'
                         .format(realm, scan_properties['security-admin-console'][realm]['secret']))

