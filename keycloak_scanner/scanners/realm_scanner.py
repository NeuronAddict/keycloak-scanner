from typing import List

from keycloak_scanner.constants import DEFAULT_REALMS
from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.properties import add_kv
from keycloak_scanner.scanners.scanner import Scanner

URL_PATTERN = '{}/auth/realms/{}'


class RealmScanner(Scanner, PrintLogger):

    def __init__(self, realms: List[str], **kwargs):
        self.realms = realms
        super().__init__(**kwargs)

    def perform(self, scan_properties):
        for realm in DEFAULT_REALMS + self.realms:
            url = URL_PATTERN.format(super().base_url(), realm)
            r = super().session().get(url)
            if r.status_code != 200:
                super().verbose('Bad status code for realm {} {}: {}'.format(realm, url, r.status_code))
            else:
                super().info('Find realm {} ({})'.format(realm, url))
                add_kv(scan_properties, 'realms', realm, r.json())
                if 'public_key' in scan_properties['realms'][realm]:
                    super().info('Public key for realm {} : {}'
                         .format(realm, scan_properties['realms'][realm]['public_key']))
        super().perform(scan_properties)
