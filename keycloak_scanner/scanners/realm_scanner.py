from typing import List, Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import Realm
from keycloak_scanner.scan_base.wrap import WrapperTypes

URL_PATTERN = '{}/auth/realms/{}'


class RealmScanner(Scanner[Realm]):

    def __init__(self, realms: List[str] = None, **kwargs):
        if realms is None:
            realms = []
        self.realms = realms
        super().__init__(result_type=WrapperTypes.REALM_TYPE, **kwargs)

    def perform(self) -> (Set[Realm], VulnFlag):

        realms: Set[Realm] = set()

        for realm_name in self.realms:

            url = URL_PATTERN.format(super().base_url(), realm_name)
            r = super().session().get(url)

            if r.status_code != 200:
                super().verbose('Bad status code for realm {} {}: {}'.format(realm_name, url, r.status_code))

            else:
                super().info('Find realm {} ({})'.format(realm_name, url))
                realm = Realm(realm_name, url, r.json())

                if 'public_key' in realm.json:
                    super().info(f'Public key for realm {realm_name} : {realm.json["public_key"]}')
                realms.add(realm)

        return realms, VulnFlag()
