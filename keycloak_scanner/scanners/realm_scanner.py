from typing import List, NewType

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.json_result import JsonResult
from keycloak_scanner.scanners.scanner import Scanner

URL_PATTERN = '{}/auth/realms/{}'


class Realm(JsonResult):
    pass


class Realms(List[Realm]):
    pass


class RealmScanner(Scanner[Realms]):

    DEFAULT_REALMS = ['master']

    def __init__(self, realms: List[str] = None, **kwargs):
        if realms is None:
            realms = RealmScanner.DEFAULT_REALMS
        self.realms = realms
        super().__init__(**kwargs)

    def perform(self) -> (Realms, VulnFlag):

        realms: Realms = Realms([])

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
                realms.append(realm)

        return realms, VulnFlag()
