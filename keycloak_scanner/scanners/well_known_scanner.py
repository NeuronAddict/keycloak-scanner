from typing import Dict, List

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.types import Realm, wellKnownType, WellKnown, realmType

URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'


class WellKnownScanner(Scanner[WellKnown]):

    def __init__(self, **kwargs):
        super().__init__(result_type=wellKnownType, needs=[realmType], **kwargs)

    def perform(self, realm: Realm, **kwargs) -> (List[WellKnown], VulnFlag):

        url = URL_PATTERN.format(super().base_url(), realm.name)
        r = super().session().get(url)

        result: List[WellKnown] = []

        if r.status_code != 200:
            super().verbose('Bad status code for realm {} {}: {}'.format(realm.name, url, r.status_code))

        else:
            super().info('Find a well known for realm {} {}'.format(realm.name, url))
            result.append(WellKnown(realm, name=realm.name, url=url, json=r.json()))

        return result, VulnFlag()
