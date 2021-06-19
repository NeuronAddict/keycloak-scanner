from typing import List, Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.types import Realm, WellKnown
from keycloak_scanner.scanners.wrap import WrapperTypes

URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'


class WellKnownScanner(Scanner[WellKnown]):

    def __init__(self, **kwargs):
        super().__init__(result_type=WrapperTypes.WELL_KNOWN_TYPE, needs=[WrapperTypes.REALM_TYPE], **kwargs)

    def perform(self, realm: Realm, **kwargs) -> (Set[WellKnown], VulnFlag):

        url = URL_PATTERN.format(super().base_url(), realm.name)
        r = super().session().get(url)

        result: Set[WellKnown] = set()

        if r.status_code != 200:
            super().verbose('Bad status code for realm {} {}: {}'.format(realm.name, url, r.status_code))

        else:
            super().info('Find a well known for realm {} {}'.format(realm.name, url))
            result.add(WellKnown(realm, name=realm.name, url=url, json=r.json()))

        return result, VulnFlag()
