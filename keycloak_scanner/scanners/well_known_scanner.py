from typing import Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import Realm, WellKnown
from keycloak_scanner.scan_base.wrap import WrapperTypes


class WellKnownScanner(Scanner[WellKnown]):

    def __init__(self, **kwargs):
        super().__init__(result_type=WrapperTypes.WELL_KNOWN_TYPE, needs=[WrapperTypes.REALM_TYPE], **kwargs)

    def perform(self, realm: Realm, **kwargs) -> (Set[WellKnown], VulnFlag):

        result: Set[WellKnown] = set()

        try:

            well_known = realm.get_well_known(self.base_url(), super().session())
            super().find(self.name(), 'Find a well known for realm {} {}'.format(realm.name, well_known.url))
            result.add(well_known)

        except Exception as e:

            super().verbose(str(e))

        return result, VulnFlag()
