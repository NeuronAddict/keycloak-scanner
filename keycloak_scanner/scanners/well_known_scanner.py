from typing import Dict

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.json_result import JsonResult
from keycloak_scanner.scanners.realm_scanner import Realm, Realms
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need

URL_PATTERN = '{}/auth/realms/{}/.well-known/openid-configuration'


class WellKnown(JsonResult):

    def __init__(self, realm: Realm, **kwargs):
        self.realm = realm
        super().__init__(**kwargs)

    def __repr__(self):
        return f"WellKnown({repr(self.realm)}, name='{self.name}', url='{self.url}', json={self.json})"

    def __eq__(self, other):
        if isinstance(other, WellKnown):
            return self.realm == other.realm and self.url == other.url and self.json == other.json
        return NotImplemented


class WellKnownDict(Dict[str, WellKnown]):
    pass


class WellKnownScanner(Need[Realms], Scanner):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, realms: Realms, **kwargs) -> (WellKnownDict, VulnFlag):

        result: WellKnownDict = WellKnownDict()

        for realm in realms:

            url = URL_PATTERN.format(super().base_url(), realm.name)
            r = super().session().get(url)

            if r.status_code != 200:
                super().verbose('Bad status code for realm {} {}: {}'.format(realm, url, r.status_code))

            else:
                super().info('Find a well known for realm {} {}'.format(realm, url))
                result[realm.name] = WellKnown(realm, name=realm.name, url=url, json=r.json())

        return result, VulnFlag()
