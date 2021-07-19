from typing import Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import Realm, SecurityConsole
from keycloak_scanner.scan_base.wrap import WrapperTypes

URL_PATTERN = '{}/auth/realms/{}/clients-registrations/default/security-admin-console'


class SecurityConsoleScanner(Scanner[SecurityConsole]):

    """
    TODO: replace with a client registration access scanner
    """

    def __init__(self, **kwargs):
        super().__init__(result_type=WrapperTypes.SECURITY_CONSOLE,
                         needs=[WrapperTypes.REALM_TYPE],
                         **kwargs)

    def perform(self, realm: Realm, **kwargs) -> (Set[SecurityConsole], VulnFlag):

        vf = VulnFlag()
        result = None

        url = URL_PATTERN.format(super().base_url(), realm.name)
        r = super().session().get(url)
        if r.status_code != 200:
            super().verbose('Bad status code for {}: {}'.format(url, r.status_code))

        else:
            super().find('SecurityAdminConsole', 'Find a security-admin-console {}: {}'.format(url, r.status_code))
            result = SecurityConsole(realm, url, r.json())
            vf.set_vuln()
            if 'secret' in r.json():
                secret = r.json()["secret"]
                super().info(f'find a secret in security console (realm {realm.name}) : {secret}')
                result.secret = secret

        return {result} if result else set(), vf
