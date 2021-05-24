from typing import Dict

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need

URL_PATTERN = '{}/auth/realms/{}/clients-registrations/default/security-admin-console'


class SecurityConsoleResult:

    def __init__(self, realm: Realm, url: str, json: dict, secret: dict = None):
        self.realm = realm
        self.url = url
        self.json = json
        self.secret = secret

    def __eq__(self, other):
        if isinstance(other, SecurityConsoleResult):
            return self.realm == other.realm and self.url == other.url and self.json == other.json and self.secret == other.secret
        return NotImplemented

    def __repr__(self):
        return f"SecurityConsoleResult({repr(self.realm)}, '{self.url}', '{self.json}', '{self.secret}')"


class SecurityConsoleResults(Dict[str, SecurityConsoleResult]):
    pass


class SecurityConsoleScanner(Need[Realms], Scanner[SecurityConsoleResult]):
    """
    TODO: replace with a client registration access scanner
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def perform(self, realms: Realms, **kwargs) -> (SecurityConsoleResults, VulnFlag):

        results = SecurityConsoleResults()
        vf = VulnFlag()

        for realm in realms:
            url = URL_PATTERN.format(super().base_url(), realm.name)
            r = super().session().get(url)
            if r.status_code != 200:
                super().verbose('Bad status code for {}: {}'.format(url, r.status_code))

            else:
                super().find('SecurityAdminConsole', 'Find a security-admin-console {}: {}'.format(url, r.status_code))
                results[realm.name] = SecurityConsoleResult(realm, url, r.json())
                vf.set_vuln()
                if 'secret' in r.json():
                    secret = r.json()["secret"]
                    super().info(f'find a secret in security console (realm {realm.name}) : {secret}')
                    results[realm.name].secret = secret

        return results, vf
