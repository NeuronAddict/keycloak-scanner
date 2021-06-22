from typing import Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import WellKnown, Client, Realm, OpenRedirect
from keycloak_scanner.scan_base.wrap import WrapperTypes

URL_PATTERN = '{}/auth/realms/{}/{}'


class OpenRedirectScanner(Scanner[OpenRedirect]):

    def __init__(self, **kwars):
        super().__init__(result_type=WrapperTypes.OPEN_REDIRECT,
                         needs=[WrapperTypes.REALM_TYPE, WrapperTypes.CLIENT_TYPE, WrapperTypes.WELL_KNOWN_TYPE],
                         **kwars)

    def perform(self, realm: Realm, client: Client, well_known: WellKnown, **kwargs) -> (Set[OpenRedirect], VulnFlag):

        results: Set[OpenRedirect] = set()

        vf = VulnFlag()

        if 'code' not in well_known.json['response_types_supported']:
            super().verbose(f'code not in supported response types, can\' test redirect_uri for realm {realm.name}')
        else:
            url = well_known.json['authorization_endpoint']

            r = super().session().get(url, params={
                'response_type': 'code',
                'client_id': client.name,
                'redirect_uri': f'https://devops-devsecops.org/auth/{realm.name}/{client.name}/'
            })

            if r.status_code == 200:
                super().find('OpenRedirection', f'Open redirection for realm {realm.name} and clientid {client.name}')
                vf.set_vuln()
                results.add(OpenRedirect(realm, client))

        return results, vf
