import uuid
from typing import List
from uuid import uuid4

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.json_result import JsonResult
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need2
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict, WellKnown


class ClientRegistration(JsonResult):
    pass


class ClientRegistrations(List[ClientRegistration]):
    pass


class RandomStr:
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def random_str(self) -> str:
        return str(uuid.uuid4())


class ClientRegistrationScanner(Need2[Realms, WellKnownDict], Scanner[ClientRegistrations], RandomStr):
    """
    This scanner check for :
    - add a client registration, with and without credentials, if provideds
    https://openid.net/specs/openid-connect-registration-1_0.html
    """

    def __init__(self, callback_url: str, **kwargs):
        self.callback_url = callback_url
        super().__init__(**kwargs)

    def perform(self, realms: Realms, well_known_dict: WellKnownDict, **kwargs) -> (ClientRegistrations, VulnFlag):

        result = ClientRegistrations()

        for realm in realms:

            well_known = well_known_dict[realm.name]

            registration_endpoint = well_known.json['registration_endpoint']

            if registration_endpoint is not None:

                cr = self.registration(realm, registration_endpoint, self.callback_url)

            else:
                cr = self.registration(realm, f'{super().base_url()}/auth/realms/{realm.name}/clients-registrations/openid'
                                       f'-connect', self.callback_url)

            if cr is not None:
                result.append(cr)

        return result, VulnFlag(len(result) > 0)

    def registration(self, realm: Realm, url: str, base_url: str, application_type: str = 'web') -> ClientRegistration:

        client_name = f'keycloak-client-{super().random_str()}'

        super().info(f'try to register client {client_name}')

        r = super().session().post(url, json={
                "application_type": application_type,
                "redirect_uris": [f"{base_url}/callback"],
                "client_name": client_name,
                "logo_uri": f"{base_url}/logo.png",
                "jwks_uri": f"{base_url}/public_keys.jwks"
        })

        if r.status_code == 201:
            cr = ClientRegistration(client_name,
                                    r.json()['registration_client_uri'] if 'registration_client_uri' in r.json() else '',
                                    r.json())
            super().find('ClientRegistrationScanner',  f'Registering a client {client_name} for realm {realm.name}')
            return cr
        else:
            super().info(f'status code {r.status_code} for client registration')
