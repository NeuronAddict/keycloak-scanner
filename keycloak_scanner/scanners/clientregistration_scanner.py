import uuid
from typing import List, Union
from uuid import uuid4

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.json_result import JsonResult
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need2
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict, WellKnown


class ClientRegistration(JsonResult):

    def __init__(self, callback_url, **kwargs):
        self.callback_url = callback_url
        super().__init__(**kwargs)

    def __eq__(self, other):
        return isinstance(other, ClientRegistration) and self.callback_url == other.callback_url \
               and super().__eq__(other)

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.callback_url)}, name={repr(self.name)}', " \
               f"url={repr(self.url)}, json={repr(self.json)})"

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

    def __init__(self, callback_url: Union[str, List[str]], **kwargs):
        self.callback_url = callback_url
        super().__init__(**kwargs)

    def perform(self, realms: Realms, well_known_dict: WellKnownDict, **kwargs) -> (ClientRegistrations, VulnFlag):

        result = ClientRegistrations()

        for realm in realms:

            well_known = well_known_dict[realm.name]

            registration_endpoint = well_known.json['registration_endpoint']

            if isinstance(self.callback_url, list):

                for c in self.callback_url:
                    cr = self.check_registration_endpoint(realm, registration_endpoint, c)
                    if cr is not None:
                        result.append(cr)

            else:
                cr = self.check_registration_endpoint(realm, registration_endpoint, self.callback_url)
                if cr is not None:
                    result.append(cr)

        return result, VulnFlag(len(result) > 0)

    def check_registration_endpoint(self, realm, registration_endpoint, callback_url: str):
        if registration_endpoint is not None:

            cr = self.registration(realm, registration_endpoint, callback_url)

        else:
            cr = self.registration(realm, f'{super().base_url()}/auth/realms/{realm.name}/clients-registrations/openid'
                                          f'-connect', callback_url)
        return cr

    def registration(self, realm: Realm, url: str, callback_url: str, application_type: str = 'web') -> ClientRegistration:

        client_name = f'keycloak-client-{super().random_str()}'

        super().info(f'try to register client {client_name}')

        r = super().session().post(url, json={
                "application_type": application_type,
                "redirect_uris": [f"{callback_url}/callback"],
                "client_name": client_name,
                "logo_uri": f"{callback_url}/logo.png",
                "jwks_uri": f"{callback_url}/public_keys.jwks"
        })

        if r.status_code == 201:
            cr = ClientRegistration(callback_url, name=client_name,
                                    url=r.json()['registration_client_uri'] if 'registration_client_uri' in r.json() else '',
                                    json=r.json())
            super().find('ClientRegistrationScanner',  f'Registering a client {client_name} for realm {realm.name} (callback : {callback_url})')
            return cr
        else:
            super().info(f'status code {r.status_code} for client registration')
