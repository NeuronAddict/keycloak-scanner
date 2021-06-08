import uuid
from typing import List, Union

import requests

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scanners.json_result import JsonResult
from keycloak_scanner.scanners.login_scanner import Credential, CredentialDict
from keycloak_scanner.scanners.realm_scanner import Realms, Realm
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.scanners.scanner_pieces import Need3
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict, WellKnown


class ClientRegistration(JsonResult):

    def __init__(self, callback_url, **kwargs):
        self.callback_url = callback_url
        super().__init__(**kwargs)

    def __eq__(self, other):
        return isinstance(other, ClientRegistration) and self.callback_url == other.callback_url \
               and super().__eq__(other)

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.callback_url)}, name={repr(self.name)}, " \
               f"url={repr(self.url)}, json={repr(self.json)})"

    def delete(self, session: requests.Session):
        session.delete(self.url, headers={'Authorization': f'Bearer {self.json["registration_access_token"]}'})


class ClientRegistrations(List[ClientRegistration]):
    pass


class RandomStr:
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def random_str(self) -> str:
        return str(uuid.uuid4())


def callbackurl_iterator(callback_url: Union[str, List[str]]):
    if isinstance(callback_url, str):
        with open(callback_url) as file:
            for line in file:
                line = line.strip('\n')
                yield line
    else:
        for cb in callback_url:
            yield cb


class ClientRegistrationScanner(Need3[Realms, WellKnownDict, CredentialDict], Scanner[ClientRegistrations], RandomStr):
    """
    This scanner add a client registration, with and without credentials, if provideds.
    After scan, client is deleted.

    https://openid.net/specs/openid-connect-registration-1_0.html
    """

    def __init__(self, callback_url: Union[str, List[str]], **kwargs):
        """
        Create a ClientRegistrationScanner
        :param callback_url: a filename (str) or a list of callback to test. if filename, one callback by line (with http://)
        :param kwargs:
        """
        # callback url can be a filename or a list of items
        if callback_url is None or callback_url == '' or len(callback_url) == 0:
            raise Exception('please provide a callback url for client registration scanner')
        self.callback_url = callback_url
        super().__init__(**kwargs)

    def perform(self, realms: Realms, well_known_dict: WellKnownDict, credential_dict: CredentialDict, **kwargs) \
            -> (ClientRegistrations, VulnFlag):
        """
        Perform scan.

        For each realm, search for registration endpoint in well known
        :param credential_dict: credentials list to test
        :param realms: realms to test
        :param well_known_dict: well known dictionary
        :param kwargs:
        :return: a list of ClientRegistration and a vuln flag. vulnerable if a client can be registered
        """

        result = ClientRegistrations()

        for realm in realms:

            well_known = well_known_dict[realm.name]

            registration_endpoint = well_known.json['registration_endpoint']

            # callback url is a file, open the file and test each line
            for callback_url in callbackurl_iterator(self.callback_url):

                cr = self.check_registration_endpoint(realm, registration_endpoint, callback_url, well_known)
                if cr is not None:
                    result.append(cr)
                else:
                    for key, credential in credential_dict.items():
                        cr = self.check_registration_endpoint(realm, registration_endpoint, callback_url, credential)
                        if cr is not None:
                            result.append(cr)

        # clean all clients
        for client_registration in result:
            try:
                client_registration.delete(super().session())
                super().info(f'Deleted client {client_registration.name}')
            except Exception as e:
                super().warn(f'Unable to delete client {client_registration.name} at {client_registration.url} {e}')

        return result, VulnFlag(len(result) > 0)

    def check_registration_endpoint(self, realm, registration_endpoint, callback_url: str, weel_known: WellKnown,
                                    credential: Credential = None):
        """
        check if an endpoint support register

        :param realm: realm to test
        :param registration_endpoint: registration endpoint to test
        :param callback_url: callback url to test. policy can forbit some callbacks
        :param kapi: keycloak api TODO : not very consistent
        :param credential: credential to test
        :return: ClientRegistration if success, or None
        """
        if registration_endpoint is not None:

            cr = self.registration(realm, registration_endpoint, callback_url, weel_known, credential)

        else:
            # we try to guess the url
            # TODO: use multiples urls
            cr = self.registration(realm, f'{super().base_url()}/auth/realms/{realm.name}/clients-registrations/openid'
                                          f'-connect', callback_url, weel_known,  credential)
        return cr

    def registration(self, realm: Realm, url: str, callback_url: str, weel_known: WellKnown,
                     credential: Credential = None,  application_type: str = 'web') -> ClientRegistration:
        """
        Perform the registration
        :param realm: realm to test
        :param url: url of the registration endpoint
        :param callback_url: callback url
         :param credential: credential to test
        :param application_type: usually 'web'. see https://openid.net/specs/openid-connect-registration-1_0.html
        :return: ClientRegistration, or None if can't register
        """
        client_name = f'keycloak-client-{super().random_str()}'

        super().info(f'try to register client {client_name}')

        headers = {}
        if credential is not None:
            try:
                access_token, _ = credential.get_token(self.session_provider, weel_known)
                headers = {'Authorization': f'Bearer {access_token}'}
            except Exception as e:
                super().warn(f'Can\'t get token: {e}')

        r = super().session().post(url, json={
                "application_type": application_type,
                "redirect_uris": [f"{callback_url}/callback"],
                "client_name": client_name,
                "logo_uri": f"{callback_url}/logo.png",
                "jwks_uri": f"{callback_url}/public_keys.jwks"
        }, headers=headers)

        if r.status_code == 201:
            cr = ClientRegistration(callback_url, name=client_name,
                                    url=r.json()['registration_client_uri'] if 'registration_client_uri' in r.json() else '',
                                    json=r.json())
            super().find('ClientRegistrationScanner',  f'Registering a client {client_name} for realm {realm.name} (callback : {callback_url})')
            return cr
        else:
            super().info(f'status code {r.status_code} for client registration')
