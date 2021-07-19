import uuid
from typing import List, Union, Set

from keycloak_scanner.logging.vuln_flag import VulnFlag
from keycloak_scanner.scan_base.scanner import Scanner
from keycloak_scanner.scan_base.types import ClientRegistration, Realm, WellKnown, Credential
from keycloak_scanner.scan_base.wrap import WrapperTypes


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


class ClientRegistrationScanner(Scanner[ClientRegistration], RandomStr):
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
        super().__init__(result_type=WrapperTypes.CLIENT_REGISTRATION,
                         needs=[WrapperTypes.REALM_TYPE, WrapperTypes.CREDENTIAL_TYPE],
                         **kwargs)
        super().verbose(f'callback urls: {callback_url}')

    def perform(self, realm: Realm, credential: Credential, **kwargs) \
            -> (Set[ClientRegistration], VulnFlag):
        """
        Perform scan.

        For each realm, search for registration endpoint in well known
        :param credential: credential to test
        :param realm: realm to test
        :param kwargs:
        :return: a list of ClientRegistration and a vuln flag. vulnerable if a client can be registered
        """

        result: Set[ClientRegistration] = set()

        well_known = realm.get_well_known(super().base_url(), super().session())

        registration_endpoint = well_known.json['registration_endpoint']

        # callback url is a file, open the file and test each line
        for callback_url in callbackurl_iterator(self.callback_url):

            cr = self.check_registration_endpoint(realm, registration_endpoint, callback_url, well_known)
            if cr is not None:
                result.add(cr)
            else:

                cr = self.check_registration_endpoint(realm, registration_endpoint, callback_url, well_known, credential)
                if cr is not None:
                    result.add(cr)


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
