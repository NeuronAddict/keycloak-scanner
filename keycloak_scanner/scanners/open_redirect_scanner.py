from keycloak_scanner.custom_logging import find
from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.scanner import Scanner

URL_PATTERN = '{}/auth/realms/{}/{}'


class OpenRedirectScanner(Scanner, PrintLogger):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, scan_properties):

        realms = scan_properties['realms'].keys()

        for realm in realms:
            clients = scan_properties['clients'][realm]
            well_known = scan_properties['wellknowns'][realm]
            if 'code' not in well_known['response_types_supported']:
                super().verbose('code not in supported response types, can\' test redirect_uri for realm {}'.format(realm))
            else:
                url = well_known['authorization_endpoint']

                for client in clients:

                    r = super().session().get(url, params={
                        'response_type': 'code',
                        'client_id': client,
                        'redirect_uri': 'https://devops-devsecops.org/auth/{}/{}/'.format(realm, client)
                    })

                    if r.status_code == 200:
                        find('OpenRedirection', 'Open redirection for realm {} and clientid {}'.format(realm, client))

