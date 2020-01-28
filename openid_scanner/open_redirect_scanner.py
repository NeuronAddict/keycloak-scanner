import requests
from termcolor import colored

from constants import DEFAULT_CLIENTS
from custom_logging import error, find
from openid_scanner.properties import add_kv, add_list
from openid_scanner.scan import Scan

URL_PATTERN = '{}/auth/realms/{}/{}'


class OpenRedirectScan(Scan):

    def perform(self, launch_properties, scan_properties):

        base_url = launch_properties['base_url']
        realms = scan_properties['realms'].keys()

        for realm in realms:
            clients = scan_properties['clients'][realm]
            well_known = scan_properties['wellknowns'][realm]
            if 'code' not in well_known['response_types_supported']:
                error('code not in supported response types, can\' test redirect_uri for realm {}'.format(realm))
            else:
                url = well_known['authorization_endpoint']

                for client in clients:

                    r = requests.get(url, params={
                        'response_type': 'code',
                        'client_id': client,
                        'redirect_uri': 'https://devops-devsecops.org/auth/{}/{}/'.format(realm, client)
                    })

                    if r.status_code == 200:
                        find('Open redirection for realm {} and clientid {}'.format(realm, client))

