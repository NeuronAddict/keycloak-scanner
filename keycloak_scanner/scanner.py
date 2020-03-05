from datetime import datetime

from custom_logging import info
from keycloak_scanner.clients_scanner import ClientScan
from keycloak_scanner.form_post_xss_scan import FormPostXssScan
from keycloak_scanner.none_sign_scan import NoneSignScan
from keycloak_scanner.open_redirect_scanner import OpenRedirectScan
from keycloak_scanner.realm_scanner import RealmScanner
from keycloak_scanner.security_console_scanner import SecurityConsoleScan
from keycloak_scanner.well_known_scanner import WellKnownScan

SCANS = [
    RealmScanner(),
    WellKnownScan(),
    ClientScan(),
    SecurityConsoleScan(),
    OpenRedirectScan(),
    FormPostXssScan(),
    NoneSignScan()
]


class Scanner:

    def __init__(self, launch_config: dict, scans=None):
        if scans is None:
            scans = SCANS
        self.launch_config = launch_config
        self.scans = scans
        self.scan_properties = {}

    def init(self):
        for scan in self.scans:
            scan.init(self.launch_config, self.scan_properties)

    def start(self):
        ofsuscated_config = self.launch_config.copy()
        ofsuscated_config['password'] = '*' * 4
        info('Start scan at {}.\nOptions {}'.format(datetime.now(), ofsuscated_config))
        for scan in self.scans:
            scan.perform(self.launch_config, self.scan_properties)
