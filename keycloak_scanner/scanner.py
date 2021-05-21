from datetime import datetime

from keycloak_scanner.custom_logging import info


class Scanner:

    def __init__(self, launch_config: dict, session, scans):
        self.launch_config = launch_config
        self.scans = scans
        self.scan_properties = {}
        self.session = session

    def init(self):
        for scan in self.scans:
            scan.init(self.launch_config, self.scan_properties, self.session)

    def start(self):
        ofsuscated_config = self.launch_config.copy()
        ofsuscated_config['password'] = '*' * 4
        info('Start scan at {}.\nOptions {}'.format(datetime.now(), ofsuscated_config))
        self.init()
        for scan in self.scans:
            scan.perform(self.launch_config, self.scan_properties)
