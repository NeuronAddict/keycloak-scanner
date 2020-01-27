from realm_scanner import RealmScanner
from well_known_scanner import WellKnownScan

SCANS = [
    RealmScanner(),
    WellKnownScan()
]


class Scanner:

    def __init__(self, launch_config, scans=None):
        if scans is None:
            scans = SCANS
        self.launch_config = launch_config
        self.scans = scans
        self.scan_properties = {}

    def init(self):
        for scan in self.scans:
            scan.init(self.launch_config, self.scan_properties)

    def start(self):
        for scan in self.scans:
            scan.perform(self.launch_config, self.scan_properties)
