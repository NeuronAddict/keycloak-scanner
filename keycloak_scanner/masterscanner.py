from typing import List

from keycloak_scanner.scanners.scanner import Scanner


class MasterScanner:

    def __init__(self, scans: List[Scanner]):
        self.scans = scans
        self.scan_properties = {}

    def start(self):
        for scan in self.scans:
            scan.perform(scan_properties=self.scan_properties)
