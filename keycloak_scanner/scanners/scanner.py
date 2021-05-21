import requests

from keycloak_scanner.scanners.session_holder import SessionHolder


class Scanner(SessionHolder):

    def __init__(self, base_url: str, **kwargs):
        self.base_url = base_url
        super().__init__(**kwargs)

    def perform(self, scan_properties):
        """
        Perform the scan
        :return: scan result (json)
        """
        assert not hasattr(super(), 'perform')
