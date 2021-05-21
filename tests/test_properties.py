from unittest import TestCase

from keycloak_scanner.properties import add_list, add_kv


class Test(TestCase):

    def test_add_list(self):
        scan_properties = {}
        add_list(scan_properties, 'realms', 'master')
        add_list(scan_properties, 'realms', 'external')
        self.assertDictEqual(scan_properties, {'realms': ['master', 'external']})

    def test_add_kv(self):
        data = {'prop': 'value'}
        scan_properties = {}
        add_kv(scan_properties, 'realms', 'master', data)
        add_kv(scan_properties, 'realms', 'external', data)
        self.assertDictEqual(scan_properties, {'realms': {'master': data, 'external': data}})
