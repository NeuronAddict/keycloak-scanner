from keycloak_scanner.scanners.none_sign_scanner import NoneSignScanner


def test_perform(full_scan_mock_session):
    scanner = NoneSignScanner(username='user', password='password', base_url='http://testscan',
                              session=full_scan_mock_session)

    scan_properties = {
        'realms': {
            'master': {}
        },
        'clients': {
            'master': ['client1']
        },
        'wellknowns': {
            'master': {
                'token_endpoint': 'http://testscan/master/token'
            }
        },
        'security-admin-console': {
            'master': {
                'secret': '123456789'
            }
        }
    }
    scanner.perform(scan_properties=scan_properties)

    assert scan_properties == {'clients': {'master': ['client1']},
                               'realms': {'master': {}},
                               'security-admin-console': {'master': {'secret': '123456789'}},
                               'wellknowns': {'master': {'token_endpoint': 'http://testscan/master/token'}}}

    # TODO : test scanner result when log was refactoreds
