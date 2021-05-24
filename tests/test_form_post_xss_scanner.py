from requests import Session

from keycloak_scanner.scanners.clients_scanner import Clients
from keycloak_scanner.scanners.form_post_xss_scanner import FormPostXssScanner, FormPostXssResults, FormPostXssResult
from keycloak_scanner.scanners.realm_scanner import Realm, Realms
from keycloak_scanner.scanners.well_known_scanner import WellKnownDict


def test_perform(base_url, full_scan_mock_session: Session, all_realms: Realms, all_clients: Clients,
                 well_known_dict: WellKnownDict, master_realm: Realm, other_realm: Realm):
    scanner = FormPostXssScanner(base_url=base_url, session=full_scan_mock_session)

    result, vf = scanner.perform(realms=all_realms, clients=all_clients, well_known_dict=well_known_dict)

    assert result == FormPostXssResults({
        'master': FormPostXssResult(master_realm, False),
        'other': FormPostXssResult(other_realm, False)
    })

    assert not vf.has_vuln


## TODO: test when vulnerable