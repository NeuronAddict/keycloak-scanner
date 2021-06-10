import pytest

from keycloak_scanner.scanners.scanner import ScannerStatus, TooManyResultsException


def test_status():
    status = ScannerStatus(3)

    status.args('machin', 2)
    status.args('machin', 4)

    status.args('truc', 'test')
    status.args('truc', 'test2')

    assert list(status.args('bidule', True)) == [(2, 'test', True), (2, 'test2', True), (4, 'test', True),
                                                 (4, 'test2', True)]


def test_should_fail_when_add_too_many_args():
    status = ScannerStatus(2)

    status.args('machin', 2)
    status.args('machin', 4)

    status.args('truc', 'test')
    status.args('truc', 'test2')

    with pytest.raises(TooManyResultsException) as e:
        status.args('bidule', True)

    assert e.value.name == 'bidule'
    assert e.value.value is True
