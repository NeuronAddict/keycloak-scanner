from keycloak_scanner.custom_logging import verbose


def test_verbose():
    # just test if no error, like in PR #13
    verbose('hello')
