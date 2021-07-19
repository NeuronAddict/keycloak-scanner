import requests
from waiting import wait


def is_keycloak_loaded():
    try:
        r = requests.get('http://localhost:8080/auth/', timeout=1)
        return 'Welcome to Keycloak' in r.text
    except Exception as e:
        print(e)


if __name__ == '__main__':
    wait(is_keycloak_loaded)
    print('Keycloak seems to be loaded')
