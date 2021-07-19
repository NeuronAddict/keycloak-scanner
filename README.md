# keycloak-scanner

## Introduction

This scanner scan keycloak for known vulnerabilities.


## Installation

```
pip install --upgrade keycloak-scanner
```


## Example
```
$ git clone https://github.com/NeuronAddict/keycloak-scanner
$ cd keycloak-scanner
$ docker-compose -f itests/docker-compose.yml up -d
$ python3 itests/wait-docker-compose.py # just wait keycloak to be load # may be you neeed 'pip install waiting'
python3 itests/wait-docker-compose.py           
('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer'))
...
HTTPConnectionPool(host='localhost', port=8080): Read timed out. (read timeout=1)
HTTPConnectionPool(host='localhost', port=8080): Read timed out. (read timeout=1)
Keycloak seems to be loaded
$ keycloak-scanner http://localhost:8080 --realms master --clients account --username admin --password Pa55w0rd 
$ # http://localhost:8080  # url to test 
$ #--realms master  # realms to scan, check if a realm exists and use this realms to further scans
$ #--clients account  # clients to scan, check if a client exists and use it to further scans
$ #--username admin  # add a username to test the auth process 
$ #--password Pa55w0rd  # password to test a password auth 
[INFO] Start scanner RealmScanner...
[INFO] Find realm master (http://localhost:8080/auth/realms/master)
[INFO] Public key for realm master : MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyF7ytt1AcJaN67GkLKNrPL6ljoTyYMzMFZ/fXmEJw52yvAXCqE2qFM4MH+fRDfzYcougyOIwNHbDqfAmKzKpeYGi+4JSaSmDGpZVuz2aDkncyXh6uA4IanjBai7IhEeWDY6HCcLxkd/ppfNclmfOrEGJGbFoz+QCFiNbWzSr0mAo1S3WmgC13297nK5iunR+eJSqCbg3FXn+8RZcwhNHhKSGV75G4ZnBDLcBcaEUflBWshv2gAErZktT0tdEtXNRpv4vAvp0yEvAKSPVOESpnZW7PFNtBPI/+GlaAWxEC9V58qzhiRTJ+MU3fzwcBMRz4DmptdSN6bDLvkPr5eS9JQIDAQAB
[INFO] Start scanner WellKnownScanner...
[INFO] Find a well known for realm Realm('master', 'http://localhost:8080/auth/realms/master', {'realm': 'master', 'public_key': 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyF7ytt1AcJaN67GkLKNrPL6ljoTyYMzMFZ/fXmEJw52yvAXCqE2qFM4MH+fRDfzYcougyOIwNHbDqfAmKzKpeYGi+4JSaSmDGpZVuz2aDkncyXh6uA4IanjBai7IhEeWDY6HCcLxkd/ppfNclmfOrEGJGbFoz+QCFiNbWzSr0mAo1S3WmgC13297nK5iunR+eJSqCbg3FXn+8RZcwhNHhKSGV75G4ZnBDLcBcaEUflBWshv2gAErZktT0tdEtXNRpv4vAvp0yEvAKSPVOESpnZW7PFNtBPI/+GlaAWxEC9V58qzhiRTJ+MU3fzwcBMRz4DmptdSN6bDLvkPr5eS9JQIDAQAB', 'token-service': 'http://localhost:8080/auth/realms/master/protocol/openid-connect', 'account-service': 'http://localhost:8080/auth/realms/master/account', 'tokens-not-before': 0}) http://localhost:8080/auth/realms/master/.well-known/openid-configuration
[INFO] Start scanner ClientScanner...
[INFO] Find a client for realm master: account
[INFO] Start scanner LoginScanner...
[+] LoginScanner - Form login work for admin on realm master, client account, (http://localhost:8080/auth/realms/master/account?session_state=4c152780-3980-439c-8e9d-15139ee19afa&code=2f821574-34e0-4917-8b00-c87c6fd302b0.4c152780-3980-439c-8e9d-15139ee19afa.3e118dc6-4780-42cf-90e7-abd81c1e7046)
[+] LoginScanner - Form login work for admin on realm master, client account, (http://localhost:8080/auth/realms/master/account?session_state=14a6cbcc-1b76-4b52-aa27-982a06b8c2a1&code=656fc3c9-3ea6-44af-9037-85288f471ab7.14a6cbcc-1b76-4b52-aa27-982a06b8c2a1.3e118dc6-4780-42cf-90e7-abd81c1e7046)
[INFO] Start scanner SecurityConsoleScanner...
[WARN] Result of SecurityConsoleScanner as no results (void list), subsequent scans can be void too.
[INFO] Start scanner OpenRedirectScanner...
[INFO] Start scanner FormPostXssScanner...
[INFO] Start scanner NoneSignScanner...
```

## scan types :

* realm : check if a realm exists
* client : check if a client exists in all realms
* well_known : get well_known for all realms
* login : test login against all clients / realms 
* client registration : try to add a new client (WARNING, client is deleted after test, if its not the case, be sure to make it manually)
* OpenRedirect : check if attack authorization flow via open redirection (unvalidated redirect_uri) is possible
* form post : check CVE 2018 14655 
* none sign : check if none sign algorithm is supported


## Help

```
$ keycloak-scanner --help
usage: keycloak-scanner [-h] --realms REALMS --clients CLIENTS [--proxy PROXY]

                        [--username USERNAME] [--password PASSWORD]

                        [--ssl-noverify] [--verbose] [--no-fail] [--fail-fast]

                        [--version]

                        (--registration-callback REGISTRATION_CALLBACK | --registration-callback-list REGISTRATION_CALLBACK_LIST)

                        base_url

KeyCloak vulnerabilities scanner.

positional arguments:

  base_url              URL to scan. ex http://localhost:8080

optional arguments:

  -h, --help            show this help message and exit

  --realms REALMS       Comma separated list of custom realms to test. ie :

                        master

  --clients CLIENTS     Comma separated list of custom clients to test. On

                        default installation, use account,admin-

                        cli,broker,realm-management,security-admin-console

  --proxy PROXY         Use a great proxy like BURP ;)

  --username USERNAME   If a username is specified, try to connect and attack

                        a token. If no password, try username as password.

  --password PASSWORD   password to test with username

  --ssl-noverify        Do not verify ssl certificates

  --verbose             Verbose mode

  --no-fail             Always exit with code 0 (by default, fail with an exit

                        code 4 if a vulnerability is discovered or 8 if an

                        error occur). Do NOT fail before all test are done.

  --fail-fast           Fail immediately if an error occur.

  --version             show program's version number and exit

  --registration-callback REGISTRATION_CALLBACK

                        Callback url to use on client registration test

  --registration-callback-list REGISTRATION_CALLBACK_LIST

                        File with one callback to test for registration by

                        line

Scans : 

- list realms

- Search well-known files

- Search for clients

- Search for valid logins

- Try client registration

- Search for security-admin-console and secret inside

- Search for open redirect via unvalidated redirect_uri

- Search for CVE-2018-14655 (reflected XSS)

- None alg in refresh token

Bugs, feature requests, request another scan, questions : https://github.com/NeuronAddict/keycloak-scanner.

*** Use it on production systems at your own risk ***

```


## Install with source code

With venv:

```
cd keycloak-scanner
python3 -m venv venv
source venv/bin/activate
pip install -e . # with -e, git pull will update code
keycloak-scanner
```

Or without venv :
```
cd keycloak-scanner
sudo pip3 install . # use sudo for install for all users
keycloak-scanner
```


## TODO

- password dictionary support
- Scanner details via command line
- 
