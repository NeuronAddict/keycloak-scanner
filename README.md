# keycloack-scanner

## Introduction

This scanner scan openid for known vulnerabilities

## example
```
keycloak-scanner http://localhost:8080 \ # url to test
--realms myorganisation \ # realms to scan
--clients mobile,webapp \ # clients to scan
--username tester@neuronaddict.org \ # add a username to test the auth process
--password P455w0rd \ # password to test a password auth
--fail-on-vuln \ # fail with an error code after tests if vulns
--proxy http://localhost:8080 \ # to usee a great proxy like burp :)
--ssl-noverify \ # don't check ssl certificates
```

## help

```
$ ./keycloak-scanner --help
usage: keycloak-scanner [-h] [--realms REALMS] [--clients CLIENTS]
                        [--proxy PROXY] [--username USERNAME]
                        [--password PASSWORD] [--ssl-noverify] [--verbose]
                        [--fail-on-vuln]
                        base_url

KeyCloak vulnerabilities scanner.

positional arguments:
  base_url             URL to scan. ex http://localhost:8080

optional arguments:
  -h, --help           show this help message and exit
  --realms REALMS      Comma separated list of custom realms to test
  --clients CLIENTS    Comma separated list of custom clients to test
  --proxy PROXY        Use a great proxy like BURP ;)
  --username USERNAME  If a username is specified, try to connect and attack a
                       token. If no password, try username as password.
  --password PASSWORD  password to test with username
  --ssl-noverify       Do not verify ssl certificates
  --verbose            Verbose mode
  --fail-on-vuln       fail with an exit code 4 if a vulnerability is
                       discovered. Do NOT fail before all test are done.

By default, master realm is already tested.
Clients always tested : account, admin-cli, broker, realm-management, security-admin-console.

Scans : 
- list realms
- Search well-known files
- Search for clients
- Search for security-admin-console and secret inside
- Search for open redirect via unvalidated redirect_uri
- Search for CVE-2018-14655 (reflected XSS)
- None alg in refresh token

Bugs, feature requests, request another scan, questions : https://github.com/NeuronAddict/keycloak-scanner.

*** Use it on production systems at your own risk ***
```

