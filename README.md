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

## Scans

- list realms
- list clients
- search well know
- search secret in admin-secure
- search open redirection
- test auth with none alg
