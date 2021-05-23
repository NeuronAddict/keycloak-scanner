from termcolor import colored

verbose_mode = False

has_vuln = False
vulns = {}

def find(scan, msg):
    global has_vuln
    has_vuln = True
    if scan in vulns:
        vulns[scan].append(msg)
    else:
        vulns[scan] = [msg]
    print(colored('[VULNERABILITY] {}'.format(msg), color='red'))
