from dns_utilis import resolve_cname, nxdomain
from requests_helper import get
from available.checker import safe_domain

import yaml
from pathlib import Path

"""
Triage step to check whether the CNAME matches
the fingerprinted CNAME of a vulnerable cloud service.
"""

def fingerprints(filename = "domain_info.yaml"):
    return yaml.safe_load(Path(filename).read_text())

def verify_CNAME(subdomain, config=[]):
    cname = resolve_cname(subdomain)
    match = False

    for n in config:
        for c in config['cname']:
            if cname in c:
                match = True
                break

        if match:
            break

    return match


def detect(url, ssl, verbose, manual, timeout, config=[]):
    service = identify(url, ssl, manual, timeout, config)
    
    if service != "":
        result = f'[{service }] {url}'
        c = f"\u001b[32;1m{service}\u001b[0m"
        result = result.replace(service, c)

        print(result)


    if service == "" and verbose:
        result = f"[\u001b[31;1mNot Vulnerable\u001b[0m] {url}\n"
        print(result)


"""

This function aims to identify whether the subdomain
is attached to a vulnerable cloud service and able to
be taken over.

"""

def identify(subdomain, forceSSL, manual, timeout, fingerprints=[]):
    body = get(subdomain, forceSSL, timeout)

    cname = resolve_cname(subdomain)
    if len(cname) <= 3:
        cname = ""

    service = ""
    nx = nxdomain(subdomain)

    for f in fingerprints:

        # Begin subdomain checks if the subdomain returns NXDOMAIN
        if nx:

            # Check if we can register this domain.
            dead, _ = safe_domain(cname)
            if dead:
                service = "DOMAIN AVAILABLE - " + cname
                break

            # Check if subdomain matches fingerprinted cname
            if f.Nxdomain:
                for n in f['cname']:
                    if f['cname'] in cname:
                        service = f['service'].upper()
                        break


            # Option to always print the CNAME and not check if it's available to be registered.
            if manual and dead and cname != "" :
                service = "DEAD DOMAIN - " + cname
                break
        
        # Check if body matches fingerprinted response
        matches = False
        for n in f['response'] :
            body_str = str(body)  
            for r in f['response']:
                if r in body_str:
                    service =  f['service'].upper()
                    matches = True
                    break
            if matches:
                break

    return service
