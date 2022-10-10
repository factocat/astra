from dns.resolver import resolve, NoAnswer, NXDOMAIN
from dns.rdatatype import CNAME
from dns.rdatatype import NS as NAMSERVER

from available.checker import safe_domain

import socket


def resolve_cname(domain):
    try:
        answer = resolve(domain, CNAME)
    except (NoAnswer, NXDOMAIN):
        print(f'CNAME record not found for {domain}')
        return ""

    cname = ""
    for rdata in answer:
        cname = rdata.target if rdata.target else None

    return cname


def nslookup(domain):
    try:
        answers = resolve(domain, NAMSERVER)
    except (NoAnswer, NXDOMAIN):
        print(f'NS record not found for {domain}')
        return []

    nameservers = []
    for answer in answers:
        nameservers.append(answer.target.to_text())

    return nameservers


def nxdomain(nameserver):
    try:
        socket.gethostbyaddr(nameserver)
    except Exception as err:
        if "nodename nor servname provided, or not known" in str(err):
            return True

    return False

def NS(domain, verbose = False):
    namservers = nslookup(domain)
    for ns in namservers:
        if verbose:
            print(f"[*] {domain}: Nameserver is {ns}\n")
		
        if nxdomain(ns):
            available, _ = safe_domain(ns)

            if available:
                print("[!] {domain}'s nameserver: {ns} is available for purchase!\n")