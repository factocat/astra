import argparse
from fingerprint import fingerprints as fp, detect, verify_CNAME

# Print the banner
with open('banner.txt') as banner:
    print(banner.read())


def process(domain, wordlist, thread, timeout, ssl, all, verbose, config, dead):
    domain_list = []
    if len(domain) > 0:
        domain_list.append(domain)
    else:
        with open(wordlist) as wordlist:
            domains = wordlist.readlines()
            domains = [_domain.rstrip() for _domain in domains]

    fingerprints = fp(config)

    for subdomain in domain_list:
        dns(subdomain, ssl, dead, timeout, verbose, fingerprints)


def dns(subdomain, ssl, manual, timeout, verbose, config):
    if all:
        detect(subdomain, ssl, verbose, manual, timeout, config)
    else:
        if verify_CNAME(subdomain, config):
            detect(subdomain, ssl, verbose, manual, timeout, config)


def main():
    parser = argparse.ArgumentParser(
        description='Astra - Subdmain Takeover Detection')
    parser.add_argument(
        "-d", "--domain", help="The domain to test", required=False)
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument(
        "-t", "--thread", help="Number of concurrent threads (Default: 10).",  default=10, type=int)
    parser.add_argument(
        "--timeout", help="Seconds to wait before connection timeout (Default: 10).", default=10)
    parser.add_argument(
        "--ssl", help="Force HTTPS connections (May increase accuracy (Default: http://).", default=False, action="store_true")
    parser.add_argument("-a", "--all", help="Find those hidden gems by sending requests to every URL. (Default: Requests are only sent to URLs with identified CNAMEs).",
                        default=False, action="store_true")
    parser.add_argument("-v", "--verbose", help="Display more information per each request.",
                        default=False, action="store_true")
    parser.add_argument(
        "-c", "--config", help="Path to configuration file.", default="domain_info.yaml")
    parser.add_argument("-m", "--dead", help="Flag the presence of a dead record, but valid CNAME entry.",
                        default=False, action="store_true")

    args = parser.parse_args()
    process(args.domain, args.wordlist, args.thread, args.timeout,
            args.ssl, args.all, args.verbose, args.config, args.dead)


if __name__ == "__main__":
    main()
