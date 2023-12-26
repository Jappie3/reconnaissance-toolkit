#!/usr/bin/env python3

import argparse
import ipaddress
import json
import logging
import os
import subprocess
from typing import Any, Dict, List, TypedDict, Union

import dns.dnssec
import dns.resolver
import dns.reversename
import nmap
import validators
from pygments import formatters, highlight, lexers

global TARGETS
TARGETS = []


class TargetDict(TypedDict):
    target: str
    type: str
    results: List


def ssh_audit(t: TargetDict, l: logging.Logger) -> Dict[str, Dict[str, Any]]:
    target = t["target"]
    l.debug(f"ssh-audit - Starting scan for {target}")
    try:
        shell = os.environ.get("SHELL")
    except Exception as e:
        l.error(f"ssh-audit - Could not retrieve shell from SHELL env var: {e}")
    else:
        try:
            result = subprocess.run(
                f"ssh-audit {target} --json",
                shell=True,
                executable=shell,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            l.debug(f"ssh-audit - Finished scan for {target}")
            return {"ssh-audit": json.loads(result.stdout)}
        except Exception as e:
            l.error(f"ssh-audit - Something went wrong while running ssh-audit: {e}")


def port_scan(t: TargetDict, l: logging.Logger) -> Dict[str, Dict[str, Any]]:
    """
    Perform a port scan on a target using the Nmap library.
    """
    target = t["target"]
    l.debug(f"port-scan - Starting scan for {target}")
    nm = nmap.PortScanner()

    try:
        nm.scan(target, arguments="-p-", sudo=True)
    except Exception as e:
        l.error(f"port-scan - Something went wrong while trying to scan {target}: {e}")
    else:
        if target in nm.all_hosts():
            host = nm[target]
            l.debug(f"port-scan - Finished scan for {target}")
            return {
                "port-scan": {
                    "vendor": host["vendor"],
                    "status": host["status"],
                    "open_ports": [
                        port
                        for port in host["tcp"].keys()
                        if host["tcp"][port]["state"] == "open"
                    ],
                    "tcp_ports": host["tcp"],
                }
            }
        else:
            return {"port-scan": "IP unreachable or invalid"}


def detect_os(t: TargetDict, l: logging.Logger) -> Dict[str, Dict[str, Any]]:
    """
    Try to detect the OS of the target using the Nmap library.
    """
    target = t["target"]
    nm = nmap.PortScanner()
    l.debug(
        f"OS-detection - Running OS scan against {target}, will request root privileges if necessary..."
    )
    try:
        nm.scan(target, arguments="-O", sudo=True)
    except Exception as e:
        l.error(
            f"OS-detection - Something went wrong while trying to scan {target}: {e}"
        )
    else:
        if target in nm.all_hosts():
            os_info = nm[target]["osmatch"]
            if os_info:
                l.debug(f"OS-detection - Finished scanning {target}")
                return {
                    "OS-detection": {
                        "name": os_info[0]["name"],
                        "accuracy": os_info[0]["accuracy"],
                    }
                }
            else:
                return {"OS-detection": "OS information not available"}
        else:
            return {"OS-detection": "IP unreachable or invalid"}


def dns_lookup(
    t: TargetDict, l: logging.Logger
) -> Dict[str, Dict[str, Union[list[str], str]]]:
    """
    Retrieve information about a target via DNS
    The resolver to be used is stored in the global variable DNS_RESOLVER
    """
    target = t["target"]
    type = t["type"]
    resolver = dns.resolver.make_resolver_at(os.getenv("DNS_RESOLVER", "9.9.9.9"))
    qname = dns.name.from_text(target)
    results = {"DNS": {}}
    if type == "domain":
        # domain -> look up some records & append them to results['DNS']
        l.debug(f"DNS - Scanning domain: {target}")
        for record in [
            dns.rdatatype.NS,
            dns.rdatatype.A,
            dns.rdatatype.AAAA,
            dns.rdatatype.TXT,
            dns.rdatatype.MX,
        ]:
            try:
                recs = resolver.resolve(qname, record)
                results["DNS"][dns.rdatatype.to_text(record)] = [str(r) for r in recs]
            except Exception as e:
                l.error(f"DNS - {target}: {e}")

        # look up NS & get NS IP
        l.debug(f"DNS - Checking & validating DNSSEC for: {target}")

        # get IP of NS
        try:
            # get NS record for target
            nameserver_ns = resolver.resolve(qname, dns.rdatatype.NS)
            # get A record for the domain of the nameserver
            nameserver_ip = (
                resolver.resolve(
                    nameserver_ns.rrset[0].to_text(),
                    dns.rdatatype.A,
                )
                .rrset[0]
                .to_text()
            )
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ) as e:
            l.error(f"DNS - Error while checking NS records for {target}: {e}")

        # validate DNSSEC
        try:
            ns_response = dns.query.udp(
                # get DNSKEY for the zone
                dns.message.make_query(qname, dns.rdatatype.DNSKEY, want_dnssec=True),
                # send query to nameserver's IP
                nameserver_ip,
            )
            # answer should contain DNSKEY and RRSIG(DNSKEY)
            if len(ns_response.answer) != 2:
                raise Exception("NS response did not contain DNSKEY and/or RRSIG")
            # validate DNSKEY & RRSIG
            dns.dnssec.validate(
                ns_response.answer[0],
                ns_response.answer[1],
                {qname: ns_response.answer[0]},
            )
            # check parent zone for a DS record (mandatory for DNSSEC)
            parent_zone = ".".join(target.split(".")[-2:])
            parent_ds = resolver.resolve(parent_zone, dns.rdatatype.DS)
            if parent_ds:
                # if we get to this point wo/ errors -> DNSSEC is valid
                results["DNS"]["DNSSEC"] = True
            else:
                raise Exception(f"no DS record found in parent zone of {target}")

        except Exception as e:
            results["DNS"]["DNSSEC"] = False
            l.error(f"DNS - Error while validating DNSSEC for {target}: {e}")

    elif type == "ip":
        # IP -> look up reverse DNS for the host & append to results['DNS']
        l.debug(f"DNS - Scanning IP: {target}")
        addr = dns.reversename.from_address(target)
        results["DNS"]["RDNS"] = {
            "IP": str(addr),
            "FQDN": str(resolver.resolve(addr, "PTR")[0]),
        }
    else:
        # this should never happen but still
        l.error(f"DNS - not an IP or domain, can't scan: {target}")
    l.debug(f"DNS - Finished scanning {target}")
    return results


# dictionary to map strings used in arguments (--scans) to function definitions
SCANS_MAP = {
    "dns-lookup": dns_lookup,
    "detect-os": detect_os,
    "port-scan": port_scan,
    "ssh-audit": ssh_audit,
}


def validate_targets(targets: List, l: logging.Logger) -> None:
    """
    Validate an array of targets
    """
    targets_res = []
    l.info(f"Validating {len(targets)} targets...")
    for target in targets:
        if validators.domain(target):
            l.debug(f"Valid domain: {target}")
            targets_res.append({"target": target, "type": "domain", "results": []})
        else:
            try:
                ipaddress.ip_address(target)
                targets_res.append({"target": target, "type": "ip", "results": []})
                l.debug(f"Valid IP: {target}")
            except ValueError:
                l.error(
                    f"Invalid target: {target}\nThe list should only contain IP addresses (both IPv4 & IPv6) and domain names (without path or protocol)."
                )
                exit(1)
    return targets_res


def init() -> logging.Logger:
    """
    Parse arguments & set necessary variables
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "scans",
        type=str,
        nargs="+",
        choices=SCANS_MAP.keys(),
        help="define which scan(s) to run on the target(s)",
    )
    parser.add_argument(
        "-t",
        "--target",
        metavar="127.0.0.1",
        type=str,
        required=False,
        help="specify a single target to scan - IP or domain. If you want to scan a list of targets, use targets.txt",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        metavar="out.json",
        type=str,
        required=False,
        help="file to which the output should be written",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        metavar="DEBUG",
        default="WARNING",
        type=str,
        required=False,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="specifies the log level (verbosity) of the program",
    )
    parser.add_argument(
        "-L",
        "--log-file",
        metavar="out.log",
        type=str,
        required=False,
        help="if provided, the logs will be written to the file specified. Note: this does not imply --silent",
    )
    parser.add_argument(
        "--dns-resolver",
        metavar="9.9.9.9",
        default="9.9.9.9",
        type=str,
        required=False,
        help="the DNS resolver to use for lookups (default: 9.9.9.9)",
    )
    parser.add_argument(
        "-s",
        "--silent",
        required=False,
        action="store_true",
        help="do not output anything to STDOUT",
    )

    # DEBUG ->    detailed information, only interesting when troubleshooting
    # INFO ->     confirm things are working as expected
    # WARNING ->  indication that something unexpected happened or some problem in the near future - software still works as expected
    # ERROR ->    serious problem, software was unable to perform some functions
    # CRITICAL -> serious error, program may be unable to continue running

    args = parser.parse_args()

    targets = (
        [args.target]
        if args.target is not None
        else open("targets.txt", "r").read().splitlines()
    )

    scans = args.scans
    output_file = args.output_file
    silent = args.silent

    # set as env var so it can be used in imported files as well
    os.environ["DNS_RESOLVER"] = args.dns_resolver

    log = logging.getLogger("logger")
    log.setLevel(args.log_level)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    if not args.silent:
        # console handler - write log to stdout
        console_handler = logging.StreamHandler()
        console_handler.setLevel(args.log_level)
        console_handler.setFormatter(formatter)
        log.addHandler(console_handler)

    # file handler - write log to file
    if args.log_file:
        if os.path.exists(args.log_file):
            log.critical(
                f"Error: file {args.log_file} exists. Either remove it or specify a different log file."
            )
            exit(1)
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(args.log_level)
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)

    log.info(f"Log level set to {args.log_level}")

    if args.output_file and os.path.exists(args.output_file):
        log.critical(
            f"Error: file {args.output_file} exists. Either remove it or specify a different output file."
        )
        exit(1)

    return targets, scans, log, output_file, silent


def main() -> None:
    targets_txt, scans, log, output_file, silent = init()
    targets = validate_targets(targets_txt, log)

    # for every scan the user specified
    for scan in scans:
        log.info(f"Main - processing scan: {scan}...")
        # TODO use threading (maybe a pool) to start a bunch of scans at the same time
        # also make an option to stay single-threaded to prevent detection?
        # run the scan for every target
        for i in range(0, len(targets)):
            targets[i]["results"].append(SCANS_MAP[scan](targets[i], log))

    log.info(f"Main - All scans processed, handling output...")

    log.debug(f"Main - Result of scans: {targets}")

    if not silent:
        log.info(f"Main - printing to STDOUT")
        print(
            highlight(
                json.dumps(targets, indent=2),
                lexers.JsonLexer(),
                formatters.TerminalFormatter(),
            )
        )

    if output_file:
        log.info(f"Main - Writing output to file...")
        with open(output_file, "w") as f:
            f.write(
                json.dumps(targets),
            )

    log.info(f"Main - Program done, exiting...")
    exit(0)


if __name__ == "__main__":
    main()
