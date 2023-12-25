#!/usr/bin/env python3

import argparse
import ipaddress
import json
import logging
import os
import subprocess
from typing import Any, Dict, List, NoReturn, TypedDict, Union

import dns.dnssec
import dns.resolver
import dns.reversename
import nmap
import validators
from pygments import formatters, highlight, lexers

verbose = False

global TARGETS
TARGETS = []


class TargetDict(TypedDict):
    target: str
    type: str
    results: List


def ssh_audit(t: TargetDict) -> Dict[str, Dict[str, Any]]:
    target = t["target"]
    LOG.info(f"ssh-audit - Starting scan for {target}")
    try:
        shell = os.environ.get("SHELL")
    except Exception as e:
        LOG.error(f"ssh-audit - Could not retrieve shell from SHELL env var: {e}")
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
            LOG.info(f"ssh-audit - Finished scan for {target}")
            return {"ssh-audit": json.loads(result.stdout)}
        except Exception as e:
            LOG.error(f"ssh-audit - Something went wrong while running ssh-audit: {e}")


def port_scan(
    t: TargetDict,
) -> Dict[str, Dict[str, Any]]:
    """
    Perform a port scan on a target using the Nmap library.
    """
    target = t["target"]
    LOG.info(f"port-scan - Starting scan for {target}")
    nm = nmap.PortScanner()

    try:
        nm.scan(target, arguments="-p-", sudo=True)
    except Exception as e:
        LOG.error(
            f"port-scan - Something went wrong while trying to scan {target}: {e}"
        )
    else:
        if target in nm.all_hosts():
            host = nm[target]
            LOG.info(f"port-scan - Finished scan for {target}")
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


def detect_os(t: TargetDict) -> Dict[str, Dict[str, Any]]:
    """
    Try to detect the OS of the target using the Nmap library.
    """
    target = t["target"]
    nm = nmap.PortScanner()
    LOG.info(
        f"OS-detection - Running OS scan against {target}, will request root privileges if necessary..."
    )
    try:
        nm.scan(target, arguments="-O", sudo=True)
    except Exception as e:
        LOG.error(
            f"OS-detection - Something went wrong while trying to scan {target}: {e}"
        )
    else:
        if target in nm.all_hosts():
            os_info = nm[target]["osmatch"]
            if os_info:
                LOG.info(f"OS-detection - Finished scanning {target}")
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


def dns_lookup(t: TargetDict) -> Dict[str, Dict[str, Union[list[str], str]]]:
    """
    Retrieve information about a target via DNS
    The resolver to be used is stored in the global variable DNS_RESOLVER
    """
    target = t["target"]
    type = t["type"]
    resolver = dns.resolver.make_resolver_at(DNS_RESOLVER)
    qname = dns.name.from_text(target)
    results = {"DNS": {}}
    if type == "domain":
        # domain -> look up some records & append them to results['DNS']
        LOG.info(f"DNS - Scanning domain: {target}")
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
                LOG.error(f"DNS - {target}: {e}")

        # look up NS & get NS IP
        LOG.info(f"DNS - Checking & validating DNSSEC for: {target}")

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
            LOG.error(f"DNS - Error while checking NS records for {target}: {e}")

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
            LOG.error(f"DNS - Error while validating DNSSEC for {target}: {e}")

    elif type == "ip":
        # IP -> look up reverse DNS for the host & append to results['DNS']
        LOG.info(f"DNS - Scanning IP: {target}")
        addr = dns.reversename.from_address(target)
        results["DNS"]["RDNS"] = {
            "IP": str(addr),
            "FQDN": str(resolver.resolve(addr, "PTR")[0]),
        }
    else:
        # this should never happen but still
        LOG.error(f"DNS - not an IP or domain, can't scan: {target}")
    LOG.info(f"DNS - Finished scanning {target}")
    return results


# dictionary to map strings used in arguments (--scans) to function definitions
SCANS_MAP = {
    "dns-lookup": dns_lookup,
    "detect-os": detect_os,
    "port-scan": port_scan,
    "ssh-audit": ssh_audit,
}


def validate_targets(targets: List) -> None:
    """
    Validate an array of targets
    """
    LOG.info(f"Validating {len(targets)} targets...")
    for target in targets:
        if validators.domain(target):
            LOG.debug(f"Valid domain: {target}")
            TARGETS.append({"target": target, "type": "domain", "results": []})
        else:
            try:
                ipaddress.ip_address(target)
                TARGETS.append({"target": target, "type": "ip", "results": []})
                LOG.debug(f"Valid IP: {target}")
            except ValueError:
                LOG.error(
                    f"Invalid target: {target}\nThe list should only contain IP addresses (both IPv4 & IPv6) and domain names (without path or protocol)."
                )
                exit(1)


def init() -> None:
    """
    Parse arguments & set necessary variables
    """
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "scans",
        type=str,
        nargs="+",
        choices=SCANS_MAP.keys(),
        help="Define which scan(s) to run on the target(s).",
    )
    parser.add_argument(
        "--target",
        "-t",
        type=str,
        required=False,
        help="Specify a single target to scan - IP or domain. If you want to scan a list of targets, use targets.txt.",
    )
    parser.add_argument(
        "--output-file",
        "-o",
        metavar="out.json",
        type=str,
        required=False,
        help="File to which the output should be written.",
    )
    parser.add_argument(
        "--log-level",
        "-l",
        metavar="",
        default="WARNING",
        type=str,
        required=False,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Specifies the log level (verbosity) of the program",
    )
    parser.add_argument(
        "--log-file",
        "-L",
        metavar="out.log",
        type=str,
        required=False,
        help="If provided, the logs will be written to the file specified. Note: this does not imply --silent.",
    )
    parser.add_argument(
        "--silent",
        "-s",
        required=False,
        action="store_true",
        help="Do not output anything to STDOUT.",
    )
    parser.add_argument(
        "--dns-resolver",
        metavar="",
        default="9.9.9.9",
        type=str,
        required=False,
        help="The DNS resolver to use for lookups",
    )

    # DEBUG ->    detailed information, only interesting when troubleshooting
    # INFO ->     confirm things are working as expected
    # WARNING ->  indication that something unexpected happened or some problem in the near future - software still works as expected
    # ERROR ->    serious problem, software was unable to perform some functions
    # CRITICAL -> serious error, program may be unable to continue running

    args = parser.parse_args()

    global TARGETS_TXT
    TARGETS_TXT = (
        [args.target]
        if args.target is not None
        else open("targets.txt", "r").read().splitlines()
    )

    global SCANS
    SCANS = args.scans

    global OUTPUT_FILE
    OUTPUT_FILE = args.output_file

    global DNS_RESOLVER
    DNS_RESOLVER = args.dns_resolver

    global SILENT
    SILENT = args.silent

    if args.log_level in ["DEBUG", "INFO"]:
        # set scapy verbosity level
        verbose = True

    global LOG
    LOG = logging.getLogger("logger")
    LOG.setLevel(args.log_level)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    if not args.silent:
        # console handler - write log to stdout
        console_handler = logging.StreamHandler()
        console_handler.setLevel(args.log_level)
        console_handler.setFormatter(formatter)
        LOG.addHandler(console_handler)
    else:
        # disable all logging
        logging.disable(logging.CRITICAL)

    # file handler - write log to file
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(args.log_level)
        file_handler.setFormatter(formatter)
        LOG.addHandler(file_handler)

    LOG.info(f"Log level set to {args.log_level}")


def main() -> NoReturn:
    init()
    validate_targets(TARGETS_TXT)

    # for every scan the user specified with --scans
    for scan in SCANS:
        # TODO use threading (maybe a pool) to start a bunch of scans at the same time
        # also make an option to stay single-threaded to prevent detection?
        # run the scan for every target
        for i in range(0, len(TARGETS)):
            TARGETS[i]["results"].append(SCANS_MAP[scan](TARGETS[i]))

    if not SILENT:
        print(
            highlight(
                json.dumps(TARGETS, indent=2),
                lexers.JsonLexer(),
                formatters.TerminalFormatter(),
            )
        )


if __name__ == "__main__":
    main()
