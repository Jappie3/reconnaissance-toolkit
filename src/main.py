#!/usr/bin/env python

from scapy.all import *
import logging, socket, nmap, argparse, ipaddress, validators


verbose = False

global TARGETS
TARGETS=[]

def search_local_network(network):
    """
    Search a network for hosts by using ARP requests.
    Parameter: network to search
    Returns an array of dicts that contain both the IP and MAC address of the found hosts
    e.g. [{'ip': '127.0.0.2', 'mac': 'ff:ff:ff:ff:ff:ff'}, {...}, ...]
    """
    # create & send ARP packet
    arp_res = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        timeout=1,
        verbose=verbose,
    )[0]
    results = []
    # get IPs & MAC addresses from result
    for element in arp_res:
        results.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return results


def host_portscan(target_ip, port_range=(1, 1023)):
    """
    Scan a host for open ports by using TCP SYN packets
    Parameters: target ip & a port range (defaults to 0-1024)
    Returns an array of ports, e.g. [22, 53, 80, 443]
    """
    ports = []
    for port in range(port_range[0], port_range[1] + 1):
        # create & send TCP SYN packet
        response = sr1(
            IP(dst=target_ip) / TCP(sport=6666, dport=port, flags="S"),
            timeout=1,
            verbose=verbose,
        )
        # check if response is a TCP packet with the SYN-ACK flag set
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            ports.append(port)
    return ports


def host_detect_os(target_ip):
    """
    Detect the OS of the target IP using the Nmap library.
    Parameter: target_ip
    """
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-O")
    if target_ip in nm.all_hosts():
        os_info = nm[target_ip]["osmatch"]
        if os_info:
            return os_info[0]["name"]
        else:
            return "OS information not available"
    else:
        return "IP unreachable or invalid"


def validate_targets(targets):
    """
    Validate an array of targets
    Returns an array of JSON objects containing the target & the target type
    """
    LOG.info(f"Validating {len(targets)} targets...")
    for target in targets:
        if validators.domain(target):
            LOG.debug(f"Valid domain: {target}")
            TARGETS.append({"target":target,"type":"domain"})
        else:
            try:
                ipaddress.ip_address(target)
                TARGETS.append({"target":target,"type":"ip"})
                LOG.debug(f"Valid IP: {target}")
            except ValueError:
                LOG.error(
                    f"Invalid target: {target}\nThe list should only contain IP addresses (both IPv4 & IPv6) and domain names (without path or protocol)."
                )
                exit(1)


def init():
    """
    Parse arguments & set loglevel
    """
    parser = argparse.ArgumentParser()

    # optionally specify a single target - will later default to sourcing targets.txt for a list of targets
    parser.add_argument("--target", "-t", type=str, required=False)

    # optionally specify log level - default is WARNING
    parser.add_argument(
        "--log-level", "-l", default="WARNING", type=str, required=False, choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    )

    # optionally silence all output
    parser.add_argument("--silent", "-s", required=False, action='store_true')

    # optionally specify output file
    parser.add_argument("--output-file", "-o", type=str, required=False)

    # DEBUG ->    detailed information, only interesting when troubleshooting
    # INFO ->     confirm things are working as expected
    # WARNING ->  indication that something unexpected happened or some problem in the near future - software still works as expected
    # ERROR ->    serious problem, software was unable to perform some functions
    # CRITICAL -> serious error, program may be unable to continue running

    args = parser.parse_args()

    global TARGETS_RAW
    TARGETS_RAW = (
        [args.target]
        if args.target is not None
        else open("targets.txt", "r").read().splitlines()
    )

    if args.log_level in ["DEBUG", "INFO"]:
        # set scapy verbosity level
        verbose = True

    global LOG
    LOG = logging.getLogger("logger")
    LOG.setLevel(args.log_level)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # console handler - write log to stdout
    if not args.silent:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(args.log_level)
        console_handler.setFormatter(formatter)
        LOG.addHandler(console_handler)

    # file handler - write log to file
    if args.output_file:
        file_handler = logging.FileHandler(args.output_file)
        file_handler.setLevel(args.log_level)
        file_handler.setFormatter(formatter)
        LOG.addHandler(file_handler)

    LOG.info(f"Log level set to {args.log_level}")


def main():
    init()
    validate_targets(TARGETS_RAW)


if __name__ == "__main__":
    main()
