import logging
import os
from typing import Dict, List, TypedDict, Union

import dns.dnssec
import dns.resolver
import dns.reversename


class TargetDict(TypedDict):
    target: str
    type: str
    results: List


def dns_lookup(
    t: TargetDict, l: logging.Logger
) -> Dict[str, Dict[str, Union[list[str], str]]]:
    """
    Retrieve information about a target via DNS
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