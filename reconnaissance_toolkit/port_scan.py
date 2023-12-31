import logging
from typing import Any, Dict, Union

import nmap

from .targetdict import TargetDict


def main(t: TargetDict) -> Dict[str, Union[str, Dict[str, Any]]]:
    """
    Perform a port scan on a target using the Nmap library.
    """
    l = logging.getLogger("logger")
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
    return {"port-scan": "Something went wrong"}
