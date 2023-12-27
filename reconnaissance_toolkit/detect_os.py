import logging
from typing import Any, Dict, Union

import nmap

from .targetdict import TargetDict


def main(t: TargetDict) -> Dict[str, Union[str, Dict[str, Any]]]:
    """
    Try to detect the OS of the target using the Nmap library.
    """
    l = logging.getLogger("logger")
    target = t["target"]
    nm = nmap.PortScanner()
    l.debug(f"OS-detection - Starting scan for {target}")
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
    return {"OS-detection": "Something went wrong"}
