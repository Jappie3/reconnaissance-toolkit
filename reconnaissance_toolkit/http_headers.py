import logging
from typing import Dict, Union

import requests

from .targetdict import TargetDict


def main(t: TargetDict) -> Dict[str, Dict[str, Union[list[str], str]]]:
    """
    Get a list of HTTP headers from the target's port 80 & 443.
    """
    l = logging.getLogger("logger")
    target = t["target"]
    l.debug(f"HTTP-headers - Starting scan for {target}")
    results = {"HTTP-headers": {}}

    # HTTP
    try:
        results["HTTP-headers"]["HTTP"] = dict(
            requests.get(f"http://{target}", verify=False).headers
        )

    except Exception as e:
        l.error(
            f"HTTP-headers - Something went wrong while trying to fetch HTTP headers from {target}: {e}"
        )
        results["HTTP-headers"]["HTTP"] = f"{e}"

    # HTTPS
    try:
        results["HTTP-headers"]["HTTPS"] = dict(
            requests.get(f"https://{target}", verify=False).headers
        )

    except Exception as e:
        l.error(
            f"HTTP-headers - Something went wrong while trying to fetch HTTPS headers from {target}: {e}"
        )
        results["HTTP-headers"]["HTTPS"] = f"{e}"

    l.debug(f"HTTP-headers - Finished scanning {target}")
    return results
