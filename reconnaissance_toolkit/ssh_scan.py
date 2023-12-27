import json
import logging
import os
import subprocess
from typing import Any, Dict, Union

from .targetdict import TargetDict


def main(t: TargetDict) -> Dict[str, Union[str, Dict[str, Any]]]:
    """
    Run ssh-audit against the target, only checks port 22.
    """
    l = logging.getLogger("logger")
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
    return {"ssh-audit": "Something went wrong"}
