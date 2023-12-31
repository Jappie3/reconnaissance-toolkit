import argparse
import ipaddress
import json
import logging
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, NoReturn, Optional, Tuple

import validators
from pygments import formatters, highlight, lexers
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import detect_os, dns_lookup, http_headers, port_scan, ssh_scan
from .targetdict import TargetDict

# dictionary to map strings passed in as arguments to function definitions
SCANS_MAP = {
    "dns-lookup": dns_lookup.main,
    "detect-os": detect_os.main,
    "port-scan": port_scan.main,
    "ssh-audit": ssh_scan.main,
    "http-headers": http_headers.main,
}

progress = Progress(
    TextColumn("[bold blue]{task.description}{task.fields[scan]}", justify="left"),
    BarColumn(bar_width=None),
    "Target {task.completed}/{task.total}" "•",
    TaskProgressColumn(),
    "•",
    TimeElapsedColumn(),
)


def validate_targets(targets: List) -> List[TargetDict]:
    """
    Validate an array of targets
    """
    l = logging.getLogger("logger")
    targets_res = []
    l.info(f"Validating {len(targets)} targets...")
    for target in targets:
        if target == "":
            continue
        if validators.domain(target):
            l.debug(f"Valid domain: {target}")
            targets_res.append({"target": target, "type": "domain", "results": []})
        else:
            try:
                ipaddress.ip_address(target)
                targets_res.append({"target": target, "type": "ip", "results": []})
                l.debug(f"Valid IP: {target}")
            except ValueError:
                l.warning(
                    f"Invalid target: skipping {target}. The list of targets should only contain IP addresses (both IPv4 & IPv6) and domain names (without path, protocol or port)."
                )
    l.info(f"Validated {len(targets)} targets")
    return targets_res


def init() -> Tuple[List, List, bool, Optional[str]]:
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

    logging.basicConfig(
        level=args.log_level if not args.silent else "CRITICAL",
        handlers=[RichHandler(level="NOTSET")],
    )

    logging.captureWarnings(True)

    # file handler - write log to file
    if args.log_file:
        if os.path.exists(args.log_file):
            log.critical(
                f"Error: file {args.log_file} exists. Either remove it or specify a different log file."
            )
            exit(1)
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setLevel(args.log_level)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        log.addHandler(file_handler)

    log.info(f"Log level set to {args.log_level}")

    if args.output_file and os.path.exists(args.output_file):
        log.critical(
            f"Error: file {args.output_file} exists. Either remove it or specify a different output file."
        )
        exit(1)

    return targets, scans, silent, output_file


def scan_target(task_id: TaskID, targets, scan) -> None:
    progress.start_task(task_id)
    log = logging.getLogger("logger")
    log.info(f"Main - Processing scan: {scan}...")
    # run the scan against every target in the list
    for i in range(0, len(targets)):
        targets[i]["results"].append(SCANS_MAP[scan](targets[i]))
        # update the progress bar
        progress.update(task_id, advance=1, done=i + 1)


def main() -> NoReturn:
    targets_txt, scans, silent, output_file = init()
    log = logging.getLogger("logger")
    targets = validate_targets(targets_txt)

    # for scans that require sudo -> ask password now, since scan will run in a separate threat without TTY access
    try:
        log.info(f"Main - Checking if root privileges should be requested")
        if any(s in scans for s in ["detect-os", "port-scan"]):
            log.info(f"Main - Requesting root privileges...")
            shell = os.environ.get("SHELL")
            subprocess.run(
                # we just need to run any sudo command so that the scan(s) won't prompt for a password again
                f"sudo whoami > /dev/null 2>&1",
                shell=True,
                executable=shell,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            log.info(f"Main - Root privileges requested successfully")
    except Exception as e:
        log.critical(f"Main - Could not retrieve shell from SHELL env var: {e}")
        exit(1)

    futures = []
    with progress:
        # with statement -> ensure all threads are cleaned up properly
        with ThreadPoolExecutor(max_workers=4) as pool:
            # for all scans the user specified
            for scan in scans:
                task_id = progress.add_task(
                    "Running scan - ",
                    scan=scan,
                    total=len(targets),
                    start=False,
                    visible=not silent,
                )
                # start a new threat that will run the scan against every target
                futures.append(pool.submit(scan_target, task_id, targets, scan))

    # wait for all the scans to complete
    as_completed(futures)

    log.info(f"Main - All scans processed, handling output...")

    log.debug(f"Main - Result of scans: {targets}")

    if not silent:
        log.info(f"Main - Printing to STDOUT")
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
    try:
        main()
    except Exception as e:
        log = logging.getLogger(__name__)
        log.fatal(e)
        raise
