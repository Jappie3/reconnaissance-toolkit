# Reconnaissance Toolkit 

Small collection of Python scripts for reconnaissance and scanning of IPs & domains.<br>

**Use at your own risk**, scanning / probing systems without authorization may get you in trouble.

## Features

- Validation of targets before running scans
- Multithreading for running multiple scans simultaneously
- Progress bars & colorful output using the [Rich library](https://github.com/Textualize/rich)
- Option to save JSON output to a file
- Option to save logs to a file & to adjust the log level
- Scans:
    - `detect-os` -> use Nmap to try & detect the OS of the target
    - `port-scan` -> use Nmap to find open TCP ports
    - `ssh-audit` -> run ssh-audit against the target
    - `dns-lookup` get some common records (NS, A, AAAA, TXT, MX) & validate DNSSEC if the target is a domain. If the target is an IP, try an RDNS lookup to find a PTR record & the FQDN associated with the target

## Usage

Run `reconnaissance-toolkit --help` to get started.<br>

First, specify the scan(s) you want to run, e.g. `reconnaissance-toolkit port-scan ssh-audit`. Targets can be specified in `targets.txt` or, if you have a single target, using `--target [IP|domain]`. The json output can be written to a file using `--output-file [file]`.<br>

Verbosity can be adjusted using `--log-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]` & the log can be written to a file using `--log-file [file]`. Logs to stdout can be silenced with `-s`.<br>

## Installation

To install, you can import this flake (NixOS only) or clone the source (see [#hacking](#hacking)). To import the flake, add this repo as an input:

```nix
reconnaissance-toolkit.url = "github:jappie3/reconnaissance-toolkit";
```

Then add the following to your `environment.systemPackages`:

```nix
inputs.reconnaissance-toolkit.packages.${pkgs.system}.default
```

## Hacking

Clone this repo & run `nix develop` (if on [NixOS](https://nixos.org)) or `direnv allow` (assuming [direnv](https://direnv.net/) is installed) to enter a dev shell with all required dependencies. Alternatively, see `flake.nix` for a list of Python packages if you use neither of these methods.

Once you cloned the source, use `python -m reconnaissance_toolkit --help` to run the code.
