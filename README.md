# Reconnaissance Toolkit 

Small collection of Python scripts for reconnaissance and scanning of IPs & domains.<br>

**Use at your own risk**, scanning / probing systems without authorization may get you in trouble.

## Usage

Run `reconnaissance-toolkit --help` to get started.<br>

First, specify the scan(s) you want to run, e.g. `reconnaissance-toolkit port-scan ssh-audit`. Targets can be specified in `targets.txt` or, if you have a single target, using `--target [IP|domain]`. The json output can be written to a file using `--output-file [file]`.<br>

Verbosity can be adjusted using `--log-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]` & the log can be written to a file using `--log-file [file]`. Logs can be silenced with `-s`.<br>

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
