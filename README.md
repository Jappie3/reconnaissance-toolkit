# Reconnaissance Toolkit 

Small collection of Python scripts for reconnaissance and scanning of IPs & domains.<br>

**Use at your own risk**, scanning / probing systems without authorization may get you in trouble.

## Usage

Run `reconnaissance-toolkit --help` to get started.

## Installation

To install, you can import this flake (NixOS only) or clone the source (see below). To import the flake, add this repo as an input:

```nix
reconnaissance-toolkit.url = "github:jappie3/reconnaissance-toolkit";
```

Then add the following to your `environment.systemPackages`:

```nix
inputs.reconnaissance-toolkit.packages.${pkgs.system}.default
```

## Hacking

Clone this repo & run `nix develop` (if on [NixOS](https://nixos.org)) or `direnv allow` (if you use [direnv](https://direnv.net/)) to enter a dev shell with all required dependencies. Alternatively, see `flake.nix` for a list of Python packages if you use neither of these methods.
