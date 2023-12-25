{
  description = "Ethical Hacking Toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = {
    self,
    nixpkgs,
    flake-parts,
    ...
  } @ inputs: let
    python-packages = ps:
      with ps; [
        requests # HTTP library
        paramiko # native Python SSHv2 protocol library
        dnspython # DNS toolkit for Python
        #scapy # network packet manipulation library
        python-nmap # nmap port scanner
        validators # data validation for humans™
        types-ipaddress # typing stubs for ipaddress
        #argh # argparse wrapper
        pygments # syntax highlighter for e.g. json output
      ];
  in
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
      ];
      perSystem = {
        pkgs,
        system,
        ...
      }: {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            python3
            black
            isort
            (pkgs.python3.withPackages python-packages)
          ];
        };
      };
    };
}
