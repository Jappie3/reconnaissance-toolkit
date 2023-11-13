{
  description = "Ethical Hacking Toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
  }: let
    pkgs = import nixpkgs {
      system = "x86_64-linux";
    };
    python-packages = ps:
      with ps; [
        requests # HTTP library
        paramiko # native Python SSHv2 protocol library
        dnspython # DNS toolkit for Python
        scapy # network packet manipulation library
        python-nmap # nmap port scanner
        validators # data validation for humans™
        types-ipaddress # typing stubs for ipaddress
        #argh # argparse wrapper
      ];
  in {
    devShell.x86_64-linux = pkgs.mkShell {
      buildInputs = with pkgs; [
        python3
        black
        isort
        (pkgs.python3.withPackages python-packages)
      ];
    };
  };
}
