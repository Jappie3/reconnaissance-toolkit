{
  description = "Ethical Hacking Toolkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
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
        # HTTP library
        requests
        # network packet manipulation library
        scapy
      ];
  in {
    devShell.x86_64-linux = pkgs.mkShell {
      nativeBuildInputs = with pkgs; [
        python3
        black
        isort
        (pkgs.python3.withPackages python-packages)
      ];
    };
  };
}
