{
  description = "A Nix-flake-based Rust development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = inputs: let
    supportedSystems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forEachSupportedSystem = f:
      inputs.nixpkgs.lib.genAttrs supportedSystems (system:
        f {
          pkgs = import inputs.nixpkgs {inherit system;};
        });

    overrides = builtins.fromTOML (builtins.readFile ./rust-toolchain.toml);
  in {
    devShells = forEachSupportedSystem ({pkgs}: {
      default = pkgs.mkShell {
        strictDeps = true;
        nativeBuildInputs = with pkgs; [
          rustup
          rustPlatform.bindgenHook
          lldb
          bpf-linker
        ];
        RUSTC_VERSION = overrides.toolchain.channel;
        # https://github.com/rust-lang/rust-bindgen#environment-variables
        shellHook = ''
          export PATH="''${CARGO_HOME:-~/.cargo}/bin":"$PATH"
          export PATH="''${RUSTUP_HOME:-~/.rustup}/toolchains/$RUSTC_VERSION-${pkgs.stdenv.hostPlatform.rust.rustcTarget}/bin":"$PATH"
        '';
      };
    });
  };
}
