{
  description = "Current native build inputs missing from the Devbox index";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/c4baab4dfb6397c20425c30441a93edf702cd1b3";
  # The OpenSSL input already has Python 3.15.2; retain the selected 3.15.0 source.
  inputs.pythonNixpkgs.url = "github:NixOS/nixpkgs/4fe25e12eb9f4c744966dd3de5a05246cf098601";

  outputs = { nixpkgs, pythonNixpkgs, ... }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
    in {
      packages = nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (final: prev: {
              # Keep libclang and its LLVM dependency on the same stable release.
              llvmPackages_23 = prev.llvmPackages_23.override {
                version = "23.1.5";
                # This libclang output parses native Ruby headers for bindgen;
                # it is not the project's general-purpose cross compiler.
                devExtraCmakeFlags = [
                  (final.lib.cmakeFeature "LLVM_TARGETS_TO_BUILD" "Native")
                ];
                monorepoSrc = final.runCommand "llvm-project-23.1.5-source" {
                  nativeBuildInputs = [ final.xz ];
                  passthru = {
                    owner = "llvm";
                    repo = "llvm-project";
                    rev = "llvmorg-23.1.5";
                  };
                } ''
                  mkdir -p "$out"
                  tar -xJf ${final.fetchurl {
                    url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-23.1.5/llvm-project-23.1.5.src.tar.xz";
                    hash = "sha256-+1Cx6sk93rOqjatM/jJN/3T0qcK97mFgyeNhiPjQam4=";
                  }} --strip-components=1 -C "$out"
                '';
              };
            }) ];
          };
          pythonPkgs = import pythonNixpkgs { inherit system; };
          python = pythonPkgs.python315.override {
            packageOverrides = _final: prev: {
              pyelftools = prev.pyelftools.overridePythonAttrs (_old: rec {
                version = "0.33";
                src = pkgs.fetchPypi {
                  pname = "pyelftools";
                  inherit version;
                  sha256 = "660d82dcbeb8e83d1702bd97f223f761625da06111c0cc988eac6b8ab0c1b61f";
                };
              });
            };
          };
        in {
          openssl = pkgs.openssl_4_1;
          python = python.withPackages (ps: [ ps.pyelftools ]);
        } // nixpkgs.lib.optionalAttrs (system != "x86_64-darwin") {
          # Native bindgen tooling supports Linux and Apple Silicon development.
          libclang = pkgs.llvmPackages_23.libclang;
        });
    };
}
