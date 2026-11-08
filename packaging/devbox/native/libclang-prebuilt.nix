{ lib, stdenvNoCC, fetchurl, zstd, autoPatchelfHook, zlib, stdenv }:
let
  archives = {
    x86_64-linux = {
      platform = "Linux-X64";
      hash = "sha256-wxBzhINfeIdo9hTbYQ6H+6cHfxJcqVDrAqeLqwowgGU=";
    };
    aarch64-linux = {
      platform = "Linux-ARM64";
      hash = "sha256-gwzrcO32OEnOZul7+FMQo78r3QTIYKny+k7xVg4pDO8=";
    };
    aarch64-darwin = {
      platform = "macOS-ARM64";
      hash = "sha256-UD3jDvkDEeCxQ2I4AbGa8iUK2sbWn67WWtAFEXAgLjs=";
    };
  };
  archive = archives.${stdenvNoCC.hostPlatform.system};
  licenseText = fetchurl {
    url = "https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-23.1.5/llvm/LICENSE.TXT";
    hash = "sha256-jYXBBX10Lll5hcfU5jILAVqROThc/0y64G/8Dr6Jr+4=";
  };
in stdenvNoCC.mkDerivation rec {
  pname = "libclang-prebuilt";
  version = "23.1.5";
  src = fetchurl {
    url = "https://github.com/llvm/llvm-project/releases/download/llvmorg-${version}/LLVM-${version}-${archive.platform}.tar.zst";
    inherit (archive) hash;
  };

  nativeBuildInputs = [ zstd ] ++ lib.optional stdenvNoCC.hostPlatform.isLinux autoPatchelfHook;
  # Official Linux libclang embeds LLVM; DT_NEEDED adds only libc, zlib and GCC runtimes.
  buildInputs = lib.optionals stdenvNoCC.hostPlatform.isLinux [ zlib stdenv.cc.cc.lib ];
  dontUnpack = true;
  dontBuild = true;
  dontStrip = true;
  # Preserve the upstream Mach-O bytes and signatures; Linux needs Nix library paths.
  dontFixup = stdenvNoCC.hostPlatform.isDarwin;

  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    tar --use-compress-program='zstd -d --long=30' -xf "$src" \
      --strip-components=1 -C "$out" --wildcards \
      ${if stdenvNoCC.hostPlatform.isDarwin then "'*/lib/libclang.dylib'" else "'*/lib/libclang.so*'"} \
      '*/lib/clang/23/include/*' '*/include/clang-c/*' \
      '*/include/llvm/Support/LICENSE.TXT'
    mkdir -p "$out/share/licenses/libclang"
    mv "$out/include/llvm/Support/LICENSE.TXT" "$out/share/licenses/libclang/Support-LICENSE.TXT"
    cp ${licenseText} "$out/share/licenses/libclang/LICENSE.TXT"
    runHook postInstall
  '';

  meta = {
    description = "Official prebuilt libclang for native bindgen";
    homepage = "https://github.com/llvm/llvm-project/releases/tag/llvmorg-${version}";
    license = [ lib.licenses.asl20 lib.licenses.llvm-exception ];
    platforms = builtins.attrNames archives;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
