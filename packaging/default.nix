# SPDX-License-Identifier: GPL-3.0-or-later
#
# Nix derivation for Vault — terminal-native Bitwarden client (Standard §5.5).
#
# Two ways in:
#
#   nix build                          # via flake.nix, builds this checkout
#   nix-build packaging/default.nix    # release build from the tagged tarball
#
# The flake passes `srcOverride = self`, skipping the fetchFromGitHub path.
# That is what makes a from-checkout build work before a release is tagged —
# and v0.1.0 is not tagged (Cargo.toml is still 0.0.1), so today the fetch path
# cannot resolve at all.
#
# Dependencies are taken from the committed Cargo.lock rather than a vendor
# hash, so there is no `cargoHash` to regenerate on every dependency bump.

{ lib
, rustPlatform
, fetchFromGitHub
  # Override to build a working tree (the flake does). When null, the tagged
  # release tarball is fetched instead.
  #
  # Deliberately not named `src`. callPackage fills any unbound argument from
  # nixpkgs, and nixpkgs *has* a `src` attribute, so a `src ? null` default is
  # silently overridden and `callPackage ./packaging/default.nix { }` fails
  # with a baffling error about that unrelated package. `version` has no such
  # clash.
, srcOverride ? null
  # Default is the tag RELEASING.md §2 will cut; the flake overrides it to
  # "0.0.1-dev" so a from-checkout build never names a tag that does not exist
  # yet. At release, collapse both to the same number (bump Cargo.toml 0.0.1 →
  # 0.1.0, drop the flake's -dev override). Note this only names the store path
  # and `meta.version`; `vault --version` reads the number from Cargo.toml.
, version ? "0.1.0"
}:

rustPlatform.buildRustPackage {
  pname = "vault";
  inherit version;

  # Under `srcOverride = self` this is the git tree, so .gitignore does the
  # source filtering for free: /target, the vendored /cruxpass and /rbw
  # reference clones, and the Arch-only /.cargo/config.toml CFLAGS override
  # never reach the store. That is why there is no hand-rolled `builtins.path`
  # filter here.
  src =
    if srcOverride != null then
      srcOverride
    else
      fetchFromGitHub {
        owner = "Spacecraft-Software";
        repo = "Vault";
        rev = "v${version}";
        # TODO at release: build once and paste the reported sha256-... here.
        # Unreachable until a v-tag exists; the flake never takes this branch.
        hash = lib.fakeHash;
      };

  # The lockfile is committed (v4, zero git sources), so Nix vendors from it
  # directly. `outputHashes` stays empty because every dependency comes from
  # crates.io — no git deps, no [patch.crates-io].
  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  # No `cargoBuildFlags` / `buildFeatures`. The root Cargo.toml is a virtual
  # workspace (no [package]), so a bare `cargo build --release` builds every
  # member on its *default* features — which is exactly the three binaries
  # (vault, vault-agent, vault-tui) with the clipboard on. Never `--all-features`
  # here: that switches on `pqc` (extra TLS kx) and `fingerprint` (zbus/fprintd),
  # neither wanted in the default package.

  # No `nativeBuildInputs` / `buildInputs`, deliberately — four reasons:
  #   1. No `build.rs` of our own to run; ring's C is compiled by stdenv's cc.
  #   2. reqwest uses rustls, not OpenSSL — no pkg-config, no openssl.
  #   3. The clipboard is pure-Rust (arboard's wayland-data-control →
  #      wl-clipboard-rs / x11rb), so no libX11 / libwayland-client to link.
  #   4. No clap_complete generation step, so no installShellFiles.

  # vault-config / vault-ipc resolve XDG paths during the test phase, and
  # stdenv's HOME=/homeless-shelter is unwritable. Point both at $TMPDIR.
  preCheck = ''
    export HOME="$TMPDIR"
    export XDG_RUNTIME_DIR="$TMPDIR"
  '';

  # doCheck stays at the default `true`. If the check phase ever fails to *link*
  # `vault-api`'s `login_sync` integration test (it pulls `ring` into a test
  # binary even though its cases are #[ignore]d — #[ignore] skips at run time,
  # not link time), the fix is to scope the run rather than disable it:
  #   cargoTestFlags = [ "--workspace" "--lib" "--bins" ];
  # See the preamble of crates/vault-api/tests/login_sync.rs.

  # No Texinfo manual yet (Standard §8 gap, tracked): Vault ships docs/*.md, so
  # the derivation installs Markdown where engram/vacuum install a .info file.
  postInstall = ''
    install -Dm644 README.md  "$out/share/doc/vault/README.md"
    install -Dm644 NOTICE.md  "$out/share/doc/vault/NOTICE.md"
    install -Dm644 CREDITS.md "$out/share/doc/vault/CREDITS.md"
    for f in docs/*.md; do
      install -Dm644 "$f" "$out/share/doc/vault/$f"
    done
  '';

  meta = {
    description = "Terminal-native Bitwarden client — CLI, TUI and key-custody agent";
    longDescription = ''
      Vault is a single-user, terminal-native Bitwarden and Vaultwarden client
      written in Rust. A ratatui TUI and a flat-verb CLI share one engine via a
      long-lived agent daemon that holds the unwrapped master key in locked,
      zeroizable memory and locks it on idle, signal, or explicit lock. Works
      online against Bitwarden's hosted service and self-hosted Vaultwarden, and
      fully offline from an encrypted local cache once synced.
    '';
    homepage = "https://Vault.SpacecraftSoftware.org/";
    license = lib.licenses.gpl3Plus;
    mainProgram = "vault";
    # linux, not unix: the agent uses the Linux kernel keyring (linux-keyutils),
    # fprintd, and $XDG_RUNTIME_DIR socket semantics.
    platforms = lib.platforms.linux;
    # maintainers omitted: no nixpkgs lib.maintainers entry to point at (engram
    # and vacuum both omit it too).
  };
}
