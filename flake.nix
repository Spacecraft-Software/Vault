# SPDX-License-Identifier: GPL-3.0-or-later
#
# Nix flake for Vault — terminal-native Bitwarden client (CLI, TUI, agent).
#
# Usage:
#   nix run .                          # run `vault` without installing it
#   nix run . -- --help
#   nix run .#vault-tui                # the TUI
#   nix run .#vault-agent -- --help    # the agent
#   nix build                          # build; result/bin/{vault,vault-agent,vault-tui}
#   nix profile install .              # install all three for the current user
#   nix develop                        # development shell
#   nix flake check                    # build + test suite
#
# The package is defined once, in packaging/default.nix (Standard §5.5); this
# flake passes `srcOverride = self` so it builds the checkout rather than a
# tagged tarball. That matters today: v0.1.0 is unreleased, so the
# fetchFromGitHub path in packaging/default.nix cannot resolve.
#
# Why nixpkgs' rustc, not fenix/oxalica: `buildRustPackage` has no rustup and
# never reads rust-toolchain.toml, so the package compiles on whatever rustc
# nixpkgs ships regardless. Pinning a toolchain overlay would add a third-party
# input and a second ~1.5 GB toolchain for no change to the build. The honest
# consequence: `nix develop`'s `cargo fmt --check` / `clippy -D warnings` are
# NOT CI-exact — CI pins 1.95.0 via dtolnay/rust-toolchain, and this shell uses
# whatever nixpkgs has. Contributors running the gates before pushing should use
# rustup (which honours rust-toolchain.toml). Drift policy: if nixpkgs ever
# regresses below the 1.95 MSRV, the fix is `makeRustPlatform` over a pinned
# toolchain in packaging/default.nix — never an MSRV edit.
#
# There is deliberately NO nixosModule or homeManagerModule here. All of Vault's
# state is per-user XDG — the agent socket at $XDG_RUNTIME_DIR/vault/agent.sock,
# config at $XDG_CONFIG_HOME/vault/config.toml, the encrypted cache at
# $XDG_DATA_HOME/vault/<account>/cache.json — so a `programs.vault.enable` whose
# only body is environment.systemPackages would advertise a system scope the
# tool does not have. Consumers install packages.default into home.packages (or
# system packages) instead. A systemd *user* unit for vault-agent is out of
# scope here too: the documented start path is the CLI's auto-spawn, and a unit
# worth shipping needs socket-path and idle-lock options — a design conversation,
# not a packaging change. Deferred deliberately.
{
  description = "Vault — terminal-native Bitwarden client (CLI, TUI, and key-custody agent)";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        vault = pkgs.callPackage ./packaging/default.nix {
          srcOverride = self;
          # Not a release: mark it so the store path never claims to be a tagged
          # 0.1.0 when it is really whatever is checked out. See the version
          # comment in packaging/default.nix.
          version = "0.0.1-dev";
        };
      in
      {
        packages.default = vault;
        packages.vault = vault;

        # One derivation carries all three binaries; expose an app per binary so
        # `nix run .#vault-tui` works. This single-output shape is load-bearing:
        # the CLI auto-spawns vault-agent from a sibling of its own path, so the
        # bins must never be split across outputs.
        apps.default = {
          type = "app";
          program = "${vault}/bin/vault";
        };
        apps.vault-agent = {
          type = "app";
          program = "${vault}/bin/vault-agent";
        };
        apps.vault-tui = {
          type = "app";
          program = "${vault}/bin/vault-tui";
        };

        # `nix flake check` builds the package, which runs `cargo test` as part
        # of buildRustPackage's check phase.
        checks.default = vault;

        devShells.default = pkgs.mkShell {
          name = "vault-dev";
          nativeBuildInputs = with pkgs; [
            # The Rust toolchain from nixpkgs rather than rustup (see the header
            # note: these gates are not CI-exact — CI pins 1.95.0).
            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer

            gcc             # ring's C objects are compiled by the C toolchain.
            mold            # Standard §3.2.1: the linker LTO wants on NixOS.

            just            # the CI-gate recipes (`just ci`).
            reuse           # §4.3 — `reuse lint` must pass.
            cargo-deny
            cargo-audit

            git
          ];
          shellHook = ''
            echo "vault dev shell (nixpkgs rustc — NOT CI-exact; CI pins 1.95.0)."
            echo "  just ci        fmt / clippy / test / headless / version-gate / deny / audit / reuse"
            echo "  just --list    all recipes"
          '';
        };
      }
    );
}
