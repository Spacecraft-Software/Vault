;; SPDX-License-Identifier: GPL-3.0-or-later
;;
;; GNU Guix package definition for vault (Steelbore Standard §5.5).
;;
;; Build:  guix build -f packaging/guix.scm
;;
;; v0.1.0 is unreleased, so the buildable path below fetches the git tree at a
;; pinned commit (an ancestor of the packaging commit, so this file is
;; self-consistent).
;;
;; THIS DEFINITION DOES NOT BUILD AS IT STANDS.  Two things block it:
;;
;;   1. The source hash is a placeholder of zeros and MUST be replaced first —
;;      Guix refuses a wrong hash, it never ignores one.  Compute it with:
;;        guix hash -rx <clean checkout at the pinned commit>
;;
;;   2. cargo-build-system does NOT vendor from Cargo.lock the way Nix does — it
;;      wants each of Vault's ~409 locked crates supplied as a #:cargo-inputs
;;      package.  Wiring all of them by hand is the work this placeholder does
;;      not do.
;;
;; So this file satisfies the §5.5 "present" requirement and pins the version
;; and commit honestly; it is not the path that builds today.  Use
;; packaging/default.nix (Nix) or the flake for a build that works now.

(use-modules (guix packages)
             (guix download)
             (guix git-download)
             (guix build-system cargo)
             ((guix licenses) #:prefix license:))

(define-public vault
  (package
    (name "vault")
    (version "0.0.1")
    ;; Release stanza — swap in at the first tagged release:
    ;;
    ;; (source
    ;;  (origin
    ;;    (method url-fetch)
    ;;    (uri (string-append
    ;;          "https://github.com/Spacecraft-Software/Vault"
    ;;          "/archive/refs/tags/v" version ".tar.gz"))
    ;;    (sha256
    ;;     (base32
    ;;      ;; TODO at release tag: set real hash (guix download <url> prints it)
    ;;      "0000000000000000000000000000000000000000000000000000"))))
    ;;
    ;; Buildable path while v0.1.0 is unreleased: a pinned git checkout.
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/Spacecraft-Software/Vault")
             (commit "8a30f324364b2e2b2578eb1753bae2bb50668df7")))
       (file-name (git-file-name name version))
       (sha256
        (base32
         ;; PLACEHOLDER — not a real hash.  Compute with:
         ;;   guix hash -rx <checkout at the commit above>
         "0000000000000000000000000000000000000000000000000000"))))
    (build-system cargo-build-system)
    (arguments
     (list #:install-source? #f))
    (synopsis "Terminal-native Bitwarden client (CLI, TUI, and key-custody agent)")
    (description
     "Vault is a single-user, terminal-native Bitwarden and Vaultwarden client
written in Rust.  A ratatui TUI and a flat-verb CLI share one engine via a
long-lived agent daemon that holds the unwrapped master key in locked,
zeroizable memory and locks it on idle, signal, or explicit lock.  It works
online against Bitwarden's hosted service and self-hosted Vaultwarden, and
fully offline from an encrypted local cache once synced.")
    (home-page "https://Vault.SpacecraftSoftware.org/")
    (license license:gpl3+)))

;; Return the package so `guix build -f packaging/guix.scm` works.
vault
