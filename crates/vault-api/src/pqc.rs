// SPDX-License-Identifier: GPL-3.0-or-later

//! Post-quantum transport (feature `pqc`, off by default).
//!
//! Adds the hybrid **X25519MLKEM768** key-exchange group to the rustls client
//! config, so a TLS 1.3 handshake negotiates a post-quantum-secure shared
//! secret when the server offers it (otherwise it silently falls back to a
//! classical group). The construction is GPL-clean: the classical half reuses
//! ring's audited X25519 (rustls's own `SupportedKxGroup`), and the
//! post-quantum half is `RustCrypto`'s `ml-kem` (Apache-2.0/MIT). We do **not**
//! use aws-lc-rs (the only rustls provider that ships X25519MLKEM768) because
//! its bundled AWS-LC carries OpenSSL-licensed code, which is GPL-incompatible.
//!
//! Wire layout (per `draft-ietf-tls-ecdhe-mlkem`, X25519MLKEM768): the
//! post-quantum element comes first in every share and in the secret. The
//! client sends `ek_ML-KEM-768 (1184) ‖ x25519_pub (32)`; the server replies
//! `ct (1088) ‖ x25519_pub (32)`; the shared secret is `ss_mlkem (32) ‖
//! ss_x25519 (32)`. This module implements the **client** role only.

use std::sync::Arc;

use kem::Decapsulate;
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use rustls::client::ClientConfig;
use rustls::crypto::ring::{default_provider, kx_group};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion, RootCertStore};

/// Byte lengths of each component (ML-KEM-768 + X25519).
const X25519_LEN: usize = 32;
const MLKEM768_ENCAP_LEN: usize = 1184;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

type DecapKey = <MlKem768 as KemCore>::DecapsulationKey;

// ---- ML-KEM-768 as a rustls key-exchange group (client / KEM initiator) ----

/// ML-KEM-768 KEM exposed as a rustls [`SupportedKxGroup`]. Only the client
/// role is implemented (generate a keypair, send the encapsulation key, then
/// decapsulate the server's ciphertext).
#[derive(Debug)]
struct MlKem768Kx;

impl SupportedKxGroup for MlKem768Kx {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (decap_key, encap_key) = MlKem768::generate(&mut OsRng);
        Ok(Box::new(MlKemActive {
            decap_key,
            encap_bytes: encap_key.as_bytes().to_vec(),
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }
}

/// In-progress ML-KEM-768 exchange: holds the decapsulation key until the
/// server's ciphertext arrives.
struct MlKemActive {
    decap_key: DecapKey,
    encap_bytes: Vec<u8>,
}

impl ActiveKeyExchange for MlKemActive {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let ciphertext =
            Ciphertext::<MlKem768>::try_from(peer_pub_key).map_err(|_| INVALID_KEY_SHARE)?;
        let shared = self
            .decap_key
            .decapsulate(&ciphertext)
            .map_err(|()| INVALID_KEY_SHARE)?;
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.encap_bytes
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::MLKEM768
    }
}

// ---- The X25519MLKEM768 hybrid (composes ring X25519 + ML-KEM-768) ----

/// Hybrid X25519MLKEM768, post-quantum element first (per the draft). Mirrors
/// rustls's own (crate-private) `aws_lc_rs::pq::hybrid` composition, but over
/// GPL-clean parts and for the client role only.
#[derive(Debug)]
struct Hybrid {
    classical: &'static dyn SupportedKxGroup,
    post_quantum: &'static dyn SupportedKxGroup,
}

impl SupportedKxGroup for Hybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = self.classical.start()?;
        let post_quantum = self.post_quantum.start()?;
        // post_quantum_first: ek_ML-KEM ‖ x25519_pub.
        let mut combined = Vec::with_capacity(MLKEM768_ENCAP_LEN + X25519_LEN);
        combined.extend_from_slice(post_quantum.pub_key());
        combined.extend_from_slice(classical.pub_key());
        Ok(Box::new(ActiveHybrid {
            classical,
            post_quantum,
            combined_pub_key: combined,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// In-progress hybrid exchange.
struct ActiveHybrid {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    combined_pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveHybrid {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // Server share: ct (1088) ‖ x25519_pub (32), post-quantum first.
        if peer_pub_key.len() != MLKEM768_CIPHERTEXT_LEN + X25519_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (pq_share, classical_share) = peer_pub_key.split_at(MLKEM768_CIPHERTEXT_LEN);
        let classical = self.classical.complete(classical_share)?;
        let post_quantum = self.post_quantum.complete(pq_share)?;
        // Combined secret: ss_ML-KEM ‖ ss_x25519.
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(post_quantum.secret_bytes());
        secret.extend_from_slice(classical.secret_bytes());
        Ok(SharedSecret::from(secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

/// The hybrid X25519MLKEM768 key-exchange group, ready to drop into a
/// [`CryptoProvider`]'s `kx_groups`.
static X25519MLKEM768: &dyn SupportedKxGroup = &Hybrid {
    classical: kx_group::X25519,
    post_quantum: &MlKem768Kx,
};

/// Build a rustls client config that prefers X25519MLKEM768, falling back to
/// the classical ring groups. Hand the result to `reqwest`'s
/// `use_preconfigured_tls`.
///
/// # Errors
///
/// Returns a [`rustls::Error`] only if the safe default protocol versions are
/// somehow rejected by the provider (not expected in practice).
pub fn client_config() -> Result<ClientConfig, Error> {
    let provider = CryptoProvider {
        kx_groups: vec![
            X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        ..default_provider()
    };

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kem::Encapsulate;
    use ml_kem::Encoded;

    type EncapKey = <MlKem768 as KemCore>::EncapsulationKey;

    #[test]
    fn mlkem_client_kx_round_trips() {
        // Client: generate keypair, expose the encapsulation key.
        let active = MlKem768Kx.start().expect("start");
        let ek_bytes = active.pub_key().to_vec();
        assert_eq!(ek_bytes.len(), MLKEM768_ENCAP_LEN);

        // "Server": reconstruct the encapsulation key, encapsulate to it.
        let encoded = Encoded::<EncapKey>::try_from(ek_bytes.as_slice()).expect("ek size");
        let encap_key = EncapKey::from_bytes(&encoded);
        let (ciphertext, server_secret) = encap_key.encapsulate(&mut OsRng).expect("encapsulate");
        assert_eq!(ciphertext.len(), MLKEM768_CIPHERTEXT_LEN);

        // Client: decapsulate the ciphertext; the two secrets must match.
        let client_secret = active.complete(&ciphertext).expect("complete");
        assert_eq!(client_secret.secret_bytes(), &server_secret[..]);
    }

    #[test]
    fn hybrid_pub_key_layout_is_pq_then_classical() {
        let active = X25519MLKEM768.start().expect("start");
        // Client share = ek_ML-KEM (1184) ‖ x25519_pub (32).
        assert_eq!(active.pub_key().len(), MLKEM768_ENCAP_LEN + X25519_LEN);
        assert_eq!(active.group(), NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn hybrid_rejects_wrong_length_server_share() {
        let active = X25519MLKEM768.start().expect("start");
        // A server share of the wrong length must be rejected, not panic.
        assert!(active.complete(&[0u8; 16]).is_err());
    }

    #[test]
    fn client_config_prefers_pqc() {
        let cfg = client_config().expect("config builds");
        let first = cfg
            .crypto_provider()
            .kx_groups
            .first()
            .expect("at least one kx group");
        assert_eq!(first.name(), NamedGroup::X25519MLKEM768);
    }
}
