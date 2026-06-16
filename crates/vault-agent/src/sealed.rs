// SPDX-License-Identifier: GPL-3.0-or-later

//! A user symmetric key locked into RAM so it can't be swapped to disk.
//!
//! The agent holds the unwrapped user keys for as long as it's unlocked. Beyond
//! zeroizing them on drop and barring core dumps / ptrace (see `harden.rs`),
//! [`SealedKey`] also `mlock`s the page(s) backing the key so the bytes never
//! reach a swap file. Locking is **surgical** — only the key's own pages, never
//! the whole process — so it's always within `RLIMIT_MEMLOCK` and can't starve
//! the tokio/rustls allocator.
//!
//! The key is boxed to give it a **stable heap address**: a `SealedKey` (and
//! the `Vault` that owns it) may be moved after construction, but the boxed
//! bytes stay put, so the lock taken at `new` remains valid for the key's life.
//! `mlock`/`munlock` go through the safe `region` crate, keeping the crate's
//! `#![forbid(unsafe_code)]`.

use std::ops::Deref;

use zeroize::{Zeroize, Zeroizing};

/// 32-byte user key, boxed + `mlock`ed for its lifetime and zeroized on drop.
pub struct SealedKey {
    /// Boxed so the address is stable across moves of `self`/the owning `Vault`.
    key: Box<Zeroizing<[u8; 32]>>,
    /// Whether the page is currently locked (best-effort; `false` if `mlock`
    /// was refused, e.g. at the `RLIMIT_MEMLOCK` ceiling).
    locked: bool,
}

impl SealedKey {
    /// Box `bytes`, then best-effort `mlock` the backing page. A failed lock is
    /// not fatal — the key is still zeroized and usable, just swappable.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        let key = Box::new(Zeroizing::new(bytes));
        // `region::lock` returns a guard that would `munlock` on drop; forget it
        // so the page stays locked, and `munlock` ourselves in `Drop` (after the
        // zeroize) — this also keeps `SealedKey: Send`, unlike holding the guard.
        let locked = region::lock(key.as_ptr(), key.len()).is_ok_and(|guard| {
            core::mem::forget(guard);
            true
        });
        Self { key, locked }
    }
}

impl Deref for SealedKey {
    type Target = [u8; 32];

    fn deref(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Drop for SealedKey {
    fn drop(&mut self) {
        // Wipe while the page is still locked, so the cleared bytes can't be
        // raced to swap; then unlock; then the boxed `Zeroizing` field-drops
        // (re-wipes harmlessly + frees).
        self.key.zeroize();
        if self.locked {
            let _ = region::unlock(self.key.as_ptr(), self.key.len());
        }
    }
}

impl std::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedKey")
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::SealedKey;

    #[test]
    fn derefs_to_the_key_bytes() {
        let k = SealedKey::new([7u8; 32]);
        assert_eq!(*k, [7u8; 32]);
        // The Deref path is what every encrypt/decrypt call site relies on.
        let same = SealedKey::new([7u8; 32]);
        assert_eq!(&*k, &*same);
    }

    #[test]
    fn debug_does_not_leak_bytes() {
        // 0xAB renders as "171" in a leaked array Debug; ours shows only `locked`.
        let rendered = format!("{:?}", SealedKey::new([0xABu8; 32]));
        assert!(rendered.contains("SealedKey"));
        assert!(
            !rendered.contains("171"),
            "Debug leaked key bytes: {rendered}"
        );
    }
}
