// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for `vault_core::generate`.

use std::collections::HashSet;

use vault_core::{GenerateOptions, generate_password};

#[test]
fn default_length_and_classes() {
    let opts = GenerateOptions::default();
    let pw = generate_password(&opts).expect("default options must succeed");
    assert_eq!(pw.len(), 20);
    assert!(pw.is_ascii());
    // Default disables symbols — every char must be alphanumeric.
    assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn includes_at_least_one_of_each_enabled_class() {
    let opts = GenerateOptions {
        length: 8,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
    };
    // Run many samples — the guarantee is per-output, not statistical, but
    // looping catches accidental Fisher–Yates bugs that destroy the prefix.
    for _ in 0..256 {
        let pw = generate_password(&opts).unwrap();
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| "!@#$%^&*".contains(c)));
    }
}

#[test]
fn zero_length_is_rejected() {
    let opts = GenerateOptions {
        length: 0,
        ..GenerateOptions::default()
    };
    assert!(generate_password(&opts).is_err());
}

#[test]
fn no_classes_is_rejected() {
    let opts = GenerateOptions {
        length: 8,
        lowercase: false,
        uppercase: false,
        digits: false,
        symbols: false,
    };
    assert!(generate_password(&opts).is_err());
}

#[test]
fn length_shorter_than_class_count_is_rejected() {
    // Three classes enabled, length 2 — cannot satisfy "at least one of each".
    let opts = GenerateOptions {
        length: 2,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: false,
    };
    assert!(generate_password(&opts).is_err());
}

#[test]
fn only_digits_yields_only_digits() {
    let opts = GenerateOptions {
        length: 16,
        lowercase: false,
        uppercase: false,
        digits: true,
        symbols: false,
    };
    let pw = generate_password(&opts).unwrap();
    assert!(pw.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn distinct_outputs_across_calls() {
    // 64 chars × full alphanumeric ≈ 380 bits of entropy. Two consecutive
    // identical outputs would mean the RNG is broken.
    let opts = GenerateOptions {
        length: 64,
        ..GenerateOptions::default()
    };
    let a = generate_password(&opts).unwrap();
    let b = generate_password(&opts).unwrap();
    assert_ne!(a.as_str(), b.as_str());
}

#[test]
fn shuffle_breaks_class_ordering() {
    // The implementation seeds the first N positions with one-per-class,
    // then shuffles. If the shuffle is doing its job, the first character
    // is not always lowercase across many trials.
    let opts = GenerateOptions {
        length: 16,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
    };
    let mut first_chars = HashSet::new();
    for _ in 0..200 {
        let pw = generate_password(&opts).unwrap();
        first_chars.insert(pw.chars().next().unwrap());
    }
    // With 4 classes shuffled across 16 positions, the first character should
    // cover at least three distinct ASCII categories over 200 trials.
    let categories: HashSet<_> = first_chars
        .iter()
        .map(|c| {
            if c.is_ascii_lowercase() {
                0
            } else if c.is_ascii_uppercase() {
                1
            } else if c.is_ascii_digit() {
                2
            } else {
                3
            }
        })
        .collect();
    assert!(
        categories.len() >= 3,
        "first-char categories seen: {categories:?}"
    );
}
