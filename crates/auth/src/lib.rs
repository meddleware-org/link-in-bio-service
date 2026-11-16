//! `link-in-bio-auth`: how a person proves who they are to the hosted service. No third party, no password, no
//! personal data:
//!
//! - [`passkey`]: WebAuthn passkeys (user verification required; RP ID = the app host), through kanidm's webauthn-rs;
//! - [`wallet`]: Sui wallet sign-in, a CAIP-122-style message signed with the wallet's personal-message signature;
//! - [`recovery`]: one-use recovery codes;
//! - [`session`]: opaque session tokens (only their SHA-256 is stored) in a `__Host-` cookie, and the CSRF rule.
//!
//! Every function here is pure or wraps a pure library: the store and the HTTP layer live elsewhere, so the
//! [`Authenticator`] methods can be swapped (a Kratos or OIDC adapter later) without touching them.

pub mod passkey;
pub mod recovery;
pub mod session;
pub mod wallet;

use ring::rand::{SecureRandom, SystemRandom};

/// The sign-in methods an instance offers (the `Authenticator` port: each is an independent way to reach an account).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authenticator {
    Passkey,
    SuiWallet,
    RecoveryCode,
}

/// `n` random bytes from the operating system's generator.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // SystemRandom fails only if the OS has no entropy source, which a running Linux always has.
    SystemRandom::new().fill(&mut b).expect("the operating system's random number generator");
    b
}

/// A random lowercase hex id of `bytes` bytes (challenge ids, domain tokens).
pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    SystemRandom::new().fill(&mut b).expect("the operating system's random number generator");
    hex::encode(b)
}
