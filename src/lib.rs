//! Measured server-side anti-replay behaviour of DPoP (RFC 9449) verifiers.
//!
//! - [`proof`]: client-side ES256 proof builder with full control of every claim.
//! - [`sut`]: one trait and three adapters (dpop-auth 0.1.3, skyauth 0.3.9, reference).
//! - [`reference`]: the small reference verifier (bounded per-key replay store,
//!   stateless rotating HMAC nonces).
//! - [`scenarios`]: the scenario matrix used by `dsa-bench`.

pub mod proof;
pub mod reference;
pub mod scenarios;
pub mod sut;

/// Seconds since the Unix epoch, from the system clock.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before 1970")
        .as_secs()
}

/// `ath` claim: base64url(SHA-256(access_token)), RFC 9449 section 4.2.
pub fn ath(access_token: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(access_token.as_bytes()))
}
