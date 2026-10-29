//! Systems under test behind one trait.
//!
//! Each adapter calls the library the way its own server integration does:
//! - dpop-auth 0.1.3: `dpop::validate_dpop_proof`, the function its `DpopLayer`
//!   calls after the access token has been verified.
//! - skyauth 0.3.9: `DPoPVerifier::verify_proof_deferred`, then the server nonce
//!   check, then `commit_replay_admission`, the order its Tower layer uses.
//! - reference: [`crate::reference::RefVerifier`].
//!
//! Access-token signature and `cnf.jkt` checks are outside the adapters; the
//! harness models a client that already holds a valid access token.

use std::time::Duration;

use dpop_auth::dpop::{validate_dpop_proof, ValidationContext};
use dpop_auth::{DpopConfig, DpopError, DpopState, TokenSigner};
use skyauth::{
    compute_access_token_hash, DPoPError, DPoPServerNonceSource, DPoPVerifier,
    InMemoryServerNonceSource,
};

use crate::reference::{RefConfig, RefError, RefVerifier};

/// What the server did with one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Reject(String),
    /// `use_dpop_nonce` challenge carrying a fresh nonce.
    NonceRequired(String),
    /// Server-side resource exhaustion (would be a 503).
    Unavailable(String),
}

impl Verdict {
    pub fn is_accept(&self) -> bool {
        matches!(self, Verdict::Accept)
    }
}

pub trait Sut: Send + Sync {
    fn name(&self) -> &'static str;
    fn verify(&self, proof: &str, htm: &str, htu: &str, access_token: &str) -> Verdict;
}

/// Public URL every adapter is configured with.
pub const ORIGIN: &str = "https://rs.example";

// ---------------------------------------------------------------- dpop-auth

pub struct DpopAuthSut {
    state: DpopState,
    rt: tokio::runtime::Runtime,
}

impl DpopAuthSut {
    /// Library defaults (clock_skew 60 s, ES256/PS256), optional nonce.
    pub fn new(nonce_required: bool) -> Self {
        let config = DpopConfig::builder()
            .public_url(ORIGIN)
            .issuer(ORIGIN)
            .audience(ORIGIN)
            .signer(
                TokenSigner::symmetric(b"harness-only-signing-key-0123456789abcdef")
                    .expect("signer"),
            )
            .nonce_required(nonce_required)
            .build()
            .expect("dpop-auth config");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .expect("tokio runtime");
        Self {
            state: DpopState::new(config),
            rt,
        }
    }
}

impl Sut for DpopAuthSut {
    fn name(&self) -> &'static str {
        "dpop-auth-0.1.3"
    }
    fn verify(&self, proof: &str, htm: &str, htu: &str, access_token: &str) -> Verdict {
        let cfg = &self.state.config;
        let ctx = ValidationContext {
            proof,
            expected_htm: htm,
            expected_htu: htu,
            access_token: Some(access_token),
            nonce_required: cfg.nonce_required,
            clock_skew: cfg.clock_skew,
            allowed_algs: &cfg.allowed_algs,
            jti_cache: &self.state.jti_cache,
            nonce_cache: &self.state.nonce_cache,
        };
        match self.rt.block_on(validate_dpop_proof(ctx)) {
            Ok(_) => Verdict::Accept,
            Err(DpopError::ResourceNonceRequired(n)) | Err(DpopError::TokenNonceRequired(n)) => {
                Verdict::NonceRequired(n)
            }
            Err(e) => Verdict::Reject(format!("{e}")),
        }
    }
}

// ---------------------------------------------------------------- skyauth

pub struct SkyauthSut {
    verifier: DPoPVerifier,
    nonces: Option<InMemoryServerNonceSource>,
}

impl SkyauthSut {
    /// Library defaults (skew 60 s, max age 300 s, replay cache on); optional
    /// server nonces with the given TTL (reusable, the library default).
    pub fn new(nonce_ttl: Option<Duration>) -> Self {
        Self {
            verifier: DPoPVerifier::new(),
            nonces: nonce_ttl.map(InMemoryServerNonceSource::new),
        }
    }
}

impl Sut for SkyauthSut {
    fn name(&self) -> &'static str {
        "skyauth-0.3.9"
    }
    fn verify(&self, proof: &str, htm: &str, htu: &str, access_token: &str) -> Verdict {
        let ath = compute_access_token_hash(access_token);
        let (claims, _jwk, admission) =
            match self
                .verifier
                .verify_proof_deferred(proof, htm, htu, None, Some(&ath), None)
            {
                Ok(t) => t,
                Err(DPoPError::ReplayCacheSaturated) => {
                    return Verdict::Unavailable("replay cache saturated".into())
                }
                Err(e) => return Verdict::Reject(format!("{e}")),
            };
        if let Some(ns) = &self.nonces {
            let ok = claims.nonce.as_deref().is_some_and(|n| ns.verify_nonce(n));
            if !ok {
                return match ns.generate_nonce() {
                    Ok(n) => Verdict::NonceRequired(n),
                    Err(e) => Verdict::Unavailable(format!("{e}")),
                };
            }
        }
        match self.verifier.commit_replay_admission(&admission) {
            Ok(()) => Verdict::Accept,
            Err(DPoPError::ReplayCacheSaturated) => {
                Verdict::Unavailable("replay cache saturated".into())
            }
            Err(e) => Verdict::Reject(format!("{e}")),
        }
    }
}

// ---------------------------------------------------------------- reference

pub struct RefSut {
    pub inner: RefVerifier,
}

impl RefSut {
    pub fn new(cfg: RefConfig) -> Self {
        Self {
            inner: RefVerifier::new(cfg),
        }
    }
}

impl Sut for RefSut {
    fn name(&self) -> &'static str {
        "reference"
    }
    fn verify(&self, proof: &str, htm: &str, htu: &str, access_token: &str) -> Verdict {
        match self
            .inner
            .verify(proof, htm, htu, access_token, crate::now_secs())
        {
            Ok(_) => Verdict::Accept,
            Err(RefError::NonceRequired(n)) => Verdict::NonceRequired(n),
            Err(e @ (RefError::Saturated | RefError::KeyQuota)) => {
                Verdict::Unavailable(format!("{e:?}"))
            }
            Err(e) => Verdict::Reject(format!("{e:?}")),
        }
    }
}
