//! Reference verifier used as the third system under test.
//!
//! It exists to check that the harness can tell behaviours apart and to measure
//! one design choice: a replay store that fails closed at capacity **and** caps
//! the live entries per key thumbprint (`jkt`), so that a single authenticated
//! client cannot fill the store for everybody. It is not a full resource server:
//! the access token itself (signature, `cnf.jkt`) is assumed to be validated
//! before the proof, as dpop-auth's middleware does.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::Mutex;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, Mac};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
use serde_json::Value;
use sha2::Sha256;

/// Why the reference verifier refused a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefError {
    Malformed(&'static str),
    Typ,
    Alg,
    PrivateKeyInJwk,
    Signature,
    Htm,
    Htu,
    Ath,
    TooOld,
    FromFuture,
    JtiTooLong,
    Replay,
    /// This `jkt` already holds `per_key_quota` live entries.
    KeyQuota,
    /// The whole store is at capacity; fail closed.
    Saturated,
    /// Nonce required; carries a fresh nonce for the challenge.
    NonceRequired(String),
}

/// Outcome of a store admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Fresh,
    Replay,
    KeyQuota,
    Saturated,
}

/// Bounded replay store keyed by (`jkt`, `jti`).
///
/// Entries expire at `iat + max_age + 1` (the first second at which the proof
/// would be rejected as too old anyway), not at insertion time + TTL. A full
/// store or a full per-key quota rejects; nothing live is ever evicted.
pub struct ReplayStore {
    inner: Mutex<StoreInner>,
    capacity: usize,
    per_key_quota: usize,
}

#[derive(Default)]
struct StoreInner {
    live: HashMap<String, u64>,
    per_key: HashMap<String, usize>,
    by_exp: BinaryHeap<Reverse<(u64, String, String)>>,
}

impl ReplayStore {
    pub fn new(capacity: usize, per_key_quota: usize) -> Self {
        Self {
            inner: Mutex::new(StoreInner::default()),
            capacity,
            per_key_quota,
        }
    }

    /// Atomic check-and-insert.
    pub fn admit(&self, jkt: &str, jti: &str, expires_at: u64, now: u64) -> Admit {
        let key = format!("{jkt}:{jti}");
        let mut g = self.inner.lock().expect("store lock");
        // Lazy expiry, oldest first.
        while let Some(Reverse((exp, _, _))) = g.by_exp.peek() {
            if *exp > now {
                break;
            }
            let Reverse((exp, k, owner)) = g.by_exp.pop().expect("peeked");
            if g.live.get(&k) == Some(&exp) {
                g.live.remove(&k);
                if let Some(c) = g.per_key.get_mut(&owner) {
                    *c -= 1;
                    if *c == 0 {
                        g.per_key.remove(&owner);
                    }
                }
            }
        }
        if let Some(&exp) = g.live.get(&key) {
            if exp > now {
                return Admit::Replay;
            }
        }
        if g.per_key.get(jkt).copied().unwrap_or(0) >= self.per_key_quota {
            return Admit::KeyQuota;
        }
        if g.live.len() >= self.capacity {
            return Admit::Saturated;
        }
        g.live.insert(key.clone(), expires_at);
        *g.per_key.entry(jkt.to_string()).or_insert(0) += 1;
        g.by_exp.push(Reverse((expires_at, key, jkt.to_string())));
        Admit::Fresh
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("store lock").live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Stateless rotating nonces: `b64(epoch_be || HMAC-SHA256(secret, epoch)[..16])`.
///
/// Valid for the current and the previous period, so every node that shares the
/// secret can check them without shared state. Multi-use within the period, which
/// RFC 9449 section 11.1 allows as long as `jti` is tracked.
pub struct NonceMint {
    secret: [u8; 32],
    period: u64,
}

impl NonceMint {
    pub fn new(secret: [u8; 32], period_secs: u64) -> Self {
        assert!(period_secs > 0);
        Self {
            secret,
            period: period_secs,
        }
    }

    fn tag(&self, epoch: u64) -> [u8; 16] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret).expect("hmac key");
        m.update(&epoch.to_be_bytes());
        let full = m.finalize().into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    pub fn issue(&self, now: u64) -> String {
        let epoch = now / self.period;
        let mut raw = epoch.to_be_bytes().to_vec();
        raw.extend_from_slice(&self.tag(epoch));
        B64.encode(raw)
    }

    pub fn check(&self, nonce: &str, now: u64) -> bool {
        let Ok(raw) = B64.decode(nonce) else {
            return false;
        };
        if raw.len() != 24 {
            return false;
        }
        let epoch = u64::from_be_bytes(raw[..8].try_into().expect("8 bytes"));
        let cur = now / self.period;
        if epoch != cur && epoch + 1 != cur {
            return false;
        }
        let want = self.tag(epoch);
        want.iter()
            .zip(&raw[8..])
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0
    }
}

/// Reference verifier configuration.
pub struct RefConfig {
    /// Oldest accepted `iat` is `now - max_age`.
    pub max_age: u64,
    /// Newest accepted `iat` is `now + future_skew`.
    pub future_skew: u64,
    pub capacity: usize,
    pub per_key_quota: usize,
    /// `Some(period)` makes nonces mandatory.
    pub nonce_period: Option<u64>,
}

impl Default for RefConfig {
    fn default() -> Self {
        Self {
            max_age: 60,
            future_skew: 60,
            capacity: 131_072,
            per_key_quota: 4096,
            nonce_period: None,
        }
    }
}

pub struct RefVerifier {
    cfg: RefConfig,
    pub store: ReplayStore,
    mint: Option<NonceMint>,
}

const MAX_JTI: usize = 64;

impl RefVerifier {
    pub fn new(cfg: RefConfig) -> Self {
        let store = ReplayStore::new(cfg.capacity, cfg.per_key_quota);
        let mint = cfg.nonce_period.map(|p| {
            let mut s = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut s);
            NonceMint::new(s, p)
        });
        Self { cfg, store, mint }
    }

    /// Validate `proof` for request `htm htu` presented with `access_token`.
    /// Returns the proof's `jkt` on success.
    pub fn verify(
        &self,
        proof: &str,
        htm: &str,
        htu: &str,
        access_token: &str,
        now: u64,
    ) -> Result<String, RefError> {
        let mut parts = proof.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(RefError::Malformed("not three parts"));
        };
        let header: Value = B64
            .decode(h)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(RefError::Malformed("header"))?;
        if header["typ"] != "dpop+jwt" {
            return Err(RefError::Typ);
        }
        if header["alg"] != "ES256" {
            return Err(RefError::Alg);
        }
        let jwk = &header["jwk"];
        if jwk.get("d").is_some() {
            return Err(RefError::PrivateKeyInJwk);
        }
        if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
            return Err(RefError::Alg);
        }
        let (Some(x), Some(y)) = (jwk["x"].as_str(), jwk["y"].as_str()) else {
            return Err(RefError::Malformed("jwk"));
        };
        let (Ok(xb), Ok(yb)) = (B64.decode(x), B64.decode(y)) else {
            return Err(RefError::Malformed("jwk b64"));
        };
        if xb.len() != 32 || yb.len() != 32 {
            return Err(RefError::Malformed("jwk size"));
        }
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&xb);
        point.extend_from_slice(&yb);
        let sig_raw = B64.decode(s).map_err(|_| RefError::Signature)?;
        if sig_raw.len() != 64 {
            return Err(RefError::Signature);
        }
        // ring rejects points not on the curve as a signature failure.
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(format!("{h}.{p}").as_bytes(), &sig_raw)
            .map_err(|_| RefError::Signature)?;

        let claims: Value = B64
            .decode(p)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or(RefError::Malformed("claims"))?;
        if claims["htm"] != htm {
            return Err(RefError::Htm);
        }
        let got_htu = claims["htu"].as_str().ok_or(RefError::Htu)?;
        if normalize_htu(got_htu) != normalize_htu(htu) {
            return Err(RefError::Htu);
        }
        let iat = claims["iat"].as_u64().ok_or(RefError::Malformed("iat"))?;
        if iat > now + self.cfg.future_skew {
            return Err(RefError::FromFuture);
        }
        if now > iat + self.cfg.max_age {
            return Err(RefError::TooOld);
        }
        let ath_ok = claims["ath"].as_str().is_some_and(|a| {
            let want = crate::ath(access_token);
            a.len() == want.len()
                && a.bytes()
                    .zip(want.bytes())
                    .fold(0u8, |acc, (x, y)| acc | (x ^ y))
                    == 0
        });
        if !ath_ok {
            return Err(RefError::Ath);
        }
        if let Some(mint) = &self.mint {
            let ok = claims["nonce"].as_str().is_some_and(|n| mint.check(n, now));
            if !ok {
                return Err(RefError::NonceRequired(mint.issue(now)));
            }
        }
        let jti = claims["jti"].as_str().ok_or(RefError::Malformed("jti"))?;
        if jti.is_empty() {
            return Err(RefError::Malformed("jti"));
        }
        if jti.len() > MAX_JTI {
            return Err(RefError::JtiTooLong);
        }
        let jkt = crate::proof::jkt_of(x, y);
        match self.store.admit(&jkt, jti, iat + self.cfg.max_age + 1, now) {
            Admit::Fresh => Ok(jkt),
            Admit::Replay => Err(RefError::Replay),
            Admit::KeyQuota => Err(RefError::KeyQuota),
            Admit::Saturated => Err(RefError::Saturated),
        }
    }
}

/// Scheme and host lower-cased, default port dropped, query and fragment removed.
pub fn normalize_htu(u: &str) -> String {
    let u = u.split(['?', '#']).next().unwrap_or("");
    let Some((scheme, rest)) = u.split_once("://") else {
        return u.to_string();
    };
    let scheme = scheme.to_ascii_lowercase();
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let mut auth = auth.to_ascii_lowercase();
    if (scheme == "https" && auth.ends_with(":443")) || (scheme == "http" && auth.ends_with(":80"))
    {
        auth.truncate(auth.rfind(':').expect("port"));
    }
    format!("{scheme}://{auth}{path}")
}
