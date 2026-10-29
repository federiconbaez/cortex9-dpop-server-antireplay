//! Client side: ES256 DPoP proofs where every claim can be chosen by the caller,
//! including values a correct server must reject.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::RngCore;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// A client DPoP key pair (P-256).
pub struct ClientKey {
    sk: SigningKey,
    x: String,
    y: String,
}

/// Claims and header knobs of one proof.
#[derive(Clone, Debug)]
pub struct ProofSpec {
    pub htm: String,
    pub htu: String,
    pub iat: u64,
    pub jti: String,
    pub nonce: Option<String>,
    pub ath: Option<String>,
    /// Header `typ`; correct value is `dpop+jwt`.
    pub typ: String,
    /// Put the private scalar `d` into the header JWK (must be rejected).
    pub leak_private: bool,
}

impl ProofSpec {
    pub fn new(htm: &str, htu: &str, iat: u64, access_token: &str) -> Self {
        Self {
            htm: htm.into(),
            htu: htu.into(),
            iat,
            jti: random_jti(),
            nonce: None,
            ath: Some(crate::ath(access_token)),
            typ: "dpop+jwt".into(),
            leak_private: false,
        }
    }
    pub fn with_nonce(mut self, n: &str) -> Self {
        self.nonce = Some(n.into());
        self
    }
}

/// 128 random bits, base64url (22 chars).
pub fn random_jti() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    B64.encode(b)
}

impl ClientKey {
    pub fn generate() -> Self {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let pt = sk.verifying_key().to_encoded_point(false);
        Self {
            x: B64.encode(pt.x().expect("x")),
            y: B64.encode(pt.y().expect("y")),
            sk,
        }
    }

    /// Public JWK (members in RFC 7638 lexicographic order).
    pub fn public_jwk(&self) -> Value {
        json!({"crv": "P-256", "kty": "EC", "x": self.x, "y": self.y})
    }

    /// RFC 7638 SHA-256 JWK thumbprint (`jkt`).
    pub fn jkt(&self) -> String {
        jkt_of(&self.x, &self.y)
    }

    /// Sign a proof described by `spec`.
    pub fn proof(&self, spec: &ProofSpec) -> String {
        let mut jwk = self.public_jwk();
        if spec.leak_private {
            jwk["d"] = Value::String(B64.encode(self.sk.to_bytes()));
        }
        let header = json!({"typ": spec.typ, "alg": "ES256", "jwk": jwk});
        let mut claims = Map::new();
        claims.insert("jti".into(), json!(spec.jti));
        claims.insert("htm".into(), json!(spec.htm));
        claims.insert("htu".into(), json!(spec.htu));
        claims.insert("iat".into(), json!(spec.iat));
        if let Some(n) = &spec.nonce {
            claims.insert("nonce".into(), json!(n));
        }
        if let Some(a) = &spec.ath {
            claims.insert("ath".into(), json!(a));
        }
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(Value::Object(claims).to_string())
        );
        let sig: Signature = self.sk.sign(input.as_bytes());
        format!("{input}.{}", B64.encode(sig.to_bytes()))
    }
}

/// RFC 7638 thumbprint of an EC P-256 key given its x/y (base64url).
pub fn jkt_of(x: &str, y: &str) -> String {
    let canon = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    B64.encode(Sha256::digest(canon.as_bytes()))
}

/// Same proof with one signature bit flipped.
pub fn tamper_signature(proof: &str) -> String {
    let (head, sig) = proof.rsplit_once('.').expect("compact JWS");
    let mut raw = B64.decode(sig).expect("b64");
    raw[10] ^= 0x01;
    format!("{head}.{}", B64.encode(raw))
}

/// Same claims with the header replaced by `{"alg":"none",...}` and no signature.
pub fn alg_none(proof: &str, jwk: &Value) -> String {
    let payload = proof.split('.').nth(1).expect("payload");
    let header = json!({"typ": "dpop+jwt", "alg": "none", "jwk": jwk});
    format!("{}.{payload}.", B64.encode(header.to_string()))
}
