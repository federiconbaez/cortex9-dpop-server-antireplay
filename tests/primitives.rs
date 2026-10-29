//! Proof builder, thumbprints, store and nonce mint.

use dpop_server_antireplay::now_secs;
use dpop_server_antireplay::proof::{jkt_of, ClientKey, ProofSpec};
use dpop_server_antireplay::reference::{
    normalize_htu, Admit, NonceMint, RefConfig, RefError, RefVerifier, ReplayStore,
};

#[test]
fn ath_matches_rfc9449_example_as_quoted_by_skyauth() {
    let token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
    assert_eq!(
        dpop_server_antireplay::ath(token),
        "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
    );
    assert_eq!(
        dpop_server_antireplay::ath(token),
        skyauth::compute_access_token_hash(token)
    );
}

#[test]
fn jkt_matches_dpop_auth_thumbprint_vector_and_random_keys() {
    // EC vector from dpop-auth 0.1.3 src/crypto/dpop.rs tests.
    assert_eq!(
        jkt_of(
            "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
            "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
        ),
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    );
    for _ in 0..20 {
        let k = ClientKey::generate();
        let jwk: dpop_auth::Jwk = serde_json::from_value(k.public_jwk()).expect("jwk");
        assert_eq!(
            k.jkt(),
            dpop_auth::crypto::compute_jwk_thumbprint(&jwk).expect("thumbprint")
        );
    }
}

#[test]
fn store_detects_replay_until_expiry() {
    let s = ReplayStore::new(100, 100);
    assert_eq!(s.admit("k", "j", 110, 100), Admit::Fresh);
    assert_eq!(s.admit("k", "j", 110, 109), Admit::Replay);
    assert_eq!(
        s.admit("k", "j", 200, 110),
        Admit::Fresh,
        "expired entry is gone"
    );
}

#[test]
fn store_keys_by_jkt_and_jti() {
    let s = ReplayStore::new(100, 100);
    assert_eq!(s.admit("k1", "j", 110, 100), Admit::Fresh);
    assert_eq!(
        s.admit("k2", "j", 110, 100),
        Admit::Fresh,
        "same jti under another key is a different proof"
    );
}

#[test]
fn store_quota_limits_one_key_not_others() {
    let s = ReplayStore::new(1000, 3);
    for i in 0..3 {
        assert_eq!(s.admit("attacker", &format!("{i}"), 500, 100), Admit::Fresh);
    }
    assert_eq!(s.admit("attacker", "x", 500, 100), Admit::KeyQuota);
    assert_eq!(s.admit("honest", "x", 500, 100), Admit::Fresh);
}

#[test]
fn store_fails_closed_at_capacity_and_never_evicts_live_entries() {
    let s = ReplayStore::new(4, 100);
    for i in 0..4 {
        assert_eq!(s.admit(&format!("k{i}"), "j", 500, 100), Admit::Fresh);
    }
    assert_eq!(s.admit("k9", "j", 500, 100), Admit::Saturated);
    for i in 0..4 {
        assert_eq!(
            s.admit(&format!("k{i}"), "j", 500, 101),
            Admit::Replay,
            "entry {i} still live"
        );
    }
    assert_eq!(s.len(), 4);
}

#[test]
fn store_frees_capacity_and_quota_when_entries_expire() {
    let s = ReplayStore::new(2, 2);
    assert_eq!(s.admit("k", "a", 150, 100), Admit::Fresh);
    assert_eq!(s.admit("k", "b", 150, 100), Admit::Fresh);
    assert_eq!(s.admit("k", "c", 300, 120), Admit::KeyQuota);
    assert_eq!(s.admit("k", "c", 300, 150), Admit::Fresh);
    assert_eq!(s.len(), 1);
}

#[test]
fn nonce_mint_accepts_current_and_previous_period_only() {
    let m = NonceMint::new([7; 32], 10);
    let n = m.issue(1000);
    assert!(m.check(&n, 1000));
    assert!(m.check(&n, 1019), "previous period still valid");
    assert!(!m.check(&n, 1020), "two periods old is stale");
    assert!(!m.check(&n, 990), "nonce from the future period");
}

#[test]
fn nonce_mint_rejects_other_secret_and_garbage() {
    let a = NonceMint::new([1; 32], 10);
    let b = NonceMint::new([2; 32], 10);
    assert!(!b.check(&a.issue(1000), 1000));
    assert!(!a.check("", 1000));
    assert!(!a.check("not-base64!!", 1000));
    let mut n = a.issue(1000).into_bytes();
    let last = n.len() - 1;
    n[last] = if n[last] == b'A' { b'B' } else { b'A' };
    assert!(!a.check(std::str::from_utf8(&n).expect("utf8"), 1000));
}

#[test]
fn reference_rejects_long_jti_before_storing_it() {
    let v = RefVerifier::new(RefConfig::default());
    let k = ClientKey::generate();
    let mut sp = ProofSpec::new("GET", "https://rs.example/r", now_secs(), "t");
    sp.jti = "x".repeat(65);
    assert_eq!(
        v.verify(
            &k.proof(&sp),
            "GET",
            "https://rs.example/r",
            "t",
            now_secs()
        ),
        Err(RefError::JtiTooLong)
    );
    assert!(v.store.is_empty());
}

#[test]
fn reference_store_expiry_follows_iat_not_arrival() {
    let v = RefVerifier::new(RefConfig::default());
    let k = ClientKey::generate();
    let now = now_secs();
    let sp = ProofSpec::new("GET", "https://rs.example/r", now - 50, "t");
    let p = k.proof(&sp);
    assert!(v
        .verify(&p, "GET", "https://rs.example/r", "t", now)
        .is_ok());
    // 11 s later the proof is too old; the verifier says so before the store.
    assert_eq!(
        v.verify(&p, "GET", "https://rs.example/r", "t", now + 11),
        Err(RefError::TooOld)
    );
    // An unrelated admission at now+11 prunes the expired entry.
    let other = k.proof(&ProofSpec::new(
        "GET",
        "https://rs.example/r",
        now + 11,
        "t",
    ));
    assert!(v
        .verify(&other, "GET", "https://rs.example/r", "t", now + 11)
        .is_ok());
    assert_eq!(v.store.len(), 1);
}

#[test]
fn htu_normalisation() {
    assert_eq!(
        normalize_htu("HTTPS://RS.Example:443/a?x=1#f"),
        "https://rs.example/a"
    );
    assert_eq!(normalize_htu("http://h:80"), "http://h/");
    assert_eq!(normalize_htu("https://h:8443/a"), "https://h:8443/a");
    assert_ne!(normalize_htu("https://h/a"), normalize_htu("https://h/A"));
}
