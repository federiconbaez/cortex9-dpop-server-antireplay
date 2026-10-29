//! The same request-level checks against all three verifiers.

use std::time::Duration;

use dpop_server_antireplay::now_secs;
use dpop_server_antireplay::proof::{alg_none, tamper_signature, ClientKey, ProofSpec};
use dpop_server_antireplay::reference::RefConfig;
use dpop_server_antireplay::scenarios::{htu, HTM, TOKEN};
use dpop_server_antireplay::sut::{DpopAuthSut, RefSut, SkyauthSut, Sut, Verdict};

fn all() -> Vec<Box<dyn Sut>> {
    vec![
        Box::new(DpopAuthSut::new(false)),
        Box::new(SkyauthSut::new(None)),
        Box::new(RefSut::new(RefConfig::default())),
    ]
}

fn all_with_nonces() -> Vec<Box<dyn Sut>> {
    vec![
        Box::new(DpopAuthSut::new(true)),
        Box::new(SkyauthSut::new(Some(Duration::from_secs(30)))),
        Box::new(RefSut::new(RefConfig {
            nonce_period: Some(30),
            ..RefConfig::default()
        })),
    ]
}

fn spec() -> ProofSpec {
    ProofSpec::new(HTM, &htu(), now_secs(), TOKEN)
}

fn send(s: &dyn Sut, proof: &str) -> Verdict {
    s.verify(proof, HTM, &htu(), TOKEN)
}

fn assert_rejected(s: &dyn Sut, proof: &str, what: &str) {
    let v = send(s, proof);
    assert!(!v.is_accept(), "{}: {what} was accepted", s.name());
}

#[test]
fn valid_proof_accepted_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        assert_eq!(
            send(s.as_ref(), &k.proof(&spec())),
            Verdict::Accept,
            "{}",
            s.name()
        );
    }
}

#[test]
fn sequential_replay_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        let p = k.proof(&spec());
        assert!(send(s.as_ref(), &p).is_accept(), "{} first use", s.name());
        for _ in 0..5 {
            assert_rejected(s.as_ref(), &p, "replay");
        }
    }
}

#[test]
fn tampered_signature_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        assert_rejected(
            s.as_ref(),
            &tamper_signature(&k.proof(&spec())),
            "tampered signature",
        );
    }
}

#[test]
fn alg_none_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        assert_rejected(
            s.as_ref(),
            &alg_none(&k.proof(&spec()), &k.public_jwk()),
            "alg none",
        );
    }
}

#[test]
fn wrong_typ_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        let mut sp = spec();
        sp.typ = "JWT".into();
        assert_rejected(s.as_ref(), &k.proof(&sp), "typ JWT");
    }
}

#[test]
fn private_key_in_header_jwk_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        let mut sp = spec();
        sp.leak_private = true;
        assert_rejected(s.as_ref(), &k.proof(&sp), "jwk with d");
    }
}

#[test]
fn wrong_method_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        let mut sp = spec();
        sp.htm = "POST".into();
        assert_rejected(s.as_ref(), &k.proof(&sp), "htm POST for GET");
    }
}

#[test]
fn wrong_uri_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        let mut sp = spec();
        sp.htu = "https://rs.example/other".into();
        assert_rejected(s.as_ref(), &k.proof(&sp), "htu other path");
        sp.htu = "https://attacker.example/resource".into();
        assert_rejected(s.as_ref(), &k.proof(&sp), "htu other host");
    }
}

#[test]
fn ath_for_another_token_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        let mut sp = spec();
        sp.ath = Some(dpop_server_antireplay::ath("some-other-token"));
        assert_rejected(s.as_ref(), &k.proof(&sp), "ath of another token");
        sp.ath = None;
        sp.jti = dpop_server_antireplay::proof::random_jti();
        assert_rejected(s.as_ref(), &k.proof(&sp), "missing ath");
    }
}

#[test]
fn iat_window_30s_tolerated_600s_rejected_by_all() {
    let k = ClientKey::generate();
    for s in all() {
        for off in [-30i64, 30] {
            let mut sp = spec();
            sp.iat = (now_secs() as i64 + off) as u64;
            assert!(
                send(s.as_ref(), &k.proof(&sp)).is_accept(),
                "{} iat {off:+}",
                s.name()
            );
        }
        for off in [-600i64, 600] {
            let mut sp = spec();
            sp.iat = (now_secs() as i64 + off) as u64;
            assert_rejected(s.as_ref(), &k.proof(&sp), "iat ±600 s");
        }
    }
}

#[test]
fn nonce_challenge_then_accept_by_all() {
    let k = ClientKey::generate();
    for s in all_with_nonces() {
        let Verdict::NonceRequired(n) = send(s.as_ref(), &k.proof(&spec())) else {
            panic!("{}: no nonce challenge", s.name());
        };
        assert_eq!(
            send(s.as_ref(), &k.proof(&spec().with_nonce(&n))),
            Verdict::Accept,
            "{}",
            s.name()
        );
    }
}

#[test]
fn forged_nonce_never_accepted_by_all() {
    let k = ClientKey::generate();
    for s in all_with_nonces() {
        for i in 0..5 {
            assert_rejected(
                s.as_ref(),
                &k.proof(&spec().with_nonce(&format!("forged-{i}"))),
                "forged nonce",
            );
        }
    }
}

#[test]
fn skyauth_and_reference_concurrent_replay_accept_exactly_once() {
    // dpop-auth is measured, not asserted: see results/ and the README.
    for s in [
        Box::new(SkyauthSut::new(None)) as Box<dyn Sut>,
        Box::new(RefSut::new(RefConfig::default())),
    ] {
        let row = dpop_server_antireplay::scenarios::replay_concurrent(s.as_ref(), 100, 16);
        assert_eq!(row.accepted, 100, "{}: {}", s.name(), row.note);
    }
}

#[test]
fn flood_on_reference_neither_replays_nor_locks_out_other_clients() {
    let s = RefSut::new(RefConfig {
        capacity: 10_000,
        per_key_quota: 500,
        ..RefConfig::default()
    });
    let rows = dpop_server_antireplay::scenarios::flood(&s, 20, 3000, 4);
    let get = |name: &str| rows.iter().find(|r| r.scenario == name).expect(name);
    assert_eq!(get("flood_victims_before").accepted, 20);
    assert_eq!(
        get("flood_attacker").accepted,
        500,
        "quota caps the flooding key"
    );
    assert_eq!(get("flood_replay_old").accepted, 0);
    assert_eq!(get("flood_honest_after").accepted, 20);
    assert_eq!(get("flood_replay_new").accepted, 0);
}
