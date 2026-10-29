//! Scenario matrix. Every scenario sends real ES256 proofs to a [`Sut`] and
//! counts verdicts; nothing is simulated except who the client is.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Barrier;
use std::time::{Duration, Instant};

use crate::now_secs;
use crate::proof::{ClientKey, ProofSpec};
use crate::sut::{Sut, Verdict, ORIGIN};

pub const HTM: &str = "GET";
pub const TOKEN: &str = "harness-access-token-bound-to-client-key";

pub fn htu() -> String {
    format!("{ORIGIN}/resource")
}

/// One measured line.
#[derive(Debug, Clone)]
pub struct Row {
    pub sut: String,
    pub scenario: &'static str,
    pub param: String,
    pub n: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub unavailable: usize,
    pub challenged: usize,
    /// `=k` exact accepted count required, or `policy` (no single right answer).
    pub expected: String,
    pub metric: Option<f64>,
    pub note: String,
}

impl Row {
    fn new(
        sut: &dyn Sut,
        scenario: &'static str,
        param: impl Into<String>,
        expected: impl Into<String>,
    ) -> Self {
        Self {
            sut: sut.name().into(),
            scenario,
            param: param.into(),
            n: 0,
            accepted: 0,
            rejected: 0,
            unavailable: 0,
            challenged: 0,
            expected: expected.into(),
            metric: None,
            note: String::new(),
        }
    }
    fn count(&mut self, v: &Verdict) {
        self.n += 1;
        match v {
            Verdict::Accept => self.accepted += 1,
            Verdict::Reject(_) => self.rejected += 1,
            Verdict::Unavailable(_) => self.unavailable += 1,
            Verdict::NonceRequired(_) => self.challenged += 1,
        }
    }
    /// `Some(pass)` when the row has an exact expectation.
    pub fn pass(&self) -> Option<bool> {
        self.expected
            .strip_prefix('=')
            .map(|k| k.parse::<usize>().ok() == Some(self.accepted))
    }
    pub const CSV_HEADER: &'static str =
        "sut,scenario,param,n,accepted,rejected,unavailable,challenged,expected,pass,metric,note";
    pub fn csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}",
            self.sut,
            self.scenario,
            self.param,
            self.n,
            self.accepted,
            self.rejected,
            self.unavailable,
            self.challenged,
            self.expected,
            self.pass()
                .map(|p| if p { "yes" } else { "NO" })
                .unwrap_or("-"),
            self.metric.map(|m| format!("{m:.1}")).unwrap_or_default(),
            self.note.replace(',', ";")
        )
    }
}

fn spec(iat: u64) -> ProofSpec {
    ProofSpec::new(HTM, &htu(), iat, TOKEN)
}

fn send(sut: &dyn Sut, proof: &str) -> Verdict {
    sut.verify(proof, HTM, &htu(), TOKEN)
}

/// `n` fresh proofs accepted, then each replayed once.
pub fn fresh_and_replay(sut: &dyn Sut, n: usize) -> Vec<Row> {
    let key = ClientKey::generate();
    let now = now_secs();
    let proofs: Vec<String> = (0..n).map(|_| key.proof(&spec(now))).collect();
    let mut fresh = Row::new(sut, "valid_fresh", "", format!("={n}"));
    for p in &proofs {
        fresh.count(&send(sut, p));
    }
    let mut replay = Row::new(sut, "replay_sequential", "", "=0");
    for p in &proofs {
        replay.count(&send(sut, p));
    }
    vec![fresh, replay]
}

/// Each of `n` proofs is submitted by `threads` threads released by a barrier.
/// `accepted` = proofs accepted exactly once; note counts proofs accepted >1 time.
pub fn replay_concurrent(sut: &dyn Sut, n: usize, threads: usize) -> Row {
    let key = ClientKey::generate();
    let now = now_secs();
    let proofs: Vec<String> = (0..n).map(|_| key.proof(&spec(now))).collect();
    let hits: Vec<AtomicU32> = (0..n).map(|_| AtomicU32::new(0)).collect();
    let barrier = Barrier::new(threads);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                for (i, p) in proofs.iter().enumerate() {
                    barrier.wait();
                    if send(sut, p).is_accept() {
                        hits[i].fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let mut row = Row::new(
        sut,
        "replay_concurrent",
        format!("threads={threads}"),
        format!("={n}"),
    );
    row.n = n;
    let once = hits
        .iter()
        .filter(|h| h.load(Ordering::Relaxed) == 1)
        .count();
    let multi = hits
        .iter()
        .filter(|h| h.load(Ordering::Relaxed) > 1)
        .count();
    let extra: u32 = hits
        .iter()
        .map(|h| h.load(Ordering::Relaxed).saturating_sub(1))
        .sum();
    row.accepted = once;
    row.rejected = n - once - multi;
    row.note = format!("proofs_accepted_more_than_once={multi} extra_acceptances={extra}");
    row
}

/// Offsets (seconds) of `iat` relative to the server clock.
pub const IAT_OFFSETS: [i64; 13] = [
    -600, -310, -290, -120, -65, -55, -30, 0, 30, 55, 65, 120, 600,
];

pub fn iat_offsets(sut: &dyn Sut, per_offset: usize) -> Vec<Row> {
    let key = ClientKey::generate();
    IAT_OFFSETS
        .iter()
        .map(|&off| {
            let expected = match off {
                -30 | 0 | 30 => format!("={per_offset}"),
                -600 | 600 => "=0".to_string(),
                _ => "policy".to_string(),
            };
            let mut row = Row::new(sut, "iat_offset", format!("{off:+}s"), expected);
            for _ in 0..per_offset {
                let iat = (now_secs() as i64 + off) as u64;
                row.count(&send(sut, &key.proof(&spec(iat))));
            }
            row
        })
        .collect()
}

/// skyauth caps nonce issuance at 64 per second (CHALLENGE_ISSUANCE_RATE_LIMIT);
/// pausing between blocks keeps that limit out of the nonce measurements.
fn pace() {
    std::thread::sleep(Duration::from_millis(1100));
}

/// Nonce behaviour on a server configured to require nonces.
/// `stale_wait` is how long a nonce is held before it is reused.
pub fn nonces(sut: &dyn Sut, n: usize, stale_wait: Duration) -> Vec<Row> {
    let key = ClientKey::generate();
    let mut rows = Vec::new();

    let mut missing = Row::new(sut, "nonce_missing", "", "=0");
    let mut first_nonce = None;
    for _ in 0..n {
        let v = send(sut, &key.proof(&spec(now_secs())));
        if let Verdict::NonceRequired(nn) = &v {
            first_nonce.get_or_insert(nn.clone());
        }
        missing.count(&v);
    }
    missing.note = format!("challenged={}", missing.challenged);
    rows.push(missing);
    pace();

    // Each proof carries a nonce obtained from its own challenge.
    let mut first_use = Row::new(sut, "nonce_first_use", "", format!("={n}"));
    for _ in 0..n {
        let challenge = send(sut, &key.proof(&spec(now_secs())));
        let Verdict::NonceRequired(nn) = challenge else {
            first_use.count(&challenge);
            continue;
        };
        first_use.count(&send(sut, &key.proof(&spec(now_secs()).with_nonce(&nn))));
    }
    rows.push(first_use);
    pace();

    // One nonce reused in n fresh proofs (fresh jti each). RFC 9449 11.1 allows it.
    let mut reuse = Row::new(sut, "nonce_reuse_fresh_jti", "", "policy");
    if let Some(nn) = &first_nonce {
        for _ in 0..n {
            reuse.count(&send(sut, &key.proof(&spec(now_secs()).with_nonce(nn))));
        }
    }
    rows.push(reuse);
    pace();

    let mut forged = Row::new(sut, "nonce_forged", "", "=0");
    for i in 0..n {
        forged.count(&send(
            sut,
            &key.proof(&spec(now_secs()).with_nonce(&format!("forged-nonce-{i}"))),
        ));
    }
    rows.push(forged);
    pace();

    // Stale: obtain a nonce, wait, then use it once with a fresh proof.
    let mut stale = Row::new(
        sut,
        "nonce_after_wait",
        format!("wait={}s", stale_wait.as_secs()),
        "policy",
    );
    let held: Vec<String> = (0..n)
        .filter_map(|_| match send(sut, &key.proof(&spec(now_secs()))) {
            Verdict::NonceRequired(nn) => Some(nn),
            _ => None,
        })
        .collect();
    std::thread::sleep(stale_wait);
    for nn in &held {
        stale.count(&send(sut, &key.proof(&spec(now_secs()).with_nonce(nn))));
    }
    rows.push(stale);
    rows
}

/// Authenticated flood: one client with a valid token sends `flood` fresh proofs.
///
/// Before the flood `victims` proofs from another client are accepted; after it,
/// those are replayed (`flood_replay_old`), a third client sends fresh proofs
/// (`flood_honest_after`) and those are replayed (`flood_replay_new`).
pub fn flood(sut: &dyn Sut, victims: usize, flood: usize, threads: usize) -> Vec<Row> {
    let victim = ClientKey::generate();
    let attacker = ClientKey::generate();
    let honest = ClientKey::generate();
    let t0 = now_secs();
    // Victim clock 50 s ahead: still inside every SUT's future window, and it
    // keeps the proofs valid long enough for the flood to finish.
    let vproofs: Vec<String> = (0..victims).map(|_| victim.proof(&spec(t0 + 50))).collect();

    // Pre-sign the flood in parallel.
    let per = flood.div_ceil(threads);
    let aproofs: Vec<String> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..threads)
            .map(|t| {
                let attacker = &attacker;
                s.spawn(move || {
                    let k = per.min(flood.saturating_sub(t * per));
                    (0..k)
                        .map(|_| attacker.proof(&spec(t0)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter()
            .flat_map(|h| h.join().expect("signer"))
            .collect()
    });

    let mut pre = Row::new(sut, "flood_victims_before", "", format!("={victims}"));
    for p in &vproofs {
        pre.count(&send(sut, p));
    }

    let start = Instant::now();
    let acc = AtomicUsize::new(0);
    let unav = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for chunk in aproofs.chunks(per.max(1)) {
            let (acc, unav) = (&acc, &unav);
            s.spawn(move || {
                for p in chunk {
                    match send(sut, p) {
                        Verdict::Accept => {
                            acc.fetch_add(1, Ordering::Relaxed);
                        }
                        Verdict::Unavailable(_) => {
                            unav.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    let flood_secs = start.elapsed().as_secs_f64();
    let mut fl = Row::new(sut, "flood_attacker", format!("flood={flood}"), "policy");
    fl.n = aproofs.len();
    fl.accepted = acc.load(Ordering::Relaxed);
    fl.unavailable = unav.load(Ordering::Relaxed);
    fl.rejected = fl.n - fl.accepted - fl.unavailable;
    fl.metric = Some(flood_secs);
    fl.note = "metric=flood seconds".into();

    // Victim proofs are valid until t0+50+60 for the narrowest window (dpop-auth).
    let in_window = now_secs() + 5 < t0 + 50 + 60;
    let mut old = Row::new(sut, "flood_replay_old", format!("flood={flood}"), "=0");
    for p in &vproofs {
        old.count(&send(sut, p));
    }
    old.note = format!("victim_proofs_still_in_iat_window={in_window}");

    let hproofs: Vec<String> = (0..victims)
        .map(|_| honest.proof(&spec(now_secs())))
        .collect();
    let mut after = Row::new(
        sut,
        "flood_honest_after",
        format!("flood={flood}"),
        "policy",
    );
    for p in &hproofs {
        after.count(&send(sut, p));
    }
    after.note = "availability for a different client after the flood".into();
    let mut newr = Row::new(sut, "flood_replay_new", format!("flood={flood}"), "=0");
    for p in &hproofs {
        newr.count(&send(sut, p));
    }
    newr.note = format!(
        "replays of the {} honest proofs accepted just before",
        after.accepted
    );
    vec![pre, fl, old, after, newr]
}

/// Verifications per second of fresh valid proofs (signing excluded).
pub fn throughput(sut: &dyn Sut, n: usize, threads: usize) -> Row {
    // A new client key every 1000 proofs, so per-key limits do not shape the number.
    let now = now_secs();
    let sets: Vec<Vec<String>> = (0..threads)
        .map(|_| {
            let mut v = Vec::with_capacity(n / threads);
            let mut key = ClientKey::generate();
            for i in 0..n / threads {
                if i > 0 && i % 1000 == 0 {
                    key = ClientKey::generate();
                }
                v.push(key.proof(&spec(now)));
            }
            v
        })
        .collect();
    let acc = AtomicUsize::new(0);
    let start = Instant::now();
    std::thread::scope(|s| {
        for set in &sets {
            let acc = &acc;
            s.spawn(move || {
                for p in set {
                    if send(sut, p).is_accept() {
                        acc.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    let secs = start.elapsed().as_secs_f64();
    let total: usize = sets.iter().map(Vec::len).sum();
    let mut row = Row::new(
        sut,
        "throughput",
        format!("threads={threads}"),
        format!("={total}"),
    );
    row.n = total;
    row.accepted = acc.load(Ordering::Relaxed);
    row.rejected = total - row.accepted;
    row.metric = Some(total as f64 / secs);
    row.note = "metric=verifications per second".into();
    row
}
