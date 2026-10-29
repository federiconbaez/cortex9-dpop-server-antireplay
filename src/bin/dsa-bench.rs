//! Runs the scenario matrix against dpop-auth 0.1.3, skyauth 0.3.9 and the
//! reference verifier, prints a table and writes CSV.
//!
//! `--check` exits 1 if any reference row with an exact expectation fails, or if
//! a flood run finished outside the victims' iat window (the replay result would
//! then be meaningless).

use std::io::Write;
use std::time::Duration;

use dpop_server_antireplay::reference::RefConfig;
use dpop_server_antireplay::scenarios::{self, Row};
use dpop_server_antireplay::sut::{DpopAuthSut, RefSut, SkyauthSut, Sut};

struct Args {
    n: usize,
    concurrent: usize,
    threads: usize,
    per_offset: usize,
    nonce_n: usize,
    stale_wait: u64,
    flood: usize,
    tp: usize,
    csv: Option<String>,
    check: bool,
    only: Option<String>,
}

fn parse() -> Args {
    let mut a = Args {
        n: 1000,
        concurrent: 200,
        threads: 16,
        per_offset: 20,
        nonce_n: 20,
        stale_wait: 12,
        flood: 150_000,
        tp: 5000,
        csv: None,
        check: false,
        only: None,
    };
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < v.len() {
        let next = |i: usize| {
            v.get(i + 1)
                .cloned()
                .unwrap_or_else(|| panic!("missing value for {}", v[i]))
        };
        match v[i].as_str() {
            "--n" => {
                a.n = next(i).parse().expect("n");
                i += 1;
            }
            "--concurrent" => {
                a.concurrent = next(i).parse().expect("concurrent");
                i += 1;
            }
            "--threads" => {
                a.threads = next(i).parse().expect("threads");
                i += 1;
            }
            "--per-offset" => {
                a.per_offset = next(i).parse().expect("per-offset");
                i += 1;
            }
            "--nonce-n" => {
                a.nonce_n = next(i).parse().expect("nonce-n");
                i += 1;
            }
            "--stale-wait" => {
                a.stale_wait = next(i).parse().expect("stale-wait");
                i += 1;
            }
            "--flood" => {
                a.flood = next(i).parse().expect("flood");
                i += 1;
            }
            "--throughput" => {
                a.tp = next(i).parse().expect("throughput");
                i += 1;
            }
            "--csv" => {
                a.csv = Some(next(i));
                i += 1;
            }
            "--only" => {
                a.only = Some(next(i));
                i += 1;
            }
            "--check" => a.check = true,
            other => panic!("unknown argument {other}"),
        }
        i += 1;
    }
    a
}

type Factory = fn() -> Box<dyn Sut>;

fn plain() -> Vec<(&'static str, Factory)> {
    vec![
        ("dpop-auth", || Box::new(DpopAuthSut::new(false))),
        ("skyauth", || Box::new(SkyauthSut::new(None))),
        ("reference", || Box::new(RefSut::new(RefConfig::default()))),
    ]
}

fn with_nonces() -> Vec<(&'static str, Factory)> {
    vec![
        ("dpop-auth", || Box::new(DpopAuthSut::new(true))),
        ("skyauth", || {
            Box::new(SkyauthSut::new(Some(Duration::from_secs(5))))
        }),
        ("reference", || {
            Box::new(RefSut::new(RefConfig {
                nonce_period: Some(5),
                ..RefConfig::default()
            }))
        }),
    ]
}

fn main() {
    let a = parse();
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    eprintln!("cores={cores}");
    let mut rows: Vec<Row> = Vec::new();
    let mut push = |r: Vec<Row>| {
        for row in &r {
            eprintln!("{}", row.csv());
        }
        rows.extend(r);
    };
    let keep = |name: &str| a.only.as_deref().is_none_or(|o| o == name);

    for (name, make) in plain() {
        if !keep(name) {
            continue;
        }
        push(scenarios::fresh_and_replay(make().as_ref(), a.n));
        push(vec![scenarios::replay_concurrent(
            make().as_ref(),
            a.concurrent,
            a.threads,
        )]);
        push(scenarios::iat_offsets(make().as_ref(), a.per_offset));
        push(vec![scenarios::throughput(make().as_ref(), a.tp, 1)]);
        push(vec![scenarios::throughput(
            make().as_ref(),
            a.tp,
            cores.min(4),
        )]);
        push(scenarios::flood(make().as_ref(), 50, a.flood, cores.max(2)));
    }
    for (name, make) in with_nonces() {
        if !keep(name) {
            continue;
        }
        push(scenarios::nonces(
            make().as_ref(),
            a.nonce_n,
            Duration::from_secs(a.stale_wait),
        ));
    }

    println!("{}", Row::CSV_HEADER);
    for r in &rows {
        println!("{}", r.csv());
    }
    if let Some(path) = &a.csv {
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).expect("csv directory");
        }
        let mut f = std::fs::File::create(path).expect("csv file");
        writeln!(f, "{}", Row::CSV_HEADER).expect("write");
        for r in &rows {
            writeln!(f, "{}", r.csv()).expect("write");
        }
    }
    if a.check {
        let mut bad = Vec::new();
        for r in &rows {
            if r.sut == "reference" && r.pass() == Some(false) {
                bad.push(format!(
                    "reference {} {} accepted={} expected {}",
                    r.scenario, r.param, r.accepted, r.expected
                ));
            }
            if r.scenario == "flood_replay_old" && !r.note.ends_with("true") {
                bad.push(format!(
                    "{} flood ran past the victims' iat window; replay result not meaningful",
                    r.sut
                ));
            }
        }
        if bad.is_empty() {
            eprintln!("CHECK OK");
        } else {
            for b in &bad {
                eprintln!("CHECK FAIL: {b}");
            }
            std::process::exit(1);
        }
    }
}
