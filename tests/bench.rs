//! Performance measurements (not pass/fail tests). Run with:
//!   cargo test --release --test bench -- --ignored --nocapture
//! The upstream is the in-process mock agent, so numbers show SigSieve's own
//! overhead, not a real agent's signing time (Secretive/Touch ID dominates
//! real signing latency).

mod common;

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use sigsieve::protocol;

fn stats(mut v: Vec<Duration>) -> String {
    v.sort();
    let n = v.len();
    let mean = v.iter().sum::<Duration>() / n as u32;
    format!(
        "mean {:>7.1} µs  p50 {:>7.1} µs  p99 {:>7.1} µs  (n={n})",
        mean.as_secs_f64() * 1e6,
        v[n / 2].as_secs_f64() * 1e6,
        v[n * 99 / 100].as_secs_f64() * 1e6
    )
}

fn time_on_connection(path: &Path, payload: &[u8], n: usize) -> Vec<Duration> {
    let mut s = UnixStream::connect(path).unwrap();
    (0..n)
        .map(|_| {
            let t = Instant::now();
            roundtrip(&mut s, payload);
            t.elapsed()
        })
        .collect()
}

fn max_rss_kib() -> i64 {
    // SAFETY: getrusage writes into a zeroed rusage we own.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    if cfg!(target_os = "macos") {
        ru.ru_maxrss / 1024 // bytes on macOS
    } else {
        ru.ru_maxrss // KiB on Linux
    }
}

#[test]
#[ignore]
fn bench() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let ids = [protocol::SSH_AGENTC_REQUEST_IDENTITIES];
    let sign = sign_request(&blob(ECDSA_CI), &[0x42; 256], 0);
    let n = 3000;
    // Warm up.
    time_on_connection(&p.path, &ids, 200);

    println!("\n== SigSieve overhead (mock upstream, release build)");
    println!(
        "identities direct : {}",
        stats(time_on_connection(&up.path, &ids, n))
    );
    println!(
        "identities proxied: {}",
        stats(time_on_connection(&p.path, &ids, n))
    );
    println!(
        "sign       direct : {}",
        stats(time_on_connection(&up.path, &sign, n))
    );
    println!(
        "sign       proxied: {}",
        stats(time_on_connection(&p.path, &sign, n))
    );

    let fresh: Vec<Duration> = (0..1000)
        .map(|_| {
            let t = Instant::now();
            request(&p.path, &ids);
            t.elapsed()
        })
        .collect();
    println!("new connection + identities (proxied): {}", stats(fresh));

    for clients in [8usize, 32] {
        let per = 500;
        let t = Instant::now();
        let hs: Vec<_> = (0..clients)
            .map(|_| {
                let path = p.path.clone();
                let sign = sign.clone();
                thread::spawn(move || time_on_connection(&path, &sign, per))
            })
            .collect();
        let mut all = Vec::new();
        for h in hs {
            all.extend(h.join().unwrap());
        }
        let el = t.elapsed();
        println!(
            "{clients:>2} concurrent clients x {per} signs: {:>8.0} req/s  {}",
            (clients * per) as f64 / el.as_secs_f64(),
            stats(all)
        );
    }
    println!(
        "max RSS of test process (proxy + mock + clients): {} KiB",
        max_rss_kib()
    );
    println!(
        "open descriptors in test process: {}",
        std::fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0)
    );
}
