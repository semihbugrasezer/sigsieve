//! Process-wide descriptor counts must not include unrelated parallel tests.

mod common;

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use sigsieve::protocol;

fn open_fds() -> usize {
    std::fs::read_dir("/dev/fd")
        .expect("descriptor inventory is available")
        .count()
}

#[test]
fn thousands_of_short_lived_connections_do_not_leak() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    // Warm up, then measure descriptors around a burst.
    for _ in 0..20 {
        list(&p.path);
    }
    thread::sleep(Duration::from_millis(200));
    let before = open_fds();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let path = p.path.clone();
            thread::spawn(move || {
                for i in 0..400 {
                    let mut s = connect(&path);
                    if i % 3 == 0 {
                        // Abandon mid-frame.
                        let _ = s.write_all(&[0, 0, 0, 9, 13]);
                    } else {
                        roundtrip(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    // Let the abandoned connections reach EOF and close.
    let start = Instant::now();
    while open_fds() > before + 4 && start.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(50));
    }
    let after = open_fds();
    assert!(after <= before + 4, "descriptor leak: {before} -> {after}");
    assert_eq!(list(&p.path).len(), 1, "proxy unresponsive after burst");
}
