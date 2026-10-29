//! End-to-end tests: hostile downstream client -> SigSieve -> fake upstream.

mod common;

use std::io::{Read, Write};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use sigsieve::protocol::{self, put_string, put_u32};
use sigsieve::proxy::Limits;
use sigsieve::{
    binding::Bindings, keys::Fingerprint, policy::Policy, proxy::Proxy, upstream::Upstream,
};

#[test]
fn exposes_only_the_approved_identity_among_three() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    assert_eq!(
        list(&p.path),
        vec![(ECDSA_CI_FP.to_string(), ECDSA_CI_COMMENT.to_string())]
    );
}

#[test]
fn empty_allowlist_exposes_nothing() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[]);
    assert!(list(&p.path).is_empty());
    let r = request(&p.path, &sign_request(&blob(ECDSA_CI), b"x", 0));
    assert_eq!(r, FAILURE);
    assert!(up.sign_requests().is_empty());
}

#[test]
fn multiple_approved_identities_keep_upstream_order() {
    let mut ids = three_identities();
    ids.push((blob(RSA_LEGACY), RSA_LEGACY_COMMENT.into()));
    let up = MockAgent::start(ids, Mode::Normal);
    let p = start_proxy(&up.path, &[RSA_LEGACY_FP, ECDSA_CI_FP]);
    let fps: Vec<_> = list(&p.path).into_iter().map(|(f, _)| f).collect();
    assert_eq!(fps, vec![ECDSA_CI_FP, RSA_LEGACY_FP]);
}

#[test]
fn duplicate_allowlist_entries_and_duplicate_upstream_keys_appear_once() {
    let mut ids = three_identities();
    ids.push((blob(ECDSA_CI), "same key, second comment".into()));
    let up = MockAgent::start(ids, Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP, ECDSA_CI_FP]);
    assert_eq!(list(&p.path).len(), 1);
}

#[test]
fn comments_are_never_used_for_authorization() {
    // A hidden key carrying the approved key's comment stays hidden.
    let ids = vec![
        (blob(ED_ADMIN), ECDSA_CI_COMMENT.into()),
        (blob(ECDSA_CI), "renamed".into()),
    ];
    let up = MockAgent::start(ids, Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    assert_eq!(
        list(&p.path),
        vec![(ECDSA_CI_FP.to_string(), "renamed".to_string())]
    );
}

#[test]
fn authorized_signing_is_delegated_for_each_key_type() {
    let mut ids = three_identities();
    ids.push((blob(RSA_LEGACY), RSA_LEGACY_COMMENT.into()));
    let up = MockAgent::start(ids, Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP, ED_PERSONAL_FP, RSA_LEGACY_FP]);
    let cases = [
        (blob(ECDSA_CI), 0),
        (blob(ED_PERSONAL), 0),
        (blob(RSA_LEGACY), 0x02), // rsa-sha2-256
        (blob(RSA_LEGACY), 0x04), // rsa-sha2-512
    ];
    for (key, flags) in &cases {
        let req = sign_request(key, b"session-id-and-userauth-request", *flags);
        let r = request(&p.path, &req);
        assert!(is_sign_response(&r), "{r:?}");
    }
    // Upstream saw exactly the authorized requests, byte for byte.
    let expected: Vec<_> = cases
        .iter()
        .map(|(k, f)| sign_request(k, b"session-id-and-userauth-request", *f))
        .collect();
    assert_eq!(up.sign_requests(), expected);
}

#[test]
fn rsa_signature_flags_are_rejected_for_non_rsa_keys() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP, ED_PERSONAL_FP]);
    for key in [blob(ECDSA_CI), blob(ED_PERSONAL)] {
        for flags in [2, 4, 6] {
            assert_eq!(
                request(&p.path, &sign_request(&key, b"synthetic auth", flags)),
                FAILURE
            );
        }
    }
    assert!(up.sign_requests().is_empty());
}

#[test]
fn rsa_requires_exactly_one_sha2_flag() {
    let mut ids = three_identities();
    ids.push((blob(RSA_LEGACY), RSA_LEGACY_COMMENT.into()));
    let up = MockAgent::start(ids, Mode::Normal);
    let p = start_proxy(&up.path, &[RSA_LEGACY_FP]);
    // 0 asks for legacy ssh-rsa (SHA-1); 6 names two hashes at once.
    for flags in [0, 0x01, 0x06, 0x08] {
        assert_eq!(
            request(&p.path, &sign_request(&blob(RSA_LEGACY), b"auth", flags)),
            FAILURE,
            "flags {flags:#x}"
        );
    }
    assert!(up.sign_requests().is_empty());
}

#[test]
fn signatures_with_an_unrequested_algorithm_are_refused() {
    // An upstream that ignores the flags and answers with ssh-rsa (SHA-1),
    // or with an algorithm foreign to the key, gets nothing through.
    let mut ids = three_identities();
    ids.push((blob(RSA_LEGACY), RSA_LEGACY_COMMENT.into()));
    let up = MockAgent::start(ids, Mode::LegacySignature);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP, RSA_LEGACY_FP]);
    for (key, flags) in [
        (blob(RSA_LEGACY), 0x02),
        (blob(RSA_LEGACY), 0x04),
        (blob(ECDSA_CI), 0),
    ] {
        assert_eq!(
            request(&p.path, &sign_request(&key, b"auth", flags)),
            FAILURE
        );
    }
    assert_eq!(up.sign_requests().len(), 3);
}

#[test]
fn production_signing_budget_bounds_a_burst_without_changing_authorization() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy_with(
        &up.path,
        &[ECDSA_CI_FP],
        Limits::default(),
        Duration::from_secs(5),
    );
    let mut s = connect(&p.path);
    let start = Instant::now();
    for i in 0u32..100 {
        let response = roundtrip(&mut s, &sign_request(&blob(ECDSA_CI), &i.to_be_bytes(), 0));
        assert!(response == FAILURE || is_sign_response(&response));
    }
    let accepted = up.sign_requests().len();
    let ceiling = 32 + (start.elapsed().as_secs_f64() * 4.0).ceil() as usize;
    assert!(
        accepted <= ceiling,
        "unbounded signing burst: {accepted} > {ceiling}"
    );
    assert!(accepted > 0, "budget must admit ordinary signing");
    assert_eq!(
        roundtrip(&mut s, &sign_request(&blob(ED_ADMIN), b"hidden", 0)),
        FAILURE
    );
}

#[test]
fn production_defaults_allow_a_32_client_session_burst() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy_with(
        &up.path,
        &[ECDSA_CI_FP],
        Limits::default(),
        Duration::from_secs(5),
    );
    let clients: Vec<_> = (0..32).map(|_| connect(&p.path)).collect();
    let workers: Vec<_> = (0u32..)
        .zip(clients)
        .map(|(id, mut s)| {
            thread::spawn(move || {
                assert_eq!(
                    roundtrip(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES])[..5],
                    [12, 0, 0, 0, 1]
                );
                assert!(is_sign_response(&roundtrip(
                    &mut s,
                    &sign_request(&blob(ECDSA_CI), &id.to_be_bytes(), 0)
                )));
                assert_eq!(
                    roundtrip(&mut s, &sign_request(&blob(ED_ADMIN), b"hidden", 0)),
                    FAILURE
                );
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(up.sign_requests().len(), 32);
}

#[test]
fn shutdown_disconnects_clients_waiting_for_a_stalled_agent() {
    let up = MockAgent::start(three_identities(), Mode::Hang);
    let p = start_proxy_with(
        &up.path,
        &[ECDSA_CI_FP],
        Limits::default(),
        Duration::from_secs(10),
    );
    let mut s = connect(&p.path);
    protocol::write_frame(&mut s, &sign_request(&blob(ECDSA_CI), b"synthetic", 0)).unwrap();
    let start = Instant::now();
    while up.received().is_empty() {
        assert!(start.elapsed() < Duration::from_secs(3));
        thread::sleep(Duration::from_millis(10));
    }
    let start = Instant::now();
    drop(p);
    assert!(read_to_eof(&mut s).is_empty());
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(up.sign_requests().len(), 1);
}

#[test]
fn one_connection_cannot_send_an_unbounded_request_burst() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy_with(
        &up.path,
        &[ECDSA_CI_FP],
        Limits::default(),
        Duration::from_secs(5),
    );
    let mut s = connect(&p.path);
    let start = Instant::now();
    let mut served = 0;
    for _ in 0..300 {
        if protocol::write_frame(&mut s, &[99]).is_err() {
            break;
        }
        let t = Duration::from_secs(2);
        match protocol::read_frame(&mut s, t, t) {
            Ok(Some(response)) => {
                assert_eq!(response, FAILURE);
                served += 1;
            }
            Ok(None) | Err(_) => break,
        }
    }
    let ceiling = 128 + (start.elapsed().as_secs_f64() * 128.0).ceil() as usize;
    assert!(
        served <= ceiling,
        "unbounded request burst: {served} > {ceiling}"
    );
    assert!(up.received().is_empty());
}

#[test]
fn destination_bound_duplicates_do_not_reach_upstream_on_another_connection() {
    let mut seed = protocol::Reader::new(include_bytes!("data/fuzz-seeds/session_bind/sequence"));
    let first = seed.string().unwrap();
    let last = seed.string().unwrap();
    let key = seed.string().unwrap();
    let auth = seed.string().unwrap();
    seed.finish().unwrap();
    let destination = Fingerprint::of_blob(protocol::Reader::new(last).string().unwrap());
    let (policy, _) = Policy::from_fingerprints(&[Fingerprint::of_blob(key).to_string()]).unwrap();
    let policy = policy
        .with_destinations(&[destination.to_string()])
        .unwrap();
    for mode in [Mode::Normal, Mode::Failure] {
        let up = MockAgent::start(three_identities(), mode);
        let proxy = Proxy::new(
            policy.clone(),
            Upstream::new(&up.path, Duration::from_secs(2)),
            Limits::default(),
        );
        for connection in 0..2 {
            let mut bindings = Bindings::default();
            for body in [first, last] {
                let mut request = vec![protocol::SSH_AGENTC_EXTENSION];
                put_string(&mut request, b"session-bind@openssh.com");
                request.extend_from_slice(body);
                assert_eq!(
                    proxy.handle_request(&request, &mut bindings),
                    Some(vec![protocol::SSH_AGENT_SUCCESS])
                );
            }
            let request = sign_request(key, auth, 0);
            let response = proxy.handle_request(&request, &mut bindings).unwrap();
            assert_eq!(
                is_sign_response(&response),
                connection == 0 && matches!(mode, Mode::Normal)
            );
        }
        assert_eq!(
            up.sign_requests().len(),
            1,
            "duplicate attempt reached upstream ({mode:?})"
        );
    }
}

#[test]
fn hidden_identity_cannot_sign_even_with_known_public_key() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    for key in [blob(ED_ADMIN), blob(ED_PERSONAL)] {
        assert_eq!(request(&p.path, &sign_request(&key, b"data", 0)), FAILURE);
    }
    assert!(up.sign_requests().is_empty());
}

#[test]
fn hidden_identity_cannot_sign_after_enumeration_on_same_connection() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let mut s = connect(&p.path);
    let ids = roundtrip(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
    assert_eq!(ids[0], protocol::SSH_AGENT_IDENTITIES_ANSWER);
    let ok = roundtrip(&mut s, &sign_request(&blob(ECDSA_CI), b"a", 0));
    assert!(is_sign_response(&ok));
    let denied = roundtrip(&mut s, &sign_request(&blob(ED_ADMIN), b"b", 0));
    assert_eq!(denied, FAILURE);
    assert_eq!(
        up.sign_requests(),
        vec![sign_request(&blob(ECDSA_CI), b"a", 0)]
    );
}

#[test]
fn identity_substitution_and_encoding_tricks_are_rejected() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let good = blob(ECDSA_CI);

    // Approved blob with a trailing byte inside the key string.
    let mut padded = good.clone();
    padded.push(0);
    // Approved blob truncated by one byte.
    let truncated = good[..good.len() - 1].to_vec();
    // Same point, but claiming a different curve name.
    let mut swapped = Vec::new();
    put_string(&mut swapped, b"ecdsa-sha2-nistp256");
    put_string(&mut swapped, b"nistp384");
    put_string(&mut swapped, &good[good.len() - 65..]);
    // Approved blob wrapped as if it were a certificate type.
    let mut cert = Vec::new();
    put_string(&mut cert, b"ecdsa-sha2-nistp256-cert-v01@openssh.com");
    cert.extend_from_slice(&good);

    for key in [padded, truncated, swapped, cert, Vec::new()] {
        assert_eq!(request(&p.path, &sign_request(&key, b"d", 0)), FAILURE);
    }
    assert!(up.sign_requests().is_empty());
}

#[test]
fn malformed_sign_requests_are_not_forwarded() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let good = sign_request(&blob(ECDSA_CI), b"data", 0);

    // Smuggled second message after an authorized request inside one frame.
    let mut smuggled = good.clone();
    smuggled.extend_from_slice(&sign_request(&blob(ED_ADMIN), b"data", 0));
    // Missing flags field.
    let no_flags = good[..good.len() - 4].to_vec();
    // Key string length pointing far past the end.
    let mut huge_len = vec![protocol::SSH_AGENTC_SIGN_REQUEST];
    put_u32(&mut huge_len, u32::MAX);
    // Unknown flag bits on an approved key.
    let bad_flags = sign_request(&blob(ECDSA_CI), b"data", 0x01);
    let high_flags = sign_request(&blob(ECDSA_CI), b"data", 0x8000_0000);

    let mut s = connect(&p.path);
    for req in [
        smuggled,
        no_flags,
        huge_len,
        bad_flags,
        high_flags,
        vec![protocol::SSH_AGENTC_SIGN_REQUEST],
    ] {
        assert_eq!(roundtrip(&mut s, &req), FAILURE);
    }
    // The connection is still usable afterwards.
    assert!(is_sign_response(&roundtrip(&mut s, &good)));
    assert_eq!(up.sign_requests(), vec![good]);
}

#[test]
fn back_to_back_frames_are_authorized_individually() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let mut s = connect(&p.path);
    let mut both = Vec::new();
    for req in [
        sign_request(&blob(ECDSA_CI), b"1", 0),
        sign_request(&blob(ED_ADMIN), b"2", 0),
    ] {
        put_string(&mut both, &req);
    }
    s.write_all(&both).unwrap();
    let t = Duration::from_secs(5);
    let r1 = protocol::read_frame(&mut s, t, t).unwrap().unwrap();
    let r2 = protocol::read_frame(&mut s, t, t).unwrap().unwrap();
    assert!(is_sign_response(&r1));
    assert_eq!(r2, FAILURE);
    assert_eq!(up.sign_requests().len(), 1);
}

#[test]
fn agent_mutations_are_rejected_and_never_forwarded() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let key = blob(ECDSA_CI);
    let mut remove = vec![protocol::SSH_AGENTC_REMOVE_IDENTITY];
    put_string(&mut remove, &key);
    let mut add = vec![protocol::SSH_AGENTC_ADD_IDENTITY];
    put_string(&mut add, b"ssh-ed25519");
    put_string(&mut add, &[1; 32]);
    put_string(&mut add, &[2; 64]);
    put_string(&mut add, b"injected");
    let mut lock = vec![protocol::SSH_AGENTC_LOCK];
    put_string(&mut lock, b"passphrase");
    let mut unlock = vec![protocol::SSH_AGENTC_UNLOCK];
    put_string(&mut unlock, b"passphrase");
    let mut pkcs11 = vec![protocol::SSH_AGENTC_ADD_SMARTCARD_KEY];
    put_string(&mut pkcs11, b"/usr/lib/evil-pkcs11.so");
    put_string(&mut pkcs11, b"");
    let mut pkcs11_rm = vec![protocol::SSH_AGENTC_REMOVE_SMARTCARD_KEY];
    put_string(&mut pkcs11_rm, b"/usr/lib/evil-pkcs11.so");
    put_string(&mut pkcs11_rm, b"");
    let mut constrained = add.clone();
    constrained[0] = protocol::SSH_AGENTC_ADD_ID_CONSTRAINED;
    let mut sc_constrained = pkcs11.clone();
    sc_constrained[0] = protocol::SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED;

    let mut s = connect(&p.path);
    for req in [
        add,
        remove,
        vec![protocol::SSH_AGENTC_REMOVE_ALL_IDENTITIES],
        lock,
        unlock,
        pkcs11,
        pkcs11_rm,
        constrained,
        sc_constrained,
        // SSH1-era operations.
        vec![1],
        vec![9],
    ] {
        assert_eq!(roundtrip(&mut s, &req), FAILURE, "type {}", req[0]);
    }
    assert!(up.received().is_empty(), "{:?}", up.received_types());
}

#[test]
fn unknown_operations_are_rejected() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let mut s = connect(&p.path);
    for t in [0u8, 2, 4, 5, 6, 12, 14, 24, 28, 29, 30, 100, 200, 255] {
        assert_eq!(roundtrip(&mut s, &[t, 0, 0, 0, 0]), FAILURE, "type {t}");
    }
    assert!(up.received().is_empty());
}

#[test]
fn extensions_including_session_bind_are_rejected_and_not_forwarded() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let mut bind = vec![protocol::SSH_AGENTC_EXTENSION];
    put_string(&mut bind, b"session-bind@openssh.com");
    put_string(&mut bind, &blob(ED_ADMIN)); // hostkey
    put_string(&mut bind, &[7; 32]); // session identifier
    put_string(&mut bind, &[8; 64]); // signature
    bind.push(1); // is_forwarding
    let mut query = vec![protocol::SSH_AGENTC_EXTENSION];
    put_string(&mut query, b"query");
    let mut other = vec![protocol::SSH_AGENTC_EXTENSION];
    put_string(&mut other, b"sign-anything@evil.example");
    put_string(&mut other, &blob(ED_ADMIN));

    let mut s = connect(&p.path);
    for req in [bind, query, other, vec![protocol::SSH_AGENTC_EXTENSION]] {
        assert_eq!(roundtrip(&mut s, &req), FAILURE);
    }
    // Rejected session-bind does not poison the connection.
    assert!(is_sign_response(&roundtrip(
        &mut s,
        &sign_request(&blob(ECDSA_CI), b"x", 0)
    )));
    assert_eq!(up.received_types(), vec![protocol::SSH_AGENTC_SIGN_REQUEST]);
}

#[test]
fn identities_request_with_payload_is_rejected() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    assert_eq!(
        request(&p.path, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES, 0]),
        FAILURE
    );
    assert!(up.received().is_empty());
}

fn read_to_eof(s: &mut std::os::unix::net::UnixStream) -> Vec<u8> {
    // EINVAL here (macOS) means the server already closed the connection.
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    // A reset after the server closes counts as closed.
    let _ = s.read_to_end(&mut buf);
    buf
}

#[test]
fn oversized_frame_is_refused_and_connection_closed() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let mut s = connect(&p.path);
    s.write_all(&(protocol::MAX_FRAME as u32 + 1).to_be_bytes())
        .unwrap();
    assert_eq!(
        read_to_eof(&mut s),
        vec![0, 0, 0, 1, protocol::SSH_AGENT_FAILURE]
    );

    let mut s = connect(&p.path);
    s.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert_eq!(
        read_to_eof(&mut s),
        vec![0, 0, 0, 1, protocol::SSH_AGENT_FAILURE]
    );
}

#[test]
fn zero_length_frame_closes_connection() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let mut s = connect(&p.path);
    s.write_all(&[0, 0, 0, 0]).unwrap();
    assert_eq!(
        read_to_eof(&mut s),
        vec![0, 0, 0, 1, protocol::SSH_AGENT_FAILURE]
    );
}

#[test]
fn abrupt_disconnects_do_not_affect_other_clients() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    for partial in [
        vec![0u8, 0],                           // half a header
        vec![0, 0, 0, 20, 13, 0, 0],            // half a body
        sign_request(&blob(ECDSA_CI), b"x", 0), // body without header framing
    ] {
        let mut s = connect(&p.path);
        s.write_all(&partial).unwrap();
        drop(s);
    }
    // Request sent, client gone before reading the reply.
    let mut s = connect(&p.path);
    protocol::write_frame(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    drop(s);
    assert_eq!(list(&p.path).len(), 1);
}

#[test]
fn slow_partial_frame_times_out() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let limits = Limits {
        frame_timeout: Duration::from_millis(300),
        ..test_limits()
    };
    let p = start_proxy_with(&up.path, &[ECDSA_CI_FP], limits, Duration::from_secs(5));
    let mut s = connect(&p.path);
    let start = Instant::now();
    // Trickle bytes slower than the frame deadline allows.
    s.write_all(&[0, 0]).unwrap();
    thread::sleep(Duration::from_millis(200));
    let _ = s.write_all(&[0]);
    thread::sleep(Duration::from_millis(200));
    let _ = s.write_all(&[5]);
    assert!(read_to_eof(&mut s).is_empty());
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn idle_client_times_out() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let limits = Limits {
        idle_timeout: Duration::from_millis(300),
        ..test_limits()
    };
    let p = start_proxy_with(&up.path, &[ECDSA_CI_FP], limits, Duration::from_secs(5));
    let mut s = connect(&p.path);
    let start = Instant::now();
    assert!(read_to_eof(&mut s).is_empty());
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn upstream_unavailable_fails_closed_without_env_fallback() {
    // A fully populated agent is reachable through SSH_AUTH_SOCK, but the
    // proxy must never use it: its configured upstream does not exist.
    let full = MockAgent::start(three_identities(), Mode::Normal);
    std::env::set_var("SSH_AUTH_SOCK", &full.path);
    let dir = private_tempdir();
    let p = start_proxy(&dir.path().join("missing.sock"), &[ECDSA_CI_FP]);
    assert_eq!(
        request(&p.path, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]),
        FAILURE
    );
    assert_eq!(
        request(&p.path, &sign_request(&blob(ECDSA_CI), b"x", 0)),
        FAILURE
    );
    assert!(full.received().is_empty());
}

#[test]
fn upstream_that_is_not_a_socket_is_refused() {
    let dir = private_tempdir();
    let file = dir.path().join("not-a-socket");
    std::fs::write(&file, b"").unwrap();
    let p = start_proxy(&file, &[ECDSA_CI_FP]);
    assert_eq!(
        request(&p.path, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]),
        FAILURE
    );
}

#[test]
fn upstream_timeout_fails_closed() {
    let up = MockAgent::start(three_identities(), Mode::Hang);
    let p = start_proxy_with(
        &up.path,
        &[ECDSA_CI_FP],
        test_limits(),
        Duration::from_millis(300),
    );
    let start = Instant::now();
    assert_eq!(
        request(&p.path, &sign_request(&blob(ECDSA_CI), b"x", 0)),
        FAILURE
    );
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[test]
fn hostile_upstream_responses_fail_closed() {
    for mode in [
        Mode::Failure,
        Mode::Garbage,
        Mode::Drop,
        Mode::Oversized,
        Mode::WrongType,
    ] {
        let up = MockAgent::start(three_identities(), mode);
        let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
        let sign = request(&p.path, &sign_request(&blob(ECDSA_CI), b"x", 0));
        assert_eq!(sign, FAILURE, "{mode:?}");
        let ids = request(&p.path, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
        if mode == Mode::WrongType {
            // Its identity answer is valid, and must still be filtered.
            assert_eq!(list(&p.path).len(), 1);
        } else {
            assert_eq!(ids, FAILURE, "{mode:?}");
        }
    }
}

#[test]
fn upstream_malformed_identity_with_allowlisted_fingerprint_is_hidden() {
    let junk = b"definitely not a public key".to_vec();
    let junk_fp = sigsieve::keys::Fingerprint::of_blob(&junk).to_string();
    let mut ids = three_identities();
    ids.push((junk.clone(), "junk".into()));
    let up = MockAgent::start(ids, Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP, &junk_fp]);
    assert_eq!(list(&p.path).len(), 1);
    assert_eq!(request(&p.path, &sign_request(&junk, b"x", 0)), FAILURE);
    assert!(up.sign_requests().is_empty());
}

#[test]
fn many_concurrent_clients() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
    let handles: Vec<_> = (0..32)
        .map(|i| {
            let path = p.path.clone();
            thread::spawn(move || {
                let mut s = connect(&path);
                for j in 0..20 {
                    let r = roundtrip(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
                    assert_eq!(r[..5], [12, 0, 0, 0, 1]);
                    let key = if (i + j) % 2 == 0 {
                        blob(ECDSA_CI)
                    } else {
                        blob(ED_ADMIN)
                    };
                    let r = roundtrip(&mut s, &sign_request(&key, b"c", 0));
                    assert_eq!(is_sign_response(&r), (i + j) % 2 == 0);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(up.sign_requests().len(), 32 * 10);
    assert!(up
        .sign_requests()
        .iter()
        .all(|r| *r == sign_request(&blob(ECDSA_CI), b"c", 0)));
}

#[test]
fn idle_connections_cannot_lock_out_new_clients() {
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let limits = Limits {
        max_clients: 4,
        ..test_limits()
    };
    let p = start_proxy_with(&up.path, &[ECDSA_CI_FP], limits, Duration::from_secs(5));
    // An attacker fills every slot with idle connections, oldest first.
    let mut held: Vec<_> = (0..4)
        .map(|_| {
            let mut s = connect(&p.path);
            roundtrip(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
            thread::sleep(Duration::from_millis(20));
            s
        })
        .collect();
    // Once they have been idle longer than `evict_after`, a new client is
    // served and the longest-idle connection is evicted.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(list(&p.path).len(), 1);
    assert!(
        read_to_eof(&mut held[0]).is_empty(),
        "oldest idle connection was not evicted"
    );
    // The other held connections still work.
    assert_eq!(
        roundtrip(&mut held[3], &[protocol::SSH_AGENTC_REQUEST_IDENTITIES])[..5],
        [12, 0, 0, 0, 1]
    );
}

#[test]
fn briefly_paused_connections_are_not_evicted() {
    // Regression (re-review): a client pausing between requests, like an ssh
    // login waiting for the server, must not be evicted by a burst of new
    // connections.
    let up = MockAgent::start(three_identities(), Mode::Normal);
    let limits = Limits {
        max_clients: 4,
        evict_after: Duration::from_secs(5),
        ..test_limits()
    };
    let p = start_proxy_with(&up.path, &[ECDSA_CI_FP], limits, Duration::from_secs(5));
    let mut legit = connect(&p.path);
    roundtrip(&mut legit, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
    let _attackers: Vec<_> = (0..3).map(|_| connect(&p.path)).collect();
    thread::sleep(Duration::from_millis(100));
    for _ in 0..8 {
        let mut s = connect(&p.path);
        let _ = protocol::write_frame(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
        assert!(
            read_to_eof(&mut s).is_empty(),
            "over-limit client was served"
        );
    }
    // The paused client continues its session.
    assert!(is_sign_response(&roundtrip(
        &mut legit,
        &sign_request(&blob(ECDSA_CI), b"x", 0)
    )));
}

#[test]
fn busy_connections_are_not_evicted_and_new_client_is_refused() {
    let up = MockAgent::start(three_identities(), Mode::Hang);
    let limits = Limits {
        max_clients: 2,
        ..test_limits()
    };
    let p = start_proxy_with(&up.path, &[ECDSA_CI_FP], limits, Duration::from_secs(3));
    // Two clients each wait on a slow upstream sign request (busy, not idle).
    let busy: Vec<_> = (0..2)
        .map(|_| {
            let mut s = connect(&p.path);
            protocol::write_frame(&mut s, &sign_request(&blob(ECDSA_CI), b"x", 0)).unwrap();
            s
        })
        .collect();
    thread::sleep(Duration::from_millis(300));
    let mut extra = connect(&p.path);
    let _ = protocol::write_frame(&mut extra, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]);
    assert!(
        read_to_eof(&mut extra).is_empty(),
        "over-limit client was served"
    );
    // Busy clients still get their (failed, timed-out) answers.
    for mut s in busy {
        let t = Duration::from_secs(10);
        assert_eq!(
            protocol::read_frame(&mut s, t, t).unwrap().unwrap(),
            FAILURE
        );
    }
}

#[test]
fn slow_reader_cannot_extend_the_reply_write_deadline() {
    // A reply larger than the socket buffers, drained a little at a time:
    // each write makes some progress, so only a deadline for the whole reply
    // stops a remote client from holding the connection indefinitely.
    let ids = vec![(blob(ECDSA_CI), "c".repeat(250_000))];
    let up = MockAgent::start(ids, Mode::Normal);
    let limits = Limits {
        write_timeout: Duration::from_millis(500),
        ..test_limits()
    };
    let p = start_proxy_with(&up.path, &[ECDSA_CI_FP], limits, Duration::from_secs(3));
    let mut s = connect(&p.path);
    protocol::write_frame(&mut s, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut header = [0u8; 4];
    s.read_exact(&mut header).unwrap();
    let declared = u32::from_be_bytes(header) as usize;
    let mut buf = [0u8; 1024];
    let mut body = 0;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        match s.read(&mut buf).unwrap() {
            0 => break,
            n => body += n,
        }
        thread::sleep(Duration::from_millis(50));
    }
    // Then drain quickly: the proxy must have given up and closed.
    while body < declared {
        match s.read(&mut buf).expect("connection left open") {
            0 => break,
            n => body += n,
        }
    }
    assert!(
        body < declared,
        "slow reader received the whole {declared}-byte reply"
    );
}

mod hostile_client {
    use super::*;
    use proptest::prelude::*;

    fn arb_request() -> impl Strategy<Value = Vec<u8>> {
        let key = prop_oneof![
            Just(blob(ECDSA_CI)),
            Just(blob(ED_ADMIN)),
            Just(blob(ED_PERSONAL)),
            proptest::collection::vec(any::<u8>(), 0..80),
        ];
        prop_oneof![
            // Fully random payloads.
            proptest::collection::vec(any::<u8>(), 1..200),
            // Well-formed sign requests with random keys/flags.
            (
                key.clone(),
                proptest::collection::vec(any::<u8>(), 0..64),
                any::<u32>()
            )
                .prop_map(|(k, d, f)| sign_request(&k, &d, f)),
            // Sign requests with random trailing bytes.
            (key, proptest::collection::vec(any::<u8>(), 1..16)).prop_map(|(k, t)| {
                let mut r = sign_request(&k, b"d", 0);
                r.extend_from_slice(&t);
                r
            }),
            // Random type byte with a random body.
            (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..64)).prop_map(|(t, b)| {
                let mut r = vec![t];
                r.extend_from_slice(&b);
                r
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

        // Whatever a hostile client sends, the upstream only ever receives
        // bare identity requests and well-formed sign requests for the
        // approved key with known flags, and identity answers stay filtered.
        #[test]
        fn upstream_only_sees_authorized_traffic(reqs in proptest::collection::vec(arb_request(), 1..12)) {
            let up = MockAgent::start(three_identities(), Mode::Normal);
            let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
            let mut s = connect(&p.path);
            for req in &reqs {
                let r = roundtrip(&mut s, req);
                if r[0] == protocol::SSH_AGENT_IDENTITIES_ANSWER {
                    let ids = sigsieve::upstream::parse_identities_answer(&r).unwrap();
                    prop_assert!(ids.iter().all(|i| i.blob == blob(ECDSA_CI)));
                }
            }
            for m in up.received() {
                match m[0] {
                    protocol::SSH_AGENTC_REQUEST_IDENTITIES => prop_assert_eq!(m.len(), 1),
                    protocol::SSH_AGENTC_SIGN_REQUEST => {
                        let mut r = protocol::Reader::new(&m[1..]);
                        prop_assert_eq!(r.string().unwrap(), &blob(ECDSA_CI)[..]);
                        r.string().unwrap();
                        let flags = r.u32().unwrap();
                        prop_assert_eq!(flags & !protocol::ALLOWED_SIGN_FLAGS, 0);
                        prop_assert!(flags == 0, "the only allowed property-test identity is ECDSA");
                        prop_assert!(r.finish().is_ok());
                    }
                    t => prop_assert!(false, "upstream received type {}", t),
                }
            }
        }
    }
}

mod failure_injection {
    use super::*;

    #[test]
    fn upstream_restart_is_recovered_without_restarting_the_proxy() {
        let dir = private_tempdir();
        let path = dir.path().join("up.sock");
        let first = MockAgent::start(three_identities(), Mode::Normal);
        // Point the proxy at a stable path that we can swap underneath it.
        std::os::unix::fs::symlink(&first.path, &path).unwrap();
        let p = start_proxy(&path, &[ECDSA_CI_FP]);
        assert_eq!(list(&p.path).len(), 1);
        // Agent crashes: requests fail closed.
        drop(first);
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            request(&p.path, &[protocol::SSH_AGENTC_REQUEST_IDENTITIES]),
            FAILURE
        );
        // Agent comes back (new process, new socket): service resumes.
        let second = MockAgent::start(three_identities(), Mode::Normal);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&second.path, &path).unwrap();
        assert_eq!(list(&p.path).len(), 1);
        assert!(is_sign_response(&request(
            &p.path,
            &sign_request(&blob(ECDSA_CI), b"x", 0)
        )));
    }

    #[test]
    fn failed_upstream_signature_is_not_retried() {
        // A retry would mean a second Touch ID prompt for one request.
        for mode in [Mode::Failure, Mode::Drop, Mode::Garbage] {
            let up = MockAgent::start(three_identities(), mode);
            let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
            assert_eq!(
                request(&p.path, &sign_request(&blob(ECDSA_CI), b"x", 0)),
                FAILURE
            );
            thread::sleep(Duration::from_millis(50));
            assert_eq!(up.sign_requests().len(), 1, "{mode:?}");
        }
    }

    #[test]
    fn byte_by_byte_frames_within_deadline_are_served() {
        let up = MockAgent::start(three_identities(), Mode::Normal);
        let p = start_proxy(&up.path, &[ECDSA_CI_FP]);
        let mut s = connect(&p.path);
        let mut frame = Vec::new();
        put_string(&mut frame, &sign_request(&blob(ECDSA_CI), b"slow", 0));
        for b in frame {
            s.write_all(&[b]).unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        let t = Duration::from_secs(5);
        let r = protocol::read_frame(&mut s, t, t).unwrap().unwrap();
        assert!(is_sign_response(&r));
    }
}

/// An upstream that announces a complete, valid sign response but closes the
/// connection before its last four bytes (all zero) arrive. Zero-filling the
/// missing tail would yield a well-formed signature, so this fails only if a
/// truncated upstream frame is ever treated as complete.
#[test]
fn truncated_upstream_sign_response_fails_closed() {
    let dir = private_tempdir();
    let path = dir.path().join("trunc.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let mut sig = Vec::new();
    put_string(&mut sig, b"ecdsa-sha2-nistp256");
    put_string(&mut sig, b"sig\0\0\0\0");
    let mut reply = vec![protocol::SSH_AGENT_SIGN_RESPONSE];
    put_string(&mut reply, &sig);
    let server = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let t = Duration::from_secs(5);
        protocol::read_frame(&mut s, t, t).unwrap().unwrap();
        let mut out = (reply.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&reply[..reply.len() - 4]);
        s.write_all(&out).unwrap();
    });
    let p = start_proxy(&path, &[ECDSA_CI_FP]);
    assert_eq!(
        request(&p.path, &sign_request(&blob(ECDSA_CI), b"x", 0)),
        FAILURE
    );
    server.join().unwrap();
}
