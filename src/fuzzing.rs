//! Fuzzing entry points shared by the cargo-fuzz targets (`fuzz/`) and the
//! stable corpus-replay test (`tests/fuzz_corpus.rs`). Each function asserts
//! the security invariant for arbitrary input, so a violation is a crash.
//! Not a stable API.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::binding::{Bindings, Denied};
use crate::keys::{parse_public_key, Fingerprint};
use crate::policy::Policy;
use crate::protocol::{self, Reader};
use crate::proxy::{Limits, Proxy};
use crate::upstream::{parse_identities_answer, Upstream};

const SOME_FP: &str = "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE";

fn unreachable_upstream() -> Upstream {
    Upstream::new("/nonexistent/sigsieve-fuzz.sock", Duration::from_millis(1))
}

/// A sequence of downstream requests (split by SSH string framing) on one
/// connection, under an identity-only and a destination-bound policy. With no
/// upstream, nothing may ever succeed except a verified session-bind.
pub fn requests(data: &[u8]) {
    let (plain, _) = Policy::from_fingerprints(&[SOME_FP]).unwrap();
    let bound = plain.clone().with_destinations(&[SOME_FP]).unwrap();
    for policy in [&plain, &bound] {
        let proxy = Proxy::new(policy.clone(), unreachable_upstream(), Limits::default());
        let mut bindings = Bindings::default();
        let mut r = Reader::new(data);
        while let Ok(req) = r.string() {
            let Some(resp) = proxy.handle_request(req, &mut bindings) else {
                break;
            };
            assert!(
                resp == [protocol::SSH_AGENT_FAILURE]
                    || resp == [protocol::SSH_AGENT_EXTENSION_FAILURE]
                    || resp == [protocol::SSH_AGENT_SUCCESS],
                "unexpected response {resp:?}"
            );
            if resp == [protocol::SSH_AGENT_SUCCESS] {
                // Only a session-bind with a valid host key signature can succeed.
                assert!(policy.destinations().is_some());
                assert_eq!(req.first(), Some(&protocol::SSH_AGENTC_EXTENSION));
            }
        }
    }
}

/// Raw bodies exercise signature verification; framed bind/bind/key/userauth
/// sequences also exercise authorization after valid bindings.
pub fn session_bind(data: &[u8]) {
    let mut b = Bindings::default();
    let _ = b.bind(data);
    let half = data.len() / 2;
    let _ = b.bind(&data[..half]);
    let _ = b.bind(&data[half..]);
    assert!(b.len() <= 3);
    // SOME_FP is not the fingerprint of any host key a fuzzer can sign for,
    // so nothing may be authorized for it.
    let dests = [SOME_FP.parse::<Fingerprint>().unwrap()]
        .into_iter()
        .collect();
    assert!(b.authorize(data, data, &dests).is_err());
    let _ = bound_authorization(data);
}

fn bound_authorization(data: &[u8]) -> Option<Result<(), Denied>> {
    let mut r = Reader::new(data);
    let (first, last, key, auth) = (
        r.string().ok()?,
        r.string().ok()?,
        r.string().ok()?,
        r.string().ok()?,
    );
    r.finish().ok()?;
    let mut b = Bindings::default();
    let _ = b.bind(first);
    let _ = b.bind(last);
    let dest = Reader::new(last).string().ok()?;
    let allowed = [Fingerprint::of_blob(dest)].into_iter().collect();
    let result = b.authorize(key, auth, &allowed);
    if result.is_ok() {
        assert!(b.authorize(key, auth, &BTreeSet::new()).is_err());
        let mut trailing = auth.to_vec();
        trailing.push(0);
        assert!(b.authorize(key, &trailing, &allowed).is_err());
    }
    Some(result)
}

/// Arbitrary key blobs through validation, fingerprinting and policy.
pub fn key_blob(data: &[u8]) {
    let fp = Fingerprint::of_blob(data);
    let (policy, _) = Policy::from_fingerprints(&[fp.to_string()]).unwrap();
    assert_eq!(policy.allows(data), parse_public_key(data).is_ok());
    assert_eq!(fp.to_string().parse::<Fingerprint>().unwrap(), fp);
}

/// Arbitrary upstream identity answers.
pub fn upstream_reply(data: &[u8]) {
    if let Ok(ids) = parse_identities_answer(data) {
        // Never more entries than the bytes could encode.
        assert!(ids.len() * 8 <= data.len());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn committed_sequence_reaches_successful_authorization() {
        let seed = include_bytes!("../fuzz/seeds/session_bind/sequence");
        assert_eq!(super::bound_authorization(seed), Some(Ok(())));
        super::session_bind(seed);
    }
}
