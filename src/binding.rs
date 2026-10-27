//! Destination binding: verified `session-bind@openssh.com` state and the
//! authorization of sign requests against it.
//!
//! This uses the checks OpenSSH's own ssh-agent applies to
//! destination-constrained keys (ssh-agent.c: `process_ext_session_bind`,
//! `parse_userauth_request`, `identity_permitted`, `process_sign_request2`),
//! with a stricter hostbound-only policy: the final authentication hop's
//! host key must be one of the allowed destination host keys.
//!
//! Why it is sound against a malicious forwarding host:
//! - Every binding is verified: the host key must have signed the session
//!   identifier (the server's KEX signature). A bind for a destination can only
//!   be produced by actually completing a key exchange with that destination.
//! - A sign request is only honoured if it is an SSH userauth request whose
//!   session identifier equals the most recent (authentication) binding, so the
//!   signature is only usable inside that one SSH session to that one server.
//! - Every authorized request must use
//!   `publickey-hostbound-v00@openssh.com`, which embeds the server host key in
//!   the signed data; the destination server checks it is its own key. This
//!   defeats an attacker who holds the private host key of a permitted host
//!   (e.g. root on the forwarding host) and forges bindings for other sessions.
//!
//! Only Ed25519 and ECDSA (P-256/384/521) host keys are supported for binding;
//! other host key types fail closed.

use std::collections::BTreeSet;
use std::fmt;

use crate::keys::{parse_public_key, Fingerprint, KeyType};
use crate::protocol::{Reader, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

/// Limits matching OpenSSH's ssh-agent.
pub const MAX_BINDINGS: usize = 16;
pub const MAX_SESSION_ID_LEN: usize = 128;

const SSH2_MSG_USERAUTH_REQUEST: u8 = 50;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    InitialBindFailed,
    Malformed,
    SessionIdTooLong,
    UnsupportedHostKey,
    BadSignature,
    AlreadyBoundForAuth,
    SessionIdKeyMismatch,
    TooManyBindings,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BindError::InitialBindFailed => "the initial binding on this connection failed",
            BindError::Malformed => "malformed session-bind",
            BindError::SessionIdTooLong => "session identifier too long",
            BindError::UnsupportedHostKey => {
                "unsupported host key type (only Ed25519/ECDSA host keys can be bound)"
            }
            BindError::BadSignature => "host key signature does not verify",
            BindError::AlreadyBoundForAuth => "connection already bound for authentication",
            BindError::SessionIdKeyMismatch => {
                "session identifier recorded with a different host key"
            }
            BindError::TooManyBindings => "too many bindings on connection",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    NotBound,
    BindFailedEarlier,
    LastHopIsForwarding,
    NotUserauth,
    SessionIdMismatch,
    HostboundRequired,
    HostKeyMismatch,
    DestinationNotAllowed(Fingerprint),
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denied::NotBound => write!(f, "connection has no verified session binding"),
            Denied::BindFailedEarlier => write!(f, "a session bind on this connection failed"),
            Denied::LastHopIsForwarding => write!(f, "sign attempted on a forwarding hop"),
            Denied::NotUserauth => write!(f, "data is not an SSH user authentication request"),
            Denied::SessionIdMismatch => {
                write!(
                    f,
                    "session identifier does not match the most recent binding"
                )
            }
            Denied::HostboundRequired => {
                write!(
                    f,
                    "destination binding requires publickey-hostbound authentication"
                )
            }
            Denied::HostKeyMismatch => {
                write!(f, "host key in request does not match the bound host key")
            }
            Denied::DestinationNotAllowed(fp) => {
                write!(f, "destination host key {fp} is not an allowed destination")
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Binding {
    hostkey: Vec<u8>,
    session_id: Vec<u8>,
    forwarding: bool,
}

/// Verified bindings of one downstream connection.
#[derive(Debug, Default)]
pub struct Bindings {
    list: Vec<Binding>,
    attempted: bool,
}

impl Bindings {
    /// Process the body of a `session-bind@openssh.com` extension (everything
    /// after the extension name).
    pub fn bind(&mut self, body: &[u8]) -> Result<(), BindError> {
        // SSH can keep forwarding after an unsupported first host key. A
        // remote peer must not replace that failure with a first-hop auth bind.
        if self.attempted && self.list.is_empty() {
            return Err(BindError::InitialBindFailed);
        }
        self.attempted = true;
        let mut r = Reader::new(body);
        let hostkey = r.string().map_err(|_| BindError::Malformed)?;
        let sid = r.string().map_err(|_| BindError::Malformed)?;
        let sig = r.string().map_err(|_| BindError::Malformed)?;
        let fwd = r.u8().map_err(|_| BindError::Malformed)?;
        r.finish().map_err(|_| BindError::Malformed)?;
        if sid.len() > MAX_SESSION_ID_LEN {
            return Err(BindError::SessionIdTooLong);
        }
        verify_hostkey_signature(hostkey, sig, sid)?;
        for b in &self.list {
            if !b.forwarding {
                return Err(BindError::AlreadyBoundForAuth);
            }
            if b.session_id == sid {
                return if b.hostkey == hostkey {
                    Ok(()) // already recorded
                } else {
                    Err(BindError::SessionIdKeyMismatch)
                };
            }
        }
        if self.list.len() >= MAX_BINDINGS {
            return Err(BindError::TooManyBindings);
        }
        self.list.push(Binding {
            hostkey: hostkey.to_vec(),
            session_id: sid.to_vec(),
            forwarding: fwd != 0,
        });
        Ok(())
    }

    /// Decide whether `key_blob` may sign `data` on this connection, given the
    /// allowed destination host keys.
    pub fn authorize(
        &self,
        key_blob: &[u8],
        data: &[u8],
        destinations: &BTreeSet<Fingerprint>,
    ) -> Result<(), Denied> {
        if self.attempted && self.list.is_empty() {
            return Err(Denied::BindFailedEarlier);
        }
        let last = self.list.last().ok_or(Denied::NotBound)?;
        if last.forwarding {
            return Err(Denied::LastHopIsForwarding);
        }
        let req = parse_userauth_request(data, key_blob).ok_or(Denied::NotUserauth)?;
        if req.session_id != last.session_id.as_slice() {
            return Err(Denied::SessionIdMismatch);
        }
        match req.hostkey {
            None => return Err(Denied::HostboundRequired),
            Some(hk) if hk != last.hostkey.as_slice() => return Err(Denied::HostKeyMismatch),
            _ => {}
        }
        let dest = Fingerprint::of_blob(&last.hostkey);
        if !destinations.contains(&dest) {
            return Err(Denied::DestinationNotAllowed(dest));
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

struct UserauthRequest<'a> {
    session_id: &'a [u8],
    hostkey: Option<&'a [u8]>,
}

/// Parse to-be-signed data as an SSH userauth request for `expected_key`.
fn parse_userauth_request<'a>(data: &'a [u8], expected_key: &[u8]) -> Option<UserauthRequest<'a>> {
    let mut r = Reader::new(data);
    let session_id = r.string().ok()?;
    if session_id.is_empty() {
        return None;
    }
    if r.u8().ok()? != SSH2_MSG_USERAUTH_REQUEST {
        return None;
    }
    let _user = r.string().ok()?;
    if r.string().ok()? != b"ssh-connection" {
        return None;
    }
    let method = r.string().ok()?;
    if r.u8().ok()? != 1 {
        return None; // signature must follow
    }
    let pkalg = r.string().ok()?;
    let key = r.string().ok()?;
    if key != expected_key || !alg_matches(pkalg, expected_key) {
        return None;
    }
    let hostkey = match method {
        b"publickey-hostbound-v00@openssh.com" => {
            let hk = r.string().ok()?;
            parse_public_key(hk).ok()?;
            Some(hk)
        }
        b"publickey" => None,
        _ => return None,
    };
    r.finish().ok()?;
    Some(UserauthRequest {
        session_id,
        hostkey,
    })
}

/// Whether the signature algorithm named in a userauth request is one the
/// proxy would sign with for the key's type (never legacy `ssh-rsa`).
fn alg_matches(pkalg: &[u8], key: &[u8]) -> bool {
    parse_public_key(key).is_ok_and(|kind| {
        [0, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512]
            .into_iter()
            .any(|flags| kind.signature_alg(flags) == Some(pkalg))
    })
}

/// Verify an SSH signature blob made by `hostkey` over `data`.
pub fn verify_hostkey_signature(hostkey: &[u8], sig: &[u8], data: &[u8]) -> Result<(), BindError> {
    let kind = parse_public_key(hostkey).map_err(|_| BindError::UnsupportedHostKey)?;
    if !matches!(
        kind,
        KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521
    ) {
        return Err(BindError::UnsupportedHostKey);
    }
    let mut k = Reader::new(hostkey);
    let key_alg = k.string().map_err(|_| BindError::Malformed)?;
    let mut s = Reader::new(sig);
    let sig_alg = s.string().map_err(|_| BindError::Malformed)?;
    let sig_body = s.string().map_err(|_| BindError::Malformed)?;
    s.finish().map_err(|_| BindError::Malformed)?;
    if sig_alg != key_alg {
        return Err(BindError::BadSignature);
    }
    match kind {
        KeyType::Ed25519 => {
            let pk: [u8; 32] = k
                .string()
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or(BindError::Malformed)?;
            let sig: [u8; 64] = sig_body.try_into().map_err(|_| BindError::BadSignature)?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk)
                .map_err(|_| BindError::BadSignature)?;
            vk.verify_strict(data, &ed25519_dalek::Signature::from_bytes(&sig))
                .map_err(|_| BindError::BadSignature)
        }
        KeyType::EcdsaP256 | KeyType::EcdsaP384 | KeyType::EcdsaP521 => {
            let _curve = k.string().map_err(|_| BindError::Malformed)?;
            let point = k.string().map_err(|_| BindError::Malformed)?;
            let mut rs = Reader::new(sig_body);
            let r = rs.string().map_err(|_| BindError::BadSignature)?;
            let s = rs.string().map_err(|_| BindError::BadSignature)?;
            rs.finish().map_err(|_| BindError::BadSignature)?;
            verify_ecdsa(kind, point, r, s, data)
        }
        _ => Err(BindError::UnsupportedHostKey),
    }
}

/// Positive SSH mpint as a big-endian unsigned integer of exactly `len`
/// bytes.
fn mpint_to_fixed(m: &[u8], len: usize) -> Option<Vec<u8>> {
    let mag = match m {
        [0, rest @ ..] if rest.first().is_some_and(|b| b & 0x80 != 0) => rest,
        [b0, ..] if b0 & 0x80 != 0 => return None, // negative
        [0, ..] => return None,                    // non-minimal
        _ => m,
    };
    if mag.is_empty() || mag.len() > len {
        return None;
    }
    let mut out = vec![0u8; len - mag.len()];
    out.extend_from_slice(mag);
    Some(out)
}

fn verify_ecdsa(
    kind: KeyType,
    point: &[u8],
    r: &[u8],
    s: &[u8],
    data: &[u8],
) -> Result<(), BindError> {
    use p256::ecdsa::signature::Verifier;
    let bad = || BindError::BadSignature;
    macro_rules! verify {
        ($curve:ident, $len:expr) => {{
            let mut rs = mpint_to_fixed(r, $len).ok_or_else(bad)?;
            rs.extend(mpint_to_fixed(s, $len).ok_or_else(bad)?);
            let sig = $curve::ecdsa::Signature::from_slice(&rs).map_err(|_| bad())?;
            let vk = $curve::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| bad())?;
            vk.verify(data, &sig).map_err(|_| bad())
        }};
    }
    match kind {
        KeyType::EcdsaP256 => verify!(p256, 32),
        KeyType::EcdsaP384 => verify!(p384, 48),
        KeyType::EcdsaP521 => verify!(p521, 66),
        _ => Err(BindError::UnsupportedHostKey),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocol::put_string;
    use proptest::prelude::*;

    /// A host identity able to sign session identifiers (test only).
    pub enum TestHost {
        Ed(ed25519_dalek::SigningKey),
        P256(p256::ecdsa::SigningKey),
        P384(p384::ecdsa::SigningKey),
        P521(p521::ecdsa::SigningKey),
    }

    fn mpint(b: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
        if v.first().is_some_and(|x| x & 0x80 != 0) {
            v.insert(0, 0);
        }
        v
    }

    impl TestHost {
        pub fn ed(seed: u8) -> Self {
            TestHost::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
        }
        pub fn p256(seed: u8) -> Self {
            TestHost::P256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
        }
        pub fn p384(seed: u8) -> Self {
            TestHost::P384(p384::ecdsa::SigningKey::from_slice(&[seed; 48]).unwrap())
        }
        pub fn p521(seed: u8) -> Self {
            let mut b = [seed; 66];
            b[0] = 0;
            TestHost::P521(p521::ecdsa::SigningKey::from_slice(&b).unwrap())
        }

        pub fn public_blob(&self) -> Vec<u8> {
            let mut out = Vec::new();
            match self {
                TestHost::Ed(k) => {
                    put_string(&mut out, b"ssh-ed25519");
                    put_string(&mut out, k.verifying_key().as_bytes());
                }
                TestHost::P256(k) => {
                    put_string(&mut out, b"ecdsa-sha2-nistp256");
                    put_string(&mut out, b"nistp256");
                    put_string(&mut out, k.verifying_key().to_sec1_point(false).as_bytes());
                }
                TestHost::P384(k) => {
                    put_string(&mut out, b"ecdsa-sha2-nistp384");
                    put_string(&mut out, b"nistp384");
                    put_string(&mut out, k.verifying_key().to_sec1_point(false).as_bytes());
                }
                TestHost::P521(k) => {
                    put_string(&mut out, b"ecdsa-sha2-nistp521");
                    put_string(&mut out, b"nistp521");
                    let vk = *k.verifying_key();
                    put_string(&mut out, vk.to_sec1_point(false).as_bytes());
                }
            }
            out
        }

        pub fn sign(&self, data: &[u8]) -> Vec<u8> {
            use p256::ecdsa::signature::Signer;
            let mut out = Vec::new();
            let mut ecdsa = |name: &[u8], r: &[u8], s: &[u8]| {
                let mut inner = Vec::new();
                put_string(&mut inner, &mpint(r));
                put_string(&mut inner, &mpint(s));
                put_string(&mut out, name);
                put_string(&mut out, &inner);
            };
            match self {
                TestHost::Ed(k) => {
                    let sig: ed25519_dalek::Signature = k.sign(data);
                    put_string(&mut out, b"ssh-ed25519");
                    put_string(&mut out, &sig.to_bytes());
                }
                TestHost::P256(k) => {
                    let sig: p256::ecdsa::Signature = k.sign(data);
                    let (r, s) = sig.split_bytes();
                    ecdsa(b"ecdsa-sha2-nistp256", &r, &s);
                }
                TestHost::P384(k) => {
                    let sig: p384::ecdsa::Signature = k.sign(data);
                    let (r, s) = sig.split_bytes();
                    ecdsa(b"ecdsa-sha2-nistp384", &r, &s);
                }
                TestHost::P521(k) => {
                    let sig: p521::ecdsa::Signature = k.sign(data);
                    let (r, s) = sig.split_bytes();
                    ecdsa(b"ecdsa-sha2-nistp521", &r, &s);
                }
            }
            out
        }

        /// Body of a session-bind extension (after the name).
        pub fn bind_body(&self, sid: &[u8], forwarding: bool) -> Vec<u8> {
            let mut b = Vec::new();
            put_string(&mut b, &self.public_blob());
            put_string(&mut b, sid);
            put_string(&mut b, &self.sign(sid));
            b.push(forwarding as u8);
            b
        }
    }

    /// To-be-signed userauth data.
    pub fn userauth(sid: &[u8], key: &[u8], pkalg: &[u8], hostkey: Option<&[u8]>) -> Vec<u8> {
        let mut d = Vec::new();
        put_string(&mut d, sid);
        d.push(SSH2_MSG_USERAUTH_REQUEST);
        put_string(&mut d, b"testuser");
        put_string(&mut d, b"ssh-connection");
        put_string(
            &mut d,
            if hostkey.is_some() {
                b"publickey-hostbound-v00@openssh.com"
            } else {
                b"publickey"
            },
        );
        d.push(1);
        put_string(&mut d, pkalg);
        put_string(&mut d, key);
        if let Some(hk) = hostkey {
            put_string(&mut d, hk);
        }
        d
    }

    fn client_key() -> Vec<u8> {
        TestHost::p256(9).public_blob()
    }

    fn dests(hosts: &[&TestHost]) -> BTreeSet<Fingerprint> {
        hosts
            .iter()
            .map(|h| Fingerprint::of_blob(&h.public_blob()))
            .collect()
    }

    #[test]
    fn bindings_verify_for_every_supported_host_key_type() {
        for host in [
            TestHost::ed(1),
            TestHost::p256(2),
            TestHost::p384(3),
            TestHost::p521(4),
        ] {
            let mut b = Bindings::default();
            b.bind(&host.bind_body(b"sid-1", false)).unwrap();
            assert_eq!(b.len(), 1);
        }
    }

    #[test]
    fn forged_or_mismatched_bindings_are_rejected() {
        let host = TestHost::ed(1);
        let other = TestHost::ed(2);
        // Signature over a different session identifier.
        let mut body = Vec::new();
        put_string(&mut body, &host.public_blob());
        put_string(&mut body, b"sid-A");
        put_string(&mut body, &host.sign(b"sid-B"));
        body.push(0);
        assert_eq!(
            Bindings::default().bind(&body),
            Err(BindError::BadSignature)
        );
        // Signature by a different key.
        let mut body = Vec::new();
        put_string(&mut body, &host.public_blob());
        put_string(&mut body, b"sid-A");
        put_string(&mut body, &other.sign(b"sid-A"));
        body.push(0);
        assert_eq!(
            Bindings::default().bind(&body),
            Err(BindError::BadSignature)
        );
        // Signature algorithm of another type.
        let p = TestHost::p256(3);
        let mut body = Vec::new();
        put_string(&mut body, &host.public_blob());
        put_string(&mut body, b"sid-A");
        put_string(&mut body, &p.sign(b"sid-A"));
        body.push(0);
        assert_eq!(
            Bindings::default().bind(&body),
            Err(BindError::BadSignature)
        );
        // Flipped bit in a valid signature, for each key type.
        for h in [
            TestHost::ed(5),
            TestHost::p256(6),
            TestHost::p384(7),
            TestHost::p521(8),
        ] {
            let mut body = h.bind_body(b"sid-x", false);
            let n = body.len();
            body[n - 3] ^= 1;
            assert_eq!(
                Bindings::default().bind(&body),
                Err(BindError::BadSignature)
            );
        }
        // Trailing data, truncation, unsupported host key types.
        let mut body = host.bind_body(b"sid", false);
        body.push(0);
        assert_eq!(Bindings::default().bind(&body), Err(BindError::Malformed));
        let body = host.bind_body(b"sid", false);
        assert_eq!(
            Bindings::default().bind(&body[..body.len() - 1]),
            Err(BindError::Malformed)
        );
        let rsa = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQDHv5D4WLpHMocNgizCnJBpBSL1aoTF3JhC1tZpjRam4a9GiCh8lL+y/iT+KN+QY3srHhZAwFmsiQRa2Aaxeb47eUDD66y3ZrDRUdz71GwZWJs5nhuMs0OAcT9hKiUZ87pUcfSxtgTLuXruU54JflI1v4tAr+wTiKwG9wk/aKz4iqSoXOtlXEn1rJDbL4J0fJ/nQQUeL0mWkZiNUCbrHcrTIB97Rr6RUCl6ZXbyO1hx39XFlAXScIbkceEBc7Uq3kWpfqyHa6OUtsiUVXZUwEABMQfkUm/DrSxKSqBMbmHylh6+amzldHDxLYg8T51vK02rgvfat8+DpYs8ddghxlxJ",
        )
        .unwrap();
        let mut body = Vec::new();
        put_string(&mut body, &rsa);
        put_string(&mut body, b"sid");
        put_string(&mut body, b"\0\0\0\x0crsa-sha2-512\0\0\0\x01x");
        body.push(0);
        assert_eq!(
            Bindings::default().bind(&body),
            Err(BindError::UnsupportedHostKey)
        );
    }

    #[test]
    fn alg_matches_accepts_only_each_key_types_own_algorithms() {
        let rsa = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQDHv5D4WLpHMocNgizCnJBpBSL1aoTF3JhC1tZpjRam4a9GiCh8lL+y/iT+KN+QY3srHhZAwFmsiQRa2Aaxeb47eUDD66y3ZrDRUdz71GwZWJs5nhuMs0OAcT9hKiUZ87pUcfSxtgTLuXruU54JflI1v4tAr+wTiKwG9wk/aKz4iqSoXOtlXEn1rJDbL4J0fJ/nQQUeL0mWkZiNUCbrHcrTIB97Rr6RUCl6ZXbyO1hx39XFlAXScIbkceEBc7Uq3kWpfqyHa6OUtsiUVXZUwEABMQfkUm/DrSxKSqBMbmHylh6+amzldHDxLYg8T51vK02rgvfat8+DpYs8ddghxlxJ",
        )
        .unwrap();
        // (name, key blob, the algorithms it may sign with)
        type Case = (&'static str, Vec<u8>, &'static [&'static [u8]]);
        let keys: [Case; 5] = [
            ("ed25519", TestHost::ed(1).public_blob(), &[b"ssh-ed25519"]),
            (
                "p256",
                TestHost::p256(2).public_blob(),
                &[b"ecdsa-sha2-nistp256"],
            ),
            (
                "p384",
                TestHost::p384(3).public_blob(),
                &[b"ecdsa-sha2-nistp384"],
            ),
            (
                "p521",
                TestHost::p521(4).public_blob(),
                &[b"ecdsa-sha2-nistp521"],
            ),
            ("rsa", rsa, &[b"rsa-sha2-256", b"rsa-sha2-512"]),
        ];
        let candidates: [&[u8]; 11] = [
            b"ssh-ed25519",
            b"ecdsa-sha2-nistp256",
            b"ecdsa-sha2-nistp384",
            b"ecdsa-sha2-nistp521",
            b"rsa-sha2-256",
            b"rsa-sha2-512",
            b"ssh-rsa",
            b"ssh-ed25519-cert-v01@openssh.com",
            b"rsa-sha2-512-cert-v01@openssh.com",
            b"sk-ssh-ed25519@openssh.com",
            b"",
        ];
        for (name, key, own) in &keys {
            for alg in candidates {
                assert_eq!(
                    alg_matches(alg, key),
                    own.contains(&alg),
                    "{name} with {}",
                    String::from_utf8_lossy(alg)
                );
            }
        }
        // Malformed or empty keys match nothing.
        let mut truncated = keys[0].1.clone();
        truncated.pop();
        for bad in [&b""[..], &truncated, b"not-a-key"] {
            assert!(!alg_matches(b"ssh-ed25519", bad));
        }
    }

    #[test]
    fn verify_hostkey_signature_rejects_edge_cases() {
        let data = b"session identifier";
        let hosts = [
            TestHost::ed(1),
            TestHost::p256(2),
            TestHost::p384(3),
            TestHost::p521(4),
        ];
        for h in &hosts {
            let key = h.public_blob();
            let sig = h.sign(data);
            assert_eq!(verify_hostkey_signature(&key, &sig, data), Ok(()));
            assert_eq!(
                verify_hostkey_signature(&key, &sig, b"session identifieR"),
                Err(BindError::BadSignature)
            );
        }
        // ECDSA: zero r or s, and trailing bytes after (r, s).
        let p = &hosts[1];
        let key = p.public_blob();
        let ecdsa = |r: &[u8], s: &[u8], extra: &[u8]| {
            let mut inner = Vec::new();
            put_string(&mut inner, r);
            put_string(&mut inner, s);
            inner.extend_from_slice(extra);
            let mut sig = Vec::new();
            put_string(&mut sig, b"ecdsa-sha2-nistp256");
            put_string(&mut sig, &inner);
            sig
        };
        let signed = p.sign(data);
        let mut r = Reader::new(&signed[4 + 19..]);
        let inner = r.string().unwrap().to_vec();
        let mut rs = Reader::new(&inner);
        let (good_r, good_s) = (rs.string().unwrap().to_vec(), rs.string().unwrap().to_vec());
        assert_eq!(
            verify_hostkey_signature(&key, &ecdsa(&good_r, &good_s, b""), data),
            Ok(())
        );
        for sig in [
            ecdsa(&[], &good_s, b""),
            ecdsa(&good_r, &[], b""),
            ecdsa(&[0], &good_s, b""),
            ecdsa(&good_r, &good_s, &[0]),
        ] {
            assert_eq!(
                verify_hostkey_signature(&key, &sig, data),
                Err(BindError::BadSignature)
            );
        }
        // Ed25519: signature body of the wrong length.
        let e = &hosts[0];
        let key = e.public_blob();
        let signed = e.sign(data);
        let mut r = Reader::new(&signed[4 + 11..]);
        let body = r.string().unwrap().to_vec();
        for len in [63, 65] {
            let mut b = body.clone();
            b.resize(len, 0);
            let mut sig = Vec::new();
            put_string(&mut sig, b"ssh-ed25519");
            put_string(&mut sig, &b);
            assert_eq!(
                verify_hostkey_signature(&key, &sig, data),
                Err(BindError::BadSignature)
            );
        }
    }

    #[test]
    fn rsa_userauth_must_name_a_sha2_algorithm() {
        let dest = TestHost::p256(2);
        let allowed = dests(&[&dest]);
        let rsa = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "AAAAB3NzaC1yc2EAAAADAQABAAABAQDHv5D4WLpHMocNgizCnJBpBSL1aoTF3JhC1tZpjRam4a9GiCh8lL+y/iT+KN+QY3srHhZAwFmsiQRa2Aaxeb47eUDD66y3ZrDRUdz71GwZWJs5nhuMs0OAcT9hKiUZ87pUcfSxtgTLuXruU54JflI1v4tAr+wTiKwG9wk/aKz4iqSoXOtlXEn1rJDbL4J0fJ/nQQUeL0mWkZiNUCbrHcrTIB97Rr6RUCl6ZXbyO1hx39XFlAXScIbkceEBc7Uq3kWpfqyHa6OUtsiUVXZUwEABMQfkUm/DrSxKSqBMbmHylh6+amzldHDxLYg8T51vK02rgvfat8+DpYs8ddghxlxJ",
        )
        .unwrap();
        let mut b = Bindings::default();
        b.bind(&dest.bind_body(b"s1", false)).unwrap();
        let auth = |alg: &[u8]| userauth(b"s1", &rsa, alg, Some(&dest.public_blob()));
        assert_eq!(b.authorize(&rsa, &auth(b"rsa-sha2-256"), &allowed), Ok(()));
        assert_eq!(b.authorize(&rsa, &auth(b"rsa-sha2-512"), &allowed), Ok(()));
        assert_eq!(
            b.authorize(&rsa, &auth(b"ssh-rsa"), &allowed),
            Err(Denied::NotUserauth)
        );
    }

    #[test]
    fn binding_state_rules_match_openssh() {
        let fwd = TestHost::ed(1);
        let dest = TestHost::ed(2);
        let mut b = Bindings::default();
        b.bind(&fwd.bind_body(b"s1", true)).unwrap();
        // Duplicate (same sid + key) is accepted without a new entry.
        b.bind(&fwd.bind_body(b"s1", true)).unwrap();
        assert_eq!(b.len(), 1);
        // Same sid, different key.
        assert_eq!(
            b.bind(&dest.bind_body(b"s1", false)),
            Err(BindError::SessionIdKeyMismatch)
        );
        b.bind(&dest.bind_body(b"s2", false)).unwrap();
        // Nothing may be bound after an authentication bind.
        assert_eq!(
            b.bind(&fwd.bind_body(b"s3", true)),
            Err(BindError::AlreadyBoundForAuth)
        );
        // Session identifier length and binding count limits.
        let mut b = Bindings::default();
        assert_eq!(
            b.bind(&fwd.bind_body(&[7; MAX_SESSION_ID_LEN + 1], true)),
            Err(BindError::SessionIdTooLong)
        );
        let mut b = Bindings::default();
        for i in 0..MAX_BINDINGS {
            b.bind(&fwd.bind_body(format!("s{i}").as_bytes(), true))
                .unwrap();
        }
        assert_eq!(
            b.bind(&fwd.bind_body(b"one-too-many", true)),
            Err(BindError::TooManyBindings)
        );
    }

    #[test]
    fn authorization_accepts_only_bound_userauth_to_allowed_destination() {
        let vps = TestHost::ed(1);
        let dest = TestHost::p256(2);
        let other = TestHost::ed(3);
        let key = client_key();
        let allowed = dests(&[&dest]);
        let alg: &[u8] = b"ecdsa-sha2-nistp256";

        let mut b = Bindings::default();
        assert_eq!(
            b.authorize(&key, &userauth(b"s2", &key, alg, None), &allowed),
            Err(Denied::NotBound)
        );
        b.bind(&vps.bind_body(b"s1", true)).unwrap();
        assert_eq!(
            b.authorize(
                &key,
                &userauth(b"s1", &key, alg, Some(&vps.public_blob())),
                &allowed
            ),
            Err(Denied::LastHopIsForwarding)
        );
        b.bind(&dest.bind_body(b"s2", false)).unwrap();
        let good = userauth(b"s2", &key, alg, Some(&dest.public_blob()));
        assert_eq!(b.authorize(&key, &good, &allowed), Ok(()));

        // Arbitrary data, wrong session, plain publickey on forwarded path,
        // host key mismatch, wrong key or algorithm.
        assert_eq!(
            b.authorize(&key, b"commit to sign", &allowed),
            Err(Denied::NotUserauth)
        );
        assert_eq!(
            b.authorize(
                &key,
                &userauth(b"s1", &key, alg, Some(&dest.public_blob())),
                &allowed
            ),
            Err(Denied::SessionIdMismatch)
        );
        assert_eq!(
            b.authorize(&key, &userauth(b"s2", &key, alg, None), &allowed),
            Err(Denied::HostboundRequired)
        );
        assert_eq!(
            b.authorize(
                &key,
                &userauth(b"s2", &key, alg, Some(&other.public_blob())),
                &allowed
            ),
            Err(Denied::HostKeyMismatch)
        );
        let other_key = TestHost::p256(4).public_blob();
        assert_eq!(
            b.authorize(
                &key,
                &userauth(b"s2", &other_key, alg, Some(&dest.public_blob())),
                &allowed
            ),
            Err(Denied::NotUserauth)
        );
        assert_eq!(
            b.authorize(
                &key,
                &userauth(b"s2", &key, b"ssh-ed25519", Some(&dest.public_blob())),
                &allowed
            ),
            Err(Denied::NotUserauth)
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            b.authorize(&key, &trailing, &allowed),
            Err(Denied::NotUserauth)
        );

        // Same flow to a destination that is not allowed.
        let mut b = Bindings::default();
        b.bind(&vps.bind_body(b"s1", true)).unwrap();
        b.bind(&other.bind_body(b"s9", false)).unwrap();
        assert!(matches!(
            b.authorize(
                &key,
                &userauth(b"s9", &key, alg, Some(&other.public_blob())),
                &allowed
            ),
            Err(Denied::DestinationNotAllowed(_))
        ));
    }

    #[test]
    fn failed_bind_disables_signing_and_single_hop_requires_hostbound() {
        let dest = TestHost::ed(2);
        let key = client_key();
        let allowed = dests(&[&dest]);
        let alg: &[u8] = b"ecdsa-sha2-nistp256";
        let mut b = Bindings::default();
        assert!(b.bind(b"garbage").is_err());
        assert_eq!(
            b.authorize(&key, &userauth(b"s", &key, alg, None), &allowed),
            Err(Denied::BindFailedEarlier)
        );
        // The proxy cannot prove that a single bind came from a local first
        // hop: older forwarding clients omit their initial session binding.
        let mut b = Bindings::default();
        b.bind(&dest.bind_body(b"s", false)).unwrap();
        assert_eq!(
            b.authorize(&key, &userauth(b"s", &key, alg, None), &allowed),
            Err(Denied::HostboundRequired)
        );
        assert_eq!(
            b.authorize(
                &key,
                &userauth(b"s", &key, alg, Some(&dest.public_blob())),
                &allowed
            ),
            Ok(())
        );
    }

    #[test]
    fn failed_initial_binding_cannot_be_replaced_by_an_authentication_bind() {
        let host = TestHost::ed(2);
        let key = client_key();
        let mut bindings = Bindings::default();
        // OpenSSH may keep forwarding after its initial bind fails, such as
        // an unsupported RSA forwarding-host key. The remote peer must not
        // replace that failure with a single authentication binding.
        assert!(bindings.bind(b"failed initial forwarding bind").is_err());
        assert_eq!(
            bindings.bind(&host.bind_body(b"victim-session", false)),
            Err(BindError::InitialBindFailed)
        );
        assert!(bindings
            .authorize(
                &key,
                &userauth(
                    b"victim-session",
                    &key,
                    b"ecdsa-sha2-nistp256",
                    Some(&host.public_blob())
                ),
                &dests(&[&host]),
            )
            .is_err());
    }

    #[test]
    fn attacker_holding_a_permitted_host_key_cannot_redirect_forwarded_auth() {
        // Root on the forwarding host owns its host key and allowlists... it
        // forges a binding of another server's session id with that key.
        let vps = TestHost::ed(1);
        let victim = TestHost::ed(7);
        let key = client_key();
        let allowed = dests(&[&vps]); // worst case: the VPS itself is allowed
        let alg: &[u8] = b"ecdsa-sha2-nistp256";
        let mut b = Bindings::default();
        b.bind(&vps.bind_body(b"s-fwd", true)).unwrap();
        b.bind(&vps.bind_body(b"s-victim", false)).unwrap(); // forged: victim's sid
                                                             // Plain publickey is refused on a forwarded path...
        assert_eq!(
            b.authorize(&key, &userauth(b"s-victim", &key, alg, None), &allowed),
            Err(Denied::HostboundRequired)
        );
        // ...and a hostbound request carries the VPS host key, which the
        // victim server rejects because it is not its own key; claiming the
        // victim's key fails here.
        assert_eq!(
            b.authorize(
                &key,
                &userauth(b"s-victim", &key, alg, Some(&victim.public_blob())),
                &allowed
            ),
            Err(Denied::HostKeyMismatch)
        );
    }

    #[test]
    fn mpint_conversion() {
        assert_eq!(mpint_to_fixed(&[1], 4), Some(vec![0, 0, 0, 1]));
        assert_eq!(mpint_to_fixed(&[0, 0x80], 2), Some(vec![0, 0x80]));
        assert_eq!(mpint_to_fixed(&[0x80], 2), None);
        assert_eq!(mpint_to_fixed(&[0, 1], 2), None);
        assert_eq!(mpint_to_fixed(&[], 2), None);
        assert_eq!(mpint_to_fixed(&[1, 2, 3], 2), None);
    }

    /// Regenerate fuzz seed corpora:
    /// `cargo test --lib write_fuzz_seeds -- --ignored`
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        use crate::protocol::put_u32;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
        let write = |target: &str, name: &str, data: &[u8]| {
            let dir = root.join(target);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), data).unwrap();
        };
        let framed = |msgs: &[Vec<u8>]| {
            let mut out = Vec::new();
            for m in msgs {
                put_string(&mut out, m);
            }
            out
        };
        let vps = TestHost::ed(1);
        let dest = TestHost::p256(2);
        let key = client_key();
        let ext = |name: &[u8], body: &[u8]| {
            let mut m = vec![27u8];
            put_string(&mut m, name);
            m.extend_from_slice(body);
            m
        };
        let sign = |data: &[u8], flags: u32| {
            let mut m = vec![13u8];
            put_string(&mut m, &key);
            put_string(&mut m, data);
            put_u32(&mut m, flags);
            m
        };
        let ua = userauth(
            b"s2",
            &key,
            b"ecdsa-sha2-nistp256",
            Some(&dest.public_blob()),
        );
        write("requests", "identities", &framed(&[vec![11]]));
        write(
            "requests",
            "sign",
            &framed(&[sign(b"data", 0), sign(b"data", 4)]),
        );
        write(
            "requests",
            "bind_then_sign",
            &framed(&[
                ext(b"session-bind@openssh.com", &vps.bind_body(b"s1", true)),
                ext(b"session-bind@openssh.com", &dest.bind_body(b"s2", false)),
                sign(&ua, 0),
            ]),
        );
        write(
            "requests",
            "mutations",
            &framed(&[
                vec![17, 0, 0, 0, 0],
                vec![18],
                vec![19],
                vec![22],
                vec![23],
                ext(b"query", b""),
            ]),
        );
        write("session_bind", "ed25519_fwd", &vps.bind_body(b"s1", true));
        write("session_bind", "p256_auth", &dest.bind_body(b"s2", false));
        write(
            "session_bind",
            "sequence",
            &framed(&[
                vps.bind_body(b"s1", true),
                dest.bind_body(b"s2", false),
                key.clone(),
                ua.clone(),
            ]),
        );
        write(
            "session_bind",
            "p384",
            &TestHost::p384(3).bind_body(b"s3", false),
        );
        write(
            "session_bind",
            "p521",
            &TestHost::p521(4).bind_body(b"s4", false),
        );
        write("key_blob", "ed25519", &vps.public_blob());
        write("key_blob", "p256", &dest.public_blob());
        write("key_blob", "p521", &TestHost::p521(4).public_blob());
        let mut ids = vec![12u8];
        put_u32(&mut ids, 2);
        for k in [vps.public_blob(), dest.public_blob()] {
            put_string(&mut ids, &k);
            put_string(&mut ids, b"comment");
        }
        write("upstream_reply", "two_identities", &ids);
    }

    proptest! {
        #[test]
        fn random_bind_bodies_never_panic_or_bind(data in proptest::collection::vec(any::<u8>(), 0..400)) {
            let mut b = Bindings::default();
            prop_assert!(b.bind(&data).is_err());
        }

        #[test]
        fn random_sign_data_is_never_authorized(data in proptest::collection::vec(any::<u8>(), 0..400)) {
            let dest = TestHost::ed(2);
            let mut b = Bindings::default();
            b.bind(&dest.bind_body(b"s", false)).unwrap();
            let key = client_key();
            let allowed = dests(&[&dest]);
            prop_assert!(b.authorize(&key, &data, &allowed).is_err());
        }

        #[test]
        fn mutated_valid_bind_never_verifies(idx in 0usize..10_000, bit in 0u8..8) {
            let host = TestHost::p256(2);
            let mut body = host.bind_body(b"session", false);
            let i = idx % body.len();
            body[i] ^= 1 << bit;
            // Mutating the forwarding flag is the only harmless change.
            if i != body.len() - 1 {
                prop_assert!(Bindings::default().bind(&body).is_err());
            }
        }
    }
}
