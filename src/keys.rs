//! Public-key blob validation and SSH SHA256 fingerprints.
//!
//! A fingerprint is `SHA256:` followed by unpadded base64 of SHA-256 over the
//! exact wire-format public-key blob, the same value `ssh-keygen -lf` prints.
//! Authorization always derives the fingerprint from the blob itself, never
//! from comments or caller-supplied strings.

use std::fmt;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::protocol::{Reader, SSH_AGENT_RSA_SHA2_256, SSH_AGENT_RSA_SHA2_512};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of_blob(blob: &[u8]) -> Self {
        Fingerprint(Sha256::digest(blob).into())
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHA256:{}", STANDARD_NO_PAD.encode(self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidFingerprint(pub String);

impl fmt::Display for InvalidFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid fingerprint {:?}: expected SHA256:<43 base64 characters> as printed by `ssh-keygen -lf`",
            self.0
        )
    }
}

impl std::error::Error for InvalidFingerprint {}

impl FromStr for Fingerprint {
    type Err = InvalidFingerprint;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || InvalidFingerprint(s.to_string());
        let b64 = s.strip_prefix("SHA256:").ok_or_else(err)?;
        let raw = STANDARD_NO_PAD.decode(b64).map_err(|_| err())?;
        let arr: [u8; 32] = raw.try_into().map_err(|_| err())?;
        Ok(Fingerprint(arr))
    }
}

/// Plain public-key algorithms SigSieve recognises. Certificates are not
/// supported and are treated as unknown (hidden, never signable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Rsa,
    SkEd25519,
    SkEcdsaP256,
}

impl KeyType {
    pub fn name(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ED25519",
            KeyType::EcdsaP256 => "ECDSA-P256",
            KeyType::EcdsaP384 => "ECDSA-P384",
            KeyType::EcdsaP521 => "ECDSA-P521",
            KeyType::Rsa => "RSA",
            KeyType::SkEd25519 => "ED25519-SK",
            KeyType::SkEcdsaP256 => "ECDSA-SK",
        }
    }

    /// The one signature algorithm a sign request with `flags` selects, or
    /// `None` if SigSieve refuses that combination. RSA must request exactly
    /// one SHA-2 algorithm: legacy `ssh-rsa` (SHA-1) is never requested or
    /// accepted. Other key types take no flags.
    pub fn signature_alg(self, flags: u32) -> Option<&'static [u8]> {
        let alg: &'static [u8] = match (self, flags) {
            (KeyType::Rsa, SSH_AGENT_RSA_SHA2_256) => b"rsa-sha2-256",
            (KeyType::Rsa, SSH_AGENT_RSA_SHA2_512) => b"rsa-sha2-512",
            (KeyType::Rsa, _) | (_, 1..) => return None,
            (KeyType::Ed25519, 0) => b"ssh-ed25519",
            (KeyType::EcdsaP256, 0) => b"ecdsa-sha2-nistp256",
            (KeyType::EcdsaP384, 0) => b"ecdsa-sha2-nistp384",
            (KeyType::EcdsaP521, 0) => b"ecdsa-sha2-nistp521",
            (KeyType::SkEd25519, 0) => b"sk-ssh-ed25519@openssh.com",
            (KeyType::SkEcdsaP256, 0) => b"sk-ecdsa-sha2-nistp256@openssh.com",
        };
        Some(alg)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    Malformed,
    Unsupported,
}

/// Validate that `blob` is a well-formed public key of a supported type.
///
/// This is a structural check (field count, lengths, encodings, no trailing
/// bytes). It deliberately does not do curve arithmetic; the upstream agent
/// holds the real key and the fingerprint binds the exact bytes.
pub fn parse_public_key(blob: &[u8]) -> Result<KeyType, KeyError> {
    let mut r = Reader::new(blob);
    let alg = r.string().map_err(|_| KeyError::Malformed)?;
    let kind = match alg {
        b"ssh-ed25519" => {
            ed25519_point(&mut r)?;
            KeyType::Ed25519
        }
        b"ecdsa-sha2-nistp256" => {
            ecdsa_point(&mut r, b"nistp256", 65)?;
            KeyType::EcdsaP256
        }
        b"ecdsa-sha2-nistp384" => {
            ecdsa_point(&mut r, b"nistp384", 97)?;
            KeyType::EcdsaP384
        }
        b"ecdsa-sha2-nistp521" => {
            ecdsa_point(&mut r, b"nistp521", 133)?;
            KeyType::EcdsaP521
        }
        b"ssh-rsa" => {
            let e = mpint(&mut r)?;
            let n = mpint(&mut r)?;
            // n must be odd and at least 1024 bits; e must be odd and > 1.
            if n.len() < 128 || n.len() > 2048 || n[n.len() - 1] & 1 == 0 {
                return Err(KeyError::Malformed);
            }
            if e.is_empty() || e.len() > 8 || e[e.len() - 1] & 1 == 0 || e == [1] {
                return Err(KeyError::Malformed);
            }
            KeyType::Rsa
        }
        b"sk-ssh-ed25519@openssh.com" => {
            ed25519_point(&mut r)?;
            r.string().map_err(|_| KeyError::Malformed)?; // application
            KeyType::SkEd25519
        }
        b"sk-ecdsa-sha2-nistp256@openssh.com" => {
            ecdsa_point(&mut r, b"nistp256", 65)?;
            r.string().map_err(|_| KeyError::Malformed)?; // application
            KeyType::SkEcdsaP256
        }
        _ => return Err(KeyError::Unsupported),
    };
    r.finish().map_err(|_| KeyError::Malformed)?;
    Ok(kind)
}

fn ed25519_point(r: &mut Reader<'_>) -> Result<(), KeyError> {
    match r.string() {
        Ok(pk) if pk.len() == 32 => Ok(()),
        _ => Err(KeyError::Malformed),
    }
}

fn ecdsa_point(r: &mut Reader<'_>, curve: &[u8], point_len: usize) -> Result<(), KeyError> {
    if r.string().map_err(|_| KeyError::Malformed)? != curve {
        return Err(KeyError::Malformed);
    }
    match r.string() {
        // Uncompressed SEC1 point, as emitted by OpenSSH and Secretive.
        Ok(q) if q.len() == point_len && q[0] == 0x04 => Ok(()),
        _ => Err(KeyError::Malformed),
    }
}

/// A positive SSH `mpint` with canonical (minimal) encoding, magnitude bytes.
fn mpint<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], KeyError> {
    let raw = r.string().map_err(|_| KeyError::Malformed)?;
    match raw {
        [] => Ok(raw),
        [b0, ..] if b0 & 0x80 != 0 => Err(KeyError::Malformed), // negative
        [0, b1, ..] if b1 & 0x80 == 0 => Err(KeyError::Malformed), // non-minimal
        [0] => Err(KeyError::Malformed),
        [0, rest @ ..] => Ok(rest),
        _ => Ok(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn decode(line: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(line.split_whitespace().nth(1).unwrap())
            .unwrap()
    }

    // Disposable keys generated with ssh-keygen for this test suite only; the
    // expected values are `ssh-keygen -lf` output.
    const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA1abwZk+OzBA5adgQFl7Qrqk5/lKinYuHEaY4UOpQdWjJ6drflUMK1bAj3EbuPY1eK8iSv24Q108y8McHLkNYk=";
    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJodCRRgD2YmhX4C1i8E4CrhCRTjXD9w8Y3QnaoqwQqJ";
    const RSA: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHv5D4WLpHMocNgizCnJBpBSL1aoTF3JhC1tZpjRam4a9GiCh8lL+y/iT+KN+QY3srHhZAwFmsiQRa2Aaxeb47eUDD66y3ZrDRUdz71GwZWJs5nhuMs0OAcT9hKiUZ87pUcfSxtgTLuXruU54JflI1v4tAr+wTiKwG9wk/aKz4iqSoXOtlXEn1rJDbL4J0fJ/nQQUeL0mWkZiNUCbrHcrTIB97Rr6RUCl6ZXbyO1hx39XFlAXScIbkceEBc7Uq3kWpfqyHa6OUtsiUVXZUwEABMQfkUm/DrSxKSqBMbmHylh6+amzldHDxLYg8T51vK02rgvfat8+DpYs8ddghxlxJ";

    #[test]
    fn fingerprints_match_ssh_keygen() {
        for (line, kind, fp) in [
            (
                ECDSA,
                KeyType::EcdsaP256,
                "SHA256:VRO/kv535DR0mIZ50/cjw2hm1/JzqMCFiQw2Iko9hXI",
            ),
            (
                ED25519,
                KeyType::Ed25519,
                "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE",
            ),
            (
                RSA,
                KeyType::Rsa,
                "SHA256:i5ZyJ0v3TndyWZIVkZBZoV3wQfM3fn8s1qjdhbqQtFE",
            ),
        ] {
            let blob = decode(line);
            assert_eq!(parse_public_key(&blob), Ok(kind));
            assert_eq!(Fingerprint::of_blob(&blob).to_string(), fp);
            assert_eq!(
                fp.parse::<Fingerprint>().unwrap(),
                Fingerprint::of_blob(&blob)
            );
        }
    }

    #[test]
    fn signature_algorithms_exclude_rsa_sha1_and_foreign_flags() {
        let rsa = KeyType::Rsa;
        assert_eq!(rsa.signature_alg(0x02), Some(&b"rsa-sha2-256"[..]));
        assert_eq!(rsa.signature_alg(0x04), Some(&b"rsa-sha2-512"[..]));
        for flags in [0, 0x01, 0x06, 0x08, u32::MAX] {
            assert_eq!(rsa.signature_alg(flags), None, "rsa flags {flags:#x}");
        }
        for kind in [
            KeyType::Ed25519,
            KeyType::EcdsaP256,
            KeyType::EcdsaP384,
            KeyType::EcdsaP521,
            KeyType::SkEd25519,
            KeyType::SkEcdsaP256,
        ] {
            assert!(kind.signature_alg(0).is_some());
            for flags in [0x02, 0x04, 0x06, 0x01] {
                assert_eq!(kind.signature_alg(flags), None, "{kind:?} {flags:#x}");
            }
        }
    }

    #[test]
    fn rejects_invalid_fingerprints() {
        for bad in [
            "",
            "SHA256:",
            "MD5:aa:bb",
            "sha256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE",
            "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzI",
            "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE=",
            "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIEAA",
            " SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE",
            "SHA256:!!3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE",
        ] {
            assert!(bad.parse::<Fingerprint>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_malformed_and_unsupported_blobs() {
        let mut blob = decode(ED25519);
        blob.push(0);
        assert_eq!(parse_public_key(&blob), Err(KeyError::Malformed));
        let blob = decode(ECDSA);
        assert_eq!(
            parse_public_key(&blob[..blob.len() - 1]),
            Err(KeyError::Malformed)
        );
        assert_eq!(parse_public_key(&[]), Err(KeyError::Malformed));

        let mut cert = Vec::new();
        crate::protocol::put_string(&mut cert, b"ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(parse_public_key(&cert), Err(KeyError::Unsupported));

        // ECDSA blob claiming the wrong curve name.
        let mut bad = Vec::new();
        crate::protocol::put_string(&mut bad, b"ecdsa-sha2-nistp256");
        crate::protocol::put_string(&mut bad, b"nistp384");
        crate::protocol::put_string(&mut bad, &[4; 65]);
        assert_eq!(parse_public_key(&bad), Err(KeyError::Malformed));
    }

    proptest! {
        #[test]
        fn parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_public_key(&data);
        }

        #[test]
        fn fingerprint_display_roundtrips(bytes in any::<[u8; 32]>()) {
            let fp = Fingerprint(bytes);
            prop_assert_eq!(fp.to_string().parse::<Fingerprint>().unwrap(), fp);
        }
    }
}
