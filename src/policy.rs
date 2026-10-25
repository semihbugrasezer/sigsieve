//! Allowlist policy. Deny by default: an identity is usable only if its blob
//! is a well-formed, supported public key whose fingerprint is allowlisted.
//!
//! Optionally, a set of allowed destination host keys turns on destination
//! binding: allowed keys may then only sign SSH user authentication requests
//! for sessions cryptographically bound to one of those host keys (see
//! [`crate::binding`]).

use std::collections::BTreeSet;

use crate::keys::{parse_public_key, Fingerprint, InvalidFingerprint};

#[derive(Debug, Default, Clone)]
pub struct Policy {
    allowed: BTreeSet<Fingerprint>,
    destinations: Option<BTreeSet<Fingerprint>>,
}

impl Policy {
    /// Build a policy from fingerprint strings. Any invalid entry rejects the
    /// whole configuration (fail closed). Duplicate entries are collapsed and
    /// returned so the caller can warn about them.
    pub fn from_fingerprints<S: AsRef<str>>(
        entries: &[S],
    ) -> Result<(Policy, Vec<Fingerprint>), InvalidFingerprint> {
        let mut allowed = BTreeSet::new();
        let mut duplicates = Vec::new();
        for e in entries {
            let fp: Fingerprint = e.as_ref().parse()?;
            if !allowed.insert(fp) {
                duplicates.push(fp);
            }
        }
        Ok((
            Policy {
                allowed,
                destinations: None,
            },
            duplicates,
        ))
    }

    /// Enable destination binding with these destination host key
    /// fingerprints. An empty list leaves destination binding off. Any invalid
    /// entry rejects the whole configuration.
    pub fn with_destinations<S: AsRef<str>>(
        mut self,
        entries: &[S],
    ) -> Result<Policy, InvalidFingerprint> {
        if entries.is_empty() {
            return Ok(self);
        }
        let mut set = BTreeSet::new();
        for e in entries {
            set.insert(e.as_ref().parse()?);
        }
        self.destinations = Some(set);
        Ok(self)
    }

    /// Allowed destination host keys, when destination binding is enforced.
    pub fn destinations(&self) -> Option<&BTreeSet<Fingerprint>> {
        self.destinations.as_ref()
    }

    /// Whether `blob` may be listed and used for signing.
    pub fn allows(&self, blob: &[u8]) -> bool {
        parse_public_key(blob).is_ok() && self.allowed.contains(&Fingerprint::of_blob(blob))
    }

    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    pub fn fingerprints(&self) -> impl Iterator<Item = &Fingerprint> {
        self.allowed.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SHA256:XL3lJQbUZ3vcFR1pKSGm15eWRuVdOR+7STUtaAipzIE";

    #[test]
    fn empty_policy_allows_nothing() {
        let (p, _) = Policy::from_fingerprints::<&str>(&[]).unwrap();
        assert!(p.is_empty());
        assert!(!p.allows(b"anything"));
    }

    #[test]
    fn one_invalid_entry_rejects_everything() {
        assert!(Policy::from_fingerprints(&[FP, "SHA256:nope"]).is_err());
    }

    #[test]
    fn duplicates_collapse_and_are_reported() {
        let (p, dups) = Policy::from_fingerprints(&[FP, FP]).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(dups.len(), 1);
    }

    #[test]
    fn allowlisted_fingerprint_of_malformed_blob_is_denied() {
        let blob = b"not a key";
        let fp = Fingerprint::of_blob(blob).to_string();
        let (p, _) = Policy::from_fingerprints(&[fp]).unwrap();
        assert!(!p.allows(blob));
    }
}
