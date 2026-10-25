//! SigSieve: an SSH agent proxy that exposes only allowlisted identities.
//!
//! Module layout:
//! - [`protocol`]: SSH agent wire framing and field parsing (untrusted input).
//! - [`keys`]: public-key blob validation and SHA256 fingerprints.
//! - [`policy`]: the default-deny allowlist and optional destination set.
//! - [`binding`]: verified session bindings and destination authorization.
//! - [`upstream`]: client for the real agent (e.g. Secretive).
//! - [`socket`]: secure creation, inspection and cleanup of Unix sockets.
//! - [`proxy`]: request authorization and the connection/accept loops.
//! - [`sshconfig`]: refuses `Match exec` before ssh evaluates a configuration.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod binding;
#[doc(hidden)]
pub mod fuzzing;
pub mod keys;
pub mod policy;
pub mod protocol;
pub mod proxy;
pub mod socket;
pub mod sshconfig;
pub mod upstream;
