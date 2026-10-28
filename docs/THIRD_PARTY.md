# Third-party components

Normal (non-dev) dependencies of the `sigsieve` binary, generated from
`cargo metadata --locked`. The list includes build-time proc-macro crates
(e.g. `syn`, `clap_derive`) that are not linked into the binary. All are
permissive licenses compatible with SigSieve's MIT license; their notices
must ship with binary releases (see RELEASE_CHECKLIST.md). `cargo deny
check licenses` enforces the allowed set.

75 crates.

| Crate | Version | License |
|---|---|---|
| anstream | 1.0.0 | MIT OR Apache-2.0 |
| anstyle | 1.0.14 | MIT OR Apache-2.0 |
| anstyle-parse | 1.0.0 | MIT OR Apache-2.0 |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 |
| base16ct | 1.0.0 | Apache-2.0 OR MIT |
| base64 | 0.23.1 | MIT OR Apache-2.0 |
| base64ct | 1.8.3 | Apache-2.0 OR MIT |
| block-buffer | 0.12.1 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| clap | 4.6.7 | MIT OR Apache-2.0 |
| clap_builder | 4.6.7 | MIT OR Apache-2.0 |
| clap_derive | 4.6.7 | MIT OR Apache-2.0 |
| clap_lex | 1.1.1 | MIT OR Apache-2.0 |
| cmov | 0.5.4 | Apache-2.0 OR MIT |
| colorchoice | 1.0.5 | MIT OR Apache-2.0 |
| const-oid | 0.10.2 | Apache-2.0 OR MIT |
| cpubits | 0.1.1 | MIT OR Apache-2.0 |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 |
| crypto-bigint | 0.7.9 | Apache-2.0 OR MIT |
| crypto-common | 0.2.2 | MIT OR Apache-2.0 |
| ctutils | 0.4.5 | Apache-2.0 OR MIT |
| curve25519-dalek | 5.0.0 | BSD-3-Clause |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 |
| der | 0.8.2 | Apache-2.0 OR MIT |
| digest | 0.11.3 | MIT OR Apache-2.0 |
| ecdsa | 0.17.0 | Apache-2.0 OR MIT |
| ed25519 | 3.0.0 | Apache-2.0 OR MIT |
| ed25519-dalek | 3.0.0 | BSD-3-Clause |
| elliptic-curve | 0.14.1 | Apache-2.0 OR MIT |
| errno | 0.3.14 | MIT OR Apache-2.0 |
| ff | 0.14.0 | MIT/Apache-2.0 |
| fiat-crypto | 0.3.0 | MIT OR Apache-2.0 OR BSD-1-Clause |
| getrandom | 0.4.3 | MIT OR Apache-2.0 |
| group | 0.14.0 | MIT/Apache-2.0 |
| heck | 0.5.0 | MIT OR Apache-2.0 |
| hmac | 0.13.0 | MIT OR Apache-2.0 |
| hybrid-array | 0.4.15 | MIT OR Apache-2.0 |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| libc | 0.2.191 | MIT OR Apache-2.0 |
| num-traits | 0.2.19 | MIT OR Apache-2.0 |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 |
| p256 | 0.14.0 | Apache-2.0 OR MIT |
| p384 | 0.14.0 | Apache-2.0 OR MIT |
| p521 | 0.14.0 | Apache-2.0 OR MIT |
| pkcs8 | 0.11.0 | Apache-2.0 OR MIT |
| primefield | 0.14.0 | Apache-2.0 OR MIT |
| primeorder | 0.14.0 | Apache-2.0 OR MIT |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later |
| rand_core | 0.10.1 | MIT OR Apache-2.0 |
| rfc6979 | 0.6.0 | Apache-2.0 OR MIT |
| sec1 | 0.8.1 | Apache-2.0 OR MIT |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive | 1.0.229 | MIT OR Apache-2.0 |
| serdect | 0.4.3 | Apache-2.0 OR MIT |
| sha2 | 0.11.1 | MIT OR Apache-2.0 |
| signal-hook | 0.4.5 | Apache-2.0/MIT |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 |
| signature | 3.0.0 | Apache-2.0 OR MIT |
| spki | 0.8.1 | Apache-2.0 OR MIT |
| strsim | 0.11.1 | MIT |
| subtle | 2.6.1 | BSD-3-Clause |
| syn | 2.0.119 | MIT OR Apache-2.0 |
| syn | 3.0.9 | MIT OR Apache-2.0 |
| typenum | 1.20.1 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT |
| windows-link | 0.2.1 | MIT OR Apache-2.0 |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 |
| wnaf | 0.14.1 | Apache-2.0 OR MIT |
| zeroize | 1.9.1 | Apache-2.0 OR MIT |

License expressions: `(MIT OR Apache-2.0) AND Unicode-3.0` ×1, `Apache-2.0 OR MIT` ×24, `Apache-2.0/MIT` ×1, `BSD-3-Clause` ×3, `MIT` ×1, `MIT OR Apache-2.0` ×40, `MIT OR Apache-2.0 OR BSD-1-Clause` ×1, `MIT OR Apache-2.0 OR LGPL-2.1-or-later` ×1, `MIT/Apache-2.0` ×3
