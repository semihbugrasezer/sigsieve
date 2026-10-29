//! Stable-toolchain fuzzing: replays the committed seeds (fuzz/seeds, read via
//! the tests/data/fuzz-seeds symlink so they ship in the .crate) through the
//! same entry points as `fuzz/` and runs a bounded, deterministic mutation
//! loop over them. This is not coverage-guided; coverage-guided fuzzing
//! needs nightly + cargo-fuzz (see docs/TESTING.md).
//!
//! Iterations per seed: SIGSIEVE_FUZZ_ITERS (default 2000).

use std::fs;
use std::path::Path;

use sigsieve::fuzzing;

type Target = fn(&[u8]);

const TARGETS: &[(&str, Target)] = &[
    ("requests", fuzzing::requests),
    ("session_bind", fuzzing::session_bind),
    ("key_blob", fuzzing::key_blob),
    ("upstream_reply", fuzzing::upstream_reply),
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut d = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] ^= 1 << rng.below(8);
            }
            1 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] = rng.next() as u8;
            }
            2 => {
                let i = rng.below(d.len() + 1);
                d.insert(i, rng.next() as u8);
            }
            3 if !d.is_empty() => {
                let i = rng.below(d.len());
                d.remove(i);
            }
            4 if d.len() >= 4 => {
                // Corrupt a plausible length prefix.
                let i = rng.below(d.len() - 3);
                let v = [0u32, 1, 0x7fff_ffff, u32::MAX, rng.next() as u32][rng.below(5)];
                d[i..i + 4].copy_from_slice(&v.to_be_bytes());
            }
            _ => d.truncate(rng.below(d.len() + 1)),
        }
    }
    d
}

fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/fuzz-seeds")
        .join(target);
    let mut v: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("missing corpus {}: {e}", dir.display()))
        .map(|e| fs::read(e.unwrap().path()).unwrap())
        .collect();
    v.push(Vec::new());
    v
}

#[test]
fn corpus_replay_and_bounded_mutation() {
    let iters: usize = std::env::var("SIGSIEVE_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    for (name, target) in TARGETS {
        let corpus = seeds(name);
        assert!(corpus.len() > 1, "{name}: empty corpus");
        let mut rng = Rng(0x5157_5156_u64 ^ name.len() as u64);
        let mut runs = 0usize;
        for seed in &corpus {
            target(seed);
            runs += 1;
            for _ in 0..iters {
                target(&mutate(&mut rng, seed));
                runs += 1;
            }
        }
        eprintln!("fuzz {name}: {runs} inputs");
    }
}
