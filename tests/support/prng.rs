//! Seeded xorshift PRNG for property tests (SPEC §9.1 note 3, §13 item 2). No `proptest`:
//! every randomised test draws from a [`Prng`] whose seed is printed on failure and can be
//! pinned with `GCLONE_TEST_SEED`.
//!
//! Use from an integration test:
//! ```ignore
//! mod support;
//! use support::prng::Prng;
//!
//! #[test]
//! fn merge_converges() {
//!     support::prng::for_each_seed("merge_converges", 200, |rng| {
//!         let n = rng.range(1, 20);
//!         // …
//!     });
//! }
//! ```
//! NOT cryptographic. Never use it for keys, salts or ids outside tests.
//!
//! This file has no tests of its own on purpose: it is compiled into every integration-test
//! binary that says `mod support;`. Its self-tests live in `src/lib.rs`'s unit-test build
//! (`src/util.rs`, module `prng_selftest`), where they run once.
#![allow(dead_code)]

/// xorshift64* (Marsaglia / Vigna): 64 bits of state, period 2^64 − 1.
#[derive(Clone, Debug)]
pub struct Prng {
    state: u64,
}

/// Name of the environment variable that pins the base seed (decimal or `0x…` hex).
pub const SEED_ENV: &str = "GCLONE_TEST_SEED";

/// Base seed used when `GCLONE_TEST_SEED` is not set: runs are reproducible by default.
pub const DEFAULT_SEED: u64 = 0x6763_6c6f_6e65_0001;

impl Prng {
    /// Any seed is fine (including 0): the seed is scrambled with splitmix64 first, so nearby
    /// seeds give unrelated streams.
    pub fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        Prng {
            state: if z == 0 { 0x2545_f491_4f6c_dd1d } else { z },
        }
    }

    /// Seeded from `GCLONE_TEST_SEED` if set (and parsable), else from [`DEFAULT_SEED`].
    pub fn from_env() -> Self {
        Prng::new(base_seed())
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform in `0..n` (unbiased, by rejection). Panics if `n == 0`.
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0, "Prng::below(0)");
        let zone = u64::MAX - (u64::MAX % n);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % n;
            }
        }
    }

    /// Uniform in `lo..hi` (end exclusive). Panics if the range is empty.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        assert!(lo < hi, "Prng::range: empty range {lo}..{hi}");
        lo + self.below(hi - lo)
    }

    /// Uniform index into a collection of `len` elements. Panics if `len == 0`.
    pub fn index(&mut self, len: usize) -> usize {
        self.below(len as u64) as usize
    }

    pub fn bool(&mut self) -> bool {
        self.next_u64() >> 63 == 1
    }

    /// True with probability `num / den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill(&mut v);
        v
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0u8; N];
        self.fill(&mut a);
        a
    }

    /// A reference to a uniformly chosen element. Panics on an empty slice.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }

    /// Fisher–Yates shuffle.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.index(i + 1);
            items.swap(i, j);
        }
    }

    /// A lowercase ASCII name of `len` characters (`a..=z`).
    pub fn name(&mut self, len: usize) -> String {
        (0..len)
            .map(|_| (b'a' + self.below(26) as u8) as char)
            .collect()
    }

    /// An independent generator derived from this one (for sub-tasks that must not disturb
    /// the parent's stream).
    pub fn fork(&mut self) -> Prng {
        Prng::new(self.next_u64())
    }
}

/// `GCLONE_TEST_SEED` (decimal or `0x…`), else [`DEFAULT_SEED`].
pub fn base_seed() -> u64 {
    match std::env::var(SEED_ENV) {
        Ok(s) => parse_seed(&s).unwrap_or(DEFAULT_SEED),
        Err(_) => DEFAULT_SEED,
    }
}

/// Decimal or `0x…` hex.
pub fn parse_seed(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Runs `f` for `cases` generators seeded `base_seed() + i`. If a case panics, the seed that
/// reproduces it alone is printed first: `GCLONE_TEST_SEED=<seed>` re-runs exactly that case
/// as case 0.
pub fn for_each_seed(name: &str, cases: u64, mut f: impl FnMut(&mut Prng)) {
    let base = base_seed();
    for i in 0..cases {
        let seed = base.wrapping_add(i);
        let guard = SeedReport { name, seed };
        let mut rng = Prng::new(seed);
        f(&mut rng);
        std::mem::forget(guard);
    }
}

struct SeedReport<'a> {
    name: &'a str,
    seed: u64,
}

impl Drop for SeedReport<'_> {
    fn drop(&mut self) {
        // Only reached when the case panicked (the guard is forgotten on success).
        eprintln!(
            "{}: failing case — reproduce with {SEED_ENV}={}",
            self.name, self.seed
        );
    }
}
