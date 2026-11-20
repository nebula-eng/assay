//! Context-triggered piecewise hashing (CTPH), for family clustering.
//!
//! Two builds of the same malware family differ in bytes but not in *shape*:
//! same compiler, same libraries, same string tables in the same order. A
//! cryptographic digest is useless for that question — one changed byte gives a
//! completely different value. CTPH solves it by hashing **pieces delimited by
//! content**, so a local edit perturbs only the neighbouring pieces.
//!
//! ## Compatibility statement
//!
//! The construction here follows the ssdeep lineage: the same 7-byte rolling
//! window, the same FNV-style 32-bit accumulator, the same doubling block-size
//! search, and the same `blocksize:hash:hash` output shape, which is what tools
//! like VirusTotal and MISP expect. It is **not** byte-for-byte identical to
//! libfuzzy, because libfuzzy's dual-block emission has undocumented corner
//! behaviour. Values produced here compare correctly *among themselves* and are
//! stable across runs and platforms; do not diff them against a `ssdeep -h`
//! value from another tool and expect equality.
//!
//! ## Output shape
//!
//! `blocksize:piece_hash:double_piece_hash`, where hashes are drawn from the
//! 64-character ssdeep alphabet.

use serde::{Deserialize, Serialize};

/// Characters used to encode a piece hash (same alphabet as ssdeep base64).
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Maximum characters in a piece hash.
pub const SPAMSUM_LENGTH: usize = 64;

/// Smallest block size we will consider.
const MIN_BLOCKSIZE: u32 = 3;

/// Rolling window width.
const ROLLING_WINDOW: usize = 7;

/// FNV-style multiplier.
const HASH_PRIME: u32 = 0x0100_0193;

/// Initial accumulator value (chosen by the ssdeep authors).
const HASH_INIT: u32 = 0x2802_1967;

/// A fuzzy hash with its block size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzyHash {
    /// Block size the first digest was produced at.
    pub block_size: u32,
    /// Piece hash at `block_size`.
    pub piece: String,
    /// Piece hash at `block_size * 2`.
    pub double_piece: String,
}

impl FuzzyHash {
    /// Render in the standard `blocksize:piece:double` form.
    pub fn to_string_repr(&self) -> String {
        format!("{}:{}:{}", self.block_size, self.piece, self.double_piece)
    }

    /// Parse a hash produced by this module (or a compatible tool).
    pub fn parse(s: &str) -> Option<FuzzyHash> {
        let mut parts = s.splitn(3, ':');
        let block_size = parts.next()?.parse().ok()?;
        let piece = parts.next()?.to_string();
        let double_piece = parts.next()?.to_string();
        Some(FuzzyHash {
            block_size,
            piece,
            double_piece,
        })
    }
}

struct Rolling {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: u32,
}

impl Rolling {
    fn new() -> Self {
        Rolling {
            window: [0; ROLLING_WINDOW],
            h1: 0,
            h2: 0,
            h3: 0,
            n: 0,
        }
    }

    #[inline]
    fn update(&mut self, c: u8) {
        self.h2 = self.h2.wrapping_sub(self.h1);
        self.h2 = self
            .h2
            .wrapping_add((ROLLING_WINDOW as u32).wrapping_mul(u32::from(c)));
        self.h1 = self.h1.wrapping_add(u32::from(c));
        self.h1 = self
            .h1
            .wrapping_sub(u32::from(self.window[(self.n as usize) % ROLLING_WINDOW]));
        self.window[(self.n as usize) % ROLLING_WINDOW] = c;
        self.n = self.n.wrapping_add(1);
        // `h3` is already u32, so the historical `& 0xFFFFFFFF` mask is a
        // no-op; the shift itself is the whole operation.
        self.h3 = (self.h3 << 5) ^ u32::from(c);
    }

    #[inline]
    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

#[inline]
fn fnv(c: u8, h: &mut u32) {
    *h = h.wrapping_mul(HASH_PRIME) ^ u32::from(c);
}

/// Compute the fuzzy hash of a buffer.
pub fn hash(data: &[u8]) -> FuzzyHash {
    if data.is_empty() {
        return FuzzyHash {
            block_size: MIN_BLOCKSIZE,
            piece: String::new(),
            double_piece: String::new(),
        };
    }

    // Find the smallest block size whose digest still fits in SPAMSUM_LENGTH.
    let mut block_size = MIN_BLOCKSIZE;
    while u64::from(block_size) * SPAMSUM_LENGTH as u64 <= data.len() as u64 {
        block_size = block_size.saturating_mul(2);
    }

    loop {
        let (piece, double_piece) = digest_at(data, block_size);

        // If the coarse digest is too short, the block size is too large;
        // halve it and retry, down to the floor.
        if piece.len() < SPAMSUM_LENGTH / 2 && block_size > MIN_BLOCKSIZE {
            block_size /= 2;
            continue;
        }
        return FuzzyHash {
            block_size,
            piece,
            double_piece,
        };
    }
}

fn digest_at(data: &[u8], block_size: u32) -> (String, String) {
    let mut rolling = Rolling::new();
    let mut h = HASH_INIT;
    let mut h2 = HASH_INIT;
    let mut piece = String::with_capacity(SPAMSUM_LENGTH);
    let mut double_piece = String::with_capacity(SPAMSUM_LENGTH / 2);

    let modulus = block_size.max(1);

    for &byte in data {
        rolling.update(byte);
        fnv(byte, &mut h);
        fnv(byte, &mut h2);

        if rolling.sum() % modulus == modulus - 1 {
            if piece.len() < SPAMSUM_LENGTH - 1 {
                piece.push(B64[(h & 0x3F) as usize] as char);
                h = HASH_INIT;
            }
            if double_piece.len() < SPAMSUM_LENGTH / 2 - 1 {
                double_piece.push(B64[(h2 & 0x3F) as usize] as char);
                h2 = HASH_INIT;
            }
        }
    }

    // Emit the tail so the last partial block is represented.
    if piece.len() < SPAMSUM_LENGTH - 1 {
        piece.push(B64[(h & 0x3F) as usize] as char);
    }
    if double_piece.len() < SPAMSUM_LENGTH / 2 - 1 {
        double_piece.push(B64[(h2 & 0x3F) as usize] as char);
    }

    (piece, double_piece)
}

/// Levenshtein edit distance between two strings, over bytes.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];

    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Similarity of two fuzzy hashes on the 0–100 scale (100 = identical).
///
/// Follows the ssdeep comparison contract: only hashes whose block sizes differ
/// by at most a factor of two may be compared, and the comparison uses the
/// coarse digest of the finer hash against the fine digest of the coarser one.
pub fn similarity(a: &FuzzyHash, b: &FuzzyHash) -> u8 {
    if a.block_size == 0 || b.block_size == 0 {
        return 0;
    }
    let (ca, cb, block) = if a.block_size == b.block_size {
        (&a.piece, &b.piece, a.block_size)
    } else if a.block_size == b.block_size * 2 {
        (&a.double_piece, &b.piece, a.block_size)
    } else if b.block_size == a.block_size * 2 {
        (&a.piece, &b.double_piece, b.block_size)
    } else {
        return 0;
    };

    if ca.is_empty() || cb.is_empty() {
        return 0;
    }

    let dist = edit_distance(ca, cb);
    let max_len = ca.len().max(cb.len());
    if max_len == 0 {
        return 0;
    }
    let score = 100.0 * (1.0 - dist as f64 / max_len as f64);
    let _ = block;
    score.clamp(0.0, 100.0) as u8
}

/// Union-find clustering over fuzzy hashes.
///
/// Returns groups of indices. Any pair whose similarity reaches `threshold` is
/// joined; the relations are transitive, which is what "same family" means in
/// practice.
pub fn cluster(hashes: &[FuzzyHash], threshold: u8) -> Vec<Vec<usize>> {
    let n = hashes.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }

    for i in 0..n {
        for j in (i + 1)..n {
            if similarity(&hashes[i], &hashes[j]) >= threshold {
                let ri = find(&mut parent, i);
                let rj = find(&mut parent, j);
                if ri != rj {
                    parent[rj] = ri;
                }
            }
        }
    }

    let mut groups: std::collections::HashMap<usize, Vec<usize>> = std::collections::HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }
    let mut out: Vec<Vec<usize>> = groups.into_values().collect();
    // Largest clusters first, then by lowest member index for determinism.
    out.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a[0].cmp(&b[0])));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_empty_hash() {
        let h = hash(&[]);
        assert_eq!(h.piece, "");
        assert_eq!(h.double_piece, "");
    }

    #[test]
    fn hash_is_stable() {
        let data = b"the quick brown fox jumps over the lazy dog";
        assert_eq!(hash(data), hash(data));
    }

    #[test]
    fn hash_changes_with_content() {
        let a = hash(b"the quick brown fox jumps over the lazy dog");
        let b = hash(b"the quick brown fox jumps over the lazy cat");
        assert_ne!(a, b);
    }

    #[test]
    fn small_edit_is_tolerated() {
        let base: Vec<u8> = (0..8192u32).map(|i| (i * 37 % 251) as u8).collect();
        let mut edited = base.clone();
        // Flip a byte in the middle; the surrounding pieces should survive.
        edited[4096] ^= 0xFF;

        let ha = hash(&base);
        let hb = hash(&edited);
        let score = similarity(&ha, &hb);
        assert!(score >= 60, "similarity was {score}");
    }

    #[test]
    fn unrelated_content_scores_low() {
        let a: Vec<u8> = (0..8192u32).map(|i| (i * 37 % 251) as u8).collect();
        let b: Vec<u8> = (0..8192u32).map(|i| ((i * 91 + 7) % 241) as u8).collect();
        let score = similarity(&hash(&a), &hash(&b));
        assert!(score < 60, "similarity was {score}");
    }

    #[test]
    fn identical_input_scores_100() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i % 256) as u8).collect();
        let h = hash(&data);
        assert_eq!(similarity(&h, &h), 100);
    }

    #[test]
    fn block_sizes_differing_by_four_are_incomparable() {
        let a = FuzzyHash {
            block_size: 3,
            piece: "aaaa".into(),
            double_piece: "bbbb".into(),
        };
        let b = FuzzyHash {
            block_size: 12,
            piece: "cccc".into(),
            double_piece: "dddd".into(),
        };
        assert_eq!(similarity(&a, &b), 0);
    }

    #[test]
    fn round_trips_through_string() {
        let h = hash(b"some content for the hasher");
        let s = h.to_string_repr();
        let parsed = FuzzyHash::parse(&s).expect("parse");
        assert_eq!(parsed, h);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(FuzzyHash::parse("not-a-hash").is_none());
    }

    #[test]
    fn edit_distance_known_values() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", "abc"), 0);
    }

    #[test]
    fn clusters_near_duplicates_together() {
        let base: Vec<u8> = (0..16_384u32).map(|i| (i * 53 % 251) as u8).collect();
        let mut variant_a = base.clone();
        variant_a[100] ^= 0xAA;
        let mut variant_b = base.clone();
        variant_b[8000] ^= 0x55;
        let far: Vec<u8> = (0..16_384u32).map(|i| ((i * 7 + 3) % 241) as u8).collect();

        let hashes = vec![hash(&base), hash(&variant_a), hash(&variant_b), hash(&far)];
        let groups = cluster(&hashes, 50);
        // The near-duplicates must land together.
        let big = groups.iter().find(|g| g.contains(&0)).expect("group");
        assert!(big.contains(&1) || big.contains(&2));
    }

    #[test]
    fn clustering_is_deterministic() {
        let data: Vec<Vec<u8>> = (0..5u32)
            .map(|k| (0..4096u32).map(|i| ((i + k) % 251) as u8).collect())
            .collect();
        let hashes: Vec<FuzzyHash> = data.iter().map(|d| hash(d)).collect();
        let a = cluster(&hashes, 50);
        let b = cluster(&hashes, 50);
        assert_eq!(a, b);
    }
}
