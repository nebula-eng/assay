//! Entropy measurement.
//!
//! Entropy is the single cheapest signal in static analysis and the easiest to
//! misread. Packed code, encrypted payloads and compressed resources all sit
//! near 8.0 bits/byte — but so does any legitimately compressed icon. This
//! module therefore reports **three** things rather than one number: the global
//! entropy, a sliding-window profile that shows *where* high entropy lives, and
//! the longest contiguous high-entropy run. A binary whose only high-entropy
//! region is `.rsrc` is a normal program with PNGs; one whose `.text` is a solid
//! 7.9 means somebody wrapped it.

use serde::{Deserialize, Serialize};

/// Shannon entropy of `data`, in bits per byte (0.0 – 8.0).
///
/// Returns 0.0 for empty input. Uses a 256-bin histogram and `log2` through
/// `f64::log2`, which is accurate to well under one part in 10^12 — far tighter
/// than the threshold differences we discriminate on.
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / len;
        entropy -= p * p.log2();
    }
    // Guard against -0.0 and values that float error pushes past the ceiling.
    entropy.clamp(0.0, 8.0)
}

/// A contiguous region of the file with an entropy reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyWindow {
    /// Byte offset of the window start.
    pub offset: u64,
    /// Window length in bytes.
    pub length: u64,
    /// Entropy in bits/byte over the window.
    pub entropy: f64,
}

/// Entropy profile of a whole buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyProfile {
    /// Entropy over the entire buffer.
    pub overall: f64,
    /// Mean of the windowed readings.
    pub mean_windowed: f64,
    /// Standard deviation of the windowed readings — high variance means the
    /// file mixes code and packed data, which is exactly what a dropper looks
    /// like.
    pub stdev_windowed: f64,
    /// Window size used.
    pub window: u64,
    /// Windowed readings, capped so a 200 MiB file cannot flood the report.
    pub windows: Vec<EntropyWindow>,
    /// Longest run of consecutive windows above `high_threshold`.
    pub longest_high_run: EntropyWindow,
    /// Offset of the highest-entropy window.
    pub peak_offset: u64,
    /// Value of the highest-entropy window.
    pub peak_entropy: f64,
    /// Fraction of the file above `high_threshold`, in the 0–1 range.
    pub high_entropy_fraction: f64,
}

/// Default window size: 4 KiB matches a page and is small enough to localise a
/// packer stub while staying cache-friendly.
pub const DEFAULT_WINDOW: usize = 4096;

/// Windows at or above this value are treated as "probably encrypted/compressed".
pub const HIGH_THRESHOLD: f64 = 7.2;

/// Windowed entropy above which a region is *almost certainly* compressed or
/// encrypted rather than merely dense code.
pub const VERY_HIGH_THRESHOLD: f64 = 7.6;

/// Compute the full entropy profile of a buffer.
///
/// `max_windows` caps how many readings are retained in the output; the summary
/// statistics are always computed over **all** windows.
pub fn profile(data: &[u8], window: usize, max_windows: usize) -> EntropyProfile {
    let window = window.max(256);
    if data.is_empty() {
        return EntropyProfile {
            overall: 0.0,
            mean_windowed: 0.0,
            stdev_windowed: 0.0,
            window: window as u64,
            windows: Vec::new(),
            longest_high_run: EntropyWindow {
                offset: 0,
                length: 0,
                entropy: 0.0,
            },
            peak_offset: 0,
            peak_entropy: 0.0,
            high_entropy_fraction: 0.0,
        };
    }

    let overall = shannon(data);
    let total_windows = data.len().div_ceil(window);

    let mut readings: Vec<(u64, u64, f64)> = Vec::with_capacity(total_windows.min(4096));
    let mut sum = 0.0f64;
    let mut sum_sq = 0.0f64;
    let mut high_count = 0usize;
    let mut peak_offset = 0u64;
    let mut peak_entropy = 0.0f64;

    // Longest run tracking.
    let mut run_start: Option<u64> = None;
    let mut run_len = 0u64;
    let mut best_start = 0u64;
    let mut best_len = 0u64;

    for (i, chunk) in data.chunks(window).enumerate() {
        let offset = (i * window) as u64;
        let e = shannon(chunk);
        sum += e;
        sum_sq += e * e;
        if e > peak_entropy {
            peak_entropy = e;
            peak_offset = offset;
        }
        if e >= HIGH_THRESHOLD {
            high_count += 1;
            if run_start.is_none() {
                run_start = Some(offset);
                run_len = 0;
            }
            run_len += chunk.len() as u64;
        } else if let Some(start) = run_start.take() {
            if run_len > best_len {
                best_len = run_len;
                best_start = start;
            }
        }
        readings.push((offset, chunk.len() as u64, e));
    }
    if let Some(start) = run_start.take() {
        if run_len > best_len {
            best_len = run_len;
            best_start = start;
        }
    }

    let n = readings.len() as f64;
    let mean = sum / n;
    let variance = (sum_sq / n - mean * mean).max(0.0);

    // Retain a bounded, evenly-sampled subset for the report.
    let windows: Vec<EntropyWindow> = if readings.len() <= max_windows {
        readings
            .iter()
            .map(|&(offset, length, entropy)| EntropyWindow {
                offset,
                length,
                entropy,
            })
            .collect()
    } else {
        let step = readings.len() as f64 / max_windows as f64;
        (0..max_windows)
            .map(|i| {
                let idx = ((i as f64) * step) as usize;
                let (offset, length, entropy) = readings[idx.min(readings.len() - 1)];
                EntropyWindow {
                    offset,
                    length,
                    entropy,
                }
            })
            .collect()
    };

    EntropyProfile {
        overall,
        mean_windowed: mean,
        stdev_windowed: variance.sqrt(),
        window: window as u64,
        windows,
        longest_high_run: EntropyWindow {
            offset: best_start,
            length: best_len,
            entropy: if best_len > 0 {
                let start = best_start as usize;
                let end = (start + best_len as usize).min(data.len());
                shannon(&data[start..end])
            } else {
                0.0
            },
        },
        peak_offset,
        peak_entropy,
        high_entropy_fraction: high_count as f64 / n,
    }
}

/// Classify a single entropy reading into a human label.
pub fn classify(entropy: f64) -> &'static str {
    if entropy >= VERY_HIGH_THRESHOLD {
        "encrypted/compressed"
    } else if entropy >= HIGH_THRESHOLD {
        "dense or packed"
    } else if entropy >= 5.0 {
        "typical compiled code"
    } else if entropy >= 3.0 {
        "mixed or structured data"
    } else if entropy > 0.05 {
        "sparse/padded"
    } else {
        "empty or constant"
    }
}

/// Byte-value histogram, used by the hex view's density ribbon.
pub fn histogram(data: &[u8]) -> [u32; 256] {
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    counts
}

/// Detect long runs of a single repeated byte (padding, NOP sleds, zero fill).
///
/// Returns `(offset, byte, length)` for the longest such run. A 3 KiB run of
/// `0x90` inside a supposedly packed section is a hand-written sled, not a
/// compiler artefact.
pub fn longest_constant_run(data: &[u8], min_len: usize) -> Option<(u64, u8, u64)> {
    if data.is_empty() || min_len == 0 {
        return None;
    }
    let mut best: Option<(u64, u8, u64)> = None;
    let mut run_byte = data[0];
    let mut run_start = 0usize;
    let mut run_len = 1usize;

    for (i, &b) in data.iter().enumerate().skip(1) {
        if b == run_byte {
            run_len += 1;
        } else {
            if run_len >= min_len {
                let better = best.is_none_or(|(_, _, l)| run_len as u64 > l);
                if better {
                    best = Some((run_start as u64, run_byte, run_len as u64));
                }
            }
            run_byte = b;
            run_start = i;
            run_len = 1;
        }
    }
    if run_len >= min_len {
        let better = best.is_none_or(|(_, _, l)| run_len as u64 > l);
        if better {
            best = Some((run_start as u64, run_byte, run_len as u64));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_has_zero_entropy() {
        assert_eq!(shannon(&[]), 0.0);
    }

    #[test]
    fn constant_input_has_zero_entropy() {
        assert!(shannon(&[0x41; 4096]).abs() < 1e-9);
    }

    #[test]
    fn uniform_bytes_have_max_entropy() {
        // Every byte value exactly once → exactly 8 bits.
        let data: Vec<u8> = (0..=255u8).collect();
        let e = shannon(&data);
        assert!((e - 8.0).abs() < 1e-9);
    }

    #[test]
    fn half_alphabet_is_seven_bits() {
        let data: Vec<u8> = (0..128u8).cycle().take(1024).collect();
        let e = shannon(&data);
        assert!((e - 7.0).abs() < 1e-6);
    }

    #[test]
    fn profile_localises_high_entropy_region() {
        let mut data = vec![0u8; 32 * 1024];
        // Bury 8 KiB of pseudo-random bytes in the middle.
        for (i, slot) in data[8192..16_384].iter_mut().enumerate() {
            *slot = ((i * 2654435761usize) >> 13) as u8;
        }
        let p = profile(&data, 4096, 64);
        assert!(p.peak_offset >= 8192 && p.peak_offset < 16_384);
        assert!(p.peak_entropy > 7.0);
        assert!(p.longest_high_run.length >= 4096);
    }

    #[test]
    fn profile_reports_mixed_content_variance() {
        let mut data = vec![0x90u8; 32 * 1024];
        for (i, slot) in data[16 * 1024..].iter_mut().enumerate() {
            *slot = ((i * 1103515245usize) >> 11) as u8;
        }
        let p = profile(&data, 4096, 64);
        assert!(p.stdev_windowed > 1.0);
        assert!(p.high_entropy_fraction > 0.2 && p.high_entropy_fraction < 0.8);
    }

    #[test]
    fn classify_thresholds() {
        assert_eq!(classify(7.9), "encrypted/compressed");
        assert_eq!(classify(7.3), "dense or packed");
        assert_eq!(classify(6.0), "typical compiled code");
        assert_eq!(classify(0.0), "empty or constant");
    }

    #[test]
    fn longest_constant_run_finds_sled() {
        let mut data = vec![0u8; 100];
        data[10..60].fill(0x90);
        let (off, byte, len) = longest_constant_run(&data, 16).unwrap();
        assert_eq!(off, 10);
        assert_eq!(byte, 0x90);
        assert_eq!(len, 50);
    }

    #[test]
    fn longest_constant_run_ignores_short_runs() {
        let data = vec![0u8, 1, 2, 3, 4];
        assert!(longest_constant_run(&data, 4).is_none());
    }

    #[test]
    fn histogram_counts_all_bytes() {
        let h = histogram(&[1, 1, 2, 3]);
        assert_eq!(h[1], 2);
        assert_eq!(h[2], 1);
        assert_eq!(h[3], 1);
        assert_eq!(h[0], 0);
    }
}
