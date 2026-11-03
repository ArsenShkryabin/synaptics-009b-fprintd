//! Integer math helpers matching Windows/C semantics in the vendor DLL.
//!
//! Ports: `FUN_180003010@0x180003010` (isqrt), `FUN_180006b90@0x180006b90` (Q16 normalize).

/// Integer square root — `FUN_180003010@0x180003010`.
pub fn isqrt(mut n: u32) -> u32 {
    let mut bit = 0x4000_0000u32;
    let mut root = 0u32;
    if n <= 0x3fff_ffff {
        while n < bit {
            bit >>= 2;
        }
    }
    while bit != 0 {
        if bit + root <= n {
            let sub = bit + root;
            root += bit * 2;
            n -= sub;
        }
        root >>= 1;
        bit >>= 2;
    }
    root
}

/// Normalize `(cos, sin)` to unit length in Q16 — `FUN_180006b90@0x180006b90`.
pub fn normalize_q16(cos: &mut i32, sin: &mut i32) {
    let half_cos = *cos >> 1;
    let half_sin = *sin >> 1;
    let mut mag = isqrt((half_sin as i64 * half_sin as i64 + half_cos as i64 * half_cos as i64) as u32);
    mag >>= 1;
    if mag == 0 {
        *cos = half_cos;
        *sin = half_sin;
    } else {
        let s = *sin;
        *cos = (*cos << 14) / mag as i32;
        *sin = (s << 14) / mag as i32;
    }
}

/// Signed truncating division (Rust `/` on integers matches MSVC for these operands).
#[inline]
pub fn div_trunc(a: i32, b: i32) -> i32 {
    a / b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isqrt_known_values() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(15), 3);
        assert_eq!(isqrt(16), 4);
        assert_eq!(isqrt(100), 10);
    }
}
