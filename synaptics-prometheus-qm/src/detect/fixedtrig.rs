//! Fixed-point trigonometry — bit-exact ports of the DLL's integer `atan2` used by the minutia
//! orientation + BRIEF descriptor (`syna_qm_minutia_orientation@0x18000d870`,
//! `syna_qm_descriptor_brief@0x18000dfe0`). The port used `f32` `atan2`/`cos`/`sin`; these reproduce the
//! DLL's exact integer arithmetic so the descriptor stage can be bit-faithful. Validated against the
//! real DLL via `tools/qm-dll-oracle` (golden/nms.txt `ATAN2Q`/`ATAN2R`).
//!
//! Note the DLL's two atan2 flavours share the first-octant polynomial but return different-scaled
//! angle units (`atan2_quadrant`: quarter-turn ≈ 102240; `atan2_q16rad`: Q16 radians, π = 0x3243f =
//! 205887). Both are reproduced exactly, unit inconsistencies and all — validated bit-for-bit.

/// `syna_qm_atan2_quadrant@0x180003050` — first-octant fixed-point arctan polynomial with quadrant
/// fold-out. Returns an angle in the DLL's `quadrant` units (0..≈408960, quarter-turn ≈ 102240).
pub fn atan2_quadrant(p1: i32, p2: i32) -> i32 {
    let i3 = if p2 < 1 { -p2 } else { p2 }; // |p2|
    let i4 = if p1 < 1 { -p1 } else { p1 }; // |p1|
    let (mut v1, v2) = if i3 < i4 { (i4, i3) } else { (i3, i4) }; // (max, min)
    v1 = ((v2 << 8) / (v1 + 1)) << 8;
    let mut v2 = v1 >> 6;
    v2 = (v2 * v2) >> 8;
    // ((((((v2·-0xa29 >>0xc)+0x23a7)·v2 >>0xc)+-0x4aac)·v2 >>0xc)+0xe522)·(v1>>4) >>6
    //
    // Horner, one step per line. `*` binds tighter than `>>` in both C and Rust, so this is the
    // same arithmetic the decompiler printed — just written so reading it does not depend on
    // knowing that.
    let p = ((v2 * -0xa29) >> 0xc) + 0x23a7;
    let p = ((p * v2) >> 0xc) + -0x4aac;
    let p = ((p * v2) >> 0xc) + 0xe522;
    v1 = (p * (v1 >> 4)) >> 6;
    if i3 < i4 {
        v1 = 0x5a0000 - v1;
    }
    if p2 < 0 {
        v1 = 0xb40000 - v1;
    }
    if p1 < 0 {
        v1 = 0x1680000 - v1;
    }
    ((v1 >> 8) * 0x47) >> 4
}

/// `syna_qm_atan2_q16rad@0x180003100` — full 4-quadrant atan2 built on [`atan2_quadrant`], returning
/// Q16.16 **radians** (0..2π, π = 0x3243f = 205887). Args are `(y, x)` as in the DLL call sites.
pub fn atan2_q16rad(y: i32, x: i32) -> i32 {
    if y < 0 {
        if x >= 0 {
            return 0x3243f - atan2_quadrant(x, -y);
        }
        return atan2_quadrant(-x, -y) + 0x3243f;
    }
    if x >= 0 {
        return atan2_quadrant(x, y);
    }
    0x6487e - atan2_quadrant(-x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atan2_matches_oracle_golden() {
        // From tools/qm-dll-oracle golden/nms.txt (ATAN2Q y x : v  /  ATAN2R y x : v).
        assert_eq!(atan2_quadrant(0, 100), 0);
        assert_eq!(atan2_quadrant(100, 0), 102240);
        assert_eq!(atan2_quadrant(0, -100), 204480);
        assert_eq!(atan2_quadrant(-100, 0), 306720);
        assert_eq!(atan2_quadrant(100, 100), 50725);
        assert_eq!(atan2_quadrant(-100, -100), 255205);
        assert_eq!(atan2_quadrant(50, 200), 15704);
        assert_eq!(atan2_quadrant(12345, 6789), 69664);
        assert_eq!(atan2_quadrant(-9999, 4321), 333136);

        assert_eq!(atan2_q16rad(0, 100), 102240);
        assert_eq!(atan2_q16rad(-100, 0), 205887); // π
        assert_eq!(atan2_q16rad(100, 100), 50725);
        assert_eq!(atan2_q16rad(-100, -100), 256612);
        assert_eq!(atan2_q16rad(-30, 70), 129638);
        assert_eq!(atan2_q16rad(12345, 6789), 32571);
        assert_eq!(atan2_q16rad(-9999, 4321), 179471);
    }
}
