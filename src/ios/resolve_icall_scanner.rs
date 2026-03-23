//! Runtime discovery of `il2cpp_resolve_icall` on iOS.
//!
//! On iOS, `il2cpp_resolve_icall` is statically linked into `UnityFramework`
//! and not exported. This module finds it at runtime by:
//!
//! 1. Looking up `UnityEngine.Behaviour::get_enabled` via the IL2CPP API.
//! 2. Scanning its ARM64 bytecode for the **ADRP+ADD** pair that loads the
//!    string `"UnityEngine.Behaviour::get_enabled()"`.
//! 3. The **next BL** instruction after that ADD is the call to
//!    `il2cpp_resolve_icall`.
//!
//! This must be called **after** `il2cpp_init` has completed and all other
//! `il2cpp_*` API pointers have been resolved by `symbols_impl`.

use crate::il2cpp::symbols;

/// The icall name string that `get_enabled` passes to `il2cpp_resolve_icall`.
const ICALL_STRING: &[u8] = b"UnityEngine.Behaviour::get_enabled()";

/// Scan `Behaviour::get_enabled` bytecode for the `il2cpp_resolve_icall` call.
///
/// Returns the virtual address of `il2cpp_resolve_icall`, or `None` on failure.
pub unsafe fn resolve() -> Option<usize> {
    info!("Scanning Behaviour::get_enabled for il2cpp_resolve_icall...");

    // Step 1 — get assembly image for UnityEngine.CoreModule.dll
    let image = symbols::get_assembly_image(c"UnityEngine.CoreModule.dll")
        .map_err(|e| { error!("scanner: get_assembly_image failed: {:?}", e); e })
        .ok()?;

    // Step 2 — get Behaviour class from UnityEngine namespace
    let class = symbols::get_class(image, c"UnityEngine", c"Behaviour")
        .map_err(|e| { error!("scanner: get_class Behaviour failed: {:?}", e); e })
        .ok()?;

    // Step 3 — get method pointer for get_enabled (0 args)
    let method = symbols::get_method(class, c"get_enabled", 0)
        .map_err(|e| { error!("scanner: get_method get_enabled failed: {:?}", e); e })
        .ok()?;

    let fn_ptr = (*method).methodPointer;
    if fn_ptr == 0 {
        error!("scanner: get_enabled methodPointer is null");
        return None;
    }

    info!("scanner: Behaviour::get_enabled @ {:#x}", fn_ptr);

    // Step 4 — scan bytecode for ADRP+ADD loading the icall string,
    //          then find the next BL after that ADD.
    const MAX_INSNS: usize = 64;
    let code = std::slice::from_raw_parts(fn_ptr as *const u32, MAX_INSNS);

    // First, find the icall string address in memory.
    // We know it's somewhere near the function (within ±4GiB for ADRP).
    // Scan each ADRP+ADD pair to reconstruct the address they compute,
    // then check if that address points to our needle string.
    for i in 0..MAX_INSNS.saturating_sub(1) {
        let insn0 = code[i];
        let insn1 = code[i + 1];

        // Check: insn0 = ADRP, insn1 = ADD #imm12
        if !is_adrp(insn0) || !is_add_imm12(insn1) {
            continue;
        }

        // Verify ADRP and ADD use the same register (Rd of ADRP == Rn of ADD)
        let adrp_rd = insn0 & 0x1F;
        let add_rn = (insn1 >> 5) & 0x1F;
        if adrp_rd != add_rn {
            continue;
        }

        // Compute the full address: ADRP page + ADD offset
        let pc = fn_ptr + i * 4;
        let page = adrp_target_page(insn0, pc as u64);
        let offset = ((insn1 >> 10) & 0xFFF) as u64;
        let target_addr = page + offset;

        // Check if the target address contains our icall string
        let candidate = std::slice::from_raw_parts(
            target_addr as *const u8,
            ICALL_STRING.len(),
        );
        if candidate != ICALL_STRING {
            continue;
        }

        info!("scanner: Found ADRP+ADD loading icall string at offset +{:#x} (addr={:#x})",
            i * 4, target_addr);

        // Now find the next BL instruction after this ADD
        for j in (i + 2)..MAX_INSNS {
            if let Some(bl_target) = decode_bl(fn_ptr + j * 4, code[j]) {
                info!("scanner: BL at offset +{:#x} → il2cpp_resolve_icall = {:#x}",
                    j * 4, bl_target);
                return Some(bl_target);
            }
        }

        error!("scanner: Found icall string load but no BL after it");
        return None;
    }

    error!("scanner: No ADRP+ADD loading icall string found in first {} insns", MAX_INSNS);
    None
}

// ── ARM64 instruction helpers ────────────────────────────────────────────────

/// Returns `true` if `insn` is an ADRP instruction.
/// ADRP: bit[31]=1, bits[28:24]=10000, bit[29:28] varies
/// Mask: (insn & 0x9F000000) == 0x90000000
#[inline]
fn is_adrp(insn: u32) -> bool {
    (insn & 0x9F000000) == 0x90000000
}

/// Compute the target page address of an ADRP instruction at `pc`.
#[inline]
fn adrp_target_page(insn: u32, pc: u64) -> u64 {
    let immlo = ((insn >> 29) & 0x3) as i64;
    let immhi = (((insn >> 5) & 0x7FFFF) as i64) << 2;
    let imm = sign_extend((immhi | immlo) as u64, 21) << 12;
    ((pc & !0xFFF) as i64).wrapping_add(imm) as u64
}

/// Returns `true` if `insn` is `ADD Xn, Xm, #imm12` (64-bit, shift=0).
#[inline]
fn is_add_imm12(insn: u32) -> bool {
    (insn & 0xFF800000) == 0x91000000
}

/// Decode a `BL` instruction at `pc`. Returns the branch target address.
#[inline]
fn decode_bl(pc: usize, insn: u32) -> Option<usize> {
    if (insn >> 26) != 0x25 {
        return None;
    }
    let imm26 = insn & 0x03FF_FFFF;
    let signed_off = if imm26 & (1 << 25) != 0 {
        (imm26 | 0xFC00_0000) as i32
    } else {
        imm26 as i32
    };
    let target = (pc as i64 + (signed_off as i64) * 4) as usize;
    Some(target)
}

/// Sign-extend a `bits`-wide value.
#[inline]
fn sign_extend(val: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((val << shift) as i64) >> shift
}
