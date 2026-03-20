//! Runtime discovery of `il2cpp_resolve_icall` on iOS.
//!
//! On iOS, `il2cpp_resolve_icall` is statically linked into `UnityFramework`
//! and not exported. This module finds it at runtime by:
//!
//! 1. Looking up `UnityEngine.Behaviour::get_enabled` via the IL2CPP API
//!    (this function is guaranteed to be a simple icall wrapper).
//! 2. Scanning its ARM64 machine code for the first `BL` instruction.
//! 3. Decoding the branch target — that address IS `il2cpp_resolve_icall`.
//!
//! This must be called **after** `il2cpp_init` has fired and all other
//! `il2cpp_*` API pointers have been resolved by `symbols_impl`.

use crate::il2cpp::symbols;

/// Scan `Behaviour::get_enabled` bytecode for the `il2cpp_resolve_icall` BL.
///
/// On success returns the virtual address of `il2cpp_resolve_icall`.
/// Returns `None` if any lookup fails or no BL is found within the scan limit.
pub unsafe fn resolve() -> Option<usize> {
    info!("Scanning Behaviour::get_enabled for il2cpp_resolve_icall BL...");

    // Step 1 — get assembly image
    let image = symbols::get_assembly_image(c"UnityEngine.CoreModule.dll")
        .map_err(|e| { error!("scanner: get_assembly_image failed: {:?}", e); e })
        .ok()?;

    // Step 2 — get Behaviour class
    let class = symbols::get_class(image, c"UnityEngine", c"Behaviour")
        .map_err(|e| { error!("scanner: get_class Behaviour failed: {:?}", e); e })
        .ok()?;

    // Step 3 — get get_enabled method (0 args)
    let method = symbols::get_method(class, c"get_enabled", 0)
        .map_err(|e| { error!("scanner: get_method get_enabled failed: {:?}", e); e })
        .ok()?;

    let fn_ptr = (*method).methodPointer;
    if fn_ptr == 0 {
        error!("scanner: get_enabled methodPointer is null");
        return None;
    }

    info!("scanner: Behaviour::get_enabled @ {:#x}", fn_ptr);

    // Step 4 — scan ARM64 BL instructions (up to 64 instructions = 256 bytes)
    const MAX_INSNS: usize = 64;
    let code = std::slice::from_raw_parts(fn_ptr as *const u32, MAX_INSNS);

    for (i, &insn) in code.iter().enumerate() {
        if let Some(target) = decode_bl(fn_ptr + i * 4, insn) {
            info!("scanner: BL found at offset +{:#x}, il2cpp_resolve_icall = {:#x}", i * 4, target);
            return Some(target);
        }
    }

    error!("scanner: No BL found in first {} instructions of get_enabled", MAX_INSNS);
    None
}

/// Decode an ARM64 `BL` instruction at `pc`.
///
/// ARM64 BL encoding:
/// ```
/// [31:26] = 100101  (0x25)
/// [25: 0] = imm26   (signed offset in instructions)
/// ```
/// `target = pc + sign_extend(imm26) * 4`
///
/// Also handles `BLR` (0xd63f0000 mask) — returns None for those to only
/// catch direct calls (static function address is in the imm26).
#[inline]
fn decode_bl(pc: usize, insn: u32) -> Option<usize> {
    // BL: top 6 bits == 0b100101
    if (insn >> 26) == 0x25 {
        let imm26 = insn & 0x03FF_FFFF;
        // Sign-extend from bit 25
        let signed_off = if imm26 & (1 << 25) != 0 {
            (imm26 | 0xFC00_0000) as i32
        } else {
            imm26 as i32
        };
        let target = (pc as i64 + (signed_off as i64) * 4) as usize;
        Some(target)
    } else {
        None
    }
}
