//! Shared ARM64 disassembly helpers backed by Capstone.
//!
//! Provides a thin `Disasm` wrapper around `Capstone` and typed helper methods
//! for the instruction patterns used by the IL2CPP scanner (ADRP+ADD+BL,
//! B-trampoline, and MOVZ-zero prologues).
//!
//! **This file only compiles on `target_os = "ios"`.**

use capstone::prelude::*;
use capstone::Insn;
use capstone::arch::arm64::{Arm64Insn, Arm64OperandType};

// ──────────────────────────────────────────────────────────────────────────────

/// Capstone-backed ARM64 disassembler with full instruction-detail support.
pub struct Disasm {
    cs: Capstone,
}

impl Disasm {
    /// Create a new instance in little-endian ARM64 mode with detail enabled.
    pub fn new() -> Option<Self> {
        match Capstone::new().arm64().mode(capstone::arch::arm64::ArchMode::Arm).detail(true).build() {
            Ok(cs) => Some(Self { cs }),
            Err(e) => {
                error!("arm64::Disasm::new failed: {:?}", e);
                None
            }
        }
    }

    /// Disassemble up to `count` instructions from `bytes` at virtual address `addr`.
    pub fn disasm_count<'a>(
        &'a self,
        bytes: &[u8],
        addr: u64,
        count: usize,
    ) -> Option<capstone::Instructions<'a>> {
        self.cs.disasm_count(bytes, addr, count).ok()
    }

    // ── Instruction-type predicates ───────────────────────────────────────────

    #[inline] pub fn is_adrp(&self, insn: &Insn) -> bool { self.is_id(insn, Arm64Insn::ARM64_INS_ADRP) }
    #[inline] pub fn is_add (&self, insn: &Insn) -> bool { self.is_id(insn, Arm64Insn::ARM64_INS_ADD)  }
    #[inline] pub fn is_bl  (&self, insn: &Insn) -> bool { self.is_id(insn, Arm64Insn::ARM64_INS_BL)   }
    #[inline] pub fn is_b   (&self, insn: &Insn) -> bool { self.is_id(insn, Arm64Insn::ARM64_INS_B)    }

    #[inline]
    fn is_id(&self, insn: &Insn, id: Arm64Insn) -> bool {
        insn.id() == InsnId(id as u32)
    }

    // ── Operand extractors ────────────────────────────────────────────────────

    /// Extract `(destination_register, computed_page_address)` from an `ADRP` instruction.
    ///
    /// Capstone resolves the PC-relative encoding; the returned address is already
    /// an absolute page address — no manual sign-extension needed.
    pub fn adrp_ops(&self, insn: &Insn) -> Option<(RegId, u64)> {
        let detail     = self.cs.insn_detail(insn).ok()?;
        let arch       = detail.arch_detail();
        let arm64      = arch.arm64()?;
        let mut ops    = arm64.operands();
        let rd   = match ops.next()?.op_type { Arm64OperandType::Reg(r) => r, _ => return None };
        let page = match ops.next()?.op_type { Arm64OperandType::Imm(i) => i as u64, _ => return None };
        Some((rd, page))
    }

    /// Extract `(source_register Rn, immediate)` from an `ADD Rd, Rn, #imm` instruction.
    pub fn add_rn_imm(&self, insn: &Insn) -> Option<(RegId, u64)> {
        let detail = self.cs.insn_detail(insn).ok()?;
        let arch   = detail.arch_detail();
        let arm64  = arch.arm64()?;
        let ops: Vec<_> = arm64.operands().collect();
        let rn  = match ops.get(1)?.op_type { Arm64OperandType::Reg(r) => r, _ => return None };
        let imm = match ops.get(2)?.op_type { Arm64OperandType::Imm(i) => i as u64, _ => return None };
        Some((rn, imm))
    }

    /// Extract the absolute branch target address from a `BL` or `B` instruction.
    ///
    /// Capstone computes the target from the PC-relative encoding; no manual
    /// sign-extension or immediate decoding is required.
    pub fn branch_target(&self, insn: &Insn) -> Option<u64> {
        let detail = self.cs.insn_detail(insn).ok()?;
        let arch   = detail.arch_detail();
        let arm64  = arch.arm64()?;
        let op = arm64.operands().next()?;
        match op.op_type { Arm64OperandType::Imm(i) => Some(i as u64), _ => None }
    }

    // ── MOVZ-zero predicates ──────────────────────────────────────────────────

    /// Returns `true` if `insn` is `MOVZ w?, #0` (32-bit destination, immediate zero).
    pub fn is_movz_wreg_zero(&self, insn: &Insn) -> bool {
        self.movz_zero_prefix(insn, 'w')
    }

    /// Returns `true` if `insn` is `MOVZ x?, #0` (64-bit destination, immediate zero).
    pub fn is_movz_xreg_zero(&self, insn: &Insn) -> bool {
        self.movz_zero_prefix(insn, 'x')
    }

    fn movz_zero_prefix(&self, insn: &Insn, prefix: char) -> bool {
        // Capstone v5 may decode `MOVZ w0, #0` as ARM64_INS_MOV (alias).
        if !self.is_id(insn, Arm64Insn::ARM64_INS_MOVZ)
            && !self.is_id(insn, Arm64Insn::ARM64_INS_MOV)
        {
            return false;
        }
        let Ok(detail) = self.cs.insn_detail(insn) else { return false };
        let arch = detail.arch_detail();
        let Some(arm64) = arch.arm64() else { return false };
        let ops: Vec<_> = arm64.operands().collect();
        let dest_ok = match ops.first().map(|o| &o.op_type) {
            Some(Arm64OperandType::Reg(r)) =>
                self.cs.reg_name(*r).map(|n| n.starts_with(prefix)).unwrap_or(false),
            _ => false,
        };
        let imm_ok = matches!(ops.get(1).map(|o| &o.op_type), Some(Arm64OperandType::Imm(0)));
        dest_ok && imm_ok
    }
}
