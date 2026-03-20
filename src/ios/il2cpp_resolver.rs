//! iOS IL2CPP API resolver
//!
//! Locates the 124 IL2CPP API functions that are statically linked into
//! `UnityFramework` and cannot be found via `dlsym`.
//!
//! # Strategy
//! 1. **Signature scan**: Find `"IL2CPP Root Domain\0"` in `__TEXT,__cstring`,
//!    then chase the ADRP+ADD+BL chain to locate `il2cpp_init`.
//! 2. **Mach-O parsing**: Parse `LC_FUNCTION_STARTS` with the `object` crate to
//!    obtain every function-start RVA in the binary.
//! 3. **Index mapping**: The 124 API functions appear in a fixed order starting at
//!    `il2cpp_init`. Walk the sorted function-starts table from that index.
//!
//! **This file only compiles on `target_os = "ios"`.**

use fnv::FnvHashMap;
use object::endian::LittleEndian as LE;
use object::macho::MachHeader64;
use object::read::macho::MachOFile64;
use object::LittleEndian;

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Resolve all 124 IL2CPP API functions from a loaded `UnityFramework` binary.
///
/// # Arguments
/// * `header_addr` – the `mach_header_64 *` as reported by dyld (slide already applied).
/// * `slide`       – the ASLR slide for this image (from `_dyld_get_image_vmaddr_slide`).
///
/// On success returns a map of function name → absolute virtual address.
pub fn resolve(header_addr: usize, slide: isize) -> Result<FnvHashMap<&'static str, usize>, &'static str> {
    info!("═══ STAGE 3: IL2CPP RESOLVER ═══");
    info!("Parsing Mach-O header at {:#x}, slide={:#x}...", header_addr, slide);

    // SAFETY: dyld guarantees the header is valid as long as the image is loaded.
    let data = unsafe { image_as_slice(header_addr) };

    let macho = MachOFile64::<LittleEndian>::parse(data)
        .map_err(|_| "il2cpp_resolver: failed to parse Mach-O header")?;
    info!("Mach-O header parsed OK");

    // ── Step 1: locate il2cpp_init via signature scan ──────────────────────
    info!("Searching for \"IL2CPP Root Domain\" signature...");
    let il2cpp_init_rva = find_il2cpp_init_rva(&macho, data)
        .ok_or("il2cpp_resolver: il2cpp_init signature not found")?;

    let base = header_addr; // TEXT base == header address for dylibs
    let il2cpp_init_va = (base as i64 + il2cpp_init_rva as i64) as usize;
    info!("il2cpp_init found: VA={:#x} RVA={:#x}", il2cpp_init_va, il2cpp_init_rva);

    // ── Step 2: parse LC_FUNCTION_STARTS ───────────────────────────────────
    info!("Parsing LC_FUNCTION_STARTS...");
    let mut fn_starts = collect_function_starts(&macho, data, slide, base)?;
    fn_starts.sort_unstable();
    info!("LC_FUNCTION_STARTS: {} functions parsed", fn_starts.len());

    // ── Step 3: locate il2cpp_init in the sorted list ─────────────────────
    let init_idx = fn_starts
        .partition_point(|&va| va < il2cpp_init_va);

    if init_idx >= fn_starts.len() || fn_starts[init_idx] != il2cpp_init_va {
        error!("il2cpp_init VA {:#x} not found in function starts table", il2cpp_init_va);
        return Err("il2cpp_resolver: il2cpp_init not found in LC_FUNCTION_STARTS");
    }
    info!("il2cpp_init at index {} of {} functions", init_idx, fn_starts.len());

    // ── Step 4: map each API name to its address ───────────────────────────
    let remaining = fn_starts.len() - init_idx;
    if remaining < IL2CPP_API_ORDER.len() {
        return Err("il2cpp_resolver: not enough function starts for full API table");
    }

    let mut table: FnvHashMap<&'static str, usize> =
        FnvHashMap::with_capacity_and_hasher(IL2CPP_API_ORDER.len(), Default::default());

    for (offset, &name) in IL2CPP_API_ORDER.iter().enumerate() {
        let va = fn_starts[init_idx + offset];
        table.insert(name, va);
    }

    info!("Mapped {} IL2CPP API functions", table.len());
    Ok(table)
}

// ──────────────────────────────────────────────────────────────────────────────
// Signature scan: find il2cpp_init RVA
// ──────────────────────────────────────────────────────────────────────────────

/// Search for `"IL2CPP Root Domain\0"` in `__TEXT,__cstring`, then trace the
/// ADRP+ADD address-formation sequence to the `BL` that calls `il2cpp_init`.
fn find_il2cpp_init_rva(macho: &MachOFile64<LittleEndian>, _data: &[u8]) -> Option<u64> {
    use object::{Object, ObjectSection};

    let cstring_sec = macho.section_by_name("__cstring").or_else(|| {
        // Some builds merge cstrings into __TEXT,__text — fall back to full scan
        None
    })?;

    let cstring_data = cstring_sec.data().ok()?;
    let cstring_base_rva = cstring_sec.address(); // RVA of start of section

    // Find "IL2CPP Root Domain\0"
    let needle = b"IL2CPP Root Domain\0";
    let offset_in_sec = cstring_data
        .windows(needle.len())
        .position(|w| w == needle)?;
    let string_rva = cstring_base_rva + offset_in_sec as u64;
    let string_va_page = string_rva & !0xFFF; // page address for ADRP matching

    // Search __TEXT,__text for the ADRP+ADD+BL sequence that loads this string
    let text_sec = macho.section_by_name("__text")?;
    let text_data = text_sec.data().ok()?;
    let text_base_rva = text_sec.address();

    // Disassemble 4-byte words looking for:
    //   ADRP Xn, page_of_string  (encodes the page VA)
    //   ADD  Xn, Xn, #offset_in_page
    //   BL   <il2cpp_init>
    let words: &[u32] = bytemuck_cast_u32(text_data);

    for (i, &w) in words.iter().enumerate() {
        if !is_adrp(w) { continue; }
        let adrp_va = text_base_rva + (i as u64) * 4;
        let computed_page = adrp_target_page(w, adrp_va);
        if computed_page != string_va_page { continue; }

        // Check the next instruction is an ADD
        let Some(&add_w) = words.get(i + 1) else { continue };
        if !is_add_imm12(add_w) { continue; }

        // Walk forward at most 8 instructions to find BL
        for j in (i + 2)..(i + 10).min(words.len()) {
            let Some(&bl_w) = words.get(j) else { break };
            if is_bl(bl_w) {
                let bl_va = text_base_rva + (j as u64) * 4;
                let target_rva = bl_target_rva(bl_w, bl_va);
                return Some(target_rva);
            }
        }
    }

    None
}

// ──────────────────────────────────────────────────────────────────────────────
// LC_FUNCTION_STARTS parser
// ──────────────────────────────────────────────────────────────────────────────

fn collect_function_starts(
    macho: &MachOFile64<LittleEndian>,
    data: &[u8],
    slide: isize,
    _base: usize,
) -> Result<Vec<usize>, &'static str> {
    let endian = macho.endian();
    let header = macho.macho_header();
    let mut offset = std::mem::size_of::<MachHeader64<LE>>();
    let ncmds = header.ncmds.get(endian) as usize;

    let mut fn_starts_off:  Option<u32> = None;
    let mut fn_starts_size: Option<u32> = None;
    // __LINKEDIT mapping: needed to convert file offsets → memory offsets
    let mut linkedit_vmaddr:  Option<u64> = None;
    let mut linkedit_fileoff: Option<u64> = None;

    for _ in 0..ncmds {
        if offset + 8 > data.len() { break; }
        let cmd     = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(data[offset+4..offset+8].try_into().unwrap()) as usize;
        if cmdsize == 0 { break; }

        const LC_SEGMENT_64:      u32 = 0x19;
        const LC_FUNCTION_STARTS: u32 = 0x26;

        match cmd {
            LC_FUNCTION_STARTS if cmdsize >= 16 => {
                fn_starts_off  = Some(u32::from_le_bytes(data[offset+8..offset+12].try_into().unwrap()));
                fn_starts_size = Some(u32::from_le_bytes(data[offset+12..offset+16].try_into().unwrap()));
            }
            LC_SEGMENT_64 if cmdsize >= 64 => {
                // segname is at offset+8, 16 bytes null-padded
                let segname = &data[offset+8..offset+24];
                if segname.starts_with(b"__LINKEDIT") {
                    // vmaddr at offset+24 (u64), fileoff at offset+40 (u64)
                    linkedit_vmaddr  = Some(u64::from_le_bytes(data[offset+24..offset+32].try_into().unwrap()));
                    linkedit_fileoff = Some(u64::from_le_bytes(data[offset+40..offset+48].try_into().unwrap()));
                }
            }
            _ => {}
        }

        offset += cmdsize;
    }

    let dataoff  = fn_starts_off.ok_or("il2cpp_resolver: LC_FUNCTION_STARTS not found")? as u64;
    let datasize = fn_starts_size.ok_or("il2cpp_resolver: LC_FUNCTION_STARTS size missing")? as u64;

    // Convert file offset → memory (vmaddr-relative) offset.
    // In the loaded image: mem_offset = dataoff - linkedit_fileoff + linkedit_vmaddr
    // If we can't find LINKEDIT, fall back to direct file offset (often works if fileoff == vmaddr).
    let mem_off: u64 = if let (Some(lv), Some(lf)) = (linkedit_vmaddr, linkedit_fileoff) {
        info!("__LINKEDIT vmaddr={:#x} fileoff={:#x}", lv, lf);
        dataoff - lf + lv
    } else {
        warn!("__LINKEDIT segment not found, using raw file offset (may be wrong)");
        dataoff
    };

    let linked_data = data
        .get(mem_off as usize .. (mem_off + datasize) as usize)
        .ok_or("il2cpp_resolver: LC_FUNCTION_STARTS data out of range")?;

    // Log first few bytes for debugging
    let preview: Vec<String> = linked_data.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    info!("LC_FUNCTION_STARTS mem_off={:#x} size={} first_bytes=[{}]",
        mem_off, datasize, preview.join(" "));

    // Decode ULEB128 delta-encoded function-start RVAs.
    // Each entry is a delta from the previous entry; first is delta from start of __TEXT.
    let text_start_rva = text_segment_rva(macho);
    let mut addresses: Vec<usize> = Vec::with_capacity(4096);
    let mut cur = text_start_rva;
    let mut i = 0usize;

    while i < linked_data.len() {
        let (delta, consumed) = decode_uleb128(&linked_data[i..]);
        if consumed == 0 || delta == 0 { break; }
        cur += delta;
        // Apply ASLR slide to get virtual address
        let va = (cur as i64 + slide as i64) as usize;
        addresses.push(va);

        i += consumed;
    }

    if addresses.is_empty() {
        return Err("il2cpp_resolver: LC_FUNCTION_STARTS decoded 0 entries");
    }

    Ok(addresses)
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Get the RVA of the first `__TEXT` segment (used as the base for FUNCTION_STARTS).
fn text_segment_rva(macho: &MachOFile64<LittleEndian>) -> u64 {
    use object::Object;
    for seg in macho.segments() {
        use object::ObjectSegment;
        if seg.name().ok().flatten() == Some("__TEXT") {
            return seg.address();
        }
    }
    0
}

/// Project the entire loaded image into a `&[u8]` slice.
///
/// We limit to 64 MiB which is larger than any known `UnityFramework` binary.
/// SAFETY: caller must ensure `header_addr` is a valid loaded Mach-O header.
unsafe fn image_as_slice(header_addr: usize) -> &'static [u8] {
    // UnityFramework is ~133 MiB on iOS 2.24.x; use 512 MiB to be safe.
    const MAX_IMAGE_SIZE: usize = 512 * 1024 * 1024;
    std::slice::from_raw_parts(header_addr as *const u8, MAX_IMAGE_SIZE)
}

// AArch64 instruction helpers ─────────────────────────────────────────────────

/// Returns `true` if `insn` is an ADRP instruction (bits [31:23] = 1_0000_0).
#[inline]
fn is_adrp(insn: u32) -> bool {
    (insn & 0x9F000000) == 0x90000000
}

/// Returns the target page VA of an ADRP instruction executed at `pc`.
#[inline]
fn adrp_target_page(insn: u32, pc: u64) -> u64 {
    // immhi = insn[23:5], immlo = insn[30:29]
    let immlo = ((insn >> 29) & 0x3) as i64;
    let immhi = (((insn >> 5) & 0x7FFFF) as i64) << 2;
    let imm = sign_extend((immhi | immlo) as u64, 21) << 12;
    ((pc & !0xFFF) as i64).wrapping_add(imm) as u64
}

/// Returns `true` if `insn` is an `ADD Xn, Xm, #imm12` (64-bit, shift=0).
#[inline]
fn is_add_imm12(insn: u32) -> bool {
    (insn & 0xFF800000) == 0x91000000
}

/// Returns `true` if `insn` is a `BL` instruction.
#[inline]
fn is_bl(insn: u32) -> bool {
    (insn & 0xFC000000) == 0x94000000
}

/// Compute the target RVA of a BL instruction at `pc`.
#[inline]
fn bl_target_rva(insn: u32, pc: u64) -> u64 {
    let imm26 = (insn & 0x03FFFFFF) as i64;
    let offset = sign_extend((imm26 << 2) as u64, 28);
    (pc as i64).wrapping_add(offset) as u64
}

/// Sign-extend a `bits`-wide value stored in a `u64`.
#[inline]
fn sign_extend(val: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((val << shift) as i64) >> shift
}

/// Decode an unsigned ULEB128 integer; returns `(value, bytes_consumed)`.
fn decode_uleb128(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        result |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return (result, i + 1);
        }
        if shift >= 64 { break; }
    }
    (0, 0)
}

/// Reinterpret a `&[u8]` as `&[u32]` (requires 4-byte alignment; on AArch64
/// Mach-O the `__text` section is always 4-byte aligned).
fn bytemuck_cast_u32(bytes: &[u8]) -> &[u32] {
    let len = bytes.len() / 4;
    // SAFETY: `__text` in a Mach-O file is aligned to at least 4 bytes.
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u32, len) }
}

// ──────────────────────────────────────────────────────────────────────────────
// API table — 124 functions in the exact order they appear in the binary
// (derived from Ghidra analysis of 2.23.6 / 2.24.0 / 2.24.5 CSV exports)
// ──────────────────────────────────────────────────────────────────────────────

pub static IL2CPP_API_ORDER: &[&str] = &[
    "il2cpp_init",
    "il2cpp_shutdown",
    "il2cpp_set_config_dir",
    "il2cpp_set_data_dir",
    "il2cpp_set_commandline_arguments",
    "il2cpp_set_config",
    "il2cpp_set_memory_callbacks",
    "il2cpp_memory_pool_set_region_size",
    "il2cpp_memory_pool_get_region_size",
    "il2cpp_get_corlib",
    "il2cpp_add_internal_call",
    "il2cpp_free",
    "il2cpp_array_class_get",
    "il2cpp_array_length",
    "il2cpp_array_new",
    "il2cpp_array_new_specific",
    "il2cpp_bounded_array_class_get",
    "il2cpp_array_element_size",
    "il2cpp_assembly_get_image",
    "il2cpp_class_enum_basetype",
    "il2cpp_class_from_system_type",
    "il2cpp_class_is_generic",
    "il2cpp_class_is_inflated",
    "il2cpp_class_is_subclass_of",
    "il2cpp_class_has_parent",
    "il2cpp_class_from_il2cpp_type",
    "il2cpp_class_from_name",
    "il2cpp_class_get_fields",
    "il2cpp_class_get_nested_types",
    "il2cpp_class_get_field_from_name",
    "il2cpp_class_get_methods",
    "il2cpp_class_get_name",
    "il2cpp_class_get_namespace",
    "il2cpp_class_get_parent",
    "il2cpp_class_get_declaring_type",
    "il2cpp_class_instance_size",
    "il2cpp_class_is_valuetype",
    "il2cpp_class_is_blittable",
    "il2cpp_class_get_flags",
    "il2cpp_class_is_abstract",
    "il2cpp_class_is_interface",
    "il2cpp_class_array_element_size",
    "il2cpp_class_get_type",
    "il2cpp_class_has_attribute",
    "il2cpp_class_is_enum",
    "il2cpp_class_get_assemblyname",
    "il2cpp_class_get_rank",
    "il2cpp_domain_get",
    "il2cpp_domain_assembly_open",
    "il2cpp_raise_exception",
    "il2cpp_exception_from_name_msg",
    "il2cpp_get_exception_argument_null",
    "il2cpp_unhandled_exception",
    "il2cpp_native_stack_trace",
    "il2cpp_field_get_flags",
    "il2cpp_field_get_offset",
    "il2cpp_field_get_type",
    "il2cpp_field_get_value",
    "il2cpp_field_has_attribute",
    "il2cpp_gc_collect",
    "il2cpp_gc_collect_a_little",
    "il2cpp_gc_enable",
    "il2cpp_gc_disable",
    "il2cpp_gc_is_incremental",
    "il2cpp_gc_get_max_time_slice_ns",
    "il2cpp_gc_set_max_time_slice_ns",
    "il2cpp_gc_get_used_size",
    "il2cpp_gc_get_heap_size",
    "il2cpp_stop_gc_world",
    "il2cpp_start_gc_world",
    "il2cpp_gchandle_new",
    "il2cpp_gchandle_new_weakref",
    "il2cpp_gchandle_get_target",
    "il2cpp_gc_wbarrier_set_field",
    "il2cpp_gchandle_free",
    "il2cpp_unity_liveness_allocate_struct",
    "il2cpp_unity_liveness_calculation_from_root",
    "il2cpp_unity_liveness_calculate_from_statics",
    "il2cpp_unity_liveness_finalize",
    "il2cpp_unity_liveness_free_struct",
    "il2cpp_method_get_return_type",
    "il2cpp_method_get_object",
    "il2cpp_method_is_generic",
    "il2cpp_method_is_inflated",
    "il2cpp_method_is_instance",
    "il2cpp_method_get_param_count",
    "il2cpp_method_get_param",
    "il2cpp_method_get_class",
    "il2cpp_method_has_attribute",
    "il2cpp_object_get_virtual_method",
    "il2cpp_object_new",
    "il2cpp_object_unbox",
    "il2cpp_monitor_enter",
    "il2cpp_monitor_try_wait",
    "il2cpp_runtime_invoke_convert_args",
    "il2cpp_runtime_invoke",
    "il2cpp_runtime_object_init_exception",
    "il2cpp_runtime_unhandled_exception_policy_set",
    "il2cpp_string_length",
    "il2cpp_string_chars",
    "il2cpp_string_new",
    "il2cpp_string_new_len",
    "il2cpp_string_intern",
    "il2cpp_thread_current",
    "il2cpp_thread_attach",
    "il2cpp_type_get_object",
    "il2cpp_type_get_type",
    "il2cpp_type_get_class_or_element_class",
    "il2cpp_type_get_name",
    "il2cpp_type_get_assembly_qualified_name",
    "il2cpp_type_is_byref",
    "il2cpp_type_get_attrs",
    "il2cpp_type_equals",
    "il2cpp_type_is_static",
    "il2cpp_image_get_class_count",
    "il2cpp_image_get_class",
    "il2cpp_unity_install_unitytls_interface",
    "il2cpp_custom_attrs_from_class",
    "il2cpp_custom_attrs_from_method",
    "il2cpp_custom_attrs_has_attr",
    "il2cpp_custom_attrs_get_attr",
    "il2cpp_custom_attrs_construct",
    "il2cpp_class_set_userdata",
    "il2cpp_class_get_userdata_offset",
];
