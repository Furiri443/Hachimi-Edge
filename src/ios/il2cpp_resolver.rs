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
use super::arm64;

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

    // ── Step 1.5: locate il2cpp_resolve_icall via signature scan ──────────
    info!("Searching for il2cpp_resolve_icall via Behaviour::get_enabled...");
    let resolve_icall_rva = find_resolve_icall_rva(&macho);

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
        FnvHashMap::with_capacity_and_hasher(IL2CPP_API_ORDER.len() + 1, Default::default());

    for (offset, &name) in IL2CPP_API_ORDER.iter().enumerate() {
        let va = fn_starts[init_idx + offset];
        table.insert(name, va);
    }

    // ── Step 4.5: locate Class::GetMethodFromName via signature scan ──────
    if let Some(&get_methods_va) = table.get("il2cpp_class_get_methods") {
        // SAFETY: image remains mapped for the lifetime of the process.
        match unsafe { super::il2cpp_missing::scan_class_get_method_from_name(get_methods_va, &fn_starts) } {
            Some(va) => {
                table.insert("il2cpp_class_get_method_from_name", va);
                info!("il2cpp_class_get_method_from_name: VA={:#x} (binary scan) ✅", va);
            }
            None => {
                warn!("il2cpp_class_get_method_from_name not found via binary scan");
            }
        }
    } else {
        warn!("il2cpp_class_get_methods not resolved; skipping Class::GetMethodFromName scan");
    }

    // Insert il2cpp_resolve_icall if found via binary scan
    if let Some(rva) = resolve_icall_rva {
        let va = (base as i64 + rva as i64) as usize;
        table.insert("il2cpp_resolve_icall", va);
        info!("il2cpp_resolve_icall: VA={:#x} RVA={:#x} ✅", va, rva);
    } else {
        warn!("il2cpp_resolve_icall not found via binary scan — will try runtime scanner later");
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

    let cstring_sec = match macho.section_by_name("__cstring") {
        Some(s) => s,
        None => { error!("find_il2cpp_init_rva: __cstring section not found"); return None; }
    };

    let cstring_data = match cstring_sec.data() {
        Ok(d) => d,
        Err(e) => { error!("find_il2cpp_init_rva: __cstring data error: {:?}", e); return None; }
    };
    let cstring_base_rva = cstring_sec.address();
    info!("find_il2cpp_init_rva: __cstring at RVA={:#x} size={}", cstring_base_rva, cstring_data.len());

    let needle = b"IL2CPP Root Domain\0";
    let offset_in_sec = match cstring_data.windows(needle.len()).position(|w| w == needle) {
        Some(o) => o,
        None => { error!("find_il2cpp_init_rva: needle not found in __cstring"); return None; }
    };
    let string_rva      = cstring_base_rva + offset_in_sec as u64;
    let string_va_page  = string_rva & !0xFFF;
    let string_page_off = string_rva & 0xFFF;
    info!("find_il2cpp_init_rva: string RVA={:#x} page={:#x} off={:#x}",
        string_rva, string_va_page, string_page_off);

    let text_sec = match macho.section_by_name("__text") {
        Some(s) => s,
        None => { error!("find_il2cpp_init_rva: __text section not found"); return None; }
    };
    let text_data = match text_sec.data() {
        Ok(d) => d,
        Err(e) => { error!("find_il2cpp_init_rva: __text data error: {:?}", e); return None; }
    };
    let text_base_rva = text_sec.address();
    info!("find_il2cpp_init_rva: __text at RVA={:#x} size={}", text_base_rva, text_data.len());

    let cs = match arm64::Disasm::new() {
        Some(c) => c,
        None => { error!("find_il2cpp_init_rva: Capstone failed to initialise"); return None; }
    };
    info!("find_il2cpp_init_rva: Capstone OK — scanning {} words for ADRP page {:#x}",
        text_data.len() / 4, string_va_page);

    let words: &[u32] = bytemuck_cast_u32(text_data);
    let mut adrp_candidates = 0u32;
    let mut page_hits = 0u32;
    let mut add_hits = 0u32;

    for (i, &w) in words.iter().enumerate() {
        if (w & 0x9F000000) != 0x90000000 { continue; }
        adrp_candidates += 1;

        let offset = i * 4;
        let pc     = text_base_rva + offset as u64;

        let insns = match cs.disasm_count(&text_data[offset..], pc, 10) { Some(v) => v, None => continue };
        let window: Vec<_> = insns.iter().collect();

        let adrp = match window.first() { Some(v) => v, None => continue };
        if !cs.is_adrp(adrp) { continue; }
        let (adrp_rd, page) = match cs.adrp_ops(adrp) { Some(v) => v, None => continue };
        if page != string_va_page { continue; }
        page_hits += 1;
        info!("find_il2cpp_init_rva: ADRP page hit at RVA={:#x}", pc);

        let add = match window.get(1) { Some(v) => v, None => continue };
        if !cs.is_add(add) {
            info!("find_il2cpp_init_rva:   next insn is not ADD (mnemonic={:?})", add.mnemonic());
            continue;
        }
        let (add_rn, add_imm) = match cs.add_rn_imm(add) { Some(v) => v, None => continue };
        if add_rn != adrp_rd || add_imm != string_page_off {
            info!("find_il2cpp_init_rva:   ADD mismatch: rn_match={} imm={:#x} want={:#x}",
                add_rn == adrp_rd, add_imm, string_page_off);
            continue;
        }
        add_hits += 1;
        info!("find_il2cpp_init_rva:   ADRP+ADD matched — searching window for BL");

        for insn in &window[2..] {
            if cs.is_bl(insn) {
                if let Some(target) = cs.branch_target(insn) {
                    info!("find_il2cpp_init_rva:   BL at RVA={:#x} → target={:#x}", insn.address(), target);
                    return Some(target);
                }
            }
        }
        info!("find_il2cpp_init_rva:   no BL found in window after ADD");
    }

    error!("find_il2cpp_init_rva: scan complete — ADRP candidates={} page_hits={} add_hits={} no match",
        adrp_candidates, page_hits, add_hits);
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Signature scan: find il2cpp_resolve_icall RVA
// ──────────────────────────────────────────────────────────────────────────────

/// Find `il2cpp_resolve_icall` by scanning `Behaviour::get_enabled` bytecode
/// in the Mach-O binary.
///
/// Strategy:
/// 1. Find `"UnityEngine.Behaviour::get_enabled()\0"` in `__cstring`
/// 2. Scan `__text` for ADRP+ADD that computes exactly that string address
/// 3. The next BL after that ADRP+ADD = `il2cpp_resolve_icall`
fn find_resolve_icall_rva(macho: &MachOFile64<LittleEndian>) -> Option<u64> {
    use object::{Object, ObjectSection};

    let cstring_sec = macho.section_by_name("__cstring")?;
    let cstring_data = cstring_sec.data().ok()?;
    let cstring_base = cstring_sec.address();

    let needle = b"UnityEngine.Behaviour::get_enabled()\0";
    
    // Find ALL instances of the string in __cstring
    let mut string_matches = Vec::new();
    let mut search_idx = 0;
    while let Some(pos) = cstring_data[search_idx..].windows(needle.len()).position(|w| w == needle) {
        let offset = search_idx + pos;
        let addr = cstring_base + offset as u64;
        string_matches.push((addr & !0xFFF, addr & 0xFFF));
        search_idx = offset + needle.len();
    }

    info!("resolve_icall: found {} instances of the string", string_matches.len());
    for (page, off) in &string_matches {
        info!("  string at page {:#x} + {:#x}", page, off);
    }

    if string_matches.is_empty() {
        return None;
    }

    let text_sec = macho.section_by_name("il2cpp")?;
    let text_data = text_sec.data().ok()?;
    let text_base = text_sec.address();

    let cs = arm64::Disasm::new()?;
    let mut page_hits = 0u32;

    let words: &[u32] = bytemuck_cast_u32(text_data);
    for (i, &w) in words.iter().enumerate() {
        if (w & 0x9F000000) != 0x90000000 { continue; } // ADRP pre-filter

        let offset = i * 4;
        let pc     = text_base + offset as u64;

        // Decode ADRP + up to 25 following instructions (ADD may not be adjacent).
        let insns = match cs.disasm_count(&text_data[offset..], pc, 26) { Some(v) => v, None => continue };
        let window: Vec<_> = insns.iter().collect();

        let adrp = match window.first() { Some(v) => v, None => continue };
        if !cs.is_adrp(adrp) { continue; }
        let (adrp_rd, page) = match cs.adrp_ops(adrp) { Some(v) => v, None => continue };

        let matching = string_matches.iter().find(|(sp, _)| *sp == page);
        let Some(&(_, string_page_off)) = matching else { continue };
        page_hits += 1;

        // Find the ADD in the next 10 instructions that uses adrp_rd and the correct offset.
        let mut add_idx: Option<usize> = None;
        for (j, insn) in window[1..].iter().enumerate().take(10) {
            if !cs.is_add(insn) { continue; }
            if let Some((rn, imm)) = cs.add_rn_imm(insn) {
                if rn == adrp_rd && imm == string_page_off {
                    add_idx = Some(j + 1); // offset into `window`
                    break;
                }
            }
        }

        let add_idx = match add_idx { Some(v) => v, None => continue };
        info!("resolve_icall: ADRP+ADD match at vmaddr {:#x}", pc);

        // Find the next BL after the ADD.
        for insn in window[add_idx + 1..].iter().take(15) {
            if cs.is_bl(insn) {
                if let Some(target) = cs.branch_target(insn) {
                    info!("resolve_icall: BL at {:#x} → target {:#x}", insn.address(), target);
                    return Some(target);
                }
            }
        }
    }

    warn!("resolve_icall: no ADRP+ADD+BL match found (page hits: {})", page_hits);
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
