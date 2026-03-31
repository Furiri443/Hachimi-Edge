//! Re-implementations of IL2CPP API functions that are absent from the game binary.
//!
//! These functions exist in the IL2CPP source code (`il2cpp-api.cpp`) but are
//! not present in the `LC_FUNCTION_STARTS` table of any known `UnityFramework`
//! version.  We implement them directly against the IL2CPP internal structs
//! (layout from `il2cpp-class-internals.h`, Unity 2022.3.62f2).
//!
//! **This file only compiles on `target_os = "ios"`.**

use std::os::raw::{c_char, c_void};
use crate::il2cpp::types::*;

// ──────────────────────────────────────────────────────────────────────────────
// Internal struct mirrors
// (layout matches il2cpp-class-internals.h @ Unity 2022.3.62f2 / ARM64)
// ──────────────────────────────────────────────────────────────────────────────

/// Mirrors the `FieldInfo` struct (il2cpp-class-internals.h).
#[repr(C)]
pub struct RawFieldInfo {
    pub name:   *const c_char,
    pub type_:  *const c_void,   // Il2CppType*
    pub parent: *mut RawKlass,
    pub offset: i32,
    pub token:  u32,
}

/// Minimal mirror of `Il2CppClass` fields we actually access.
/// Full struct is 200+ bytes on AArch64; we only need up to `method_count`.
#[repr(C)]
pub struct RawKlass {
    // ── always-valid fields (0x00 – 0x68) ─────────────────────────────────
    pub image:             *const c_void,   // 0x00
    pub gc_desc:           *mut c_void,     // 0x08
    pub name:              *const c_char,   // 0x10
    pub namespaze:         *const c_char,   // 0x18
    pub byval_arg:         [u8; 0x18],      // 0x20  (Il2CppType, 24 bytes)
    pub this_arg:          [u8; 0x18],      // 0x38
    pub element_class:     *mut RawKlass,   // 0x50
    pub cast_class:        *mut RawKlass,   // 0x58
    pub declaring_type:    *mut RawKlass,   // 0x60
    pub parent:            *mut RawKlass,   // 0x68
    pub generic_class:     *mut c_void,     // 0x70
    pub type_meta_handle:  *mut c_void,     // 0x78
    pub interop_data:      *const c_void,   // 0x80
    pub klass:             *mut RawKlass,   // 0x88 (self-pointer)
    // ── init-required fields ───────────────────────────────────────────────
    pub fields:            *mut RawFieldInfo,   // 0x90
    pub events:            *const c_void,       // 0x98
    pub properties:        *const c_void,       // 0xa0
    pub methods:           *mut *const RawMethodInfo, // 0xa8
    pub nested_types:      *mut *mut RawKlass,  // 0xb0
    pub implemented_ifaces:*mut *mut RawKlass,  // 0xb8
    pub iface_offsets:     *mut c_void,         // 0xc0
    pub static_fields:     *mut c_void,         // 0xc8
    pub rgctx_data:        *const c_void,       // 0xd0
    pub type_hierarchy:    *mut *mut RawKlass,  // 0xd8
    // ── remaining scalar fields ────────────────────────────────────────────
    pub unity_user_data:           *mut c_void,     // 0xe0
    pub init_exception_gc_handle:  u32,             // 0xe8
    pub cctor_started:             u32,             // 0xec
    pub cctor_finished:            u32,             // 0xf0
    pub _pad_cctor:                u32,             // 0xf4
    pub cctor_thread:              usize,           // 0xf8
    pub generic_container_handle:  *mut c_void,     // 0x100
    pub instance_size:             u32,             // 0x108
    pub stack_slot_size:           u32,             // 0x10c
    pub actual_size:               u32,             // 0x110
    pub element_size:              u32,             // 0x114
    pub native_size:               i32,             // 0x118
    pub static_fields_size:        u32,             // 0x11c
    pub thread_static_fields_size: u32,             // 0x120
    pub thread_static_fields_offset: i32,           // 0x124
    pub flags:                     u32,             // 0x128
    pub token:                     u32,             // 0x12c
    pub method_count:              u16,             // 0x130
    pub property_count:            u16,             // 0x132
    pub field_count:               u16,             // 0x134
    pub event_count:               u16,             // 0x136
    pub nested_type_count:         u16,             // 0x138
    pub vtable_count:              u16,             // 0x13a
    pub interfaces_count:          u16,             // 0x13c
    pub iface_offsets_count:       u16,             // 0x13e
    pub type_hierarchy_depth:      u8,              // 0x140
    pub generic_recursion_depth:   u8,              // 0x141
    pub rank:                      u8,              // 0x142
    pub minimum_alignment:         u8,              // 0x143
    pub packing_size:              u8,              // 0x144
    pub bitflags:                  u8,              // 0x145  (initialized & friends)
    pub bitflags2:                 u8,              // 0x146
}

impl RawKlass {
    /// `initialized` bit = bit 0 of `bitflags` (after 5 padding bits from `packingSize`).
    #[inline]
    pub fn is_initialized(&self) -> bool {
        (self.bitflags & 0x02) != 0
    }
}

/// Minimal mirror of `MethodInfo` (only the fields we need).
#[repr(C)]
pub struct RawMethodInfo {
    pub method_ptr:           *const c_void,    // 0x00
    pub virtual_method_ptr:   *const c_void,    // 0x08
    pub invoker_method:       *const c_void,    // 0x10
    pub name:                 *const c_char,    // 0x18
    pub klass:                *mut RawKlass,    // 0x20
    pub return_type:          *const c_void,    // 0x28
    pub parameters:           *const *const c_void, // 0x30
    // 0x38: union (rgctx_data / methodMetadataHandle)
    // 0x40: union (genericMethod / genericContainerHandle)
    pub _rgctx_and_generic:   [u8; 16],
    pub token:                u32,              // 0x48
    pub flags:                u16,              // 0x4c
    pub iflags:               u16,             // 0x4e
    pub slot:                 u16,              // 0x50
    pub parameters_count:     u8,              // 0x52
    pub bitflags:             u8,              // 0x53
}

// ──────────────────────────────────────────────────────────────────────────────
// Re-implemented functions (called when the table returns 0 for these names)
// ──────────────────────────────────────────────────────────────────────────────

/// `il2cpp_class_is_inited` — directly mirrors `klass->initialized`.
///
/// Source: `return klass->initialized;` (il2cpp-api.cpp:247)
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_class_is_inited(klass: *const Il2CppClass) -> bool {
    if klass.is_null() { return false; }
    let k = klass as *const RawKlass;
    (*k).is_initialized()
}

/// Locate `Class::GetMethodFromName` (and thus `il2cpp_class_get_method_from_name`)
/// via a binary signature scan at runtime.
///
/// # Algorithm
/// 1. Read the `B` instruction at `get_methods_va` (`il2cpp_class_get_methods`) and
///    decode its target to obtain the address of `Class::GetMethods`.
/// 2. Binary-search `fn_starts` (sorted VAs from LC_FUNCTION_STARTS) to locate
///    `Class::GetMethods`.
/// 3. Walk forward from that index, checking each function's first three instructions
///    for the `Class::GetMethodFromName` prologue:
///    ```
///    MOV w?, #0      (MOVZ w?, #0)
///    MOV x?, #0      (MOVZ x?, #0)
///    B   <target>
///    ```
///
/// Returns the virtual address of `Class::GetMethodFromName`, or `None` on failure.
///
/// # Safety
/// Reads from live mapped memory; the caller must ensure the image remains loaded.
pub unsafe fn scan_class_get_method_from_name(
    get_methods_va: usize,
    fn_starts: &[usize],
) -> Option<usize> {
    // Step 1 — follow B at il2cpp_class_get_methods → Class::GetMethods
    let insn0 = std::ptr::read_unaligned(get_methods_va as *const u32);
    let class_get_methods_va = decode_b(get_methods_va, insn0)?;
    info!("scan_get_method_from_name: Class::GetMethods @ {:#x}", class_get_methods_va);

    // Step 2 — locate Class::GetMethods in the (sorted) function-starts table
    let idx = fn_starts.partition_point(|&va| va < class_get_methods_va);
    if idx >= fn_starts.len() || fn_starts[idx] != class_get_methods_va {
        warn!("scan_get_method_from_name: Class::GetMethods not found in LC_FUNCTION_STARTS");
        return None;
    }
    info!("scan_get_method_from_name: Class::GetMethods at fn_starts[{}]", idx);

    // Step 3 — scan forward for the Class::GetMethodFromName prologue
    const MAX_SEARCH: usize = 128;
    for &fn_va in fn_starts[idx + 1..].iter().take(MAX_SEARCH) {
        let i0 = std::ptr::read_unaligned(fn_va as *const u32);
        let i1 = std::ptr::read_unaligned((fn_va + 4) as *const u32);
        let i2 = std::ptr::read_unaligned((fn_va + 8) as *const u32);

        if is_movz_w_zero(i0) && is_movz_x_zero(i1) && is_b(i2) {
            info!("scan_get_method_from_name: Class::GetMethodFromName @ {:#x}", fn_va);
            return Some(fn_va);
        }
    }

    warn!("scan_get_method_from_name: signature not found in {} functions after Class::GetMethods",
        MAX_SEARCH);
    None
}

// ── ARM64 helpers (local to this scan) ───────────────────────────────────────

/// `MOVZ w?, #0, LSL #0` — sf=0, opc=01, 100101, hw=00, imm16=0, Rd=any
#[inline]
fn is_movz_w_zero(insn: u32) -> bool {
    (insn & 0xFFFFFFE0) == 0x52800000
}

/// `MOVZ x?, #0, LSL #0` — sf=1, opc=01, 100101, hw=00, imm16=0, Rd=any
#[inline]
fn is_movz_x_zero(insn: u32) -> bool {
    (insn & 0xFFFFFFE0) == 0xD2800000
}

/// Unconditional `B`: bits[31:26] = 0b000101
#[inline]
fn is_b(insn: u32) -> bool {
    (insn >> 26) == 0x05
}

/// Decode a `B` instruction at `pc`; returns the branch target address.
#[inline]
fn decode_b(pc: usize, insn: u32) -> Option<usize> {
    if !is_b(insn) { return None; }
    let imm26 = (insn & 0x03FF_FFFF) as u64;
    let shift = 64 - 26;
    let signed_off = ((imm26 << shift) as i64) >> shift; // sign-extend 26 bits
    Some((pc as i64).wrapping_add(signed_off * 4) as usize)
}

/// `il2cpp_class_is_assignable_from` — walk `oklass->typeHierarchy`.
///
/// Source: `Class::IsAssignableFrom` checks include interface list and
/// type-hierarchy array. We implement the common case (non-interface classes).
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_class_is_assignable_from(
    klass:  *mut Il2CppClass,
    oklass: *mut Il2CppClass,
) -> bool {
    if klass.is_null() || oklass.is_null() { return false; }
    if klass == oklass { return true; }

    let k  = klass  as *mut RawKlass;
    let ok = oklass as *mut RawKlass;

    // Check type hierarchy array of oklass
    let depth = (*ok).type_hierarchy_depth as usize;
    let hier  = (*ok).type_hierarchy;
    if !hier.is_null() {
        for i in 0..depth {
            if *hier.add(i) == k { return true; }
        }
    }

    // Check implemented interfaces of oklass
    let icount = (*ok).interfaces_count as usize;
    let ifaces  = (*ok).implemented_ifaces;
    if !ifaces.is_null() {
        for i in 0..icount {
            let iface = *ifaces.add(i);
            if iface == k { return true; }
        }
    }

    false
}

/// `il2cpp_field_set_value` — write into instance field by offset.
///
/// Source: `Field::SetValue(obj, field, value)` (il2cpp-api.cpp:677)
/// For non-thread-static fields: `memcpy((u8*)obj + field->offset, value, size)`.
/// The size isn't trivially available without the type's instance_size, so we
/// delegate to `il2cpp_field_get_offset` + a conservative memcpy of the value
/// pointer.  The caller passes a correctly-sized value.
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_field_set_value(
    obj:   *mut Il2CppObject,
    field: *mut FieldInfo,
    value: *mut c_void,
) {
    if obj.is_null() || field.is_null() || value.is_null() { return; }
    let fi = field as *const RawFieldInfo;
    let offset = (*fi).offset;
    if offset < 0 { return; } // thread-static — not implemented
    let dest = (obj as *mut u8).add(offset as usize) as *mut c_void;
    // We don't know the exact size here; copy 8 bytes (pointer-sized).
    // For value types the caller is responsible for matching the type size.
    std::ptr::copy_nonoverlapping(value as *const u8, dest as *mut u8, 8);
}

/// `il2cpp_field_static_get_value` — read from static field data.
///
/// Source: `Field::StaticGetValue(field, value)` → `klass->static_fields + offset`.
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_field_static_get_value(
    field: *mut FieldInfo,
    value: *mut c_void,
) {
    if field.is_null() || value.is_null() { return; }
    let fi = field as *const RawFieldInfo;
    let offset = (*fi).offset;
    if offset < 0 { return; }
    let klass = (*fi).parent;
    if klass.is_null() { return; }
    let static_fields = (*klass).static_fields;
    if static_fields.is_null() { return; }
    let src = (static_fields as *const u8).add(offset as usize);
    std::ptr::copy_nonoverlapping(src, value as *mut u8, 8);
}

/// `il2cpp_field_static_set_value` — write to static field data.
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_field_static_set_value(
    field: *mut FieldInfo,
    value: *mut c_void,
) {
    if field.is_null() || value.is_null() { return; }
    let fi = field as *const RawFieldInfo;
    let offset = (*fi).offset;
    if offset < 0 { return; }
    let klass = (*fi).parent;
    if klass.is_null() { return; }
    let static_fields = (*klass).static_fields;
    if static_fields.is_null() { return; }
    let dest = (static_fields as *mut u8).add(offset as usize);
    std::ptr::copy_nonoverlapping(value as *const u8, dest, 8);
}

/// `il2cpp_runtime_object_init` — delegates to `il2cpp_runtime_object_init_exception`
/// with a NULL exception pointer.
///
/// Source: `il2cpp_runtime_object_init(obj)` in il2cpp-api.cpp calls
/// `Runtime::ObjectInit(obj, nullptr)`.
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_runtime_object_init(obj: *mut Il2CppObject) {
    crate::il2cpp::api::il2cpp_runtime_object_init_exception(obj, std::ptr::null_mut());
}

/// `il2cpp_runtime_class_init` — trigger .cctor if not already initialized.
///
/// On iOS we rely on the fact that `il2cpp_object_new` already calls this
/// internally. If invoked explicitly we just check the flag.
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_runtime_class_init(klass: *mut Il2CppClass) {
    if klass.is_null() { return; }
    let k = klass as *mut RawKlass;
    if (*k).is_initialized() { return; }
    // We cannot safely invoke the .cctor without the full runtime, so we log
    // and continue; the game's own bootstrap will complete initialization.
    warn!("iOS: il2cpp_runtime_class_init called for uninitialized class — skipping");
}

/// `il2cpp_thread_get_all_attached_threads` — not safely implementable without
/// access to the IL2CPP thread registry. Returns an empty list.
#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_thread_get_all_attached_threads(
    size: *mut usize,
) -> *mut *mut Il2CppThread {
    if !size.is_null() { *size = 0; }
    warn!("iOS: il2cpp_thread_get_all_attached_threads not implemented — returning empty");
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn hachimi_ios_il2cpp_string_new_utf16(
    text: *const u16,
    len: i32,
) -> *mut Il2CppString {
    if text.is_null() || len < 0 {
        return std::ptr::null_mut();
    }

    let utf16_slice = std::slice::from_raw_parts(text, len as usize);
    let rust_string = String::from_utf16_lossy(utf16_slice);

    let c_str = std::ffi::CString::new(rust_string).unwrap();

    crate::il2cpp::api::il2cpp_string_new(c_str.as_ptr())
}

// ──────────────────────────────────────────────────────────────────────────────
// Shim table — populated into the resolver map for missing functions
// ──────────────────────────────────────────────────────────────────────────────

/// Returns a table of `(name, fn_ptr_as_usize)` for every re-implemented function.
/// Called by `hachimi_impl::on_il2cpp_loaded` to patch the resolver map.
pub fn missing_fn_table() -> Vec<(&'static str, usize)> {
    vec![
        ("il2cpp_class_is_inited",
            hachimi_ios_il2cpp_class_is_inited as usize),
        ("il2cpp_class_is_assignable_from",
            hachimi_ios_il2cpp_class_is_assignable_from as usize),
        ("il2cpp_field_set_value",
            hachimi_ios_il2cpp_field_set_value as usize),
        ("il2cpp_field_static_get_value",
            hachimi_ios_il2cpp_field_static_get_value as usize),
        ("il2cpp_field_static_set_value",
            hachimi_ios_il2cpp_field_static_set_value as usize),
        ("il2cpp_runtime_object_init",
            hachimi_ios_il2cpp_runtime_object_init as usize),
        ("il2cpp_runtime_class_init",
            hachimi_ios_il2cpp_runtime_class_init as usize),
        ("il2cpp_thread_get_all_attached_threads",
            hachimi_ios_il2cpp_thread_get_all_attached_threads as usize),
        ("il2cpp_string_new_utf16",
            hachimi_ios_il2cpp_string_new_utf16 as usize),
    ]
}
