//! The checks of `src/checks/libc.rs` for the `libc` items of `libc_items.rs` which the ESP-IDF
//! bindings have as well

use std::collections::{HashMap, HashSet};
use std::fmt::{Arguments, Write};
use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::libc_items::{CONSTS, STRUCTS, TYPES};

/// Known mismatches, as `(item, cfg)`: the item (`<name>`, or `<struct>::<field>`) is checked only
/// where `cfg` holds, or never if it is `None`. The entry of a struct covers its fields too.
const MISMATCHES: &[(&str, Option<&str>)] = &[
    // 1 byte on Xtensa (esp32/s2/s3) before ESP-IDF v5.4, 4 bytes in libc
    (
        "wchar_t",
        Some("any(not(any(esp32, esp32s2, esp32s3)), esp_idf_version_at_least_5_4_0)"),
    ),
    // LWIP sizes it for the largest sockaddr, while libc assumes that IPv6 is there
    ("sockaddr_storage", Some("esp_idf_lwip_ipv6")),
    // TODO: picolibc incompatibility, see https://github.com/esp-rs/esp-idf-sys/issues/410
    ("O_APPEND", Some("not(esp_idf_libc_picolibc)")),
    ("O_CREAT", Some("not(esp_idf_libc_picolibc)")),
    ("O_TRUNC", Some("not(esp_idf_libc_picolibc)")),
    // TODO: size/alignment mismatches, to be fixed, or at least carefully investigated
    ("pthread_attr_t", None),
    ("pthread_cond_t", None),
    ("pthread_condattr_t", None),
    ("pthread_mutex_t", None),
    ("pthread_mutexattr_t", None),
    ("pthread_rwlock_t", None),
    ("pthread_rwlockattr_t", None),
    // TODO: size: ESP-IDF 0, libc 16
    ("tms", None),
    // TODO: the values come from LWIP rather than from the libc headers; double-check
    ("IF_NAMESIZE", None),
    ("IFNAMSIZ", None),
    // libc's newlib `termios` has a `c_line` before `c_cc`, which ESP-IDF's does not
    ("termios::c_cc", None),
];

/// The (C) integer types a constant has to resolve to, to be checked by value
const INT_TYPES: &[&str] = &[
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "c_char",
    "c_schar",
    "c_uchar",
    "c_short",
    "c_ushort",
    "c_int",
    "c_uint",
    "c_long",
    "c_ulong",
    "c_longlong",
    "c_ulonglong",
];

/// The top-level items of the (formatted) bindings
#[derive(Default)]
struct Bindings {
    /// Struct name -> its public fields
    structs: HashMap<String, HashSet<String>>,
    /// Type aliases, unions and the other structs
    types: HashSet<String>,
    /// Constant name -> its type
    consts: HashMap<String, String>,
    /// Type alias name -> the aliased type
    aliases: HashMap<String, String>,
}

impl Bindings {
    fn scan(source: &str) -> Self {
        let mut bindings = Self::default();
        let mut current: Option<(String, HashSet<String>)> = None;

        for line in source.lines() {
            if let Some((_, fields)) = &mut current {
                if line == "}" {
                    let (name, fields) = current.take().unwrap();
                    bindings.structs.insert(name, fields);
                } else if let Some((field, _)) = line
                    .strip_prefix("    pub ")
                    .and_then(|rest| rest.split_once(':'))
                {
                    fields.insert(field.to_string());
                }
            } else if let Some(rest) = line.strip_prefix("pub struct ") {
                match rest.strip_suffix(" {") {
                    Some(name) => current = Some((name.to_string(), HashSet::new())),
                    None => {
                        bindings.types.insert(ident(rest).to_string());
                    }
                }
            } else if let Some(rest) = line.strip_prefix("pub union ") {
                bindings.types.insert(ident(rest).to_string());
            } else if let Some(rest) = line.strip_prefix("pub type ") {
                let name = ident(rest);

                bindings.types.insert(name.to_string());

                if let Some((_, ty)) = rest.split_once(" = ") {
                    bindings
                        .aliases
                        .insert(name.to_string(), ty.trim_end_matches(';').to_string());
                }
            } else if let Some((name, rest)) = line
                .strip_prefix("pub const ")
                .and_then(|rest| rest.split_once(": "))
            {
                if let Some((ty, _)) = rest.split_once(" =") {
                    bindings.consts.insert(name.to_string(), ty.to_string());
                }
            }
        }

        bindings
    }

    fn has_type(&self, name: &str) -> bool {
        self.structs.contains_key(name) || self.types.contains(name)
    }

    fn has_int_const(&self, name: &str) -> bool {
        self.consts.get(name).is_some_and(|ty| self.is_int(ty, 0))
    }

    fn is_int(&self, ty: &str, depth: usize) -> bool {
        let name = ty.rsplit("::").next().unwrap_or(ty).trim();

        INT_TYPES.contains(&name)
            || depth < 8
                && self
                    .aliases
                    .get(name)
                    .is_some_and(|ty| self.is_int(ty, depth + 1))
    }
}

/// Writes to `out_file` the checks of the items which both `libc_items.rs` and `bindings_file` have
pub fn generate(bindings_file: &Path, out_file: &Path) -> Result<()> {
    let bindings = Bindings::scan(&fs::read_to_string(bindings_file)?);
    let mut out = String::new();

    for (name, fields) in STRUCTS {
        if !bindings.has_type(name) {
            continue;
        }

        check(&mut out, name, format_args!("check_types!({name});"));

        let Some(sys_fields) = bindings.structs.get(*name) else {
            continue;
        };

        let mut unconditional = Vec::new();

        for field in fields.iter().filter(|field| sys_fields.contains(**field)) {
            let item = format!("{name}::{field}");

            if mismatch(&item).is_some() {
                check(
                    &mut out,
                    &item,
                    format_args!("check_fields!({name}, {field});"),
                );
            } else {
                unconditional.push(*field);
            }
        }

        if !unconditional.is_empty() {
            let fields = unconditional.join(", ");
            check(
                &mut out,
                name,
                format_args!("check_fields!({name}, {fields});"),
            );
        }
    }

    for name in TYPES.iter().filter(|name| bindings.has_type(name)) {
        check(&mut out, name, format_args!("check_types!({name});"));
    }

    for name in CONSTS.iter().filter(|name| bindings.has_int_const(name)) {
        check(&mut out, name, format_args!("check_constants!({name});"));
    }

    fs::write(out_file, out)?;

    Ok(())
}

/// Appends `code` to `out`, under the cfg of `item` if a known mismatch
fn check(out: &mut String, item: &str, code: Arguments) {
    match mismatch(item) {
        Some(None) => (),
        Some(Some(cfg)) => writeln!(out, "#[cfg({cfg})]\n{code}").unwrap(),
        None => writeln!(out, "{code}").unwrap(),
    }
}

fn mismatch(item: &str) -> Option<Option<&'static str>> {
    MISMATCHES
        .iter()
        .find(|(name, _)| *name == item)
        .map(|(_, cfg)| *cfg)
}

/// The identifier `item` starts with
fn ident(item: &str) -> &str {
    let end = item
        .find(|c: char| !c.is_alphanumeric() && c != '_')
        .unwrap_or(item.len());

    &item[..end]
}
