use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use super::resolved::ResolvedProfile;
use super::symbols::SymbolSidecar;
use super::types::RawProfile;

pub fn load_raw_profile(path: &Path) -> Result<RawProfile> {
    let (profile, _) = load_raw_profile_and_symbols(path)?;
    Ok(profile)
}

fn load_raw_profile_and_symbols(path: &Path) -> Result<(RawProfile, Option<SymbolSidecar>)> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let reader = BufReader::new(file);

    let is_gzip = path
        .to_str()
        .is_some_and(|s| s.ends_with(".gz") || s.ends_with(".gzip"));

    let mut profile: RawProfile = if is_gzip {
        let decoder = GzDecoder::new(reader);
        serde_json::from_reader(decoder).context("Failed to parse gzipped profile JSON")?
    } else {
        serde_json::from_reader(reader).context("Failed to parse profile JSON")?
    };

    // Auto-apply .syms.json sidecar if present alongside the profile
    let symbols = find_syms_sidecar(path)
        .map(|syms_path| {
            SymbolSidecar::load(&syms_path)
                .with_context(|| format!("Failed to apply symbols from {}", syms_path.display()))
        })
        .transpose()?;
    if let Some(symbols) = &symbols {
        apply_symbols(&mut profile, symbols);
    }

    Ok((profile, symbols))
}

pub fn load_profile(path: &Path) -> Result<ResolvedProfile> {
    let (raw, symbols) = load_raw_profile_and_symbols(path)?;
    let resolved = ResolvedProfile::from_raw_with_symbols(&raw, symbols.as_ref());
    Ok(resolved)
}

/// Look for a `.syms.json` sidecar next to the profile file.
/// Samply writes e.g. `profile.json.gz` → `profile.json.syms.json`
pub(crate) fn find_syms_sidecar(profile_path: &Path) -> Option<std::path::PathBuf> {
    // Samply writes: profile.json.gz -> profile.json.syms.json
    // i.e. appends ".syms.json" after stripping the final ".gz"
    let file_name = profile_path.file_name()?.to_string_lossy();
    let dir = profile_path.parent()?;

    let stem = file_name.strip_suffix(".gz").unwrap_or(&file_name);

    let candidate = dir.join(format!("{stem}.syms.json"));
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Merge symbol names from a samply `.syms.json` sidecar into per-thread string tables.
fn apply_symbols(profile: &mut RawProfile, symbols: &SymbolSidecar) {
    // A presymbolicated profile already has its intended function and inline
    // frame names. The sidecar is still retained for instruction/source lookup.
    if profile.meta.symbolicated {
        return;
    }

    let shared_strings = profile
        .shared
        .as_ref()
        .map(|shared| shared.string_array.clone())
        .unwrap_or_default();

    // Apply to each thread's string array
    for thread in &mut profile.threads {
        if thread.string_array.is_none() && !shared_strings.is_empty() {
            thread.string_array = Some(shared_strings.clone());
        }
        let string_array = match &mut thread.string_array {
            Some(sa) => sa,
            None => continue,
        };

        let ft = &thread.frame_table;
        let func_t = &thread.func_table;
        let rt = &thread.resource_table;
        let rt_lib = rt.lib.as_deref().unwrap_or(&[]);
        let func_resources = func_t.resource.as_deref().unwrap_or(&[]);
        let frame_addresses = ft.address.as_deref().unwrap_or(&[]);

        let mut resolved_strs = std::collections::HashSet::new();

        for fi in 0..ft.length {
            if ft
                .inline_depth
                .as_ref()
                .and_then(|depths| depths.get(fi))
                .is_some_and(|depth| *depth > 0)
            {
                continue;
            }

            let addr_val = frame_addresses.get(fi);
            let addr = match addr_val {
                Some(serde_json::Value::Number(n)) => match n.as_u64() {
                    Some(a) if a != u64::MAX => a,
                    _ => continue,
                },
                _ => continue,
            };

            let func_idx = match ft.func.get(fi) {
                Some(&i) => i,
                None => continue,
            };

            let res_val = match func_resources.get(func_idx) {
                Some(serde_json::Value::Number(n)) => match n.as_i64() {
                    Some(r) if r >= 0 => r as usize,
                    _ => continue,
                },
                _ => continue,
            };

            let lib_idx = match rt_lib.get(res_val) {
                Some(Some(i)) => *i,
                _ => continue,
            };

            let lib = match profile.libs.get(lib_idx) {
                Some(lib) => lib,
                None => continue,
            };

            let symbol = match symbols.lookup(&lib.breakpad_id, &lib.debug_name, addr) {
                Some(symbol) => symbol,
                None => continue,
            };

            let str_idx = match func_t.name.get(func_idx) {
                Some(&i) => i,
                None => continue,
            };
            if resolved_strs.insert(str_idx)
                && let Some(slot) = string_array.get_mut(str_idx)
            {
                *slot = symbol.symbol_name.clone();
            }
        }
    }
}
