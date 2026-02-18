use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use super::resolved::ResolvedProfile;
use super::types::RawProfile;

pub fn load_raw_profile(path: &Path) -> Result<RawProfile> {
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
    if let Some(syms_path) = find_syms_sidecar(path) {
        apply_symbols(&mut profile, &syms_path)
            .with_context(|| format!("Failed to apply symbols from {}", syms_path.display()))?;
    }

    Ok(profile)
}

pub fn load_profile(path: &Path) -> Result<ResolvedProfile> {
    let raw = load_raw_profile(path)?;
    let resolved = ResolvedProfile::from_raw(&raw);
    Ok(resolved)
}

/// Look for a `.syms.json` sidecar next to the profile file.
/// Samply writes e.g. `profile.json.gz` → `profile.json.syms.json`
fn find_syms_sidecar(profile_path: &Path) -> Option<std::path::PathBuf> {
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

/// Merge symbol names from a samply `.syms.json` sidecar into the profile's string tables.
fn apply_symbols(profile: &mut RawProfile, syms_path: &Path) -> Result<()> {
    let syms: serde_json::Value = serde_json::from_reader(BufReader::new(
        File::open(syms_path).with_context(|| format!("Failed to open {}", syms_path.display()))?,
    ))?;

    let sym_strings: Vec<&str> = syms["string_table"]
        .as_array()
        .context("syms string_table is not an array")?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    // Build: normalized_debug_id -> {frame_address -> symbol_name}
    let mut lib_sym_names: std::collections::HashMap<String, std::collections::HashMap<u64, &str>> =
        std::collections::HashMap::new();

    if let Some(data) = syms["data"].as_array() {
        for entry in data {
            let debug_id = entry["debug_id"].as_str().unwrap_or("");
            let key = normalize_debug_id(debug_id);
            let symbol_table = entry["symbol_table"]
                .as_array()
                .map(|v| v.as_slice())
                .unwrap_or(&[]);

            let mut addr_to_name: std::collections::HashMap<u64, &str> =
                std::collections::HashMap::new();

            if let Some(known) = entry["known_addresses"].as_array() {
                for pair in known {
                    let arr = pair.as_array().filter(|a| a.len() == 2);
                    if let Some(arr) = arr {
                        let addr = arr[0].as_u64();
                        let sym_idx = arr[1].as_u64().map(|i| i as usize);
                        if let (Some(addr), Some(sym_idx)) = (addr, sym_idx)
                            && let Some(sym) = symbol_table.get(sym_idx)
                            && let Some(name_idx) = sym["symbol"].as_u64().map(|i| i as usize)
                            && let Some(name) = sym_strings.get(name_idx)
                        {
                            addr_to_name.insert(addr, name);
                        }
                    }
                }
            }

            lib_sym_names.insert(key, addr_to_name);
        }
    }

    // Build lib index -> normalized breakpad ID
    let lib_keys: Vec<String> = profile
        .libs
        .iter()
        .map(|lib| normalize_debug_id(&lib.breakpad_id))
        .collect();

    // Apply to each thread's string array
    for thread in &mut profile.threads {
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

            let key = match lib_keys.get(lib_idx) {
                Some(k) => k,
                None => continue,
            };

            let name_map = match lib_sym_names.get(key) {
                Some(m) => m,
                None => continue,
            };

            if let Some(&name) = name_map.get(&addr) {
                let str_idx = match func_t.name.get(func_idx) {
                    Some(&i) => i,
                    None => continue,
                };
                if resolved_strs.insert(str_idx)
                    && let Some(slot) = string_array.get_mut(str_idx)
                {
                    *slot = name.to_string();
                }
            }
        }
    }

    Ok(())
}

fn normalize_debug_id(s: &str) -> String {
    s.replace('-', "")
        .to_lowercase()
        .trim_end_matches('0')
        .to_string()
}
