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

    let profile: RawProfile = if is_gzip {
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
    Ok((profile, symbols))
}

pub fn load_profile(path: &Path) -> Result<ResolvedProfile> {
    let (raw, symbols) = load_raw_profile_and_symbols(path)?;
    let resolved = ResolvedProfile::from_raw_with_symbols(raw, symbols.as_ref())
        .context("Failed to resolve profile tables")?;
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
