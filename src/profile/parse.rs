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

    if is_gzip {
        let decoder = GzDecoder::new(reader);
        let profile: RawProfile =
            serde_json::from_reader(decoder).context("Failed to parse gzipped profile JSON")?;
        Ok(profile)
    } else {
        let profile: RawProfile =
            serde_json::from_reader(reader).context("Failed to parse profile JSON")?;
        Ok(profile)
    }
}

pub fn load_profile(path: &Path) -> Result<ResolvedProfile> {
    let raw = load_raw_profile(path)?;
    let resolved = ResolvedProfile::from_raw(&raw);
    Ok(resolved)
}
