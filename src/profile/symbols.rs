use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Symbol and source information for one sampled instruction address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolAddressInfo {
    pub symbol_name: String,
    pub symbol_start_address: u64,
    pub symbol_size: Option<u64>,
    /// Debug frames ordered from the outer function to the deepest inline frame.
    pub frames: Vec<SymbolSourceFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSourceFrame {
    pub function_name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct SymbolSidecar {
    libraries: Vec<LibrarySymbols>,
    library_by_debug_id: HashMap<String, usize>,
    library_by_debug_name: HashMap<String, usize>,
}

#[derive(Debug)]
struct LibrarySymbols {
    addresses: HashMap<u64, Arc<SymbolAddressInfo>>,
}

#[derive(Debug, Deserialize)]
struct RawSymbolSidecar {
    #[serde(default)]
    data: Vec<RawLibrarySymbols>,
    #[serde(default)]
    string_table: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawLibrarySymbols {
    #[serde(default)]
    debug_name: String,
    #[serde(default)]
    debug_id: String,
    #[serde(default)]
    symbol_table: Vec<RawSymbolAddressInfo>,
    #[serde(default)]
    known_addresses: Vec<(u64, usize)>,
}

#[derive(Debug, Deserialize)]
struct RawSymbolAddressInfo {
    rva: u64,
    #[serde(default)]
    size: Option<u64>,
    symbol: usize,
    #[serde(default)]
    frames: Option<Vec<RawSymbolSourceFrame>>,
}

#[derive(Debug, Deserialize)]
struct RawSymbolSourceFrame {
    #[serde(default)]
    function: Option<usize>,
    #[serde(default)]
    file: Option<usize>,
    #[serde(default)]
    line: Option<u32>,
}

impl SymbolSidecar {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let raw: RawSymbolSidecar = serde_json::from_reader(BufReader::new(
            File::open(path).with_context(|| format!("Failed to open {}", path.display()))?,
        ))
        .with_context(|| format!("Failed to parse {}", path.display()))?;
        Ok(Self::from_raw(raw))
    }

    fn from_raw(raw: RawSymbolSidecar) -> Self {
        let mut libraries = Vec::with_capacity(raw.data.len());
        let mut library_by_debug_id = HashMap::new();
        let mut library_by_debug_name = HashMap::new();

        for raw_library in raw.data {
            let mut symbols = Vec::with_capacity(raw_library.symbol_table.len());
            for raw_symbol in raw_library.symbol_table {
                let Some(symbol_name) = raw.string_table.get(raw_symbol.symbol).cloned() else {
                    symbols.push(None);
                    continue;
                };

                // samply stores these deepest-inline first. MCP consumers generally
                // reason about stacks from outermost to innermost, so normalize once.
                let frames = raw_symbol
                    .frames
                    .unwrap_or_default()
                    .into_iter()
                    .rev()
                    .filter_map(|frame| {
                        let function_name = raw.string_table.get(frame.function?).cloned()?;
                        let file = frame
                            .file
                            .and_then(|index| raw.string_table.get(index).cloned());
                        Some(SymbolSourceFrame {
                            function_name,
                            file,
                            line: frame.line,
                        })
                    })
                    .collect();

                symbols.push(Some(Arc::new(SymbolAddressInfo {
                    symbol_name,
                    symbol_start_address: raw_symbol.rva,
                    symbol_size: raw_symbol.size,
                    frames,
                })));
            }

            let mut addresses = HashMap::with_capacity(raw_library.known_addresses.len());
            for (address, symbol_index) in raw_library.known_addresses {
                if let Some(Some(symbol)) = symbols.get(symbol_index) {
                    addresses.insert(address, Arc::clone(symbol));
                }
            }

            let library_index = libraries.len();
            let normalized_debug_id = normalize_debug_id(&raw_library.debug_id);
            if !normalized_debug_id.is_empty() {
                library_by_debug_id.insert(normalized_debug_id, library_index);
            }
            if !raw_library.debug_name.is_empty() {
                library_by_debug_name.insert(raw_library.debug_name, library_index);
            }
            libraries.push(LibrarySymbols { addresses });
        }

        Self {
            libraries,
            library_by_debug_id,
            library_by_debug_name,
        }
    }

    pub(crate) fn lookup(
        &self,
        breakpad_id: &str,
        debug_name: &str,
        address: u64,
    ) -> Option<&Arc<SymbolAddressInfo>> {
        let normalized_debug_id = normalize_debug_id(breakpad_id);
        let library_index = self
            .library_by_debug_id
            .get(&normalized_debug_id)
            .copied()
            .or_else(|| self.library_by_debug_name.get(debug_name).copied())?;
        self.libraries.get(library_index)?.addresses.get(&address)
    }
}

pub(crate) fn normalize_debug_id(value: &str) -> String {
    value
        .replace('-', "")
        .to_lowercase()
        .trim_end_matches('0')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_source_and_reverses_inline_frames() {
        let raw: RawSymbolSidecar = serde_json::from_value(serde_json::json!({
            "string_table": ["outer", "inner", "outer.rs", "inner.rs", "linkage"],
            "data": [{
                "debug_name": "app",
                "debug_id": "AB-CD-00",
                "symbol_table": [{
                    "rva": 256,
                    "size": 32,
                    "symbol": 4,
                    "frames": [
                        {"function": 1, "file": 3, "line": 20},
                        {"function": 0, "file": 2, "line": 10}
                    ]
                }],
                "known_addresses": [[260, 0]]
            }]
        }))
        .unwrap();

        let sidecar = SymbolSidecar::from_raw(raw);
        let info = sidecar.lookup("ABCD0", "app", 260).unwrap();

        assert_eq!(info.symbol_name, "linkage");
        assert_eq!(info.symbol_start_address, 256);
        assert_eq!(info.frames[0].function_name, "outer");
        assert_eq!(info.frames[1].function_name, "inner");
        assert_eq!(info.frames[1].line, Some(20));
    }
}
