use std::borrow::Cow;
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};

use addr2line::Loader;
use anyhow::{Context, Result, anyhow, bail};
use memmap2::Mmap;
use object::{BinaryFormat, FileFlags, Object, ObjectSegment};

use super::resolved::ResolvedLibrary;

/// Per-instruction source information read directly from a recorded library's DWARF data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfAddressInfo {
    pub symbol_name: Option<String>,
    pub symbol_start_address: Option<u64>,
    /// Debug frames ordered from the outer function to the deepest inline frame.
    pub frames: Vec<DwarfSourceFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwarfSourceFrame {
    pub function_name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

/// An owning DWARF resolver for one binary or debug file.
pub struct DwarfLibraryResolver {
    loader: Loader,
    path: PathBuf,
    identity_verified: bool,
    relative_address_base: u64,
}

impl DwarfLibraryResolver {
    pub fn load(library: &ResolvedLibrary) -> Result<Self> {
        let mut candidates = Vec::new();
        let mut seen = HashSet::new();
        for candidate in [&library.debug_path, &library.path] {
            if candidate.is_empty() {
                continue;
            }
            let path = PathBuf::from(candidate);
            if seen.insert(path.clone()) {
                candidates.push(path);
            }
        }

        if candidates.is_empty() {
            bail!(
                "profile has no binary or debug-file path for library '{}'",
                library.name
            );
        }

        let mut failures = Vec::new();
        for path in candidates {
            match Self::load_candidate(&path, library) {
                Ok(resolver) => return Ok(resolver),
                Err(error) => failures.push(format!("{}: {error:#}", path.display())),
            }
        }

        bail!(
            "could not load matching DWARF for library '{}': {}",
            library.name,
            failures.join("; ")
        )
    }

    fn load_candidate(path: &Path, library: &ResolvedLibrary) -> Result<Self> {
        let (identity_verified, relative_address_base) = inspect_object(path, library)?;
        let loader = Loader::new(path)
            .map_err(|error| anyhow!(error.to_string()))
            .with_context(|| format!("failed to load DWARF from {}", path.display()))?;
        Ok(Self {
            loader,
            path: path.to_path_buf(),
            identity_verified,
            relative_address_base,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity_verified(&self) -> bool {
        self.identity_verified
    }

    pub fn resolve(&self, relative_address: u64) -> Result<Option<DwarfAddressInfo>> {
        let probe = relative_address
            .checked_add(self.relative_address_base)
            .context("instruction address overflowed the object address space")?;

        let symbol = self.loader.find_symbol_info(probe);
        let symbol_name = symbol.as_ref().map(|symbol| demangle_symbol(symbol.name()));
        let symbol_start_address = symbol
            .as_ref()
            .and_then(|symbol| symbol.address().checked_sub(self.relative_address_base));

        let mut frames = Vec::new();
        let mut frame_iter = self
            .loader
            .find_frames(probe)
            .map_err(|error| anyhow!(error.to_string()))
            .with_context(|| format!("failed to resolve address {relative_address:#x}"))?;
        while let Some(frame) = frame_iter
            .next()
            .map_err(|error| anyhow!(error.to_string()))
            .with_context(|| format!("failed to read frames for address {relative_address:#x}"))?
        {
            let function_name = frame
                .function
                .as_ref()
                .and_then(|function| function.demangle().ok())
                .map(Cow::into_owned);
            let (file, line) = frame
                .location
                .as_ref()
                .map(|location| (location.file.map(ToOwned::to_owned), location.line))
                .unwrap_or_default();
            frames.push((function_name, file, line));
        }

        // addr2line returns the deepest inline frame first. MCP stack-like output
        // is consistently outer-to-inner.
        frames.reverse();
        let frames: Vec<DwarfSourceFrame> = frames
            .into_iter()
            .enumerate()
            .map(|(index, (function_name, file, line))| DwarfSourceFrame {
                function_name: function_name.unwrap_or_else(|| {
                    if index == 0 {
                        symbol_name
                            .clone()
                            .unwrap_or_else(|| "<unknown function>".to_string())
                    } else {
                        "<unknown inline function>".to_string()
                    }
                }),
                file,
                line,
            })
            .collect();

        if symbol_name.is_none() && frames.is_empty() {
            return Ok(None);
        }

        Ok(Some(DwarfAddressInfo {
            symbol_name,
            symbol_start_address,
            frames,
        }))
    }
}

fn demangle_symbol(name: &str) -> String {
    addr2line::demangle_auto(Cow::Borrowed(name), None).into_owned()
}

/// Reject an overwritten or otherwise stale ELF/Mach-O image when the profile
/// contains a code id that can be compared to the file's native identity.
fn inspect_object(path: &Path, library: &ResolvedLibrary) -> Result<(bool, u64)> {
    let expected = library
        .code_id
        .as_deref()
        .map(normalize_hex)
        .filter(|value| !value.is_empty());
    let file = File::open(path)
        .with_context(|| format!("failed to open recorded library {}", path.display()))?;
    // SAFETY: The mapping is read-only and remains alive for the entire object parse.
    let mapping = unsafe { Mmap::map(&file) }
        .with_context(|| format!("failed to map recorded library {}", path.display()))?;
    let object = object::File::parse(&*mapping)
        .with_context(|| format!("failed to parse recorded library {}", path.display()))?;
    let relative_address_base = samply_relative_address_base(&object);

    let Some(expected) = expected else {
        return Ok((false, relative_address_base));
    };

    let actual = match object.format() {
        BinaryFormat::Elf => object
            .build_id()
            .context("failed to read ELF build id")?
            .map(hex_bytes),
        BinaryFormat::MachO => object
            .mach_uuid()
            .context("failed to read Mach-O UUID")?
            .map(|uuid| hex_bytes(&uuid)),
        _ => None,
    };

    let Some(actual) = actual else {
        // PE and other formats need a different code-id translation. Loading
        // still works, but the result is explicitly reported as unverified.
        return Ok((false, relative_address_base));
    };
    if actual != expected {
        bail!("recorded code id {expected} does not match file identity {actual}");
    }
    Ok((true, relative_address_base))
}

/// Samply's `LookupAddress::Relative` base is broader than object's generic
/// helper: it is `__TEXT` for Mach-O and the first load segment for ELF.
fn samply_relative_address_base<'data>(object: &impl Object<'data>) -> u64 {
    if let Some(text_segment) = object
        .segments()
        .find(|segment| segment.name() == Ok(Some("__TEXT")))
    {
        return text_segment.address();
    }
    if matches!(object.flags(), FileFlags::Elf { .. })
        && let Some(first_segment) = object.segments().next()
    {
        return first_segment.address();
    }
    object.relative_address_base()
}

fn normalize_hex(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .flat_map(char::to_lowercase)
        .collect()
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use object::ObjectSymbol;

    use super::*;

    #[unsafe(no_mangle)]
    #[inline(never)]
    extern "C" fn samply_mcp_dwarf_line_fixture(value: u64) -> u64 {
        let incremented = std::hint::black_box(value.wrapping_add(7));
        let multiplied = std::hint::black_box(incremented.wrapping_mul(3));
        std::hint::black_box(multiplied.rotate_left(5))
    }

    #[test]
    fn normalizes_native_identifiers() {
        assert_eq!(normalize_hex("CA5D-70E6"), "ca5d70e6");
        assert_eq!(hex_bytes(&[0xca, 0x5d, 0x00]), "ca5d00");
    }

    #[test]
    fn resolves_distinct_source_lines_for_pcs_in_one_symbol() {
        assert_eq!(samply_mcp_dwarf_line_fixture(2), 864);
        let executable = std::env::current_exe().unwrap();
        let (symbol_address, symbol_size) = {
            let file = File::open(&executable).unwrap();
            // SAFETY: The mapping is read-only and is dropped after the object scan.
            let mapping = unsafe { Mmap::map(&file) }.unwrap();
            let object = object::File::parse(&*mapping).unwrap();
            let symbol = object
                .symbols()
                .find(|symbol| symbol.name().ok() == Some("samply_mcp_dwarf_line_fixture"))
                .expect("test fixture symbol should be retained");
            (symbol.address(), symbol.size())
        };
        assert!(symbol_size > 1);

        let resolver = DwarfLibraryResolver::load(&ResolvedLibrary {
            name: "samply-mcp-test".to_string(),
            path: executable.to_string_lossy().into_owned(),
            debug_name: String::new(),
            debug_path: String::new(),
            breakpad_id: String::new(),
            code_id: None,
        })
        .unwrap();
        let mut source_lines = BTreeSet::new();
        for address in symbol_address..symbol_address + symbol_size {
            let Some(info) = resolver.resolve(address).unwrap() else {
                continue;
            };
            for frame in info.frames {
                if frame
                    .file
                    .as_deref()
                    .is_some_and(|file| file.ends_with("src/profile/dwarf.rs"))
                    && let Some(line) = frame.line
                {
                    source_lines.insert(line);
                }
            }
        }

        assert!(
            source_lines.len() >= 2,
            "expected multiple per-PC source lines, got {source_lines:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_a_binary_with_the_wrong_recorded_code_id() {
        let executable = std::env::current_exe().unwrap();
        let error = DwarfLibraryResolver::load(&ResolvedLibrary {
            name: "stale-test-binary".to_string(),
            path: executable.to_string_lossy().into_owned(),
            debug_name: String::new(),
            debug_path: String::new(),
            breakpad_id: String::new(),
            code_id: Some("0000000000000000000000000000000000000000".to_string()),
        })
        .err()
        .expect("a mismatched ELF build id must be rejected");

        assert!(error.to_string().contains("does not match file identity"));
    }
}
