pub fn function_id(name: &str) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("fn:{hash:016x}")
}

pub fn compact_function_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    let mut token = String::new();

    for ch in name.chars() {
        if is_path_char(ch) {
            token.push(ch);
        } else {
            push_compact_token(&mut output, &token);
            token.clear();
            output.push(ch);
        }
    }

    push_compact_token(&mut output, &token);

    if output.len() < name.len() {
        output
    } else {
        name.to_string()
    }
}

pub fn is_framework_function(name: &str, library: Option<&str>) -> bool {
    let lower = name.to_lowercase();
    if lower.starts_with("std::")
        || lower.starts_with("core::")
        || lower.starts_with("alloc::")
        || lower.starts_with("criterion::")
        || lower.starts_with("<criterion::")
        || lower.contains("::criterion::")
        || lower == "start"
        || lower == "_libc_start_main"
        || lower.contains("__rust_begin_short_backtrace")
        || lower.starts_with("fun_")
        || looks_like_hex_symbol(&lower)
    {
        return true;
    }

    if let Some(library) = library {
        let lib = library.to_lowercase();
        return lib.contains("libc.so")
            || lib.contains("ld-linux")
            || lib.contains("libpthread")
            || lib.contains("libgcc_s");
    }

    false
}

fn is_path_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '#' | '$')
}

fn push_compact_token(output: &mut String, token: &str) {
    if token.is_empty() {
        return;
    }

    if token.contains("::") {
        let leading_path = token.starts_with("::");
        let last = token
            .split("::")
            .filter(|segment| !segment.is_empty())
            .last()
            .unwrap_or(token);

        if leading_path {
            output.push_str("::");
        }
        output.push_str(last);
    } else {
        output.push_str(token);
    }
}

fn looks_like_hex_symbol(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compacts_rust_paths_inside_generics() {
        let name = "<steel_core::worldgen::generators::vanilla::VanillaGenerator<steel_worldgen::density_functions::overworld::OverworldNoises>>::new";

        assert_eq!(
            compact_function_name(name),
            "<VanillaGenerator<OverworldNoises>>::new"
        );
    }

    #[test]
    fn compacts_trait_impls() {
        let name = "<steel_core::foo::Bar as steel_core::traits::Baz>::apply_carvers";

        assert_eq!(compact_function_name(name), "<Bar as Baz>::apply_carvers");
    }

    #[test]
    fn function_ids_are_stable() {
        assert_eq!(function_id("foo"), function_id("foo"));
        assert_ne!(function_id("foo"), function_id("bar"));
    }
}
