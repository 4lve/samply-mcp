mod helpers {
    use std::path::PathBuf;

    pub fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profile.json.gz")
    }
}

#[test]
fn test_load_profile() {
    let path = helpers::fixture_path();
    assert!(
        path.exists(),
        "fixture profile not found at {}",
        path.display()
    );

    // Decompress and parse as JSON to verify it's valid
    let file = std::fs::File::open(&path).unwrap();
    let reader = std::io::BufReader::new(file);
    let decoder = flate2::read::GzDecoder::new(reader);
    let profile: serde_json::Value = serde_json::from_reader(decoder).unwrap();

    // Basic structure checks
    assert!(profile.get("meta").is_some());
    assert!(profile.get("threads").is_some());
    assert!(profile.get("libs").is_some());

    let threads = profile["threads"].as_array().unwrap();
    assert!(!threads.is_empty());

    let thread = &threads[0];
    assert_eq!(thread["name"].as_str().unwrap(), "gen_profile");

    let sample_count = thread["samples"]["length"].as_u64().unwrap();
    assert!(
        sample_count > 100,
        "expected many samples, got {sample_count}"
    );

    // Verify symbolication worked
    let string_array = thread["stringArray"].as_array().unwrap();
    let func_names: Vec<&str> = string_array.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        func_names.iter().any(|n| n.contains("hot_function")),
        "expected hot_function in string array, got: {:?}",
        &func_names[..20.min(func_names.len())]
    );
    assert!(func_names.iter().any(|n| n.contains("cold_function")));
    assert!(func_names.iter().any(|n| n.contains("medium_function")));
    assert!(func_names.iter().any(|n| n.contains("caller_a")));
    assert!(func_names.iter().any(|n| n.contains("caller_b")));
}

#[test]
fn test_profile_has_expected_structure() {
    let file = std::fs::File::open(helpers::fixture_path()).unwrap();
    let reader = std::io::BufReader::new(file);
    let decoder = flate2::read::GzDecoder::new(reader);
    let profile: serde_json::Value = serde_json::from_reader(decoder).unwrap();

    let thread = &profile["threads"][0];

    // Verify all expected tables exist
    assert!(thread.get("frameTable").is_some());
    assert!(thread.get("funcTable").is_some());
    assert!(thread.get("stackTable").is_some());
    assert!(thread.get("samples").is_some());
    assert!(thread.get("resourceTable").is_some());

    // Stack table has prefix-based tree structure
    let stack_table = &thread["stackTable"];
    let stack_len = stack_table["length"].as_u64().unwrap();
    assert!(stack_len > 0);
    assert_eq!(
        stack_table["prefix"].as_array().unwrap().len(),
        stack_len as usize
    );
    assert_eq!(
        stack_table["frame"].as_array().unwrap().len(),
        stack_len as usize
    );

    // Meta has expected fields
    let meta = &profile["meta"];
    assert!(meta["interval"].as_f64().unwrap() > 0.0);
    assert!(meta.get("categories").is_some());
}
