use serde::Deserialize;

/// Top-level profile JSON structure
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawProfile {
    pub meta: RawMeta,
    pub libs: Vec<RawLib>,
    #[serde(default)]
    pub shared: Option<RawShared>,
    pub threads: Vec<RawThread>,
}

/// Shared data (contains the global string table)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawShared {
    #[serde(default)]
    pub string_array: Vec<String>,
}

/// Profile metadata
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMeta {
    pub categories: Vec<RawCategory>,
    pub interval: f64,
    pub product: Option<String>,
    #[serde(default)]
    pub oscpu: Option<String>,
    #[serde(default)]
    pub start_time: f64,
    #[serde(default)]
    pub symbolicated: bool,
    #[serde(default)]
    pub marker_schema: Vec<RawMarkerSchema>,
    #[serde(default)]
    pub sample_units: Option<RawSampleUnits>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawSampleUnits {
    pub time: Option<String>,
    pub event_delay: Option<String>,
    #[serde(rename = "threadCPUDelta")]
    pub thread_cpu_delta: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawCategory {
    pub name: String,
    pub color: String,
    #[serde(default)]
    pub subcategories: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarkerSchema {
    pub name: String,
    #[serde(default)]
    pub display: Vec<serde_json::Value>,
    #[serde(default)]
    pub data: Vec<RawMarkerSchemaField>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarkerSchemaField {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawLib {
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub debug_name: String,
    #[serde(default)]
    pub debug_path: String,
    #[serde(default)]
    pub breakpad_id: String,
    #[serde(default)]
    pub code_id: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
}

/// A single thread's data
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawThread {
    pub name: String,
    #[serde(default)]
    pub is_main_thread: bool,
    pub pid: serde_json::Value,
    pub tid: serde_json::Value,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub register_time: f64,
    pub unregister_time: Option<f64>,
    pub frame_table: RawFrameTable,
    pub func_table: RawFuncTable,
    pub stack_table: RawStackTable,
    pub samples: RawSampleTable,
    #[serde(default)]
    pub markers: Option<RawMarkerTable>,
    pub resource_table: RawResourceTable,
    pub native_symbols: RawNativeSymbolTable,
    #[serde(default)]
    pub string_array: Option<Vec<String>>,
    #[serde(default)]
    pub show_markers_in_timeline: bool,
}

/// Frame table — parallel arrays
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawFrameTable {
    pub length: usize,
    pub func: Vec<usize>,
    #[serde(default)]
    pub category: Option<Vec<usize>>,
    #[serde(default)]
    pub subcategory: Option<Vec<usize>>,
    #[serde(default)]
    pub line: Option<Vec<Option<u32>>>,
    #[serde(default)]
    pub column: Option<Vec<Option<u32>>>,
    #[serde(default)]
    pub address: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub native_symbol: Option<Vec<Option<usize>>>,
    #[serde(default)]
    pub inline_depth: Option<Vec<u16>>,
}

/// Function table — parallel arrays
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawFuncTable {
    pub length: usize,
    pub name: Vec<usize>,
    #[serde(default)]
    pub is_js: Option<Vec<bool>>,
    #[serde(default)]
    pub relevant_for_js: Option<Vec<bool>>,
    #[serde(default)]
    pub resource: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub file_name: Option<Vec<Option<usize>>>,
    #[serde(default)]
    pub line_number: Option<Vec<Option<u32>>>,
    #[serde(default)]
    pub column_number: Option<Vec<Option<u32>>>,
}

/// Stack table — prefix-based tree
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawStackTable {
    pub length: usize,
    pub prefix: Vec<Option<usize>>,
    pub frame: Vec<usize>,
}

/// Sample table
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawSampleTable {
    pub length: usize,
    pub stack: Vec<Option<usize>>,
    #[serde(default)]
    pub time_deltas: Option<Vec<f64>>,
    #[serde(default)]
    pub time: Option<Vec<f64>>,
    #[serde(default)]
    pub weight: Option<Vec<i32>>,
    #[serde(default)]
    pub weight_type: Option<String>,
    #[serde(rename = "threadCPUDelta")]
    #[serde(default)]
    pub thread_cpu_delta: Option<Vec<Option<serde_json::Value>>>,
}

/// Resource table
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawResourceTable {
    pub length: usize,
    #[serde(default)]
    pub lib: Option<Vec<Option<usize>>>,
    #[serde(default)]
    pub name: Option<Vec<usize>>,
    #[serde(default)]
    pub r#type: Option<Vec<usize>>,
}

/// Marker table
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawMarkerTable {
    pub length: usize,
    #[serde(default)]
    pub name: Option<Vec<usize>>,
    #[serde(default)]
    pub start_time: Option<Vec<Option<f64>>>,
    #[serde(default)]
    pub end_time: Option<Vec<Option<f64>>>,
    #[serde(default)]
    pub phase: Option<Vec<u8>>,
    #[serde(default)]
    pub category: Option<Vec<usize>>,
    #[serde(default)]
    pub data: Option<Vec<Option<serde_json::Value>>>,
}

/// Native symbols table
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawNativeSymbolTable {
    pub length: usize,
    #[serde(default)]
    pub address: Option<Vec<u64>>,
    #[serde(default)]
    pub function_size: Option<Vec<Option<u64>>>,
    #[serde(default)]
    pub lib_index: Option<Vec<usize>>,
    #[serde(default)]
    pub name: Option<Vec<usize>>,
}
