use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use super::symbols::{SymbolAddressInfo, SymbolSidecar};
use super::types::{RawMarkerSchema, RawProfile, RawThread};

#[derive(Debug, Clone)]
pub struct ResolvedProfile {
    pub threads: Vec<ResolvedThread>,
    pub libraries: Vec<ResolvedLibrary>,
    pub product: String,
    pub interval_ms: f64,
    pub categories: Vec<String>,
    /// Earliest observed sample timestamp in the profile's original clock domain.
    pub observed_start_time_ms: f64,
    pub duration_ms: f64,
    pub total_sample_count: usize,
}

#[derive(Debug, Clone)]
pub struct ResolvedLibrary {
    pub name: String,
    pub path: String,
    pub debug_name: String,
    pub debug_path: String,
    pub breakpad_id: String,
    pub code_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedThread {
    pub name: String,
    pub pid: String,
    pub tid: String,
    pub is_main: bool,
    pub sample_weight_type: SampleWeightType,
    pub samples: Vec<ResolvedSample>,
    pub markers: Vec<ResolvedMarker>,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleWeightType {
    Samples,
    TracingMilliseconds,
    Bytes,
}

#[derive(Debug, Clone)]
pub struct ResolvedSample {
    pub timestamp_ms: f64,
    pub weight: i32,
    pub cpu_delta_us: Option<i64>,
    /// Root-first resolved stack shared by every sample with the same stack-table index.
    pub stack: ResolvedStack,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedStack(Arc<[Arc<ResolvedFrame>]>);

impl ResolvedStack {
    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        Arc::ptr_eq(&left.0, &right.0)
    }
}

impl Deref for ResolvedStack {
    type Target = [Arc<ResolvedFrame>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<ResolvedFrame>> for ResolvedStack {
    fn from(frames: Vec<ResolvedFrame>) -> Self {
        Self(frames.into_iter().map(Arc::new).collect())
    }
}

impl From<Vec<Arc<ResolvedFrame>>> for ResolvedStack {
    fn from(frames: Vec<Arc<ResolvedFrame>>) -> Self {
        Self(frames.into())
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedFrame {
    pub function_name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub category: String,
    pub library: Option<String>,
    pub instruction: Option<ResolvedInstruction>,
}

#[derive(Debug, Clone)]
pub struct ResolvedInstruction {
    /// Library-relative sampled instruction address.
    pub address: u64,
    pub inline_depth: u16,
    pub library_index: Option<usize>,
    pub library_debug_id: Option<String>,
    pub symbol: Option<Arc<SymbolAddressInfo>>,
}

#[derive(Debug, Clone)]
pub struct ResolvedMarker {
    pub name: String,
    pub start_time: Option<f64>,
    pub end_time: Option<f64>,
    pub phase: Option<u8>,
    pub category: String,
    pub data: Option<ResolvedMarkerData>,
    pub context_switch: Option<ResolvedContextSwitchMarker>,
}

#[derive(Debug, Clone)]
pub struct ResolvedMarkerData {
    raw: Arc<str>,
    context: Arc<MarkerDataContext>,
}

#[derive(Debug, Clone)]
pub struct ResolvedContextSwitchMarker {
    pub cpu: Arc<str>,
    pub switch_out_reason: Arc<str>,
}

#[derive(Debug)]
struct MarkerDataContext {
    schema: Arc<[RawMarkerSchema]>,
    strings: Arc<[String]>,
}

impl ResolvedProfile {
    pub fn from_raw(raw: RawProfile) -> Result<Self, serde_json::Error> {
        Self::from_raw_with_symbols(raw, None)
    }

    pub(crate) fn from_raw_with_symbols(
        raw: RawProfile,
        symbols: Option<&SymbolSidecar>,
    ) -> Result<Self, serde_json::Error> {
        let categories: Vec<String> = raw.meta.categories.iter().map(|c| c.name.clone()).collect();

        // The string table can be in shared.stringArray (newer format) or per-thread
        let shared_strings: &[String] = raw
            .shared
            .as_ref()
            .map(|s| s.string_array.as_slice())
            .unwrap_or_default();
        let shared_marker_strings: Arc<[String]> = shared_strings.to_vec().into();
        let marker_schema: Arc<[RawMarkerSchema]> = raw.meta.marker_schema.clone().into();
        let thread_resolution = ThreadResolutionContext {
            categories: &categories,
            libs: &raw.libs,
            marker_schema,
            apply_symbol_names: !raw.meta.symbolicated,
            symbols,
        };

        let mut threads = Vec::new();
        let mut total_sample_count = 0;
        let mut global_min_time = f64::MAX;
        let mut global_max_time = f64::MIN;

        for raw_thread_json in raw.threads {
            let raw_thread: RawThread = serde_json::from_str(&raw_thread_json.0)?;

            // Per-thread string table takes priority, fall back to shared
            let strings = if let Some(ref ts) = raw_thread.string_array {
                ts
            } else {
                shared_strings
            };
            let marker_strings = raw_thread
                .markers
                .as_ref()
                .filter(|markers| markers.length > 0)
                .map(|_| {
                    raw_thread.string_array.as_ref().map_or_else(
                        || Arc::clone(&shared_marker_strings),
                        |strings| Arc::from(strings.clone()),
                    )
                });

            let resolved = resolve_thread(&raw_thread, strings, marker_strings, &thread_resolution);
            total_sample_count += resolved.samples.len();

            for sample in &resolved.samples {
                if sample.timestamp_ms.is_finite() {
                    global_min_time = global_min_time.min(sample.timestamp_ms);
                    global_max_time = global_max_time.max(sample.timestamp_ms);
                }
            }

            threads.push(resolved);
        }

        let observed_start_time_ms = if global_min_time.is_finite() {
            global_min_time
        } else {
            0.0
        };
        let duration_ms = if global_max_time.is_finite() && global_max_time > global_min_time {
            global_max_time - global_min_time
        } else {
            0.0
        };

        Ok(ResolvedProfile {
            threads,
            libraries: raw
                .libs
                .iter()
                .map(|library| ResolvedLibrary {
                    name: library.name.clone(),
                    path: library.path.clone(),
                    debug_name: library.debug_name.clone(),
                    debug_path: library.debug_path.clone(),
                    breakpad_id: library.breakpad_id.clone(),
                    code_id: library.code_id.clone(),
                })
                .collect(),
            product: raw.meta.product.clone().unwrap_or_default(),
            interval_ms: raw.meta.interval,
            categories,
            observed_start_time_ms,
            duration_ms,
            total_sample_count,
        })
    }
}

impl ResolvedMarker {
    pub fn data_value(&self) -> Option<serde_json::Value> {
        let data = self.data.as_ref()?;
        let mut data_value = serde_json::from_str(&data.raw).ok()?;
        resolve_marker_strings(&mut data_value, &data.context.schema, &data.context.strings);
        Some(data_value)
    }
}

struct ThreadResolutionContext<'a> {
    categories: &'a [String],
    libs: &'a [super::types::RawLib],
    marker_schema: Arc<[RawMarkerSchema]>,
    apply_symbol_names: bool,
    symbols: Option<&'a SymbolSidecar>,
}

fn resolve_thread(
    thread: &RawThread,
    strings: &[String],
    marker_strings: Option<Arc<[String]>>,
    context: &ThreadResolutionContext<'_>,
) -> ResolvedThread {
    let categories = context.categories;
    let libs = context.libs;
    let marker_schema = context.marker_schema.as_ref();
    let apply_symbol_names = context.apply_symbol_names;
    let symbols = context.symbols;

    let str_at = |idx: usize| -> String {
        strings
            .get(idx)
            .cloned()
            .unwrap_or_else(|| format!("<string:{idx}>"))
    };

    let category_name = |idx: usize| -> String {
        categories
            .get(idx)
            .cloned()
            .unwrap_or_else(|| "Other".to_string())
    };

    // Resolve func table: func_index -> (name, file, line, resource_index)
    let func_count = thread.func_table.length;
    let mut func_names: Vec<String> = Vec::with_capacity(func_count);
    let mut func_files: Vec<Option<String>> = Vec::with_capacity(func_count);
    let mut func_lines: Vec<Option<u32>> = Vec::with_capacity(func_count);
    let mut func_resource: Vec<Option<usize>> = Vec::with_capacity(func_count);

    for i in 0..func_count {
        func_names.push(str_at(thread.func_table.name[i]));

        let file = thread
            .func_table
            .file_name
            .as_ref()
            .and_then(|f| f.get(i).copied().flatten())
            .map(&str_at);
        func_files.push(file);

        let line = thread
            .func_table
            .line_number
            .as_ref()
            .and_then(|l| l.get(i).copied().flatten());
        func_lines.push(line);

        let res = thread
            .func_table
            .resource
            .as_ref()
            .and_then(|resources| resources.get(i).copied().flatten())
            .and_then(|resource| usize::try_from(resource).ok());
        func_resource.push(res);
    }

    // Resolve resource -> lib name
    let resource_lib_name = |res_idx: usize| -> Option<String> {
        let lib_indices = thread.resource_table.lib.as_ref()?;
        let lib_idx = lib_indices.get(res_idx).copied().flatten()?;
        libs.get(lib_idx).map(|l| l.name.clone())
    };

    // Build frame resolution: frame_index -> ResolvedFrame data
    let frame_count = thread.frame_table.length;
    let mut frame_func_idx: Vec<usize> = Vec::with_capacity(frame_count);
    let mut frame_category: Vec<String> = Vec::with_capacity(frame_count);
    let mut frame_line: Vec<Option<u32>> = Vec::with_capacity(frame_count);
    let mut frame_address: Vec<Option<u64>> = Vec::with_capacity(frame_count);
    let mut frame_inline_depth: Vec<u16> = Vec::with_capacity(frame_count);

    for i in 0..frame_count {
        frame_func_idx.push(thread.frame_table.func[i]);

        let cat_idx = thread
            .frame_table
            .category
            .as_ref()
            .and_then(|c| c.get(i).copied())
            .unwrap_or(0);
        frame_category.push(category_name(cat_idx));

        let line = thread
            .frame_table
            .line
            .as_ref()
            .and_then(|l| l.get(i).copied().flatten());
        frame_line.push(line);

        frame_address.push(
            thread
                .frame_table
                .address
                .as_ref()
                .and_then(|addresses| addresses.get(i))
                .and_then(|address| address.and_then(|address| u64::try_from(address).ok())),
        );
        frame_inline_depth.push(
            thread
                .frame_table
                .inline_depth
                .as_ref()
                .and_then(|depths| depths.get(i).copied())
                .unwrap_or(0),
        );
    }

    // Resolve each frame once. Stacks contain cheap Arc pointers to these
    // templates rather than cloning frame strings for every unique stack.
    let resolved_frames: Vec<Arc<ResolvedFrame>> = (0..frame_count)
        .map(|frame_idx| {
            let fi = frame_func_idx[frame_idx];
            let library_index =
                func_resource
                    .get(fi)
                    .copied()
                    .flatten()
                    .and_then(|resource_index| {
                        thread
                            .resource_table
                            .lib
                            .as_ref()
                            .and_then(|indices| indices.get(resource_index).copied().flatten())
                    });
            let library = library_index.and_then(|index| libs.get(index));
            let instruction = frame_address[frame_idx].map(|address| {
                let symbol = library.and_then(|library| {
                    symbols.and_then(|symbols| {
                        symbols
                            .lookup(&library.breakpad_id, &library.debug_name, address)
                            .cloned()
                    })
                });
                ResolvedInstruction {
                    address,
                    inline_depth: frame_inline_depth[frame_idx],
                    library_index,
                    library_debug_id: library.map(|library| library.breakpad_id.clone()),
                    symbol,
                }
            });
            let function_name = instruction
                .as_ref()
                .filter(|instruction| apply_symbol_names && instruction.inline_depth == 0)
                .and_then(|instruction| instruction.symbol.as_ref())
                .map_or_else(
                    || func_names.get(fi).cloned().unwrap_or_default(),
                    |symbol| symbol.symbol_name.clone(),
                );
            Arc::new(ResolvedFrame {
                function_name,
                file: func_files.get(fi).cloned().flatten(),
                line: frame_line[frame_idx].or_else(|| func_lines.get(fi).copied().flatten()),
                category: frame_category[frame_idx].clone(),
                library: func_resource
                    .get(fi)
                    .copied()
                    .flatten()
                    .and_then(&resource_lib_name),
                instruction,
            })
        })
        .collect();

    // Resolve a stack index into frame pointers (leaf first, then reversed to root-first).
    let resolve_stack = |stack_idx: usize| -> Vec<Arc<ResolvedFrame>> {
        let mut frames = Vec::new();
        let mut current = Some(stack_idx);

        while let Some(idx) = current {
            if idx >= thread.stack_table.length {
                break;
            }
            let frame_idx = thread.stack_table.frame[idx];

            if frame_idx < frame_count {
                frames.push(Arc::clone(&resolved_frames[frame_idx]));
            }

            current = thread.stack_table.prefix[idx];
        }

        frames.reverse(); // root first
        frames
    };

    // Resolve samples. Firefox's processed-profile format interns stacks in the
    // stack table, so preserve that sharing instead of cloning every frame and
    // its strings into every sample.
    let sample_count = thread.samples.length;
    let mut samples = Vec::with_capacity(sample_count);
    let mut resolved_stacks: Vec<Option<ResolvedStack>> = vec![None; thread.stack_table.length];
    let empty_stack = ResolvedStack::default();

    // Reconstruct absolute timestamps from time deltas
    let timestamps = if let Some(ref time) = thread.samples.time {
        time.clone()
    } else if let Some(ref deltas) = thread.samples.time_deltas {
        let mut times = Vec::with_capacity(deltas.len());
        let mut t = 0.0_f64;
        for &d in deltas {
            t += d;
            times.push(t);
        }
        times
    } else {
        vec![0.0; sample_count]
    };

    for i in 0..sample_count {
        let stack = match thread.samples.stack[i] {
            Some(stack_index) if stack_index < resolved_stacks.len() => {
                if let Some(stack) = &resolved_stacks[stack_index] {
                    stack.clone()
                } else {
                    let stack: ResolvedStack = resolve_stack(stack_index).into();
                    resolved_stacks[stack_index] = Some(stack.clone());
                    stack
                }
            }
            _ => empty_stack.clone(),
        };

        let weight = thread
            .samples
            .weight
            .as_ref()
            .and_then(|w| w.get(i).copied())
            .unwrap_or(1);

        let cpu_delta_us = thread
            .samples
            .thread_cpu_delta
            .as_ref()
            .and_then(|deltas| deltas.get(i).copied().flatten());

        samples.push(ResolvedSample {
            timestamp_ms: timestamps.get(i).copied().unwrap_or(0.0),
            weight,
            cpu_delta_us,
            stack,
        });
    }

    // Resolve markers
    let mut markers = Vec::new();
    let mut marker_string_intern = HashMap::new();
    let marker_data_context = marker_strings.map(|strings| {
        Arc::new(MarkerDataContext {
            schema: Arc::clone(&context.marker_schema),
            strings,
        })
    });
    if let Some(ref marker_table) = thread.markers {
        let marker_count = marker_table.length;
        for i in 0..marker_count {
            let name = marker_table
                .name
                .as_ref()
                .and_then(|n| n.get(i).copied())
                .map(&str_at)
                .unwrap_or_default();

            let start_time = marker_table
                .start_time
                .as_ref()
                .and_then(|t| t.get(i).copied().flatten());

            let end_time = marker_table
                .end_time
                .as_ref()
                .and_then(|t| t.get(i).copied().flatten());

            let phase = marker_table
                .phase
                .as_ref()
                .and_then(|phases| phases.get(i).copied());

            let cat = marker_table
                .category
                .as_ref()
                .and_then(|c| c.get(i).copied())
                .map(&category_name)
                .unwrap_or_else(|| "Other".to_string());

            let data = marker_table
                .data
                .as_ref()
                .and_then(|data| data.get(i).cloned().flatten())
                .map(|data| data.0);
            let context_switch = data.as_deref().and_then(|data| {
                resolve_context_switch_marker(
                    data,
                    marker_schema,
                    strings,
                    &mut marker_string_intern,
                )
            });
            let data = data
                .zip(marker_data_context.as_ref())
                .map(|(raw, context)| ResolvedMarkerData {
                    raw,
                    context: Arc::clone(context),
                });

            markers.push(ResolvedMarker {
                name,
                start_time,
                end_time,
                phase,
                category: cat,
                data,
                context_switch,
            });
        }
    }

    // Thread duration
    let (first_time_ms, last_time_ms) = samples.iter().fold(
        (f64::INFINITY, f64::NEG_INFINITY),
        |(first, last), sample| {
            if sample.timestamp_ms.is_finite() {
                (
                    first.min(sample.timestamp_ms),
                    last.max(sample.timestamp_ms),
                )
            } else {
                (first, last)
            }
        },
    );
    let duration_ms = if first_time_ms.is_finite() && last_time_ms > first_time_ms {
        last_time_ms - first_time_ms
    } else {
        0.0
    };

    let pid = match &thread.pid {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        v => v.to_string(),
    };
    let tid = match &thread.tid {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        v => v.to_string(),
    };

    ResolvedThread {
        name: thread.name.clone(),
        pid,
        tid,
        is_main: thread.is_main_thread,
        sample_weight_type: match thread.samples.weight_type.as_deref() {
            Some("tracing-ms") => SampleWeightType::TracingMilliseconds,
            Some("bytes") => SampleWeightType::Bytes,
            _ => SampleWeightType::Samples,
        },
        samples,
        markers,
        duration_ms,
    }
}

fn resolve_context_switch_marker(
    raw_data: &str,
    marker_schema: &[RawMarkerSchema],
    strings: &[String],
    intern: &mut HashMap<String, Arc<str>>,
) -> Option<ResolvedContextSwitchMarker> {
    let mut data = serde_json::from_str(raw_data).ok()?;
    resolve_marker_strings(&mut data, marker_schema, strings);
    let data = data.as_object()?;
    if data.get("type")?.as_str()? != "OnCpu" {
        return None;
    }

    let cpu = marker_string_field(data, "cpu")?;
    let switch_out_reason =
        marker_string_field(data, "outwhy").unwrap_or_else(|| "unknown".to_string());

    Some(ResolvedContextSwitchMarker {
        cpu: intern_marker_string(intern, cpu),
        switch_out_reason: intern_marker_string(intern, switch_out_reason),
    })
}

fn intern_marker_string(intern: &mut HashMap<String, Arc<str>>, value: String) -> Arc<str> {
    if let Some(value) = intern.get(&value) {
        return Arc::clone(value);
    }

    let interned: Arc<str> = Arc::from(value.as_str());
    intern.insert(value, Arc::clone(&interned));
    interned
}

fn marker_string_field(
    data: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    match data.get(key)? {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn resolve_marker_strings(
    data: &mut serde_json::Value,
    marker_schema: &[RawMarkerSchema],
    strings: &[String],
) {
    let serde_json::Value::Object(data) = data else {
        return;
    };
    let Some(marker_type) = data.get("type").and_then(serde_json::Value::as_str) else {
        return;
    };
    let Some(schema) = marker_schema
        .iter()
        .find(|schema| schema.name == marker_type)
    else {
        return;
    };

    for field in &schema.data {
        if field.format.as_deref() != Some("unique-string") {
            continue;
        }
        let Some(key) = field.key.as_deref() else {
            continue;
        };
        let Some(index) = data.get(key).and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(value) = strings.get(index as usize) else {
            continue;
        };
        data.insert(key.to_string(), serde_json::Value::String(value.clone()));
    }
}
