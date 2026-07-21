use std::sync::Arc;

use super::symbols::{SymbolAddressInfo, SymbolSidecar};
use super::types::{RawMarkerSchema, RawProfile, RawThread};

#[derive(Debug, Clone)]
pub struct ResolvedProfile {
    pub threads: Vec<ResolvedThread>,
    pub product: String,
    pub interval_ms: f64,
    pub categories: Vec<String>,
    /// Earliest observed sample timestamp in the profile's original clock domain.
    pub observed_start_time_ms: f64,
    pub duration_ms: f64,
    pub total_sample_count: usize,
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
    pub stack: Vec<ResolvedFrame>,
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
    pub data: Option<serde_json::Value>,
}

impl ResolvedProfile {
    pub fn from_raw(raw: &RawProfile) -> Self {
        Self::from_raw_with_symbols(raw, None)
    }

    pub(crate) fn from_raw_with_symbols(raw: &RawProfile, symbols: Option<&SymbolSidecar>) -> Self {
        let categories: Vec<String> = raw.meta.categories.iter().map(|c| c.name.clone()).collect();

        // The string table can be in shared.stringArray (newer format) or per-thread
        let shared_strings: Vec<String> = raw
            .shared
            .as_ref()
            .map(|s| s.string_array.clone())
            .unwrap_or_default();

        let mut threads = Vec::new();
        let mut total_sample_count = 0;
        let mut global_min_time = f64::MAX;
        let mut global_max_time = f64::MIN;

        for raw_thread in &raw.threads {
            // Per-thread string table takes priority, fall back to shared
            let strings = if let Some(ref ts) = raw_thread.string_array {
                ts
            } else {
                &shared_strings
            };

            let resolved = resolve_thread(
                raw_thread,
                strings,
                &categories,
                &raw.libs,
                &raw.meta.marker_schema,
                symbols,
            );
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

        ResolvedProfile {
            threads,
            product: raw.meta.product.clone().unwrap_or_default(),
            interval_ms: raw.meta.interval,
            categories,
            observed_start_time_ms,
            duration_ms,
            total_sample_count,
        }
    }
}

fn resolve_thread(
    thread: &RawThread,
    strings: &[String],
    categories: &[String],
    libs: &[super::types::RawLib],
    marker_schema: &[RawMarkerSchema],
    symbols: Option<&SymbolSidecar>,
) -> ResolvedThread {
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

        let res = thread.func_table.resource.as_ref().and_then(|r| {
            r.get(i).and_then(|v| match v {
                serde_json::Value::Number(n) => {
                    let n = n.as_i64()?;
                    if n < 0 { None } else { Some(n as usize) }
                }
                _ => None,
            })
        });
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
                .and_then(nonnegative_u64),
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

    // Resolve a stack index into a Vec<ResolvedFrame> (leaf first, then reversed to root-first)
    let resolve_stack = |stack_idx: usize| -> Vec<ResolvedFrame> {
        let mut frames = Vec::new();
        let mut current = Some(stack_idx);

        while let Some(idx) = current {
            if idx >= thread.stack_table.length {
                break;
            }
            let frame_idx = thread.stack_table.frame[idx];

            if frame_idx < frame_count {
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
                let instruction = frame_address[frame_idx].map(|address| ResolvedInstruction {
                    address,
                    inline_depth: frame_inline_depth[frame_idx],
                    library_debug_id: library.map(|library| library.breakpad_id.clone()),
                    symbol: library.and_then(|library| {
                        symbols.and_then(|symbols| {
                            symbols
                                .lookup(&library.breakpad_id, &library.debug_name, address)
                                .cloned()
                        })
                    }),
                });
                let frame = ResolvedFrame {
                    function_name: func_names.get(fi).cloned().unwrap_or_default(),
                    file: func_files.get(fi).cloned().flatten(),
                    line: frame_line[frame_idx].or_else(|| func_lines.get(fi).copied().flatten()),
                    category: frame_category[frame_idx].clone(),
                    library: func_resource
                        .get(fi)
                        .copied()
                        .flatten()
                        .and_then(&resource_lib_name),
                    instruction,
                };
                frames.push(frame);
            }

            current = thread.stack_table.prefix[idx];
        }

        frames.reverse(); // root first
        frames
    };

    // Resolve samples
    let sample_count = thread.samples.length;
    let mut samples = Vec::with_capacity(sample_count);

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
        let stack = thread.samples.stack[i]
            .map(&resolve_stack)
            .unwrap_or_default();

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
            .and_then(|d| d.get(i).and_then(|v| v.as_ref().and_then(|v| v.as_i64())));

        samples.push(ResolvedSample {
            timestamp_ms: timestamps.get(i).copied().unwrap_or(0.0),
            weight,
            cpu_delta_us,
            stack,
        });
    }

    // Resolve markers
    let mut markers = Vec::new();
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

            let mut data = marker_table
                .data
                .as_ref()
                .and_then(|d| d.get(i).cloned().flatten());
            resolve_marker_strings(&mut data, marker_schema, strings);

            markers.push(ResolvedMarker {
                name,
                start_time,
                end_time,
                phase,
                category: cat,
                data,
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

fn nonnegative_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
}

fn resolve_marker_strings(
    data: &mut Option<serde_json::Value>,
    marker_schema: &[RawMarkerSchema],
    strings: &[String],
) {
    let Some(serde_json::Value::Object(data)) = data else {
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
