use super::types::{RawProfile, RawThread};

#[derive(Debug, Clone)]
pub struct ResolvedProfile {
    pub threads: Vec<ResolvedThread>,
    pub product: String,
    pub interval_ms: f64,
    pub categories: Vec<String>,
    pub duration_ms: f64,
    pub total_sample_count: usize,
}

#[derive(Debug, Clone)]
pub struct ResolvedThread {
    pub name: String,
    pub pid: String,
    pub tid: String,
    pub is_main: bool,
    pub samples: Vec<ResolvedSample>,
    pub markers: Vec<ResolvedMarker>,
    pub duration_ms: f64,
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
}

#[derive(Debug, Clone)]
pub struct ResolvedMarker {
    pub name: String,
    pub start_time: Option<f64>,
    pub end_time: Option<f64>,
    pub category: String,
    pub data: Option<serde_json::Value>,
}

impl ResolvedProfile {
    pub fn from_raw(raw: &RawProfile) -> Self {
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

            let resolved = resolve_thread(raw_thread, strings, &categories, &raw.libs);
            total_sample_count += resolved.samples.len();

            if let (Some(first), Some(last)) = (resolved.samples.first(), resolved.samples.last()) {
                global_min_time = global_min_time.min(first.timestamp_ms);
                global_max_time = global_max_time.max(last.timestamp_ms);
            }

            threads.push(resolved);
        }

        let duration_ms = if global_max_time > global_min_time {
            global_max_time - global_min_time
        } else {
            0.0
        };

        ResolvedProfile {
            threads,
            product: raw.meta.product.clone().unwrap_or_default(),
            interval_ms: raw.meta.interval,
            categories,
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
                let frame = ResolvedFrame {
                    function_name: func_names.get(fi).cloned().unwrap_or_default(),
                    file: func_files.get(fi).cloned().flatten(),
                    line: frame_line[frame_idx],
                    category: frame_category[frame_idx].clone(),
                    library: func_resource
                        .get(fi)
                        .copied()
                        .flatten()
                        .and_then(&resource_lib_name),
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

            let cat = marker_table
                .category
                .as_ref()
                .and_then(|c| c.get(i).copied())
                .map(&category_name)
                .unwrap_or_else(|| "Other".to_string());

            let data = marker_table
                .data
                .as_ref()
                .and_then(|d| d.get(i).cloned().flatten());

            markers.push(ResolvedMarker {
                name,
                start_time,
                end_time,
                category: cat,
                data,
            });
        }
    }

    // Thread duration
    let duration_ms = if let (Some(first), Some(last)) = (samples.first(), samples.last()) {
        last.timestamp_ms - first.timestamp_ms
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
        samples,
        markers,
        duration_ms,
    }
}
