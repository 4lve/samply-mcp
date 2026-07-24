use std::collections::HashMap;

use crate::analysis::samples::{self, AnalysisRange};
use crate::profile::resolved::ResolvedThread;

#[derive(Debug, Clone)]
pub struct FunctionStats {
    pub name: String,
    pub self_time_ms: f64,
    pub total_time_ms: f64,
    pub self_percent: f64,
    pub total_percent: f64,
    pub sample_count: usize,
    pub library: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

pub fn compute_function_stats(
    thread: &ResolvedThread,
    interval_ms: f64,
    range: Option<&AnalysisRange>,
) -> Vec<FunctionStats> {
    let total_profile_time = samples::thread_sample_time_ms(thread, interval_ms, range);

    // Accumulate per-function data
    let mut stats_map: HashMap<String, FunctionStatsAccum> = HashMap::new();

    for sample in thread
        .samples
        .iter()
        .filter(|sample| range.is_none_or(|range| range.contains(sample)))
    {
        if sample.stack.is_empty() {
            continue;
        }
        let sample_time_ms = samples::sample_time_ms(thread, sample, interval_ms);

        // Self-time goes to the leaf frame (last in root-first order)
        let leaf = &sample.stack[sample.stack.len() - 1];
        let entry = stats_map
            .entry(leaf.function_name.clone())
            .or_insert_with(|| FunctionStatsAccum::new(leaf));
        entry.self_time_ms += sample_time_ms;
        entry.sample_count += 1;

        // Total-time goes to all unique frames in the stack
        let mut seen = std::collections::HashSet::new();
        for frame in sample.stack.iter() {
            if seen.insert(&frame.function_name) {
                let entry = stats_map
                    .entry(frame.function_name.clone())
                    .or_insert_with(|| FunctionStatsAccum::new(frame));
                entry.total_time_ms += sample_time_ms;
            }
        }
    }

    let mut result: Vec<FunctionStats> = stats_map
        .into_iter()
        .map(|(name, acc)| FunctionStats {
            name,
            self_time_ms: acc.self_time_ms,
            total_time_ms: acc.total_time_ms,
            self_percent: if total_profile_time > 0.0 {
                acc.self_time_ms / total_profile_time * 100.0
            } else {
                0.0
            },
            total_percent: if total_profile_time > 0.0 {
                acc.total_time_ms / total_profile_time * 100.0
            } else {
                0.0
            },
            sample_count: acc.sample_count,
            library: acc.library,
            file: acc.file,
            line: acc.line,
        })
        .collect();

    result.sort_by(|a, b| b.self_time_ms.total_cmp(&a.self_time_ms));
    result
}

struct FunctionStatsAccum {
    self_time_ms: f64,
    total_time_ms: f64,
    sample_count: usize,
    library: Option<String>,
    file: Option<String>,
    line: Option<u32>,
}

impl FunctionStatsAccum {
    fn new(frame: &crate::profile::resolved::ResolvedFrame) -> Self {
        Self {
            self_time_ms: 0.0,
            total_time_ms: 0.0,
            sample_count: 0,
            library: frame.library.clone(),
            file: frame.file.clone(),
            line: frame.line,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::resolved::{ResolvedFrame, ResolvedSample, SampleWeightType};

    fn make_frame(name: &str) -> ResolvedFrame {
        ResolvedFrame {
            function_name: name.to_string(),
            file: None,
            line: None,
            category: "Other".to_string(),
            library: None,
            instruction: None,
        }
    }

    #[test]
    fn test_function_stats_basic() {
        let thread = ResolvedThread {
            name: "test".to_string(),
            pid: "1".to_string(),
            tid: "1".to_string(),
            is_main: true,
            sample_weight_type: SampleWeightType::Samples,
            duration_ms: 30.0,
            markers: vec![],
            samples: vec![
                ResolvedSample {
                    timestamp_ms: 0.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")].into(),
                },
                ResolvedSample {
                    timestamp_ms: 10.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("foo")].into(),
                },
                ResolvedSample {
                    timestamp_ms: 20.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("baz")].into(),
                },
                ResolvedSample {
                    timestamp_ms: 30.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")].into(),
                },
            ],
        };

        let stats = compute_function_stats(&thread, 10.0, None);

        let bar = stats.iter().find(|s| s.name == "bar").unwrap();
        assert_eq!(bar.sample_count, 2); // bar is leaf in 2 samples

        let main_fn = stats.iter().find(|s| s.name == "main").unwrap();
        assert_eq!(main_fn.sample_count, 0); // main is never a leaf
        assert!(main_fn.total_time_ms > 0.0); // but it's in all stacks
    }

    #[test]
    fn sparse_samples_use_the_recording_interval() {
        let thread = ResolvedThread {
            name: "sparse".to_string(),
            pid: "1".to_string(),
            tid: "1".to_string(),
            is_main: true,
            sample_weight_type: SampleWeightType::Samples,
            duration_ms: 1_000.0,
            markers: vec![],
            samples: vec![
                ResolvedSample {
                    timestamp_ms: 0.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("work")].into(),
                },
                ResolvedSample {
                    timestamp_ms: 1_000.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("work")].into(),
                },
            ],
        };

        let stats = compute_function_stats(&thread, 2.0, None);
        let work = stats.iter().find(|stat| stat.name == "work").unwrap();

        assert_eq!(work.self_time_ms, 4.0);
        assert_eq!(work.total_time_ms, 4.0);
        assert_eq!(work.self_percent, 100.0);
    }
}
