use std::collections::HashMap;

use crate::analysis::samples::{self, AnalysisRange};
use crate::analysis::symbols;
use crate::profile::resolved::ResolvedThread;

pub fn collapsed_stacks_for_threads_with_options(
    threads: &[&ResolvedThread],
    range: Option<&AnalysisRange>,
    focus_function: Option<&str>,
    mut include_frame: impl FnMut(&str) -> bool,
    short_names: bool,
) -> String {
    let mut stack_counts: HashMap<String, u64> = HashMap::new();

    for thread in threads {
        for sample in thread
            .samples
            .iter()
            .filter(|sample| range.is_none_or(|range| range.contains(sample)))
        {
            if sample.stack.is_empty() {
                continue;
            }

            let frames = if let Some(function_name) = focus_function {
                let Some(index) = sample
                    .stack
                    .iter()
                    .position(|frame| frame.function_name == function_name)
                else {
                    continue;
                };
                &sample.stack[index..]
            } else {
                &sample.stack
            };

            let stack_str: String = frames
                .iter()
                .filter(|frame| {
                    focus_function == Some(frame.function_name.as_str())
                        || include_frame(&frame.function_name)
                })
                .map(|f| f.function_name.as_str())
                .map(|name| {
                    if short_names {
                        symbols::compact_function_name(name)
                    } else {
                        name.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(";");

            if stack_str.is_empty() {
                continue;
            }

            *stack_counts.entry(stack_str).or_default() +=
                u64::from(samples::sample_weight(sample));
        }
    }

    // Sort by count descending for deterministic output
    let mut stacks: Vec<(String, u64)> = stack_counts.into_iter().collect();
    stacks.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

    let mut output = String::new();
    for (stack, count) in stacks {
        output.push_str(&format!("{stack} {count}\n"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::resolved::{
        ResolvedFrame, ResolvedSample, ResolvedThread, SampleWeightType,
    };

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
    fn test_collapsed_stacks() {
        let thread = ResolvedThread {
            name: "test".to_string(),
            pid: "1".to_string(),
            tid: "1".to_string(),
            is_main: true,
            sample_weight_type: SampleWeightType::Samples,
            duration_ms: 20.0,
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
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")].into(),
                },
                ResolvedSample {
                    timestamp_ms: 20.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("baz")].into(),
                },
            ],
        };

        let output =
            collapsed_stacks_for_threads_with_options(&[&thread], None, None, |_| true, false);
        assert!(output.contains("main;foo;bar 2\n"));
        assert!(output.contains("main;baz 1\n"));
    }

    #[test]
    fn test_collapsed_stacks_for_function() {
        let thread = ResolvedThread {
            name: "test".to_string(),
            pid: "1".to_string(),
            tid: "1".to_string(),
            is_main: true,
            sample_weight_type: SampleWeightType::Samples,
            duration_ms: 20.0,
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
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")].into(),
                },
                ResolvedSample {
                    timestamp_ms: 20.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("baz")].into(),
                },
            ],
        };

        let output = collapsed_stacks_for_threads_with_options(
            &[&thread],
            None,
            Some("foo"),
            |_| true,
            false,
        );

        assert!(output.contains("foo;bar 2\n"));
        assert!(!output.contains("main;foo;bar"));
        assert!(!output.contains("main;baz"));
    }
}
