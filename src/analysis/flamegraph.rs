use std::collections::HashMap;

use crate::profile::resolved::ResolvedThread;

/// Generate collapsed stacks in Brendan Gregg's folded format.
/// Each line: `func1;func2;func3 count`
pub fn collapsed_stacks(thread: &ResolvedThread) -> String {
    let mut stack_counts: HashMap<String, usize> = HashMap::new();

    for sample in &thread.samples {
        if sample.stack.is_empty() {
            continue;
        }

        let stack_str: String = sample
            .stack
            .iter()
            .map(|f| f.function_name.as_str())
            .collect::<Vec<_>>()
            .join(";");

        *stack_counts.entry(stack_str).or_default() += 1;
    }

    // Sort by count descending for deterministic output
    let mut stacks: Vec<(String, usize)> = stack_counts.into_iter().collect();
    stacks.sort_by(|a, b| b.1.cmp(&a.1));

    let mut output = String::new();
    for (stack, count) in stacks {
        output.push_str(&format!("{stack} {count}\n"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::resolved::{ResolvedFrame, ResolvedSample, ResolvedThread};

    fn make_frame(name: &str) -> ResolvedFrame {
        ResolvedFrame {
            function_name: name.to_string(),
            file: None,
            line: None,
            category: "Other".to_string(),
            library: None,
        }
    }

    #[test]
    fn test_collapsed_stacks() {
        let thread = ResolvedThread {
            name: "test".to_string(),
            pid: "1".to_string(),
            tid: "1".to_string(),
            is_main: true,
            duration_ms: 20.0,
            markers: vec![],
            samples: vec![
                ResolvedSample {
                    timestamp_ms: 0.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")],
                },
                ResolvedSample {
                    timestamp_ms: 10.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")],
                },
                ResolvedSample {
                    timestamp_ms: 20.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("baz")],
                },
            ],
        };

        let output = collapsed_stacks(&thread);
        assert!(output.contains("main;foo;bar 2\n"));
        assert!(output.contains("main;baz 1\n"));
    }
}
