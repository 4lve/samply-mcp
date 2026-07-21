use std::collections::HashMap;

use crate::analysis::samples::{self, AnalysisRange};
use crate::analysis::symbols;
use crate::profile::resolved::{ResolvedFrame, ResolvedThread};

#[derive(Debug, Clone)]
pub struct CallTreeNode {
    pub function_name: String,
    pub self_time_ms: f64,
    pub total_time_ms: f64,
    pub total_percent: f64,
    pub thread_percent: f64,
    pub children: Vec<CallTreeNode>,
}

#[derive(Debug, Clone)]
pub struct FocusedCallTree {
    pub tree: CallTreeNode,
    pub sample_count: usize,
    pub total_samples: usize,
    pub focused_time_ms: f64,
    pub focused_percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerRelationship {
    Ancestor,
    Immediate,
}

#[cfg(test)]
pub fn build_call_tree_with_filter(
    thread: &ResolvedThread,
    max_depth: usize,
    min_percent: f64,
    include_frame: impl FnMut(&str) -> bool,
) -> CallTreeNode {
    build_call_tree_for_threads_with_filter(
        &[thread],
        inferred_test_interval_ms(thread),
        None,
        max_depth,
        min_percent,
        include_frame,
    )
}

pub fn build_call_tree_for_threads_with_filter(
    threads: &[&ResolvedThread],
    interval_ms: f64,
    range: Option<&AnalysisRange>,
    max_depth: usize,
    min_percent: f64,
    mut include_frame: impl FnMut(&str) -> bool,
) -> CallTreeNode {
    let total_time: f64 = threads
        .iter()
        .map(|thread| samples::thread_sample_time_ms(thread, interval_ms, range))
        .sum();

    let mut root = TreeBuilder::new("(root)".to_string());

    for thread in threads {
        for sample in thread
            .samples
            .iter()
            .filter(|sample| range.is_none_or(|range| range.contains(sample)))
        {
            let sample_time_ms = samples::sample_time_ms(thread, sample, interval_ms);
            if sample.stack.is_empty() {
                root.self_time += sample_time_ms;
                root.total_time += sample_time_ms;
                continue;
            }

            root.total_time += sample_time_ms;
            let mut node = &mut root;
            let mut assigned_self_time = false;

            for (included_depth, frame) in sample
                .stack
                .iter()
                .filter(|frame| include_frame(&frame.function_name))
                .enumerate()
            {
                if included_depth >= max_depth {
                    // Attribute remaining time as self-time of the deepest node
                    node.self_time += sample_time_ms;
                    assigned_self_time = true;
                    break;
                }

                node = node
                    .children
                    .entry(frame.function_name.clone())
                    .or_insert_with(|| TreeBuilder::new(frame.function_name.clone()));
                node.total_time += sample_time_ms;

                // Leaf self-time is assigned after filtering below.
            }

            if !assigned_self_time {
                node.self_time += sample_time_ms;
            }
        }
    }

    root.into_node(total_time, total_time, min_percent)
}

#[cfg(test)]
pub fn build_focused_call_tree_with_filter(
    thread: &ResolvedThread,
    function_name: &str,
    max_depth: usize,
    min_percent: f64,
    include_frame: impl FnMut(&str) -> bool,
) -> Option<FocusedCallTree> {
    build_focused_call_tree_for_threads_with_filter(
        &[thread],
        inferred_test_interval_ms(thread),
        None,
        function_name,
        max_depth,
        min_percent,
        include_frame,
    )
}

pub fn build_focused_call_tree_for_threads_with_filter(
    threads: &[&ResolvedThread],
    interval_ms: f64,
    range: Option<&AnalysisRange>,
    function_name: &str,
    max_depth: usize,
    min_percent: f64,
    mut include_frame: impl FnMut(&str) -> bool,
) -> Option<FocusedCallTree> {
    let total_thread_time: f64 = threads
        .iter()
        .map(|thread| samples::thread_sample_time_ms(thread, interval_ms, range))
        .sum();
    let total_samples = threads
        .iter()
        .map(|thread| samples::sample_count(thread, range))
        .sum();

    let mut root = TreeBuilder::new(function_name.to_string());
    let mut matched_samples = 0usize;

    for thread in threads {
        for sample in thread
            .samples
            .iter()
            .filter(|sample| range.is_none_or(|range| range.contains(sample)))
        {
            let Some(focus_index) = sample
                .stack
                .iter()
                .position(|frame| frame.function_name == function_name)
            else {
                continue;
            };

            matched_samples += 1;
            let sample_time_ms = samples::sample_time_ms(thread, sample, interval_ms);
            root.total_time += sample_time_ms;

            if max_depth == 0 {
                root.self_time += sample_time_ms;
                continue;
            }

            let mut node = &mut root;
            let mut assigned_self_time = false;
            for (included_depth, frame) in (1usize..).zip(
                sample.stack[focus_index + 1..]
                    .iter()
                    .filter(|frame| include_frame(&frame.function_name)),
            ) {
                if included_depth >= max_depth {
                    node.self_time += sample_time_ms;
                    assigned_self_time = true;
                    break;
                }

                node = node
                    .children
                    .entry(frame.function_name.clone())
                    .or_insert_with(|| TreeBuilder::new(frame.function_name.clone()));
                node.total_time += sample_time_ms;
            }

            if !assigned_self_time {
                node.self_time += sample_time_ms;
            }
        }
    }

    if matched_samples == 0 {
        return None;
    }

    let focused_time_ms = root.total_time;
    let focused_percent = if total_thread_time > 0.0 {
        focused_time_ms / total_thread_time * 100.0
    } else {
        0.0
    };

    Some(FocusedCallTree {
        tree: root.into_node(focused_time_ms, total_thread_time, min_percent),
        sample_count: matched_samples,
        total_samples,
        focused_time_ms,
        focused_percent,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_focused_call_tree_under_caller_with_filter(
    threads: &[&ResolvedThread],
    interval_ms: f64,
    range: Option<&AnalysisRange>,
    function_name: &str,
    caller_name: &str,
    caller_relationship: CallerRelationship,
    max_depth: usize,
    min_percent: f64,
    mut include_frame: impl FnMut(&str) -> bool,
) -> Option<FocusedCallTree> {
    let total_thread_time: f64 = threads
        .iter()
        .map(|thread| samples::thread_sample_time_ms(thread, interval_ms, range))
        .sum();
    let total_samples = threads
        .iter()
        .map(|thread| samples::sample_count(thread, range))
        .sum();

    let mut root = TreeBuilder::new(function_name.to_string());
    let mut matched_samples = 0usize;

    for thread in threads {
        for sample in thread
            .samples
            .iter()
            .filter(|sample| range.is_none_or(|range| range.contains(sample)))
        {
            let Some(focus_index) = function_under_caller_index(
                &sample.stack,
                function_name,
                caller_name,
                caller_relationship,
            ) else {
                continue;
            };

            matched_samples += 1;
            let sample_time_ms = samples::sample_time_ms(thread, sample, interval_ms);
            root.total_time += sample_time_ms;

            if max_depth == 0 {
                root.self_time += sample_time_ms;
                continue;
            }

            let mut node = &mut root;
            let mut assigned_self_time = false;
            for (included_depth, frame) in (1usize..).zip(
                sample.stack[focus_index + 1..]
                    .iter()
                    .filter(|frame| include_frame(&frame.function_name)),
            ) {
                if included_depth >= max_depth {
                    node.self_time += sample_time_ms;
                    assigned_self_time = true;
                    break;
                }

                node = node
                    .children
                    .entry(frame.function_name.clone())
                    .or_insert_with(|| TreeBuilder::new(frame.function_name.clone()));
                node.total_time += sample_time_ms;
            }

            if !assigned_self_time {
                node.self_time += sample_time_ms;
            }
        }
    }

    if matched_samples == 0 {
        return None;
    }

    let focused_time_ms = root.total_time;
    let focused_percent = if total_thread_time > 0.0 {
        focused_time_ms / total_thread_time * 100.0
    } else {
        0.0
    };

    Some(FocusedCallTree {
        tree: root.into_node(focused_time_ms, total_thread_time, min_percent),
        sample_count: matched_samples,
        total_samples,
        focused_time_ms,
        focused_percent,
    })
}

pub fn function_under_caller_index(
    stack: &[ResolvedFrame],
    function_name: &str,
    caller_name: &str,
    caller_relationship: CallerRelationship,
) -> Option<usize> {
    let mut first_match = None;

    for (index, frame) in stack.iter().enumerate() {
        if frame.function_name != function_name {
            continue;
        }

        let has_caller = match caller_relationship {
            CallerRelationship::Ancestor => stack[..index]
                .iter()
                .any(|frame| frame.function_name == caller_name),
            CallerRelationship::Immediate => {
                index > 0 && stack[index - 1].function_name == caller_name
            }
        };

        if !has_caller {
            continue;
        }

        if index + 1 == stack.len() {
            return Some(index);
        }

        first_match.get_or_insert(index);
    }

    first_match
}

#[cfg(test)]
fn inferred_test_interval_ms(thread: &ResolvedThread) -> f64 {
    if thread.samples.len() >= 2 {
        thread
            .samples
            .windows(2)
            .map(|samples| samples[1].timestamp_ms - samples[0].timestamp_ms)
            .find(|delta| *delta > 0.0 && delta.is_finite())
            .unwrap_or(1.0)
    } else {
        1.0
    }
}

struct TreeBuilder {
    name: String,
    self_time: f64,
    total_time: f64,
    children: HashMap<String, TreeBuilder>,
}

impl TreeBuilder {
    fn new(name: String) -> Self {
        Self {
            name,
            self_time: 0.0,
            total_time: 0.0,
            children: HashMap::new(),
        }
    }

    fn into_node(
        self,
        percent_denominator_ms: f64,
        thread_denominator_ms: f64,
        min_percent: f64,
    ) -> CallTreeNode {
        let total_percent = if percent_denominator_ms > 0.0 {
            self.total_time / percent_denominator_ms * 100.0
        } else {
            0.0
        };
        let thread_percent = if thread_denominator_ms > 0.0 {
            self.total_time / thread_denominator_ms * 100.0
        } else {
            0.0
        };

        let mut children: Vec<CallTreeNode> = self
            .children
            .into_values()
            .filter(|c| {
                let pct = if percent_denominator_ms > 0.0 {
                    c.total_time / percent_denominator_ms * 100.0
                } else {
                    0.0
                };
                pct >= min_percent
            })
            .map(|c| c.into_node(percent_denominator_ms, thread_denominator_ms, min_percent))
            .collect();

        children.sort_by(|a, b| b.total_time_ms.total_cmp(&a.total_time_ms));

        CallTreeNode {
            function_name: self.name,
            self_time_ms: self.self_time,
            total_time_ms: self.total_time,
            total_percent,
            thread_percent,
            children,
        }
    }
}

impl CallTreeNode {
    pub fn render_text_with_options(
        &self,
        max_depth: usize,
        short_names: bool,
        show_thread_percent: bool,
    ) -> String {
        let mut output = String::new();
        self.render_recursive(&mut output, 0, max_depth, short_names, show_thread_percent);
        output
    }

    fn render_recursive(
        &self,
        output: &mut String,
        depth: usize,
        max_depth: usize,
        short_names: bool,
        show_thread_percent: bool,
    ) {
        if depth > max_depth {
            return;
        }
        let indent = "  ".repeat(depth);
        let name = if short_names {
            symbols::compact_function_name(&self.function_name)
        } else {
            self.function_name.clone()
        };

        if show_thread_percent {
            output.push_str(&format!(
                "{}{} [{:.1}% focus / {:.2}% thread, {:.1}ms self]\n",
                indent, name, self.total_percent, self.thread_percent, self.self_time_ms,
            ));
        } else {
            output.push_str(&format!(
                "{}{} [{:.1}% total, {:.1}ms self]\n",
                indent, name, self.total_percent, self.self_time_ms,
            ));
        }

        for child in &self.children {
            child.render_recursive(
                output,
                depth + 1,
                max_depth,
                short_names,
                show_thread_percent,
            );
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
    fn test_call_tree_basic() {
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
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")],
                },
                ResolvedSample {
                    timestamp_ms: 10.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("foo")],
                },
                ResolvedSample {
                    timestamp_ms: 20.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("baz")],
                },
            ],
        };

        let tree = build_call_tree_with_filter(&thread, 10, 0.0, |_| true);
        assert_eq!(tree.function_name, "(root)");
        assert_eq!(tree.children.len(), 1); // just "main"
        let main_node = &tree.children[0];
        assert_eq!(main_node.function_name, "main");
        assert_eq!(main_node.children.len(), 2); // "foo" and "baz"
    }

    #[test]
    fn test_focused_call_tree_scales_to_matching_samples() {
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
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("bar")],
                },
                ResolvedSample {
                    timestamp_ms: 10.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("foo"), make_frame("baz")],
                },
                ResolvedSample {
                    timestamp_ms: 20.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("other")],
                },
                ResolvedSample {
                    timestamp_ms: 30.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![make_frame("main"), make_frame("other")],
                },
            ],
        };

        let focused =
            build_focused_call_tree_with_filter(&thread, "foo", 10, 0.0, |_| true).unwrap();

        assert_eq!(focused.sample_count, 2);
        assert_eq!(focused.total_samples, 4);
        assert_eq!(focused.focused_percent, 50.0);
        assert_eq!(focused.tree.function_name, "foo");
        assert_eq!(focused.tree.total_percent, 100.0);
        assert_eq!(focused.tree.children.len(), 2);
    }

    #[test]
    fn function_under_caller_distinguishes_ancestor_and_immediate() {
        let stack = vec![
            make_frame("main"),
            make_frame("finish_generation_status"),
            make_frame("fluid_system"),
            make_frame("WaterFluid::tick"),
        ];

        assert_eq!(
            function_under_caller_index(
                &stack,
                "WaterFluid::tick",
                "finish_generation_status",
                CallerRelationship::Ancestor
            ),
            Some(3)
        );
        assert_eq!(
            function_under_caller_index(
                &stack,
                "WaterFluid::tick",
                "finish_generation_status",
                CallerRelationship::Immediate
            ),
            None
        );
    }

    #[test]
    fn focused_call_tree_can_be_scoped_to_a_caller() {
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
                    stack: vec![
                        make_frame("main"),
                        make_frame("finish_generation_status"),
                        make_frame("WaterFluid::tick"),
                        make_frame("child"),
                    ],
                },
                ResolvedSample {
                    timestamp_ms: 10.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![
                        make_frame("main"),
                        make_frame("finish_generation_status"),
                        make_frame("WaterFluid::tick"),
                    ],
                },
                ResolvedSample {
                    timestamp_ms: 20.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![
                        make_frame("main"),
                        make_frame("other_status"),
                        make_frame("WaterFluid::tick"),
                    ],
                },
                ResolvedSample {
                    timestamp_ms: 30.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![
                        make_frame("main"),
                        make_frame("finish_generation_status"),
                        make_frame("LavaFluid::tick"),
                    ],
                },
            ],
        };

        let focused = build_focused_call_tree_under_caller_with_filter(
            &[&thread],
            10.0,
            None,
            "WaterFluid::tick",
            "finish_generation_status",
            CallerRelationship::Ancestor,
            10,
            0.0,
            |_| true,
        )
        .unwrap();

        assert_eq!(focused.sample_count, 2);
        assert_eq!(focused.total_samples, 4);
        assert_eq!(focused.focused_percent, 50.0);
        assert_eq!(focused.tree.function_name, "WaterFluid::tick");
        assert_eq!(focused.tree.self_time_ms, 10.0);
        assert_eq!(focused.tree.children.len(), 1);
        assert_eq!(focused.tree.children[0].function_name, "child");
    }
}
