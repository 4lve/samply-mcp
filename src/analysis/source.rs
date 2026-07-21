use std::collections::{BTreeSet, HashMap};

use crate::analysis::samples::{self, AnalysisRange};
use crate::profile::resolved::{ResolvedFrame, ResolvedProfile, ResolvedSample};

#[derive(Debug, Clone)]
pub struct InlineSourceFrame {
    pub function_name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ExclusiveInstructionBreakdown {
    pub address: Option<u64>,
    pub library: Option<String>,
    pub library_debug_id: Option<String>,
    pub symbol_name: Option<String>,
    pub symbol_start_address: Option<u64>,
    pub symbol_size: Option<u64>,
    pub focus_file: Option<String>,
    pub focus_line: Option<u32>,
    pub source_origin: &'static str,
    pub inline_frames: Vec<InlineSourceFrame>,
    pub sample_count: usize,
    pub cpu_sample_time_ms: f64,
}

#[derive(Debug, Clone)]
pub struct ExclusiveSourceLineBreakdown {
    pub library: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub instruction_addresses: Vec<u64>,
    pub sample_count: usize,
    pub cpu_sample_time_ms: f64,
}

#[derive(Debug, Default)]
pub struct ExclusiveSourceBreakdown {
    pub scope_sample_count: usize,
    pub scope_time_ms: f64,
    pub exclusive_sample_count: usize,
    pub exclusive_time_ms: f64,
    pub instruction_resolved_samples: usize,
    pub source_resolved_samples: usize,
    pub sidecar_symbolicated_samples: usize,
    pub matched_thread_indices: Vec<usize>,
    pub instructions: Vec<ExclusiveInstructionBreakdown>,
    pub source_lines: Vec<ExclusiveSourceLineBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InstructionKey {
    library_identity: Option<String>,
    address: Option<u64>,
    fallback_file: Option<String>,
    fallback_line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SourceLineKey {
    library_identity: Option<String>,
    file: Option<String>,
    line: Option<u32>,
}

#[derive(Debug)]
struct SourceLineAccum {
    library: Option<String>,
    file: Option<String>,
    line: Option<u32>,
    instruction_addresses: BTreeSet<u64>,
    sample_count: usize,
    cpu_sample_time_ms: f64,
}

pub fn exclusive_source_breakdown(
    profile: &ResolvedProfile,
    thread_indices: &[usize],
    range: &AnalysisRange,
    function_name: &str,
) -> ExclusiveSourceBreakdown {
    let mut result = ExclusiveSourceBreakdown::default();
    let mut instructions: HashMap<InstructionKey, ExclusiveInstructionBreakdown> = HashMap::new();
    let mut source_lines: HashMap<SourceLineKey, SourceLineAccum> = HashMap::new();

    for thread_index in thread_indices {
        let Some(thread) = profile.threads.get(*thread_index) else {
            continue;
        };
        let mut thread_matched = false;

        for sample in thread
            .samples
            .iter()
            .filter(|sample| range.contains(sample))
        {
            let sample_time_ms = samples::sample_time_ms(thread, sample, profile.interval_ms);
            result.scope_sample_count += 1;
            result.scope_time_ms += sample_time_ms;

            let Some(leaf) = sample.stack.last() else {
                continue;
            };
            if leaf.function_name != function_name {
                continue;
            }

            thread_matched = true;
            result.exclusive_sample_count += 1;
            result.exclusive_time_ms += sample_time_ms;

            let address = leaf
                .instruction
                .as_ref()
                .map(|instruction| instruction.address);
            if address.is_some() {
                result.instruction_resolved_samples += 1;
            }
            if leaf
                .instruction
                .as_ref()
                .and_then(|instruction| instruction.symbol.as_ref())
                .is_some()
            {
                result.sidecar_symbolicated_samples += 1;
            }

            let inline_frames = inline_frames_for_leaf(sample, leaf);
            let focus_source = inline_frames
                .iter()
                .rev()
                .find(|frame| frame.function_name == function_name)
                .or_else(|| {
                    let symbol = leaf.instruction.as_ref()?.symbol.as_ref()?;
                    if symbol.symbol_name == function_name {
                        inline_frames.first()
                    } else {
                        None
                    }
                });
            let focus_file = focus_source
                .and_then(|frame| frame.file.clone())
                .or_else(|| leaf.file.clone());
            let focus_line = focus_source.and_then(|frame| frame.line).or(leaf.line);
            if focus_file.is_some() || focus_line.is_some() {
                result.source_resolved_samples += 1;
            }

            let library_debug_id = leaf
                .instruction
                .as_ref()
                .and_then(|instruction| instruction.library_debug_id.clone());
            let library_identity = library_debug_id.clone().or_else(|| leaf.library.clone());
            let instruction_key = InstructionKey {
                library_identity: library_identity.clone(),
                address,
                fallback_file: address.is_none().then(|| focus_file.clone()).flatten(),
                fallback_line: address.is_none().then_some(focus_line).flatten(),
            };
            let symbol = leaf
                .instruction
                .as_ref()
                .and_then(|instruction| instruction.symbol.as_ref());
            let source_origin = if symbol.is_some() {
                "sidecar"
            } else if focus_file.is_some() || focus_line.is_some() {
                "profile"
            } else {
                "unresolved"
            };
            let instruction = instructions.entry(instruction_key).or_insert_with(|| {
                ExclusiveInstructionBreakdown {
                    address,
                    library: leaf.library.clone(),
                    library_debug_id,
                    symbol_name: symbol.map(|symbol| symbol.symbol_name.clone()),
                    symbol_start_address: symbol.map(|symbol| symbol.symbol_start_address),
                    symbol_size: symbol.and_then(|symbol| symbol.symbol_size),
                    focus_file: focus_file.clone(),
                    focus_line,
                    source_origin,
                    inline_frames,
                    sample_count: 0,
                    cpu_sample_time_ms: 0.0,
                }
            });
            instruction.sample_count += 1;
            instruction.cpu_sample_time_ms += sample_time_ms;

            let source_key = SourceLineKey {
                library_identity,
                file: focus_file.clone(),
                line: focus_line,
            };
            let source_line = source_lines
                .entry(source_key)
                .or_insert_with(|| SourceLineAccum {
                    library: leaf.library.clone(),
                    file: focus_file,
                    line: focus_line,
                    instruction_addresses: BTreeSet::new(),
                    sample_count: 0,
                    cpu_sample_time_ms: 0.0,
                });
            if let Some(address) = address {
                source_line.instruction_addresses.insert(address);
            }
            source_line.sample_count += 1;
            source_line.cpu_sample_time_ms += sample_time_ms;
        }

        if thread_matched {
            result.matched_thread_indices.push(*thread_index);
        }
    }

    result.instructions = instructions.into_values().collect();
    result.instructions.sort_by(|a, b| {
        b.cpu_sample_time_ms
            .total_cmp(&a.cpu_sample_time_ms)
            .then_with(|| a.address.cmp(&b.address))
    });
    result.source_lines = source_lines
        .into_values()
        .map(|line| ExclusiveSourceLineBreakdown {
            library: line.library,
            file: line.file,
            line: line.line,
            instruction_addresses: line.instruction_addresses.into_iter().collect(),
            sample_count: line.sample_count,
            cpu_sample_time_ms: line.cpu_sample_time_ms,
        })
        .collect();
    result.source_lines.sort_by(|a, b| {
        b.cpu_sample_time_ms
            .total_cmp(&a.cpu_sample_time_ms)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    result
}

fn inline_frames_for_leaf(sample: &ResolvedSample, leaf: &ResolvedFrame) -> Vec<InlineSourceFrame> {
    if let Some(symbol) = leaf
        .instruction
        .as_ref()
        .and_then(|instruction| instruction.symbol.as_ref())
        && !symbol.frames.is_empty()
    {
        return symbol
            .frames
            .iter()
            .map(|frame| InlineSourceFrame {
                function_name: frame.function_name.clone(),
                file: frame.file.clone(),
                line: frame.line,
            })
            .collect();
    }

    let Some(leaf_instruction) = &leaf.instruction else {
        return vec![frame_source(leaf)];
    };

    let mut frames: Vec<InlineSourceFrame> = sample
        .stack
        .iter()
        .rev()
        .take_while(|frame| {
            frame.instruction.as_ref().is_some_and(|instruction| {
                instruction.address == leaf_instruction.address
                    && instruction.library_debug_id == leaf_instruction.library_debug_id
            })
        })
        .map(frame_source)
        .collect();
    frames.reverse();

    if frames.is_empty() {
        frames.push(frame_source(leaf));
    }
    frames
}

fn frame_source(frame: &ResolvedFrame) -> InlineSourceFrame {
    InlineSourceFrame {
        function_name: frame.function_name.clone(),
        file: frame.file.clone(),
        line: frame.line,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::profile::resolved::{
        ResolvedInstruction, ResolvedSample, ResolvedThread, SampleWeightType,
    };
    use crate::profile::symbols::{SymbolAddressInfo, SymbolSourceFrame};

    fn frame(name: &str, address: u64, line: u32) -> ResolvedFrame {
        ResolvedFrame {
            function_name: name.to_string(),
            file: None,
            line: None,
            category: "Other".to_string(),
            library: Some("app".to_string()),
            instruction: Some(ResolvedInstruction {
                address,
                inline_depth: 0,
                library_debug_id: Some("DEBUG".to_string()),
                symbol: Some(Arc::new(SymbolAddressInfo {
                    symbol_name: name.to_string(),
                    symbol_start_address: 0x100,
                    symbol_size: Some(32),
                    frames: vec![
                        SymbolSourceFrame {
                            function_name: name.to_string(),
                            file: Some("outer.rs".to_string()),
                            line: Some(line),
                        },
                        SymbolSourceFrame {
                            function_name: "inlined".to_string(),
                            file: Some("inline.rs".to_string()),
                            line: Some(20),
                        },
                    ],
                })),
            }),
        }
    }

    #[test]
    fn groups_only_exclusive_samples_by_instruction_and_focus_line() {
        let thread = ResolvedThread {
            name: "worker-0".to_string(),
            pid: "1".to_string(),
            tid: "1".to_string(),
            is_main: true,
            sample_weight_type: SampleWeightType::Samples,
            samples: vec![
                ResolvedSample {
                    timestamp_ms: 100.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![frame("tick", 0x104, 10)],
                },
                ResolvedSample {
                    timestamp_ms: 102.0,
                    weight: 1,
                    cpu_delta_us: None,
                    stack: vec![frame("tick", 0x108, 11)],
                },
            ],
            markers: vec![],
            duration_ms: 2.0,
        };
        let profile = ResolvedProfile {
            threads: vec![thread],
            product: "test".to_string(),
            interval_ms: 2.0,
            categories: vec![],
            observed_start_time_ms: 100.0,
            duration_ms: 2.0,
            total_sample_count: 2,
        };
        let range = AnalysisRange::resolve(&profile, None, None).unwrap();

        let breakdown = exclusive_source_breakdown(&profile, &[0], &range, "tick");

        assert_eq!(breakdown.exclusive_sample_count, 2);
        assert_eq!(breakdown.exclusive_time_ms, 4.0);
        assert_eq!(breakdown.instructions.len(), 2);
        assert_eq!(breakdown.source_lines.len(), 2);
        assert_eq!(breakdown.instructions[0].inline_frames.len(), 2);
        assert_eq!(
            breakdown.instructions[0].focus_file.as_deref(),
            Some("outer.rs")
        );
    }
}
