use std::cmp::Reverse;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::analysis::call_tree;
use crate::analysis::flamegraph;
use crate::analysis::functions::{self, FunctionStats};
use crate::analysis::symbols;
use crate::profile::parse::load_profile;
use crate::profile::resolved::{ResolvedProfile, ResolvedThread};

/// Pre-computed analysis data cached per thread
#[derive(Debug)]
struct AnalysisCache {
    function_stats: Vec<Vec<FunctionStats>>,
}

impl AnalysisCache {
    fn build(profile: &ResolvedProfile) -> Self {
        let function_stats = profile
            .threads
            .iter()
            .map(functions::compute_function_stats)
            .collect();
        AnalysisCache { function_stats }
    }
}

/// A loaded and analyzed profile with its cache.
struct CachedProfile {
    profile: Arc<ResolvedProfile>,
    cache: Arc<AnalysisCache>,
}

#[derive(Clone)]
pub struct ProfileServer {
    profiles: Arc<Mutex<HashMap<PathBuf, Arc<CachedProfile>>>>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for ProfileServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileServer").finish()
    }
}

impl ProfileServer {
    pub fn new() -> Self {
        Self {
            profiles: Arc::new(Mutex::new(HashMap::new())),
            tool_router: Self::tool_router(),
        }
    }

    fn get_profile(&self, path: &str) -> Result<Arc<CachedProfile>, String> {
        let canonical =
            std::fs::canonicalize(path).map_err(|e| format!("Invalid path '{}': {}", path, e))?;

        {
            let cache = self.profiles.lock().unwrap();
            if let Some(cached) = cache.get(&canonical) {
                return Ok(Arc::clone(cached));
            }
        }

        let profile = load_profile(&canonical)
            .map_err(|e| format!("Failed to load profile '{}': {}", path, e))?;
        let analysis_cache = AnalysisCache::build(&profile);
        let cached = Arc::new(CachedProfile {
            profile: Arc::new(profile),
            cache: Arc::new(analysis_cache),
        });

        self.profiles
            .lock()
            .unwrap()
            .insert(canonical, Arc::clone(&cached));
        Ok(cached)
    }
}

struct SelectedThread<'a> {
    index: usize,
    thread: &'a ResolvedThread,
}

fn select_thread<'a>(
    profile: &'a ResolvedProfile,
    thread_name: &Option<String>,
    tid: &Option<String>,
    thread_index: Option<usize>,
) -> Result<SelectedThread<'a>, String> {
    if let Some(index) = thread_index {
        let thread = profile
            .threads
            .get(index)
            .ok_or_else(|| format!("Thread index {index} not found"))?;
        return Ok(SelectedThread { index, thread });
    }

    if let Some(tid) = tid {
        let (index, thread) = profile
            .threads
            .iter()
            .enumerate()
            .find(|(_, t)| t.tid == *tid)
            .ok_or_else(|| format!("Thread tid '{tid}' not found"))?;
        return Ok(SelectedThread { index, thread });
    }

    if let Some(name) = thread_name {
        let (index, thread) = profile
            .threads
            .iter()
            .enumerate()
            .filter(|(_, t)| t.name == *name)
            .max_by_key(|(_, t)| t.samples.len())
            .ok_or_else(|| format!("Thread '{name}' not found"))?;
        return Ok(SelectedThread { index, thread });
    }

    let (index, thread) = profile
        .threads
        .iter()
        .enumerate()
        .filter(|(_, t)| t.is_main)
        .max_by_key(|(_, t)| t.samples.len())
        .or_else(|| {
            profile
                .threads
                .iter()
                .enumerate()
                .max_by_key(|(_, t)| t.samples.len())
        })
        .ok_or("No threads found")?;

    Ok(SelectedThread { index, thread })
}

fn thread_label(index: usize, thread: &ResolvedThread) -> String {
    format!("{} [tid={}, index={}]", thread.name, thread.tid, index)
}

fn default_match_mode() -> String {
    "contains".to_string()
}

fn default_short_names() -> bool {
    true
}

fn function_matches(name: &str, query: &str, match_mode: &str) -> bool {
    if match_mode == "exact" {
        name == query
    } else {
        name.to_lowercase().contains(&query.to_lowercase())
    }
}

fn pattern_matches(value: &str, patterns: &str) -> bool {
    let value = value.to_lowercase();
    patterns
        .split('|')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .any(|p| value.contains(&p.to_lowercase()))
}

fn function_passes_filters(
    stats: &FunctionStats,
    include: &Option<String>,
    exclude: &Option<String>,
    exclude_framework: bool,
) -> bool {
    let mut searchable = stats.name.clone();
    if let Some(library) = &stats.library {
        searchable.push(' ');
        searchable.push_str(library);
    }
    if let Some(file) = &stats.file {
        searchable.push(' ');
        searchable.push_str(file);
    }

    if let Some(include) = include
        && !pattern_matches(&searchable, include)
    {
        return false;
    }

    if let Some(exclude) = exclude
        && pattern_matches(&searchable, exclude)
    {
        return false;
    }

    if exclude_framework && symbols::is_framework_function(&stats.name, stats.library.as_deref()) {
        return false;
    }

    true
}

fn sort_function_stats(stats: &mut [FunctionStats], sort_by: &str) {
    if sort_by == "total" {
        stats.sort_by(|a, b| b.total_time_ms.total_cmp(&a.total_time_ms));
    } else {
        stats.sort_by(|a, b| b.self_time_ms.total_cmp(&a.self_time_ms));
    }
}

fn resolve_function_name(
    stats_by_thread: &[Vec<FunctionStats>],
    query: Option<&str>,
    function_id: Option<&str>,
    match_mode: &str,
    thread_index: Option<usize>,
) -> Option<String> {
    if let Some(thread_index) = thread_index {
        return resolve_function_name_in_threads(
            stats_by_thread,
            query,
            function_id,
            match_mode,
            Some(&[thread_index]),
        );
    }

    resolve_function_name_in_threads(stats_by_thread, query, function_id, match_mode, None)
}

fn resolve_function_name_in_threads(
    stats_by_thread: &[Vec<FunctionStats>],
    query: Option<&str>,
    function_id: Option<&str>,
    match_mode: &str,
    thread_indices: Option<&[usize]>,
) -> Option<String> {
    if let Some(function_id) = function_id {
        return stats_by_thread
            .iter()
            .enumerate()
            .filter(|(index, _)| thread_indices.is_none_or(|selected| selected.contains(index)))
            .flat_map(|(_, stats)| stats.iter())
            .find(|stats| symbols::function_id(&stats.name) == function_id)
            .map(|stats| stats.name.clone());
    }

    let query = query?;
    let stats_iter = stats_by_thread
        .iter()
        .enumerate()
        .filter(|(index, _)| thread_indices.is_none_or(|selected| selected.contains(index)))
        .flat_map(|(_, stats)| stats.iter());

    let mut candidates: Vec<&FunctionStats> = stats_iter
        .filter(|stats| function_matches(&stats.name, query, match_mode))
        .collect();

    if let Some(exact) = candidates.iter().find(|stats| stats.name == query) {
        return Some(exact.name.clone());
    }

    candidates.sort_by(|a, b| b.total_time_ms.total_cmp(&a.total_time_ms));
    candidates.first().map(|stats| stats.name.clone())
}

fn source_location(file: &Option<String>, line: Option<u32>) -> Option<String> {
    match (file, line) {
        (Some(file), Some(line)) => Some(format!("{file}:{line}")),
        (Some(file), None) => Some(file.clone()),
        _ => None,
    }
}

fn exclude_framework_enabled(exclude_framework: bool, user_code_only: bool) -> bool {
    exclude_framework || user_code_only
}

fn requested_thread_prefixes(
    thread_name_prefix: &Option<String>,
    thread_name_prefixes: &[String],
) -> Vec<String> {
    let mut prefixes = Vec::new();
    if let Some(prefix) = thread_name_prefix {
        let prefix = prefix.trim();
        if !prefix.is_empty() {
            prefixes.push(prefix.to_string());
        }
    }

    for prefix in thread_name_prefixes {
        let prefix = prefix.trim();
        if !prefix.is_empty() && !prefixes.iter().any(|existing| existing == prefix) {
            prefixes.push(prefix.to_string());
        }
    }

    prefixes
}

fn normalized_thread_prefix(prefix: &str) -> String {
    prefix
        .trim()
        .strip_suffix('*')
        .unwrap_or(prefix.trim())
        .to_string()
}

fn thread_name_matches_prefix(thread_name: &str, prefix: &str) -> bool {
    thread_name.starts_with(&normalized_thread_prefix(prefix))
}

fn thread_infos(profile: &ResolvedProfile, thread_indices: &[usize]) -> Vec<ThreadInfo> {
    thread_indices
        .iter()
        .filter_map(|index| profile.threads.get(*index).map(|thread| (*index, thread)))
        .map(|(index, thread)| ThreadInfo {
            index,
            name: thread.name.clone(),
            pid: thread.pid.clone(),
            tid: thread.tid.clone(),
            sample_count: thread.samples.len(),
            duration_ms: thread.duration_ms,
            is_main: thread.is_main,
        })
        .collect()
}

fn scope_total_time_ms(profile: &ResolvedProfile, thread_indices: &[usize]) -> f64 {
    thread_indices
        .iter()
        .filter_map(|index| profile.threads.get(*index))
        .map(|thread| call_tree::sample_interval_ms(thread) * thread.samples.len() as f64)
        .sum()
}

fn aggregate_function_stats(
    cached: &CachedProfile,
    thread_indices: &[usize],
) -> (Vec<FunctionStats>, f64, usize) {
    let total_time_ms = scope_total_time_ms(&cached.profile, thread_indices);
    let total_samples = thread_indices
        .iter()
        .filter_map(|index| cached.profile.threads.get(*index))
        .map(|thread| thread.samples.len())
        .sum();

    let mut by_name: HashMap<String, AggregatedFunctionStatsAccum> = HashMap::new();

    for index in thread_indices {
        let Some(stats) = cached.cache.function_stats.get(*index) else {
            continue;
        };

        for stat in stats {
            let entry = by_name.entry(stat.name.clone()).or_default();
            entry.self_time_ms += stat.self_time_ms;
            entry.total_time_ms += stat.total_time_ms;
            entry.sample_count += stat.sample_count;
            if entry.library.is_none() {
                entry.library = stat.library.clone();
            }
            if entry.file.is_none() {
                entry.file = stat.file.clone();
            }
            if entry.line.is_none() {
                entry.line = stat.line;
            }
        }
    }

    let mut stats: Vec<FunctionStats> = by_name
        .into_iter()
        .map(|(name, acc)| FunctionStats {
            name,
            self_time_ms: acc.self_time_ms,
            total_time_ms: acc.total_time_ms,
            self_percent: percent(acc.self_time_ms, total_time_ms),
            total_percent: percent(acc.total_time_ms, total_time_ms),
            sample_count: acc.sample_count,
            library: acc.library,
            file: acc.file,
            line: acc.line,
        })
        .collect();
    sort_function_stats(&mut stats, "self");

    (stats, total_time_ms, total_samples)
}

#[derive(Default)]
struct AggregatedFunctionStatsAccum {
    self_time_ms: f64,
    total_time_ms: f64,
    sample_count: usize,
    library: Option<String>,
    file: Option<String>,
    line: Option<u32>,
}

fn select_thread_indices_for_scope(
    profile: &ResolvedProfile,
    thread: &Option<String>,
    tid: &Option<String>,
    thread_index: Option<usize>,
    thread_name_prefix: &Option<String>,
    thread_name_prefixes: &[String],
) -> Result<(String, Vec<usize>), String> {
    let prefixes = requested_thread_prefixes(thread_name_prefix, thread_name_prefixes);
    let has_explicit_thread_selector = thread.is_some() || tid.is_some() || thread_index.is_some();

    if has_explicit_thread_selector && !prefixes.is_empty() {
        return Err(
            "Use either thread/tid/thread_index or thread_name_prefix, not both".to_string(),
        );
    }

    if has_explicit_thread_selector {
        let selected = select_thread(profile, thread, tid, thread_index)?;
        return Ok((
            thread_label(selected.index, selected.thread),
            vec![selected.index],
        ));
    }

    if !prefixes.is_empty() {
        let mut indices = Vec::new();
        for (index, thread) in profile.threads.iter().enumerate() {
            if prefixes
                .iter()
                .any(|prefix| thread_name_matches_prefix(&thread.name, prefix))
            {
                indices.push(index);
            }
        }

        if indices.is_empty() {
            return Err(format!(
                "No threads matched prefix(es): {}",
                prefixes.join(", ")
            ));
        }

        return Ok((
            format!("thread prefix(es): {}", prefixes.join(", ")),
            indices,
        ));
    }

    let indices: Vec<usize> = profile
        .threads
        .iter()
        .enumerate()
        .filter(|(_, thread)| !thread.samples.is_empty())
        .map(|(index, _)| index)
        .collect();

    if indices.is_empty() {
        return Err("No sampled threads found".to_string());
    }

    Ok(("all sampled threads".to_string(), indices))
}

fn parse_caller_relationship(value: &str) -> Result<call_tree::CallerRelationship, String> {
    match value.trim().to_lowercase().as_str() {
        "ancestor" => Ok(call_tree::CallerRelationship::Ancestor),
        "immediate" => Ok(call_tree::CallerRelationship::Immediate),
        _ => Err("caller_mode must be 'ancestor' or 'immediate'".to_string()),
    }
}

fn caller_relationship_label(value: call_tree::CallerRelationship) -> &'static str {
    match value {
        call_tree::CallerRelationship::Ancestor => "ancestor",
        call_tree::CallerRelationship::Immediate => "immediate",
    }
}

#[derive(Debug, Default)]
struct FunctionUnderCallerMetrics {
    exclusive_time_ms: f64,
    descendant_time_ms: f64,
    caller_context_time_ms: f64,
    scope_time_ms: f64,
    exclusive_samples: usize,
    descendant_samples: usize,
    caller_context_samples: usize,
    total_scope_samples: usize,
    matched_thread_indices: Vec<usize>,
}

fn compute_function_under_caller_metrics(
    profile: &ResolvedProfile,
    thread_indices: &[usize],
    function_name: &str,
    caller_name: &str,
    caller_relationship: call_tree::CallerRelationship,
) -> FunctionUnderCallerMetrics {
    let mut metrics = FunctionUnderCallerMetrics {
        scope_time_ms: scope_total_time_ms(profile, thread_indices),
        ..Default::default()
    };

    for index in thread_indices {
        let Some(thread) = profile.threads.get(*index) else {
            continue;
        };
        let interval_ms = call_tree::sample_interval_ms(thread);
        let mut thread_matched = false;

        for sample in &thread.samples {
            metrics.total_scope_samples += 1;

            if sample
                .stack
                .iter()
                .any(|frame| frame.function_name == caller_name)
            {
                metrics.caller_context_time_ms += interval_ms;
                metrics.caller_context_samples += 1;
            }

            let Some(function_index) = call_tree::function_under_caller_index(
                &sample.stack,
                function_name,
                caller_name,
                caller_relationship,
            ) else {
                continue;
            };

            metrics.descendant_time_ms += interval_ms;
            metrics.descendant_samples += 1;
            thread_matched = true;

            if function_index + 1 == sample.stack.len() {
                metrics.exclusive_time_ms += interval_ms;
                metrics.exclusive_samples += 1;
            }
        }

        if thread_matched {
            metrics.matched_thread_indices.push(*index);
        }
    }

    metrics
}

fn percent(numerator: f64, denominator: f64) -> f64 {
    if denominator > 0.0 {
        numerator / denominator * 100.0
    } else {
        0.0
    }
}

// ── Request types ──

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProfileInfoRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProfileThreadsRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TopFunctionsRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Thread name to analyze. If multiple threads have this name, the one with the most samples is used."
    )]
    #[serde(default)]
    pub thread: Option<String>,

    #[schemars(
        description = "Thread id to analyze. Prefer this when profile_threads shows duplicate names."
    )]
    #[serde(default)]
    pub tid: Option<String>,

    #[schemars(
        description = "Zero-based thread index from profile_threads. Prefer this for stable thread selection."
    )]
    #[serde(default)]
    pub thread_index: Option<usize>,

    #[schemars(description = "Sort by 'self' (default) or 'total' time")]
    #[serde(default = "default_sort_by")]
    pub sort_by: String,

    #[schemars(description = "Maximum number of functions to return (default: 20)")]
    #[serde(default = "default_limit")]
    pub limit: usize,

    #[schemars(
        description = "Optional case-insensitive include filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub include: Option<String>,

    #[schemars(
        description = "Optional case-insensitive exclude filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub exclude: Option<String>,

    #[schemars(
        description = "Exclude framework/runtime frames such as criterion, std/core/alloc, libc, and raw addresses"
    )]
    #[serde(default)]
    pub exclude_framework: bool,

    #[schemars(description = "Alias for exclude_framework")]
    #[serde(default)]
    pub user_code_only: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ThreadGroupTopFunctionsRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Thread name prefix to aggregate. A trailing '*' is accepted, e.g. rayon-gen-* matches names starting with rayon-gen-."
    )]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Thread name prefixes to aggregate into separate groups. A trailing '*' is accepted for prefix-style globs."
    )]
    #[serde(default)]
    pub thread_name_prefixes: Vec<String>,

    #[schemars(description = "Sort by 'self' (default) or 'total' time")]
    #[serde(default = "default_sort_by")]
    pub sort_by: String,

    #[schemars(description = "Maximum number of functions per group to return (default: 20)")]
    #[serde(default = "default_limit")]
    pub limit: usize,

    #[schemars(
        description = "Optional case-insensitive include filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub include: Option<String>,

    #[schemars(
        description = "Optional case-insensitive exclude filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub exclude: Option<String>,

    #[schemars(
        description = "Exclude framework/runtime frames such as criterion, std/core/alloc, libc, and raw addresses"
    )]
    #[serde(default)]
    pub exclude_framework: bool,

    #[schemars(description = "Alias for exclude_framework")]
    #[serde(default)]
    pub user_code_only: bool,
}

fn default_sort_by() -> String {
    "self".to_string()
}

fn default_limit() -> usize {
    20
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CallTreeRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Thread name to analyze. If multiple threads have this name, the one with the most samples is used."
    )]
    #[serde(default)]
    pub thread: Option<String>,

    #[schemars(
        description = "Thread id to analyze. Prefer this when profile_threads shows duplicate names."
    )]
    #[serde(default)]
    pub tid: Option<String>,

    #[schemars(
        description = "Zero-based thread index from profile_threads. Prefer this for stable thread selection."
    )]
    #[serde(default)]
    pub thread_index: Option<usize>,

    #[schemars(description = "Maximum depth of the call tree (default: 10)")]
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    #[schemars(description = "Minimum percentage to include a node (default: 1.0)")]
    #[serde(default = "default_min_percent")]
    pub min_percent: f64,

    #[schemars(
        description = "Exclude framework/runtime frames such as criterion, std/core/alloc, libc, and raw addresses"
    )]
    #[serde(default)]
    pub exclude_framework: bool,

    #[schemars(description = "Alias for exclude_framework")]
    #[serde(default)]
    pub user_code_only: bool,

    #[schemars(description = "Use compact Rust display names in the rendered tree")]
    #[serde(default)]
    pub short_names: bool,
}

fn default_max_depth() -> usize {
    10
}

fn default_min_percent() -> f64 {
    1.0
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FunctionDetailRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(description = "Full function name or substring to look up")]
    #[serde(default)]
    pub function_name: Option<String>,

    #[schemars(
        description = "Stable function id returned by profile_search_functions or profile_top_functions"
    )]
    #[serde(default)]
    pub function_id: Option<String>,

    #[schemars(description = "Match mode: 'contains' (default) or 'exact'")]
    #[serde(default = "default_match_mode")]
    pub match_mode: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkersRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Thread name. If multiple threads have this name, the one with the most samples is used."
    )]
    #[serde(default)]
    pub thread: Option<String>,

    #[schemars(description = "Thread id. Prefer this when profile_threads shows duplicate names.")]
    #[serde(default)]
    pub tid: Option<String>,

    #[schemars(description = "Zero-based thread index from profile_threads.")]
    #[serde(default)]
    pub thread_index: Option<usize>,

    #[schemars(description = "Maximum number of markers to return (default: 50)")]
    #[serde(default = "default_marker_limit")]
    pub limit: usize,
}

fn default_marker_limit() -> usize {
    50
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FlamegraphRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Thread name. If multiple threads have this name, the one with the most samples is used."
    )]
    #[serde(default)]
    pub thread: Option<String>,

    #[schemars(description = "Thread id. Prefer this when profile_threads shows duplicate names.")]
    #[serde(default)]
    pub tid: Option<String>,

    #[schemars(description = "Zero-based thread index from profile_threads.")]
    #[serde(default)]
    pub thread_index: Option<usize>,

    #[schemars(
        description = "Optional full function name or substring. If set, output stacks are sliced from that function down to leaf frames."
    )]
    #[serde(default)]
    pub focus_function: Option<String>,

    #[schemars(
        description = "Stable function id returned by profile_search_functions or profile_top_functions"
    )]
    #[serde(default)]
    pub focus_function_id: Option<String>,

    #[schemars(description = "Match mode for focus_function: 'contains' (default) or 'exact'")]
    #[serde(default = "default_match_mode")]
    pub match_mode: String,

    #[schemars(
        description = "Exclude framework/runtime frames such as criterion, std/core/alloc, libc, and raw addresses"
    )]
    #[serde(default)]
    pub exclude_framework: bool,

    #[schemars(description = "Alias for exclude_framework")]
    #[serde(default)]
    pub user_code_only: bool,

    #[schemars(description = "Use compact Rust display names in folded stacks")]
    #[serde(default)]
    pub short_names: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchFunctionsRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(description = "Function name substring or exact function name")]
    pub query: String,

    #[schemars(description = "Match mode: 'contains' (default) or 'exact'")]
    #[serde(default = "default_match_mode")]
    pub match_mode: String,

    #[schemars(description = "Optional thread name. If omitted, searches all threads.")]
    #[serde(default)]
    pub thread: Option<String>,

    #[schemars(
        description = "Optional thread id. Prefer this when profile_threads shows duplicate names."
    )]
    #[serde(default)]
    pub tid: Option<String>,

    #[schemars(description = "Optional zero-based thread index from profile_threads.")]
    #[serde(default)]
    pub thread_index: Option<usize>,

    #[schemars(description = "Sort by 'total' (default) or 'self' time")]
    #[serde(default = "default_search_sort_by")]
    pub sort_by: String,

    #[schemars(description = "Maximum number of functions to return (default: 20)")]
    #[serde(default = "default_limit")]
    pub limit: usize,

    #[schemars(
        description = "Optional case-insensitive include filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub include: Option<String>,

    #[schemars(
        description = "Optional case-insensitive exclude filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub exclude: Option<String>,

    #[schemars(
        description = "Exclude framework/runtime frames such as criterion, std/core/alloc, libc, and raw addresses"
    )]
    #[serde(default)]
    pub exclude_framework: bool,

    #[schemars(description = "Alias for exclude_framework")]
    #[serde(default)]
    pub user_code_only: bool,
}

fn default_search_sort_by() -> String {
    "total".to_string()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FocusFunctionRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(description = "Full function name or substring to focus on")]
    #[serde(default)]
    pub query: Option<String>,

    #[schemars(
        description = "Stable function id returned by profile_search_functions or profile_top_functions"
    )]
    #[serde(default)]
    pub function_id: Option<String>,

    #[schemars(description = "Match mode: 'contains' (default) or 'exact'")]
    #[serde(default = "default_match_mode")]
    pub match_mode: String,

    #[schemars(
        description = "Thread name. If multiple threads have this name, the one with the most samples is used."
    )]
    #[serde(default)]
    pub thread: Option<String>,

    #[schemars(description = "Thread id. Prefer this when profile_threads shows duplicate names.")]
    #[serde(default)]
    pub tid: Option<String>,

    #[schemars(description = "Zero-based thread index from profile_threads.")]
    #[serde(default)]
    pub thread_index: Option<usize>,

    #[schemars(description = "Maximum depth of the focused call tree (default: 10)")]
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    #[schemars(description = "Minimum focused percentage to include a node (default: 1.0)")]
    #[serde(default = "default_min_percent")]
    pub min_percent: f64,

    #[schemars(
        description = "Exclude framework/runtime frames such as criterion, std/core/alloc, libc, and raw addresses"
    )]
    #[serde(default)]
    pub exclude_framework: bool,

    #[schemars(description = "Alias for exclude_framework")]
    #[serde(default)]
    pub user_code_only: bool,

    #[schemars(description = "Use compact Rust display names in the rendered tree")]
    #[serde(default = "default_short_names")]
    pub short_names: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FunctionUnderCallerRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(description = "Full function name or substring for the function being measured")]
    #[serde(default)]
    pub function_name: Option<String>,

    #[schemars(
        description = "Stable function id for the function being measured, returned by profile_search_functions or profile_top_functions"
    )]
    #[serde(default)]
    pub function_id: Option<String>,

    #[schemars(description = "Full caller/ancestor function name or substring")]
    #[serde(default)]
    pub caller_name: Option<String>,

    #[schemars(
        description = "Stable function id for the caller/ancestor, returned by profile_search_functions or profile_top_functions"
    )]
    #[serde(default)]
    pub caller_function_id: Option<String>,

    #[schemars(description = "Match mode for function_name: 'contains' (default) or 'exact'")]
    #[serde(default = "default_match_mode")]
    pub match_mode: String,

    #[schemars(description = "Match mode for caller_name: 'contains' (default) or 'exact'")]
    #[serde(default = "default_match_mode")]
    pub caller_match_mode: String,

    #[schemars(
        description = "Caller relationship: 'ancestor' (default) allows any parent frame; 'immediate' requires the direct caller"
    )]
    #[serde(default = "default_caller_mode")]
    pub caller_mode: String,

    #[schemars(
        description = "Thread name. If multiple threads have this name, the one with the most samples is used."
    )]
    #[serde(default)]
    pub thread: Option<String>,

    #[schemars(description = "Thread id. Prefer this when profile_threads shows duplicate names.")]
    #[serde(default)]
    pub tid: Option<String>,

    #[schemars(description = "Zero-based thread index from profile_threads.")]
    #[serde(default)]
    pub thread_index: Option<usize>,

    #[schemars(
        description = "Thread name prefix to aggregate before measuring. A trailing '*' is accepted, e.g. chunk-worker*."
    )]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Thread name prefixes to aggregate before measuring. A trailing '*' is accepted for prefix-style globs."
    )]
    #[serde(default)]
    pub thread_name_prefixes: Vec<String>,

    #[schemars(description = "Maximum depth of the returned descendant tree (default: 10)")]
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,

    #[schemars(description = "Minimum focused percentage to include a tree node (default: 1.0)")]
    #[serde(default = "default_min_percent")]
    pub min_percent: f64,

    #[schemars(
        description = "Exclude framework/runtime frames such as criterion, std/core/alloc, libc, and raw addresses"
    )]
    #[serde(default)]
    pub exclude_framework: bool,

    #[schemars(description = "Alias for exclude_framework")]
    #[serde(default)]
    pub user_code_only: bool,

    #[schemars(description = "Use compact Rust display names in the rendered tree")]
    #[serde(default = "default_short_names")]
    pub short_names: bool,
}

fn default_caller_mode() -> String {
    "ancestor".to_string()
}

// ── Response types ──

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProfileInfoResult {
    pub product: String,
    pub duration_ms: f64,
    pub total_samples: usize,
    pub thread_count: usize,
    pub interval_ms: f64,
    pub categories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadInfo {
    pub index: usize,
    pub name: String,
    pub pid: String,
    pub tid: String,
    pub sample_count: usize,
    pub duration_ms: f64,
    pub is_main: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProfileThreadsResult {
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionRow {
    pub function_id: String,
    pub name: String,
    pub display_name: String,
    pub self_percent: f64,
    pub total_percent: f64,
    pub self_time_ms: f64,
    pub total_time_ms: f64,
    pub sample_count: usize,
    pub library: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TopFunctionsResult {
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub sort_by: String,
    pub functions: Vec<FunctionRow>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadGroupTopFunctionsResult {
    pub groups: Vec<ThreadGroupTopFunctionsGroup>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadGroupTopFunctionsGroup {
    pub thread_name_prefix: String,
    pub normalized_thread_name_prefix: String,
    pub thread_count: usize,
    pub sample_count: usize,
    pub total_time_ms: f64,
    pub sort_by: String,
    pub threads: Vec<ThreadInfo>,
    pub functions: Vec<FunctionRow>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionSearchRow {
    pub function_id: String,
    pub name: String,
    pub display_name: String,
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub self_percent: f64,
    pub total_percent: f64,
    pub self_time_ms: f64,
    pub total_time_ms: f64,
    pub sample_count: usize,
    pub library: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SearchFunctionsResult {
    pub query: String,
    pub match_mode: String,
    pub functions: Vec<FunctionSearchRow>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CallerCalleeEntry {
    pub function_id: String,
    pub function_name: String,
    pub display_name: String,
    pub count: usize,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionDetailResult {
    pub function_id: String,
    pub function_name: String,
    pub display_name: String,
    pub self_time_ms: f64,
    pub total_time_ms: f64,
    pub self_percent: f64,
    pub total_percent: f64,
    pub sample_count: usize,
    pub library: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub source: Option<String>,
    pub callers: Vec<CallerCalleeEntry>,
    pub callees: Vec<CallerCalleeEntry>,
    pub threads: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CallTreeResult {
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub tree: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarkerInfo {
    pub name: String,
    pub start_time: Option<f64>,
    pub end_time: Option<f64>,
    pub category: String,
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarkersResult {
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub markers: Vec<MarkerInfo>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FlamegraphResult {
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub focus_function: Option<String>,
    pub focus_function_id: Option<String>,
    pub focus_display_name: Option<String>,
    pub collapsed_stacks: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FocusFunctionResult {
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub function_id: String,
    pub function_name: String,
    pub display_name: String,
    pub matched_samples: usize,
    pub total_thread_samples: usize,
    pub focused_percent: f64,
    pub focused_time_ms: f64,
    pub tree: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionUnderCallerResult {
    pub scope: String,
    pub thread_count: usize,
    pub threads: Vec<ThreadInfo>,
    pub matched_threads: Vec<ThreadInfo>,
    pub function_id: String,
    pub function_name: String,
    pub display_name: String,
    pub caller_function_id: String,
    pub caller_function_name: String,
    pub caller_display_name: String,
    pub caller_mode: String,
    pub exclusive_time_ms: f64,
    pub descendant_time_ms: f64,
    pub caller_context_time_ms: f64,
    pub scope_time_ms: f64,
    pub exclusive_percent_of_scope: f64,
    pub descendant_percent_of_scope: f64,
    pub caller_context_percent_of_scope: f64,
    pub descendant_percent_of_caller: f64,
    pub exclusive_samples: usize,
    pub descendant_samples: usize,
    pub caller_context_samples: usize,
    pub total_scope_samples: usize,
    pub tree: String,
}

// ── Tool implementations ──

#[tool_router]
impl ProfileServer {
    #[tool(
        description = "Get profile metadata: duration, sample count, thread count, sampling interval, and categories"
    )]
    fn profile_info(
        &self,
        Parameters(req): Parameters<ProfileInfoRequest>,
    ) -> Result<Json<ProfileInfoResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let profile = &cached.profile;

        Ok(Json(ProfileInfoResult {
            product: profile.product.clone(),
            duration_ms: profile.duration_ms,
            total_samples: profile.total_sample_count,
            thread_count: profile.threads.len(),
            interval_ms: profile.interval_ms,
            categories: profile.categories.clone(),
        }))
    }

    #[tool(
        description = "List all threads with names, sample counts, time ranges, and whether they are the main thread"
    )]
    fn profile_threads(
        &self,
        Parameters(req): Parameters<ProfileThreadsRequest>,
    ) -> Result<Json<ProfileThreadsResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let profile = &cached.profile;

        let threads = profile
            .threads
            .iter()
            .enumerate()
            .map(|(index, t)| ThreadInfo {
                index,
                name: t.name.clone(),
                pid: t.pid.clone(),
                tid: t.tid.clone(),
                sample_count: t.samples.len(),
                duration_ms: t.duration_ms,
                is_main: t.is_main,
            })
            .collect();

        Ok(Json(ProfileThreadsResult { threads }))
    }

    #[tool(
        description = "Get top N functions by self-time or total-time for a thread. Use sort_by='self' for CPU hotspots, sort_by='total' for functions dominating the call tree."
    )]
    fn profile_top_functions(
        &self,
        Parameters(req): Parameters<TopFunctionsRequest>,
    ) -> Result<Json<TopFunctionsResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let selected = select_thread(&cached.profile, &req.thread, &req.tid, req.thread_index)?;
        let thread = selected.thread;

        let mut stats = cached
            .cache
            .function_stats
            .get(selected.index)
            .cloned()
            .unwrap_or_default();

        sort_function_stats(&mut stats, &req.sort_by);
        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);

        let functions = stats
            .into_iter()
            .filter(|s| function_passes_filters(s, &req.include, &req.exclude, exclude_framework))
            .take(req.limit)
            .map(|s| FunctionRow {
                function_id: symbols::function_id(&s.name),
                display_name: symbols::compact_function_name(&s.name),
                source: source_location(&s.file, s.line),
                name: s.name,
                self_percent: round2(s.self_percent),
                total_percent: round2(s.total_percent),
                self_time_ms: round2(s.self_time_ms),
                total_time_ms: round2(s.total_time_ms),
                sample_count: s.sample_count,
                library: s.library,
                file: s.file,
                line: s.line,
            })
            .collect();

        Ok(Json(TopFunctionsResult {
            thread: thread.name.clone(),
            tid: thread.tid.clone(),
            thread_index: selected.index,
            sort_by: req.sort_by,
            functions,
        }))
    }

    #[tool(
        description = "Aggregate top functions across groups of threads selected by name prefix, e.g. rayon-gen-* or chunk-worker."
    )]
    fn profile_thread_group_top_functions(
        &self,
        Parameters(req): Parameters<ThreadGroupTopFunctionsRequest>,
    ) -> Result<Json<ThreadGroupTopFunctionsResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let prefixes =
            requested_thread_prefixes(&req.thread_name_prefix, &req.thread_name_prefixes);

        if prefixes.is_empty() {
            return Err(
                "Provide thread_name_prefix or thread_name_prefixes, e.g. rayon-gen-*".to_string(),
            );
        }

        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let mut groups = Vec::new();
        let mut matched_any = false;

        for prefix in prefixes {
            let normalized_prefix = normalized_thread_prefix(&prefix);
            let thread_indices: Vec<usize> = cached
                .profile
                .threads
                .iter()
                .enumerate()
                .filter(|(_, thread)| thread.name.starts_with(&normalized_prefix))
                .map(|(index, _)| index)
                .collect();

            if !thread_indices.is_empty() {
                matched_any = true;
            }

            let (mut stats, total_time_ms, sample_count) =
                aggregate_function_stats(&cached, &thread_indices);
            sort_function_stats(&mut stats, &req.sort_by);

            let functions = stats
                .into_iter()
                .filter(|s| {
                    function_passes_filters(s, &req.include, &req.exclude, exclude_framework)
                })
                .take(req.limit)
                .map(|s| FunctionRow {
                    function_id: symbols::function_id(&s.name),
                    display_name: symbols::compact_function_name(&s.name),
                    source: source_location(&s.file, s.line),
                    name: s.name,
                    self_percent: round2(s.self_percent),
                    total_percent: round2(s.total_percent),
                    self_time_ms: round2(s.self_time_ms),
                    total_time_ms: round2(s.total_time_ms),
                    sample_count: s.sample_count,
                    library: s.library,
                    file: s.file,
                    line: s.line,
                })
                .collect();

            groups.push(ThreadGroupTopFunctionsGroup {
                thread_name_prefix: prefix,
                normalized_thread_name_prefix: normalized_prefix,
                thread_count: thread_indices.len(),
                sample_count,
                total_time_ms: round2(total_time_ms),
                sort_by: req.sort_by.clone(),
                threads: thread_infos(&cached.profile, &thread_indices),
                functions,
            });
        }

        if !matched_any {
            return Err("No threads matched the requested prefix group(s)".to_string());
        }

        Ok(Json(ThreadGroupTopFunctionsResult { groups }))
    }

    #[tool(
        description = "Search function names by substring or exact match. Returns full symbol names with thread ids and timing so follow-up tools can use exact names or stable thread selectors."
    )]
    fn profile_search_functions(
        &self,
        Parameters(req): Parameters<SearchFunctionsRequest>,
    ) -> Result<Json<SearchFunctionsResult>, String> {
        let cached = self.get_profile(&req.path)?;

        let selected = if req.thread.is_some() || req.tid.is_some() || req.thread_index.is_some() {
            Some(select_thread(
                &cached.profile,
                &req.thread,
                &req.tid,
                req.thread_index,
            )?)
        } else {
            None
        };

        let mut rows = Vec::new();
        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        for (index, thread) in cached.profile.threads.iter().enumerate() {
            if let Some(selected) = &selected
                && selected.index != index
            {
                continue;
            }

            let Some(stats) = cached.cache.function_stats.get(index) else {
                continue;
            };

            for stat in stats {
                if !function_matches(&stat.name, &req.query, &req.match_mode)
                    || !function_passes_filters(stat, &req.include, &req.exclude, exclude_framework)
                {
                    continue;
                }

                rows.push(FunctionSearchRow {
                    function_id: symbols::function_id(&stat.name),
                    display_name: symbols::compact_function_name(&stat.name),
                    name: stat.name.clone(),
                    thread: thread.name.clone(),
                    tid: thread.tid.clone(),
                    thread_index: index,
                    self_percent: round2(stat.self_percent),
                    total_percent: round2(stat.total_percent),
                    self_time_ms: round2(stat.self_time_ms),
                    total_time_ms: round2(stat.total_time_ms),
                    sample_count: stat.sample_count,
                    library: stat.library.clone(),
                    file: stat.file.clone(),
                    line: stat.line,
                    source: source_location(&stat.file, stat.line),
                });
            }
        }

        if req.sort_by == "self" {
            rows.sort_by(|a, b| b.self_time_ms.total_cmp(&a.self_time_ms));
        } else {
            rows.sort_by(|a, b| b.total_time_ms.total_cmp(&a.total_time_ms));
        }
        rows.truncate(req.limit);

        Ok(Json(SearchFunctionsResult {
            query: req.query,
            match_mode: req.match_mode,
            functions: rows,
        }))
    }

    #[tool(
        description = "Get detailed information about a specific function: callers, callees, source locations, time breakdown. Searches across all threads."
    )]
    fn profile_function_detail(
        &self,
        Parameters(req): Parameters<FunctionDetailRequest>,
    ) -> Result<Json<FunctionDetailResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let profile = &cached.profile;
        let target = resolve_function_name(
            &cached.cache.function_stats,
            req.function_name.as_deref(),
            req.function_id.as_deref(),
            &req.match_mode,
            None,
        )
        .ok_or_else(|| {
            "Function not found in any thread. Provide function_id or function_name; try profile_search_functions for substring matches.".to_string()
        })?;

        let mut total_self_time = 0.0;
        let mut total_total_time = 0.0;
        let mut total_self_pct = 0.0;
        let mut total_total_pct = 0.0;
        let mut total_samples = 0usize;
        let mut library = None;
        let mut file = None;
        let mut line = None;
        let mut callers: HashMap<String, usize> = HashMap::new();
        let mut callees: HashMap<String, usize> = HashMap::new();
        let mut found_threads = Vec::new();

        for (thread_index, thread) in profile.threads.iter().enumerate() {
            // Check function stats
            if let Some(stats) = cached.cache.function_stats.get(thread_index)
                && let Some(s) = stats.iter().find(|s| s.name == target)
            {
                total_self_time += s.self_time_ms;
                total_total_time += s.total_time_ms;
                total_self_pct += s.self_percent;
                total_total_pct += s.total_percent;
                total_samples += s.sample_count;
                if library.is_none() {
                    library = s.library.clone();
                }
                if file.is_none() {
                    file = s.file.clone();
                }
                if line.is_none() {
                    line = s.line;
                }
                found_threads.push(thread_label(thread_index, thread));
            }

            // Find callers and callees from actual stacks
            for sample in &thread.samples {
                for (i, frame) in sample.stack.iter().enumerate() {
                    if frame.function_name == target {
                        // Caller is the previous frame in the stack
                        if i > 0 {
                            *callers
                                .entry(sample.stack[i - 1].function_name.clone())
                                .or_default() += 1;
                        }
                        // Callee is the next frame
                        if i + 1 < sample.stack.len() {
                            *callees
                                .entry(sample.stack[i + 1].function_name.clone())
                                .or_default() += 1;
                        }
                    }
                }
            }
        }

        if found_threads.is_empty() {
            return Err(format!("Function '{target}' not found in any thread"));
        }

        let mut callers: Vec<CallerCalleeEntry> = callers
            .into_iter()
            .map(|(name, count)| CallerCalleeEntry {
                function_id: symbols::function_id(&name),
                display_name: symbols::compact_function_name(&name),
                function_name: name,
                count,
            })
            .collect();
        callers.sort_by_key(|entry| Reverse(entry.count));

        let mut callees: Vec<CallerCalleeEntry> = callees
            .into_iter()
            .map(|(name, count)| CallerCalleeEntry {
                function_id: symbols::function_id(&name),
                display_name: symbols::compact_function_name(&name),
                function_name: name,
                count,
            })
            .collect();
        callees.sort_by_key(|entry| Reverse(entry.count));

        Ok(Json(FunctionDetailResult {
            function_id: symbols::function_id(&target),
            display_name: symbols::compact_function_name(&target),
            function_name: target,
            self_time_ms: round2(total_self_time),
            total_time_ms: round2(total_total_time),
            self_percent: round2(total_self_pct),
            total_percent: round2(total_total_pct),
            sample_count: total_samples,
            library,
            source: source_location(&file, line),
            file,
            line,
            callers,
            callees,
            threads: found_threads,
        }))
    }

    #[tool(
        description = "Get a hierarchical call tree showing where time is spent, with configurable depth and minimum percentage threshold"
    )]
    fn profile_call_tree(
        &self,
        Parameters(req): Parameters<CallTreeRequest>,
    ) -> Result<Json<CallTreeResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let selected = select_thread(&cached.profile, &req.thread, &req.tid, req.thread_index)?;
        let thread = selected.thread;

        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let tree = call_tree::build_call_tree_with_filter(
            thread,
            req.max_depth,
            req.min_percent,
            |name| !exclude_framework || !symbols::is_framework_function(name, None),
        );
        let text = tree.render_text_with_options(req.max_depth, req.short_names, false);

        Ok(Json(CallTreeResult {
            thread: thread.name.clone(),
            tid: thread.tid.clone(),
            thread_index: selected.index,
            tree: text,
        }))
    }

    #[tool(
        description = "Focus on a function by full name or substring. Reroots stacks at the matched function and reports a call tree relative only to samples containing that function."
    )]
    fn profile_focus_function(
        &self,
        Parameters(req): Parameters<FocusFunctionRequest>,
    ) -> Result<Json<FocusFunctionResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let selected = select_thread(&cached.profile, &req.thread, &req.tid, req.thread_index)?;
        let thread = selected.thread;

        let function_name = resolve_function_name(
            &cached.cache.function_stats,
            req.query.as_deref(),
            req.function_id.as_deref(),
            &req.match_mode,
            Some(selected.index),
        )
        .ok_or_else(|| {
            format!(
                "Function not found in thread {}. Provide function_id or query; try profile_search_functions first.",
                thread_label(selected.index, thread)
            )
        })?;

        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let focused = call_tree::build_focused_call_tree_with_filter(
            thread,
            &function_name,
            req.max_depth,
            req.min_percent,
            |name| !exclude_framework || !symbols::is_framework_function(name, None),
        )
        .ok_or_else(|| {
            format!(
                "Function '{}' did not appear in any samples on thread {}",
                function_name,
                thread_label(selected.index, thread)
            )
        })?;
        let text = focused
            .tree
            .render_text_with_options(req.max_depth, req.short_names, true);

        Ok(Json(FocusFunctionResult {
            thread: thread.name.clone(),
            tid: thread.tid.clone(),
            thread_index: selected.index,
            function_id: symbols::function_id(&function_name),
            display_name: symbols::compact_function_name(&function_name),
            function_name,
            matched_samples: focused.sample_count,
            total_thread_samples: focused.total_samples,
            focused_percent: round2(focused.focused_percent),
            focused_time_ms: round2(focused.focused_time_ms),
            tree: text,
        }))
    }

    #[tool(
        description = "Measure a function only when it appears under a specific caller/ancestor, including exclusive and descendant time. Can aggregate across thread name prefixes."
    )]
    fn profile_function_under_caller(
        &self,
        Parameters(req): Parameters<FunctionUnderCallerRequest>,
    ) -> Result<Json<FunctionUnderCallerResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let profile = &cached.profile;
        let (scope, thread_indices) = select_thread_indices_for_scope(
            profile,
            &req.thread,
            &req.tid,
            req.thread_index,
            &req.thread_name_prefix,
            &req.thread_name_prefixes,
        )?;
        let caller_relationship = parse_caller_relationship(&req.caller_mode)?;

        let function_name = resolve_function_name_in_threads(
            &cached.cache.function_stats,
            req.function_name.as_deref(),
            req.function_id.as_deref(),
            &req.match_mode,
            Some(&thread_indices),
        )
        .ok_or_else(|| {
            "Function not found in selected thread scope. Provide function_id or function_name; try profile_search_functions first.".to_string()
        })?;

        let caller_name = resolve_function_name_in_threads(
            &cached.cache.function_stats,
            req.caller_name.as_deref(),
            req.caller_function_id.as_deref(),
            &req.caller_match_mode,
            Some(&thread_indices),
        )
        .ok_or_else(|| {
            "Caller function not found in selected thread scope. Provide caller_function_id or caller_name; try profile_search_functions first.".to_string()
        })?;

        let metrics = compute_function_under_caller_metrics(
            profile,
            &thread_indices,
            &function_name,
            &caller_name,
            caller_relationship,
        );

        if metrics.descendant_samples == 0 {
            return Err(format!(
                "Function '{}' did not appear under caller '{}' in scope {}",
                function_name, caller_name, scope
            ));
        }

        let thread_refs: Vec<&ResolvedThread> = thread_indices
            .iter()
            .filter_map(|index| profile.threads.get(*index))
            .collect();
        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let focused = call_tree::build_focused_call_tree_under_caller_with_filter(
            &thread_refs,
            &function_name,
            &caller_name,
            caller_relationship,
            req.max_depth,
            req.min_percent,
            |name| !exclude_framework || !symbols::is_framework_function(name, None),
        )
        .ok_or_else(|| {
            format!(
                "Function '{}' did not appear under caller '{}' in scope {}",
                function_name, caller_name, scope
            )
        })?;
        let tree = focused
            .tree
            .render_text_with_options(req.max_depth, req.short_names, true);

        Ok(Json(FunctionUnderCallerResult {
            scope,
            thread_count: thread_indices.len(),
            threads: thread_infos(profile, &thread_indices),
            matched_threads: thread_infos(profile, &metrics.matched_thread_indices),
            function_id: symbols::function_id(&function_name),
            display_name: symbols::compact_function_name(&function_name),
            function_name,
            caller_function_id: symbols::function_id(&caller_name),
            caller_display_name: symbols::compact_function_name(&caller_name),
            caller_function_name: caller_name,
            caller_mode: caller_relationship_label(caller_relationship).to_string(),
            exclusive_time_ms: round2(metrics.exclusive_time_ms),
            descendant_time_ms: round2(metrics.descendant_time_ms),
            caller_context_time_ms: round2(metrics.caller_context_time_ms),
            scope_time_ms: round2(metrics.scope_time_ms),
            exclusive_percent_of_scope: round2(percent(
                metrics.exclusive_time_ms,
                metrics.scope_time_ms,
            )),
            descendant_percent_of_scope: round2(percent(
                metrics.descendant_time_ms,
                metrics.scope_time_ms,
            )),
            caller_context_percent_of_scope: round2(percent(
                metrics.caller_context_time_ms,
                metrics.scope_time_ms,
            )),
            descendant_percent_of_caller: round2(percent(
                metrics.descendant_time_ms,
                metrics.caller_context_time_ms,
            )),
            exclusive_samples: metrics.exclusive_samples,
            descendant_samples: metrics.descendant_samples,
            caller_context_samples: metrics.caller_context_samples,
            total_scope_samples: metrics.total_scope_samples,
            tree,
        }))
    }

    #[tool(
        description = "Get timeline markers/events for a thread, including their timing, category, and associated data"
    )]
    fn profile_markers(
        &self,
        Parameters(req): Parameters<MarkersRequest>,
    ) -> Result<Json<MarkersResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let selected = select_thread(&cached.profile, &req.thread, &req.tid, req.thread_index)?;
        let thread = selected.thread;

        let markers: Vec<MarkerInfo> = thread
            .markers
            .iter()
            .take(req.limit)
            .map(|m| MarkerInfo {
                name: m.name.clone(),
                start_time: m.start_time,
                end_time: m.end_time,
                category: m.category.clone(),
                data: m.data.clone(),
            })
            .collect();

        Ok(Json(MarkersResult {
            thread: thread.name.clone(),
            tid: thread.tid.clone(),
            thread_index: selected.index,
            markers,
        }))
    }

    #[tool(
        description = "Get collapsed stack format (Brendan Gregg's folded format) for generating flamegraphs. Each line: func1;func2;func3 count"
    )]
    fn profile_flamegraph(
        &self,
        Parameters(req): Parameters<FlamegraphRequest>,
    ) -> Result<Json<FlamegraphResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let selected = select_thread(&cached.profile, &req.thread, &req.tid, req.thread_index)?;
        let thread = selected.thread;

        let focus_function = if let Some(query) = &req.focus_function {
            Some(
                resolve_function_name(
                    &cached.cache.function_stats,
                    Some(query),
                    req.focus_function_id.as_deref(),
                    &req.match_mode,
                    Some(selected.index),
                )
                .ok_or_else(|| {
                    format!(
                        "Function '{}' not found in thread {}. Try profile_search_functions first.",
                        query,
                        thread_label(selected.index, thread)
                    )
                })?,
            )
        } else if let Some(function_id) = &req.focus_function_id {
            Some(
                resolve_function_name(
                    &cached.cache.function_stats,
                    None,
                    Some(function_id),
                    &req.match_mode,
                    Some(selected.index),
                )
                .ok_or_else(|| {
                    format!(
                        "Function id '{}' not found in thread {}. Try profile_search_functions first.",
                        function_id,
                        thread_label(selected.index, thread)
                    )
                })?,
            )
        } else {
            None
        };

        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let stacks = flamegraph::collapsed_stacks_with_options(
            thread,
            focus_function.as_deref(),
            |name| !exclude_framework || !symbols::is_framework_function(name, None),
            req.short_names,
        );
        let focus_function_id = focus_function
            .as_ref()
            .map(|function_name| symbols::function_id(function_name));
        let focus_display_name = focus_function
            .as_ref()
            .map(|function_name| symbols::compact_function_name(function_name));

        Ok(Json(FlamegraphResult {
            thread: thread.name.clone(),
            tid: thread.tid.clone(),
            thread_index: selected.index,
            focus_function,
            focus_function_id,
            focus_display_name,
            collapsed_stacks: stacks,
        }))
    }
}

// ── Server handler ──

#[tool_handler]
impl ServerHandler for ProfileServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Samply profiler analysis tools. Every tool requires a `path` parameter \
                 pointing to a profile JSON file (or .json.gz). Use profile_info for metadata \
                 overview and profile_threads to list threads. Prefer `thread_index` or `tid` \
                 from profile_threads when selecting a thread, because thread names can repeat. \
                 Use profile_top_functions to find CPU hotspots, profile_search_functions to \
                 find full Rust symbol names and stable function_id values from short substrings, \
                 profile_thread_group_top_functions to aggregate hotspots across thread name \
                 prefixes such as rayon-gen-* or chunk-worker, \
                 profile_focus_function to reroot stacks at a function with percentages scaled \
                 to matching samples, profile_function_under_caller for exclusive/descendant \
                 time when a function appears under a specific caller/ancestor, \
                 profile_call_tree for full hierarchical call analysis, \
                 profile_function_detail for callers/callees, profile_markers for timeline \
                 events, and profile_flamegraph for collapsed stack output. Prefer \
                 exclude_framework=true or user_code_only=true for Rust/Criterion profiles. \
                 Result rows include display_name for compact Rust symbols and source when \
                 file/line data is present. Focused trees show both focus and thread percentages."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

pub async fn run_server() -> Result<()> {
    let server = ProfileServer::new();

    let service = server
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;

    service.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::resolved::ResolvedSample;

    fn sample() -> ResolvedSample {
        ResolvedSample {
            timestamp_ms: 0.0,
            weight: 1,
            cpu_delta_us: None,
            stack: vec![],
        }
    }

    fn thread(name: &str, tid: &str, is_main: bool, sample_count: usize) -> ResolvedThread {
        ResolvedThread {
            name: name.to_string(),
            pid: "1".to_string(),
            tid: tid.to_string(),
            is_main,
            samples: (0..sample_count).map(|_| sample()).collect(),
            markers: vec![],
            duration_ms: sample_count as f64,
        }
    }

    fn profile() -> ResolvedProfile {
        ResolvedProfile {
            threads: vec![
                thread("app", "1", true, 5),
                thread("app", "2", true, 50),
                thread("worker", "3", false, 100),
            ],
            product: "test".to_string(),
            interval_ms: 1.0,
            categories: vec![],
            duration_ms: 100.0,
            total_sample_count: 155,
        }
    }

    #[test]
    fn select_thread_defaults_to_main_thread_with_most_samples() {
        let profile = profile();

        let selected = select_thread(&profile, &None, &None, None).unwrap();

        assert_eq!(selected.index, 1);
        assert_eq!(selected.thread.tid, "2");
    }

    #[test]
    fn select_thread_name_uses_matching_thread_with_most_samples() {
        let profile = profile();

        let selected = select_thread(&profile, &Some("app".to_string()), &None, None).unwrap();

        assert_eq!(selected.index, 1);
        assert_eq!(selected.thread.tid, "2");
    }

    #[test]
    fn select_thread_tid_and_index_are_stable() {
        let profile = profile();

        let by_tid = select_thread(&profile, &None, &Some("1".to_string()), None).unwrap();
        let by_index = select_thread(&profile, &None, &None, Some(2)).unwrap();

        assert_eq!(by_tid.index, 0);
        assert_eq!(by_index.thread.name, "worker");
    }
}
