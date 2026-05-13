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
    if let Some(function_id) = function_id {
        return stats_by_thread
            .iter()
            .enumerate()
            .filter(|(index, _)| thread_index.is_none_or(|selected| selected == *index))
            .flat_map(|(_, stats)| stats.iter())
            .find(|stats| symbols::function_id(&stats.name) == function_id)
            .map(|stats| stats.name.clone());
    }

    let query = query?;
    let stats_iter = stats_by_thread
        .iter()
        .enumerate()
        .filter(|(index, _)| thread_index.is_none_or(|selected| selected == *index))
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
                 profile_focus_function to reroot stacks at a function with percentages scaled \
                 to matching samples, profile_call_tree for full hierarchical call analysis, \
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
