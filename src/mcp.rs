use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::SystemTime;

use anyhow::Result;
use regex::Regex;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router};
use serde::{Deserialize, Serialize};

use crate::analysis::call_tree;
use crate::analysis::context_switch;
use crate::analysis::flamegraph;
use crate::analysis::functions::{self, FunctionStats};
use crate::analysis::samples::{self, AnalysisRange};
use crate::analysis::source;
use crate::analysis::symbols;
use crate::c2c::{
    C2cCallchainFrame, C2cProfile, C2cSample, C2cStats, MappedDataAddress, MappedInstruction,
};
use crate::profile::dwarf::DwarfLibraryResolver;
use crate::profile::parse::{find_syms_sidecar, load_profile};
use crate::profile::resolved::{ResolvedLibrary, ResolvedProfile, ResolvedThread};

/// Pre-computed analysis data cached per thread
#[derive(Debug)]
struct AnalysisCache {
    function_stats: Vec<OnceLock<Vec<FunctionStats>>>,
}

impl AnalysisCache {
    fn build(profile: &ResolvedProfile) -> Self {
        let function_stats = (0..profile.threads.len())
            .map(|_| OnceLock::new())
            .collect();
        AnalysisCache { function_stats }
    }

    fn function_stats<'a>(
        &'a self,
        profile: &ResolvedProfile,
        thread_index: usize,
    ) -> Option<&'a Vec<FunctionStats>> {
        let stats = self.function_stats.get(thread_index)?;
        let thread = profile.threads.get(thread_index)?;
        Some(
            stats.get_or_init(|| {
                functions::compute_function_stats(thread, profile.interval_ms, None)
            }),
        )
    }
}

/// A loaded and analyzed profile with its cache.
struct CachedProfile {
    profile: Arc<ResolvedProfile>,
    cache: Arc<AnalysisCache>,
    fingerprint: ProfileFingerprint,
}

struct ProfileCacheEntry {
    path: PathBuf,
    profile: Arc<CachedProfile>,
}

#[derive(Default)]
struct ProfileCacheState {
    entry: Option<ProfileCacheEntry>,
    active_path: Option<PathBuf>,
    active_requests: usize,
    loading_path: Option<PathBuf>,
    waiters: HashMap<PathBuf, usize>,
    #[cfg(test)]
    loads_started: usize,
}

#[derive(Default)]
struct ProfileCache {
    state: Mutex<ProfileCacheState>,
    idle: Condvar,
}

struct C2cCacheEntry {
    path: PathBuf,
    fingerprint: FileFingerprint,
    profile: Arc<C2cProfile>,
}

struct CachedProfileLease {
    cached: Arc<CachedProfile>,
    owner: Arc<ProfileCache>,
    path: PathBuf,
}

impl Deref for CachedProfileLease {
    type Target = CachedProfile;

    fn deref(&self) -> &Self::Target {
        &self.cached
    }
}

impl Drop for CachedProfileLease {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap();
        debug_assert_eq!(state.active_path.as_ref(), Some(&self.path));
        debug_assert!(state.active_requests > 0);

        state.active_requests -= 1;
        if state.active_requests == 0 {
            state.active_path = None;
            self.owner.idle.notify_all();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    modified: SystemTime,
    len: u64,
}

impl FileFingerprint {
    fn read(path: &PathBuf) -> Result<Self, String> {
        let metadata = fs::metadata(path)
            .map_err(|e| format!("Failed to stat '{}': {}", path.display(), e))?;
        let modified = metadata
            .modified()
            .map_err(|e| format!("Failed to read mtime for '{}': {}", path.display(), e))?;

        Ok(Self {
            modified,
            len: metadata.len(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProfileFingerprint {
    profile: FileFingerprint,
    symbols: Option<FileFingerprint>,
}

impl ProfileFingerprint {
    fn read(path: &PathBuf) -> Result<Self, String> {
        let profile = FileFingerprint::read(path)?;
        let symbols = find_syms_sidecar(path)
            .map(|path| FileFingerprint::read(&path))
            .transpose()?;

        Ok(Self { profile, symbols })
    }
}

#[derive(Clone)]
pub struct ProfileServer {
    profiles: Arc<ProfileCache>,
    c2c_profile: Arc<Mutex<Option<C2cCacheEntry>>>,
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
            profiles: Arc::new(ProfileCache::default()),
            c2c_profile: Arc::new(Mutex::new(None)),
            tool_router: Self::tool_router(),
        }
    }

    fn get_profile(&self, path: &str) -> Result<CachedProfileLease, String> {
        let canonical =
            std::fs::canonicalize(path).map_err(|e| format!("Invalid path '{}': {}", path, e))?;

        let mut state = self.profiles.state.lock().unwrap();
        *state.waiters.entry(canonical.clone()).or_default() += 1;

        loop {
            if state.loading_path.is_some() {
                state = self.profiles.idle.wait(state).unwrap();
                continue;
            }

            if state
                .entry
                .as_ref()
                .is_some_and(|entry| entry.path == canonical)
            {
                let fingerprint = match ProfileFingerprint::read(&canonical) {
                    Ok(fingerprint) => fingerprint,
                    Err(error) => {
                        remove_profile_waiter(&mut state, &canonical);
                        self.profiles.idle.notify_all();
                        return Err(error);
                    }
                };
                if let Some(profile) = state.entry.as_ref().and_then(|entry| {
                    (entry.profile.fingerprint == fingerprint).then(|| Arc::clone(&entry.profile))
                }) {
                    remove_profile_waiter(&mut state, &canonical);
                    state.active_path = Some(canonical.clone());
                    state.active_requests += 1;
                    return Ok(CachedProfileLease {
                        cached: profile,
                        owner: Arc::clone(&self.profiles),
                        path: canonical,
                    });
                }
            }

            if state.active_requests > 0 {
                state = self.profiles.idle.wait(state).unwrap();
                continue;
            }

            // Let requests already waiting for the resident path consume it
            // before a different path evicts it. This turns a concurrent
            // info/threads pair into one load even when cross-path waiters race.
            let resident_has_waiters = state.entry.as_ref().is_some_and(|entry| {
                entry.path != canonical && state.waiters.get(&entry.path).copied().unwrap_or(0) > 0
            });
            if resident_has_waiters {
                state = self.profiles.idle.wait(state).unwrap();
                continue;
            }

            remove_profile_waiter(&mut state, &canonical);
            state.entry = None;
            state.loading_path = Some(canonical.clone());
            #[cfg(test)]
            {
                state.loads_started += 1;
            }
            drop(state);

            let loaded = (|| {
                let profile = load_profile(&canonical)
                    .map_err(|e| format!("Failed to load profile '{}': {}", path, e))?;
                let analysis_cache = AnalysisCache::build(&profile);
                let fingerprint = ProfileFingerprint::read(&canonical)?;
                Ok::<_, String>(Arc::new(CachedProfile {
                    profile: Arc::new(profile),
                    cache: Arc::new(analysis_cache),
                    fingerprint,
                }))
            })();

            state = self.profiles.state.lock().unwrap();
            debug_assert_eq!(state.loading_path.as_ref(), Some(&canonical));
            state.loading_path = None;

            match loaded {
                Ok(cached) => {
                    state.entry = Some(ProfileCacheEntry {
                        path: canonical.clone(),
                        profile: Arc::clone(&cached),
                    });
                    state.active_path = Some(canonical.clone());
                    state.active_requests += 1;
                    self.profiles.idle.notify_all();
                    return Ok(CachedProfileLease {
                        cached,
                        owner: Arc::clone(&self.profiles),
                        path: canonical,
                    });
                }
                Err(error) => {
                    self.profiles.idle.notify_all();
                    return Err(error);
                }
            }
        }
    }

    fn get_c2c_profile(&self, path: &str) -> Result<Arc<C2cProfile>, String> {
        let canonical = std::fs::canonicalize(path)
            .map_err(|error| format!("Invalid path '{path}': {error}"))?;
        let fingerprint = FileFingerprint::read(&canonical)?;
        let mut cached = self.c2c_profile.lock().unwrap();
        if let Some(entry) = cached.as_ref()
            && entry.path == canonical
            && entry.fingerprint == fingerprint
        {
            return Ok(Arc::clone(&entry.profile));
        }

        let profile = crate::c2c::load_profile(&canonical)
            .map_err(|error| format!("Failed to load c2c profile '{path}': {error:#}"))?;
        let profile = Arc::new(profile);
        *cached = Some(C2cCacheEntry {
            path: canonical,
            fingerprint,
            profile: Arc::clone(&profile),
        });
        Ok(profile)
    }
}

fn remove_profile_waiter(state: &mut ProfileCacheState, path: &PathBuf) {
    let Some(waiter_count) = state.waiters.get_mut(path) else {
        return;
    };
    *waiter_count -= 1;
    if *waiter_count == 0 {
        state.waiters.remove(path);
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

fn select_sample_thread<'a>(
    profile: &'a ResolvedProfile,
    thread_name: &Option<String>,
    tid: &Option<String>,
    thread_index: Option<usize>,
    range: &AnalysisRange,
) -> Result<SelectedThread<'a>, String> {
    if thread_index.is_some() || tid.is_some() {
        return select_thread(profile, thread_name, tid, thread_index);
    }

    if let Some(name) = thread_name {
        let (index, thread) = profile
            .threads
            .iter()
            .enumerate()
            .filter(|(_, candidate)| candidate.name == *name)
            .filter(|(_, candidate)| samples::sample_count(candidate, Some(range)) > 0)
            .max_by_key(|(_, candidate)| samples::sample_count(candidate, Some(range)))
            .ok_or_else(|| format!("Thread '{name}' has no samples in the selected time range"))?;
        return Ok(SelectedThread { index, thread });
    }

    let (index, thread) = profile
        .threads
        .iter()
        .enumerate()
        .filter(|(_, candidate)| candidate.is_main)
        .filter(|(_, candidate)| samples::sample_count(candidate, Some(range)) > 0)
        .max_by_key(|(_, candidate)| samples::sample_count(candidate, Some(range)))
        .or_else(|| {
            profile
                .threads
                .iter()
                .enumerate()
                .filter(|(_, candidate)| samples::sample_count(candidate, Some(range)) > 0)
                .max_by_key(|(_, candidate)| samples::sample_count(candidate, Some(range)))
        })
        .ok_or("No sampled threads found in the selected time range")?;

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

fn compile_optional_regex(pattern: &Option<String>, label: &str) -> Result<Option<Regex>, String> {
    let Some(pattern) = pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };

    Regex::new(pattern)
        .map(Some)
        .map_err(|e| format!("Invalid {label} regex '{pattern}': {e}"))
}

struct FrameNameFilter {
    include: Option<String>,
    exclude: Option<String>,
    include_regex: Option<Regex>,
    exclude_regex: Option<Regex>,
    exclude_framework: bool,
}

impl FrameNameFilter {
    fn new(
        include: &Option<String>,
        exclude: &Option<String>,
        include_regex: &Option<String>,
        exclude_regex: &Option<String>,
        exclude_framework: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            include: include.clone(),
            exclude: exclude.clone(),
            include_regex: compile_optional_regex(include_regex, "include")?,
            exclude_regex: compile_optional_regex(exclude_regex, "exclude")?,
            exclude_framework,
        })
    }

    fn includes(&self, name: &str) -> bool {
        if let Some(include) = &self.include
            && !pattern_matches(name, include)
        {
            return false;
        }

        if let Some(include_regex) = &self.include_regex
            && !include_regex.is_match(name)
        {
            return false;
        }

        if let Some(exclude) = &self.exclude
            && pattern_matches(name, exclude)
        {
            return false;
        }

        if let Some(exclude_regex) = &self.exclude_regex
            && exclude_regex.is_match(name)
        {
            return false;
        }

        if self.exclude_framework && symbols::is_framework_function(name, None) {
            return false;
        }

        true
    }
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

fn summary_thread_name_prefix(thread_name: &str) -> String {
    let prefix = thread_name.trim_end_matches(|c: char| c.is_ascii_digit());
    if prefix.is_empty() {
        thread_name.to_string()
    } else {
        prefix.to_string()
    }
}

#[derive(Debug, Clone, Copy)]
struct ThreadSampleSummary {
    sample_count: usize,
    wall_time_ms: f64,
    cpu_sample_time_ms: f64,
    cpu_sample_percent_of_wall: f64,
    samples_per_second: f64,
}

fn thread_sample_summary(
    profile: &ResolvedProfile,
    thread_indices: &[usize],
    range: Option<&AnalysisRange>,
) -> ThreadSampleSummary {
    let sample_count: usize = thread_indices
        .iter()
        .filter_map(|index| profile.threads.get(*index))
        .map(|thread| samples::sample_count(thread, range))
        .sum();
    let wall_time_ms: f64 = thread_indices
        .iter()
        .filter_map(|index| profile.threads.get(*index))
        .map(|thread| samples::thread_wall_time_ms(thread, range))
        .sum();
    let cpu_sample_time_ms = thread_indices
        .iter()
        .filter_map(|index| profile.threads.get(*index))
        .map(|thread| samples::thread_sample_time_ms(thread, profile.interval_ms, range))
        .sum();
    let samples_per_second = if wall_time_ms > 0.0 {
        sample_count as f64 / wall_time_ms * 1000.0
    } else {
        0.0
    };

    ThreadSampleSummary {
        sample_count,
        wall_time_ms,
        cpu_sample_time_ms,
        cpu_sample_percent_of_wall: percent(cpu_sample_time_ms, wall_time_ms),
        samples_per_second,
    }
}

fn thread_info(
    profile: &ResolvedProfile,
    index: usize,
    thread: &ResolvedThread,
    range: Option<&AnalysisRange>,
) -> ThreadInfo {
    let summary = thread_sample_summary(profile, &[index], range);

    ThreadInfo {
        index,
        name: thread.name.clone(),
        pid: thread.pid.clone(),
        tid: thread.tid.clone(),
        sample_count: summary.sample_count,
        duration_ms: round2(summary.wall_time_ms),
        wall_time_ms: round2(summary.wall_time_ms),
        cpu_sample_time_ms: round2(summary.cpu_sample_time_ms),
        cpu_sample_percent_of_wall: round2(summary.cpu_sample_percent_of_wall),
        samples_per_second: round2(summary.samples_per_second),
        is_main: thread.is_main,
    }
}

fn thread_infos(
    profile: &ResolvedProfile,
    thread_indices: &[usize],
    range: Option<&AnalysisRange>,
) -> Vec<ThreadInfo> {
    thread_indices
        .iter()
        .filter_map(|index| profile.threads.get(*index).map(|thread| (*index, thread)))
        .map(|(index, thread)| thread_info(profile, index, thread, range))
        .collect()
}

fn thread_summary_groups(
    profile: &ResolvedProfile,
    thread_indices: &[usize],
    range: Option<&AnalysisRange>,
) -> Vec<ThreadSummaryGroup> {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();

    for index in thread_indices {
        let Some(thread) = profile.threads.get(*index) else {
            continue;
        };
        groups
            .entry(summary_thread_name_prefix(&thread.name))
            .or_default()
            .push(*index);
    }

    let mut summaries: Vec<ThreadSummaryGroup> = groups
        .into_iter()
        .map(|(name_prefix, indices)| {
            let summary = thread_sample_summary(profile, &indices, range);
            let max_thread_duration_ms = indices
                .iter()
                .filter_map(|index| profile.threads.get(*index))
                .map(|thread| samples::thread_wall_time_ms(thread, range))
                .fold(0.0, f64::max);
            let main_thread_count = indices
                .iter()
                .filter_map(|index| profile.threads.get(*index))
                .filter(|thread| thread.is_main)
                .count();

            ThreadSummaryGroup {
                name_prefix,
                thread_count: indices.len(),
                sample_count: summary.sample_count,
                wall_time_ms: round2(summary.wall_time_ms),
                cpu_sample_time_ms: round2(summary.cpu_sample_time_ms),
                cpu_sample_percent_of_wall: round2(summary.cpu_sample_percent_of_wall),
                samples_per_second: round2(summary.samples_per_second),
                max_thread_duration_ms: round2(max_thread_duration_ms),
                main_thread_count,
            }
        })
        .collect();

    summaries.sort_by(|a, b| {
        b.sample_count
            .cmp(&a.sample_count)
            .then_with(|| a.name_prefix.cmp(&b.name_prefix))
    });
    summaries
}

fn scope_total_time_ms(
    profile: &ResolvedProfile,
    thread_indices: &[usize],
    range: Option<&AnalysisRange>,
) -> f64 {
    thread_indices
        .iter()
        .filter_map(|index| profile.threads.get(*index))
        .map(|thread| samples::thread_sample_time_ms(thread, profile.interval_ms, range))
        .sum()
}

fn function_stats_for_thread(
    cached: &CachedProfile,
    thread_index: usize,
    range: &AnalysisRange,
) -> Vec<FunctionStats> {
    if range.is_full_profile(&cached.profile) {
        return cached
            .cache
            .function_stats(&cached.profile, thread_index)
            .cloned()
            .unwrap_or_default();
    }

    cached
        .profile
        .threads
        .get(thread_index)
        .map(|thread| {
            functions::compute_function_stats(thread, cached.profile.interval_ms, Some(range))
        })
        .unwrap_or_default()
}

fn function_stats_for_threads(
    cached: &CachedProfile,
    thread_indices: &[usize],
    range: &AnalysisRange,
) -> Vec<Vec<FunctionStats>> {
    let mut stats = vec![Vec::new(); cached.profile.threads.len()];
    for index in thread_indices {
        if *index < stats.len() {
            stats[*index] = function_stats_for_thread(cached, *index, range);
        }
    }
    stats
}

fn aggregate_function_stats(
    cached: &CachedProfile,
    thread_indices: &[usize],
    range: &AnalysisRange,
) -> (Vec<FunctionStats>, f64, usize) {
    let total_time_ms = scope_total_time_ms(&cached.profile, thread_indices, Some(range));
    let total_samples = thread_indices
        .iter()
        .filter_map(|index| cached.profile.threads.get(*index))
        .map(|thread| samples::sample_count(thread, Some(range)))
        .sum();

    let mut by_name: HashMap<String, AggregatedFunctionStatsAccum> = HashMap::new();

    for index in thread_indices {
        let stats = function_stats_for_thread(cached, *index, range);

        for stat in &stats {
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
    range: &AnalysisRange,
) -> Result<(String, Vec<usize>), String> {
    let prefixes = requested_thread_prefixes(thread_name_prefix, thread_name_prefixes);
    let has_explicit_thread_selector = thread.is_some() || tid.is_some() || thread_index.is_some();

    if has_explicit_thread_selector && !prefixes.is_empty() {
        return Err(
            "Use either thread/tid/thread_index or thread_name_prefix, not both".to_string(),
        );
    }

    if has_explicit_thread_selector {
        let selected = select_sample_thread(profile, thread, tid, thread_index, range)?;
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
                && samples::sample_count(thread, Some(range)) > 0
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
        .filter(|(_, thread)| samples::sample_count(thread, Some(range)) > 0)
        .map(|(index, _)| index)
        .collect();

    if indices.is_empty() {
        return Err("No sampled threads found".to_string());
    }

    Ok(("all sampled threads".to_string(), indices))
}

struct ThreadScopeSelection<'a> {
    scope: String,
    thread_indices: Vec<usize>,
    selected_thread: Option<SelectedThread<'a>>,
}

fn select_thread_indices_for_single_or_prefix_scope<'a>(
    profile: &'a ResolvedProfile,
    thread: &Option<String>,
    tid: &Option<String>,
    thread_index: Option<usize>,
    thread_name_prefix: &Option<String>,
    thread_name_prefixes: &[String],
    range: &AnalysisRange,
) -> Result<ThreadScopeSelection<'a>, String> {
    let prefixes = requested_thread_prefixes(thread_name_prefix, thread_name_prefixes);
    let has_explicit_thread_selector = thread.is_some() || tid.is_some() || thread_index.is_some();

    if has_explicit_thread_selector && !prefixes.is_empty() {
        return Err(
            "Use either thread/tid/thread_index or thread_name_prefix, not both".to_string(),
        );
    }

    if !prefixes.is_empty() {
        let mut thread_indices = Vec::new();
        for (index, thread) in profile.threads.iter().enumerate() {
            if prefixes
                .iter()
                .any(|prefix| thread_name_matches_prefix(&thread.name, prefix))
                && samples::sample_count(thread, Some(range)) > 0
            {
                thread_indices.push(index);
            }
        }

        if thread_indices.is_empty() {
            return Err(format!(
                "No threads matched prefix(es): {}",
                prefixes.join(", ")
            ));
        }

        return Ok(ThreadScopeSelection {
            scope: format!("thread prefix(es): {}", prefixes.join(", ")),
            thread_indices,
            selected_thread: None,
        });
    }

    let selected = select_sample_thread(profile, thread, tid, thread_index, range)?;
    let scope = thread_label(selected.index, selected.thread);
    let thread_indices = vec![selected.index];

    Ok(ThreadScopeSelection {
        scope,
        thread_indices,
        selected_thread: Some(selected),
    })
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
    range: &AnalysisRange,
    function_name: &str,
    caller_name: &str,
    caller_relationship: call_tree::CallerRelationship,
) -> FunctionUnderCallerMetrics {
    let mut metrics = FunctionUnderCallerMetrics {
        scope_time_ms: scope_total_time_ms(profile, thread_indices, Some(range)),
        ..Default::default()
    };

    for index in thread_indices {
        let Some(thread) = profile.threads.get(*index) else {
            continue;
        };
        let mut thread_matched = false;

        for sample in thread
            .samples
            .iter()
            .filter(|sample| range.contains(sample))
        {
            let sample_time_ms = samples::sample_time_ms(thread, sample, profile.interval_ms);
            metrics.total_scope_samples += 1;

            if sample
                .stack
                .iter()
                .any(|frame| frame.function_name == caller_name)
            {
                metrics.caller_context_time_ms += sample_time_ms;
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

            metrics.descendant_time_ms += sample_time_ms;
            metrics.descendant_samples += 1;
            thread_matched = true;

            if function_index + 1 == sample.stack.len() {
                metrics.exclusive_time_ms += sample_time_ms;
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

struct C2cFilter<'a> {
    pid: Option<i32>,
    tid: Option<i32>,
    thread_name_prefix: Option<&'a str>,
    start_time_ms: Option<f64>,
    end_time_ms: Option<f64>,
}

impl C2cFilter<'_> {
    fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("start_time_ms", self.start_time_ms),
            ("end_time_ms", self.end_time_ms),
        ] {
            if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
                return Err(format!("{name} must be a finite, non-negative number"));
            }
        }
        if self
            .start_time_ms
            .zip(self.end_time_ms)
            .is_some_and(|(start, end)| start > end)
        {
            return Err("start_time_ms must be less than or equal to end_time_ms".to_string());
        }
        Ok(())
    }

    fn matches(&self, profile: &C2cProfile, sample: &C2cSample) -> bool {
        if self.pid.is_some_and(|pid| sample.pid != pid)
            || self.tid.is_some_and(|tid| sample.tid != tid)
            || self
                .thread_name_prefix
                .is_some_and(|prefix| !thread_name_matches_prefix(&sample.thread_name, prefix))
        {
            return false;
        }

        if self.start_time_ms.is_none() && self.end_time_ms.is_none() {
            return true;
        }
        let Some(first) = profile.first_timestamp_ns else {
            return false;
        };
        let Some(timestamp) = sample.timestamp_ns else {
            return false;
        };
        let relative_ms = timestamp.saturating_sub(first) as f64 / 1_000_000.0;
        !self.start_time_ms.is_some_and(|start| relative_ms < start)
            && !self.end_time_ms.is_some_and(|end| relative_ms > end)
    }
}

#[derive(Default)]
struct C2cCachelineAccum {
    stats: C2cStats,
    physical_addresses: BTreeSet<u64>,
    cpus: BTreeSet<u32>,
    pids: BTreeSet<i32>,
    tids: BTreeSet<i32>,
    thread_names: BTreeSet<String>,
}

impl C2cCachelineAccum {
    fn add_sample(&mut self, sample: &C2cSample, cacheline_size: u64) {
        self.stats.add_sample(sample);
        if let Some(address) = sample.physical_address {
            self.physical_addresses
                .insert(align_cacheline(address, cacheline_size));
        }
        self.cpus.insert(sample.cpu);
        self.pids.insert(sample.pid);
        self.tids.insert(sample.tid);
        self.thread_names.insert(sample.thread_name.to_string());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct C2cAccessKey {
    offset: u64,
    pid: i32,
    tid: i32,
    cpu: u32,
    thread_name: Arc<str>,
    instruction_address: u64,
    exact_ip: bool,
    data_source: crate::c2c::MemoryDataSource,
    mapped_data_address: Option<MappedDataAddress>,
    mapped_instruction: Option<MappedInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct C2cDataMappingKey {
    path: Arc<str>,
    mapping_start: u64,
    mapping_end: u64,
    page_offset: u64,
    build_id: Option<Arc<str>>,
}

impl From<&MappedDataAddress> for C2cDataMappingKey {
    fn from(mapped: &MappedDataAddress) -> Self {
        Self {
            path: Arc::clone(&mapped.path),
            mapping_start: mapped.mapping_start,
            mapping_end: mapped.mapping_end,
            page_offset: mapped.page_offset,
            build_id: mapped.build_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct C2cAccessAccum {
    key: C2cAccessKey,
    stats: C2cStats,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct C2cInstructionIdentity {
    mapped: Option<MappedInstruction>,
    raw_address: u64,
}

impl C2cInstructionIdentity {
    fn new(instruction_address: u64, mapped: Option<&MappedInstruction>) -> Self {
        Self {
            mapped: mapped.cloned(),
            raw_address: if mapped.is_some() {
                0
            } else {
                instruction_address
            },
        }
    }

    fn from_callchain(frame: &C2cCallchainFrame) -> Self {
        Self::new(frame.instruction_address, frame.mapped_instruction.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct C2cSiteKey {
    instruction: C2cInstructionIdentity,
    callchain: Option<Arc<[C2cInstructionIdentity]>>,
}

impl C2cSiteKey {
    fn for_sample(sample: &C2cSample, group_by_callchain: bool) -> Self {
        Self {
            instruction: C2cInstructionIdentity::new(
                sample.instruction_address,
                sample.mapped_instruction.as_ref(),
            ),
            callchain: group_by_callchain.then(|| {
                sample
                    .callchain
                    .iter()
                    .map(C2cInstructionIdentity::from_callchain)
                    .collect::<Vec<_>>()
                    .into()
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct C2cCallchainAccum {
    frames: Arc<[C2cCallchainFrame]>,
    stats: C2cStats,
}

#[derive(Debug, Clone)]
struct C2cSiteAccum {
    key: C2cSiteKey,
    stats: C2cStats,
    instruction_addresses: BTreeSet<u64>,
    virtual_cachelines: HashMap<(i32, u64), C2cStats>,
    physical_cachelines: BTreeSet<u64>,
    cpus: BTreeSet<u32>,
    pids: BTreeSet<i32>,
    tids: BTreeSet<i32>,
    thread_names: BTreeSet<String>,
    data_sources: HashMap<crate::c2c::MemoryDataSource, C2cStats>,
    grouped_callchain: Option<Arc<[C2cCallchainFrame]>>,
    callchains: HashMap<Arc<[C2cInstructionIdentity]>, C2cCallchainAccum>,
}

impl C2cSiteAccum {
    fn new(key: C2cSiteKey, grouped_callchain: Option<Arc<[C2cCallchainFrame]>>) -> Self {
        Self {
            key,
            stats: C2cStats::default(),
            instruction_addresses: BTreeSet::new(),
            virtual_cachelines: HashMap::new(),
            physical_cachelines: BTreeSet::new(),
            cpus: BTreeSet::new(),
            pids: BTreeSet::new(),
            tids: BTreeSet::new(),
            thread_names: BTreeSet::new(),
            data_sources: HashMap::new(),
            grouped_callchain,
            callchains: HashMap::new(),
        }
    }

    fn add_sample(&mut self, sample: &C2cSample, cacheline_size: u64, include_callchains: bool) {
        self.stats.add_sample(sample);
        self.instruction_addresses
            .insert(sample.instruction_address);
        self.virtual_cachelines
            .entry((
                sample.pid,
                align_cacheline(sample.data_address, cacheline_size),
            ))
            .or_default()
            .add_sample(sample);
        if let Some(address) = sample.physical_address {
            self.physical_cachelines
                .insert(align_cacheline(address, cacheline_size));
        }
        self.cpus.insert(sample.cpu);
        self.pids.insert(sample.pid);
        self.tids.insert(sample.tid);
        self.thread_names.insert(sample.thread_name.to_string());
        self.data_sources
            .entry(sample.data_source)
            .or_default()
            .add_sample(sample);

        if include_callchains && !sample.callchain.is_empty() {
            let identity: Arc<[C2cInstructionIdentity]> = sample
                .callchain
                .iter()
                .map(C2cInstructionIdentity::from_callchain)
                .collect::<Vec<_>>()
                .into();
            self.callchains
                .entry(identity)
                .or_insert_with(|| C2cCallchainAccum {
                    frames: Arc::clone(&sample.callchain),
                    stats: C2cStats::default(),
                })
                .stats
                .add_sample(sample);
        }
    }

    fn hitm_cacheline_count(&self) -> usize {
        self.virtual_cachelines
            .values()
            .filter(|stats| stats.total_hitm() > 0)
            .count()
    }
}

#[derive(Debug, Clone, Default)]
struct C2cDetailedCachelineAccum {
    stats: C2cStats,
    physical_cachelines: BTreeSet<u64>,
    offsets: HashMap<u64, C2cStats>,
    data_mappings: HashMap<C2cDataMappingKey, C2cStats>,
}

impl C2cDetailedCachelineAccum {
    fn add_sample(&mut self, sample: &C2cSample, cacheline_size: u64) {
        let cacheline = align_cacheline(sample.data_address, cacheline_size);
        self.stats.add_sample(sample);
        if let Some(address) = sample.physical_address {
            self.physical_cachelines
                .insert(align_cacheline(address, cacheline_size));
        }
        self.offsets
            .entry(sample.data_address - cacheline)
            .or_default()
            .add_sample(sample);
        if let Some(mapped) = &sample.mapped_data_address {
            self.data_mappings
                .entry(mapped.into())
                .or_default()
                .add_sample(sample);
        }
    }
}

#[derive(Debug, Clone, Default)]
struct C2cThreadBreakdownAccum {
    stats: C2cStats,
    cachelines: BTreeSet<(i32, u64)>,
    cpus: BTreeSet<u32>,
}

#[derive(Debug, Clone, Default)]
struct C2cCpuBreakdownAccum {
    stats: C2cStats,
    cachelines: BTreeSet<(i32, u64)>,
    tids: BTreeSet<i32>,
    thread_names: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct C2cRelatedSiteAccum {
    identity: C2cInstructionIdentity,
    stats: C2cStats,
    instruction_addresses: BTreeSet<u64>,
    cachelines: BTreeSet<(i32, u64)>,
    cpus: BTreeSet<u32>,
    pids: BTreeSet<i32>,
    tids: BTreeSet<i32>,
    thread_names: BTreeSet<String>,
}

impl C2cRelatedSiteAccum {
    fn new(identity: C2cInstructionIdentity) -> Self {
        Self {
            identity,
            stats: C2cStats::default(),
            instruction_addresses: BTreeSet::new(),
            cachelines: BTreeSet::new(),
            cpus: BTreeSet::new(),
            pids: BTreeSet::new(),
            tids: BTreeSet::new(),
            thread_names: BTreeSet::new(),
        }
    }

    fn add_sample(&mut self, sample: &C2cSample, cacheline_size: u64) {
        self.stats.add_sample(sample);
        self.instruction_addresses
            .insert(sample.instruction_address);
        self.cachelines.insert((
            sample.pid,
            align_cacheline(sample.data_address, cacheline_size),
        ));
        self.cpus.insert(sample.cpu);
        self.pids.insert(sample.pid);
        self.tids.insert(sample.tid);
        self.thread_names.insert(sample.thread_name.to_string());
    }
}

fn c2c_site_id(key: &C2cSiteKey) -> String {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    fn write_bytes(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV_PRIME);
        }
        write_separator(hash);
    }

    fn write_separator(hash: &mut u64) {
        *hash ^= 0xff;
        *hash = hash.wrapping_mul(FNV_PRIME);
    }

    fn write_instruction(hash: &mut u64, instruction: &C2cInstructionIdentity) {
        if let Some(mapped) = &instruction.mapped {
            write_bytes(hash, b"mapped");
            if let Some(build_id) = &mapped.build_id {
                write_bytes(hash, build_id.as_bytes());
            } else {
                write_bytes(hash, mapped.path.as_bytes());
            }
            write_bytes(hash, &mapped.relative_address.to_le_bytes());
        } else {
            write_bytes(hash, b"raw");
            write_bytes(hash, &instruction.raw_address.to_le_bytes());
        }
    }

    let mut hash = FNV_OFFSET;
    write_instruction(&mut hash, &key.instruction);
    if let Some(callchain) = &key.callchain {
        write_bytes(&mut hash, b"callchain");
        for frame in callchain.iter() {
            write_instruction(&mut hash, frame);
        }
    }
    format!("site:{hash:016x}")
}

fn select_c2c_site_key(
    sample: &C2cSample,
    instruction_address: Option<u64>,
    site_id: Option<&str>,
) -> Option<C2cSiteKey> {
    if instruction_address.is_some_and(|address| sample.instruction_address == address) {
        return Some(C2cSiteKey::for_sample(sample, false));
    }
    let site_id = site_id?;
    let instruction_key = C2cSiteKey::for_sample(sample, false);
    if c2c_site_id(&instruction_key) == site_id {
        return Some(instruction_key);
    }
    let callchain_key = C2cSiteKey::for_sample(sample, true);
    if c2c_site_id(&callchain_key) == site_id {
        return Some(callchain_key);
    }
    None
}

fn c2c_profile_summary(profile: &C2cProfile, matched_memory_samples: usize) -> C2cProfileSummary {
    let mut warnings = Vec::new();
    if profile.missing_data_address_samples > 0 {
        warnings.push(format!(
            "{} of {} memory sample records had no data address and were excluded; {} usable memory samples remain",
            profile.missing_data_address_samples,
            profile.memory_sample_records,
            profile.samples.len()
        ));
    }
    if profile.missing_physical_address_samples > 0 {
        warnings.push(format!(
            "{} memory samples had no physical address; physical cacheline reporting may be incomplete",
            profile.missing_physical_address_samples
        ));
    }
    if profile.global_stats.instruction_latency_samples == 0 {
        warnings.push(
            "no usable memory sample contains instruction-latency data; latency averages are unavailable and latency sorting is rejected"
                .to_string(),
        );
    }
    if profile.global_stats.non_unit_weight_samples == 0 {
        warnings.push(
            "all usable memory samples have weight 1; weight totals do not estimate latency or wall time"
                .to_string(),
        );
    }
    let non_exact_ip_samples = profile
        .global_stats
        .samples
        .saturating_sub(profile.global_stats.exact_ip_samples);
    if non_exact_ip_samples > 0 {
        warnings.push(format!(
            "{non_exact_ip_samples} usable memory samples lack PERF_RECORD_MISC_EXACT_IP; instruction attribution uses the unmodified sampled IP and may have skid"
        ));
    }
    warnings.push(format!(
        "cacheline size is currently assumed to be {} bytes",
        profile.cacheline_size
    ));

    C2cProfileSummary {
        arch: profile.arch.clone(),
        cpu_description: profile.cpu_description.clone(),
        perf_version: profile.perf_version.clone(),
        event_names: profile.event_names.clone(),
        cacheline_size: profile.cacheline_size,
        duration_ms: profile
            .first_timestamp_ns
            .zip(profile.last_timestamp_ns)
            .map_or(0.0, |(first, last)| {
                last.saturating_sub(first) as f64 / 1_000_000.0
            }),
        total_sample_records: profile.memory_sample_records + profile.skipped_samples,
        total_memory_samples: profile.memory_sample_records,
        usable_memory_samples: profile.samples.len(),
        instruction_ip_policy: "raw_perf_sample_ip_no_adjustment".to_string(),
        global_stats: c2c_stats_result(&profile.global_stats),
        global_memory_levels: c2c_memory_level_rows(&profile.global_memory_levels),
        samples_with_callchains: profile.samples_with_callchains,
        matched_memory_samples,
        skipped_non_memory_samples: profile.skipped_samples,
        missing_data_address_samples: profile.missing_data_address_samples,
        missing_physical_address_samples: profile.missing_physical_address_samples,
        warnings,
    }
}

fn c2c_memory_level_rows(levels: &BTreeMap<&'static str, C2cStats>) -> Vec<C2cMemoryLevelRow> {
    let mut levels: Vec<_> = levels.iter().collect();
    levels.sort_unstable_by(|(left_level, left), (right_level, right)| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left_level.cmp(right_level))
    });
    levels
        .into_iter()
        .map(|(memory_level, stats)| C2cMemoryLevelRow {
            memory_level: (*memory_level).to_string(),
            stats: c2c_stats_result(stats),
        })
        .collect()
}

fn c2c_raw_data_source_rows(
    data_sources: HashMap<crate::c2c::MemoryDataSource, C2cStats>,
) -> Vec<C2cRawDataSourceRow> {
    let mut data_sources: Vec<_> = data_sources.into_iter().collect();
    data_sources.sort_unstable_by(|(left_source, left), (right_source, right)| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left_source.raw.cmp(&right_source.raw))
    });
    data_sources
        .into_iter()
        .map(|(source, stats)| C2cRawDataSourceRow {
            raw_data_source: format!("0x{:x}", source.raw),
            operation: source.operation().to_string(),
            memory_level: source.level().to_string(),
            stats: c2c_stats_result(&stats),
        })
        .collect()
}

fn c2c_data_mapping_rows(
    data_mappings: HashMap<C2cDataMappingKey, C2cStats>,
) -> Vec<C2cDataMappingRow> {
    let mut data_mappings: Vec<_> = data_mappings.into_iter().collect();
    data_mappings.sort_unstable_by(|(left_key, left), (right_key, right)| {
        right
            .samples
            .cmp(&left.samples)
            .then_with(|| left_key.path.cmp(&right_key.path))
            .then_with(|| left_key.mapping_start.cmp(&right_key.mapping_start))
    });
    data_mappings
        .into_iter()
        .map(|(mapping, stats)| C2cDataMappingRow {
            path: mapping.path.to_string(),
            mapping_start: format_address(mapping.mapping_start),
            mapping_end: format_address(mapping.mapping_end),
            page_offset: format_address(mapping.page_offset),
            build_id: mapping.build_id.map(|build_id| build_id.to_string()),
            stats: c2c_stats_result(&stats),
        })
        .collect()
}

fn c2c_mapped_data_address(mapped: MappedDataAddress) -> C2cMappedDataAddress {
    C2cMappedDataAddress {
        path: mapped.path.to_string(),
        mapping_start: format_address(mapped.mapping_start),
        mapping_end: format_address(mapped.mapping_end),
        page_offset: format_address(mapped.page_offset),
        mapping_offset: format_address(mapped.mapping_offset),
        file_offset: format_address(mapped.file_offset),
        build_id: mapped.build_id.map(|build_id| build_id.to_string()),
    }
}

fn c2c_stats_result(stats: &C2cStats) -> C2cCachelineStats {
    C2cCachelineStats {
        samples: stats.samples,
        loads: stats.loads,
        stores: stats.stores,
        total_hitm: stats.total_hitm(),
        local_hitm: stats.local_hitm,
        remote_hitm: stats.remote_hitm,
        total_peer: stats.total_peer(),
        local_peer: stats.local_peer,
        remote_peer: stats.remote_peer,
        locked: stats.locked,
        exact_ip_samples: stats.exact_ip_samples,
        non_exact_ip_samples: stats.samples.saturating_sub(stats.exact_ip_samples),
        non_unit_weight_samples: stats.non_unit_weight_samples,
        average_weight: stats.average_weight(),
        instruction_latency_samples: stats.instruction_latency_samples,
        average_instruction_latency: stats.average_instruction_latency(),
    }
}

fn validate_c2c_latency_sort(
    sort_by: &str,
    matched_memory_samples: usize,
    stats: &C2cStats,
) -> Result<(), String> {
    if sort_by == "latency" && stats.instruction_latency_samples == 0 {
        return Err(format!(
            "cannot sort by latency: none of the {matched_memory_samples} memory samples matched by the requested filters contains instruction-latency data"
        ));
    }
    Ok(())
}

fn align_cacheline(address: u64, cacheline_size: u64) -> u64 {
    address - address % cacheline_size
}

fn format_address(address: u64) -> String {
    format!("0x{address:x}")
}

fn parse_address(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .map_err(|error| format!("invalid hexadecimal address: {error}"))
    } else {
        value
            .parse()
            .map_err(|error| format!("invalid decimal address: {error}"))
    }
}

#[derive(Default)]
struct ResolvedC2cInstruction {
    function_name: Option<String>,
    file: Option<String>,
    line: Option<u32>,
    inline_frames: Vec<C2cInlineFrame>,
}

fn resolve_c2c_instruction(
    mapped: Option<&MappedInstruction>,
    resolvers: &mut HashMap<Arc<str>, DwarfLibraryResolver>,
    failures: &mut HashMap<Arc<str>, String>,
) -> ResolvedC2cInstruction {
    let Some(mapped) = mapped else {
        return ResolvedC2cInstruction::default();
    };
    if !resolvers.contains_key(&mapped.path) && !failures.contains_key(&mapped.path) {
        let library = ResolvedLibrary {
            name: mapped.path.to_string(),
            path: mapped.path.to_string(),
            debug_name: String::new(),
            debug_path: String::new(),
            breakpad_id: String::new(),
            code_id: mapped.build_id.as_deref().map(ToOwned::to_owned),
        };
        match DwarfLibraryResolver::load(&library) {
            Ok(resolver) => {
                resolvers.insert(Arc::clone(&mapped.path), resolver);
            }
            Err(error) => {
                failures.insert(Arc::clone(&mapped.path), format!("{error:#}"));
            }
        }
    }

    let Some(resolver) = resolvers.get(&mapped.path) else {
        return ResolvedC2cInstruction::default();
    };
    let Ok(Some(info)) = resolver.resolve(mapped.relative_address) else {
        return ResolvedC2cInstruction::default();
    };
    let deepest = info.frames.last();
    let function_name = deepest
        .map(|frame| frame.function_name.clone())
        .or(info.symbol_name);
    let file = deepest.and_then(|frame| frame.file.clone());
    let line = deepest.and_then(|frame| frame.line);
    let inline_frames = info
        .frames
        .into_iter()
        .map(|frame| C2cInlineFrame {
            function_name: frame.function_name,
            file: frame.file,
            line: frame.line,
        })
        .collect();
    ResolvedC2cInstruction {
        function_name,
        file,
        line,
        inline_frames,
    }
}

fn resolve_c2c_callchain(
    frames: &[C2cCallchainFrame],
    resolvers: &mut HashMap<Arc<str>, DwarfLibraryResolver>,
    failures: &mut HashMap<Arc<str>, String>,
) -> Vec<C2cResolvedCallchainFrame> {
    frames
        .iter()
        .map(|frame| {
            let resolved =
                resolve_c2c_instruction(frame.mapped_instruction.as_ref(), resolvers, failures);
            C2cResolvedCallchainFrame {
                instruction_address: format_address(frame.instruction_address),
                relative_instruction_address: frame
                    .mapped_instruction
                    .as_ref()
                    .map(|mapped| format_address(mapped.relative_address)),
                function_name: resolved.function_name,
                dso: frame
                    .mapped_instruction
                    .as_ref()
                    .map(|mapped| mapped.path.to_string()),
                file: resolved.file,
                line: resolved.line,
                inline_frames: resolved.inline_frames,
            }
        })
        .collect()
}

fn c2c_symbolication_warnings(failures: HashMap<Arc<str>, String>) -> Vec<String> {
    let mut warnings: Vec<_> = failures
        .into_iter()
        .map(|(path, error)| format!("{path}: {error}"))
        .collect();
    warnings.sort_unstable();
    warnings
}

fn render_c2c_callchains(
    mut callchains: Vec<C2cCallchainAccum>,
    limit: usize,
    resolvers: &mut HashMap<Arc<str>, DwarfLibraryResolver>,
    failures: &mut HashMap<Arc<str>, String>,
) -> Vec<C2cCallchainRow> {
    callchains.sort_unstable_by(|left, right| {
        right
            .stats
            .total_hitm()
            .cmp(&left.stats.total_hitm())
            .then_with(|| right.stats.locked.cmp(&left.stats.locked))
            .then_with(|| right.stats.samples.cmp(&left.stats.samples))
    });
    callchains.truncate(limit.min(1_000));
    callchains
        .into_iter()
        .map(|callchain| C2cCallchainRow {
            samples: callchain.stats.samples,
            total_hitm: callchain.stats.total_hitm(),
            locked: callchain.stats.locked,
            frames: resolve_c2c_callchain(&callchain.frames, resolvers, failures),
        })
        .collect()
}

// ── Request types ──

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProfileInfoRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct C2cTopCachelinesRequest {
    #[schemars(description = "Path to a perf.data file recorded with perf c2c record")]
    pub path: String,

    #[schemars(description = "Optional process id filter")]
    #[serde(default)]
    pub pid: Option<i32>,

    #[schemars(description = "Optional thread id filter")]
    #[serde(default)]
    pub tid: Option<i32>,

    #[schemars(description = "Optional thread-name prefix filter")]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Optional inclusive start in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive end in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

    #[schemars(description = "Sort by 'hitm' (default), 'peer', 'samples', or 'weight'")]
    #[serde(default = "default_c2c_sort_by")]
    pub sort_by: String,

    #[schemars(description = "Maximum number of cachelines to return (default: 20)")]
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct C2cTopAccessSitesRequest {
    #[schemars(description = "Path to a perf.data file recorded with perf c2c record")]
    pub path: String,

    #[schemars(description = "Optional process id filter")]
    #[serde(default)]
    pub pid: Option<i32>,

    #[schemars(description = "Optional thread id filter")]
    #[serde(default)]
    pub tid: Option<i32>,

    #[schemars(description = "Optional thread-name prefix filter")]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Optional inclusive start in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive end in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

    #[schemars(
        description = "Sort by 'hitm' (default), 'locked', 'samples', 'weight', or 'latency'"
    )]
    #[serde(default = "default_c2c_access_site_sort_by")]
    pub sort_by: String,

    #[schemars(
        description = "Group identical instructions separately for each recorded callchain. Captures without callchains are unaffected"
    )]
    #[serde(default)]
    pub group_by_callchain: bool,

    #[schemars(description = "Include the most common recorded callchains for each access site")]
    #[serde(default)]
    pub include_callchains: bool,

    #[schemars(description = "Maximum callchains per access-site row (default: 3)")]
    #[serde(default = "default_c2c_callchain_limit")]
    pub callchain_limit: usize,

    #[schemars(description = "Maximum number of access sites to return (default: 20)")]
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct C2cAccessSiteDetailRequest {
    #[schemars(description = "Path to a perf.data file recorded with perf c2c record")]
    pub path: String,

    #[schemars(
        description = "Instruction address returned by c2c_top_access_sites, as hexadecimal or decimal. Provide this or site_id"
    )]
    #[serde(default)]
    pub instruction_address: Option<String>,

    #[schemars(
        description = "Stable site ID returned by c2c_top_access_sites. Provide this or instruction_address"
    )]
    #[serde(default)]
    pub site_id: Option<String>,

    #[schemars(description = "Optional process id filter")]
    #[serde(default)]
    pub pid: Option<i32>,

    #[schemars(description = "Optional thread id filter")]
    #[serde(default)]
    pub tid: Option<i32>,

    #[schemars(description = "Optional thread-name prefix filter")]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Optional inclusive start in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive end in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

    #[schemars(description = "Maximum cacheline rows to return (default: 200, maximum: 10000)")]
    #[serde(default = "default_c2c_cacheline_detail_limit")]
    pub cacheline_limit: usize,

    #[schemars(description = "Zero-based cacheline row offset for pagination")]
    #[serde(default)]
    pub cacheline_offset: usize,

    #[schemars(
        description = "Maximum related access sites, thread rows, CPU rows, and callchains to return (default: 20)"
    )]
    #[serde(default = "default_limit")]
    pub related_limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct C2cCachelineDetailRequest {
    #[schemars(description = "Path to a perf.data file recorded with perf c2c record")]
    pub path: String,

    #[schemars(
        description = "Cacheline address returned by c2c_top_cachelines, as hexadecimal or decimal"
    )]
    pub cacheline_address: String,

    #[schemars(description = "Optional process id filter")]
    #[serde(default)]
    pub pid: Option<i32>,

    #[schemars(description = "Optional thread id filter")]
    #[serde(default)]
    pub tid: Option<i32>,

    #[schemars(description = "Optional thread-name prefix filter")]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Optional inclusive start in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive end in milliseconds relative to the first memory sample"
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

    #[schemars(description = "Maximum number of access sites to return (default: 20)")]
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProfileThreadsRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

    #[schemars(
        description = "Optional thread name prefix filter. A trailing '*' is accepted for convenience."
    )]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Optional thread name prefix filters. A trailing '*' is accepted for convenience."
    )]
    #[serde(default)]
    pub thread_name_prefixes: Vec<String>,

    #[schemars(description = "Optional regex filter for thread names.")]
    #[serde(default)]
    pub thread_name_regex: Option<String>,

    #[schemars(description = "Only include threads with at least this many samples.")]
    #[serde(default)]
    pub min_samples: Option<usize>,

    #[schemars(description = "Only include threads alive for at least this many milliseconds.")]
    #[serde(default)]
    pub min_duration_ms: Option<f64>,

    #[schemars(description = "Return compact groups by inferred thread name prefix.")]
    #[serde(default)]
    pub group_by_name_prefix: bool,

    #[schemars(description = "Include per-thread rows in the result (default: true).")]
    #[serde(default = "default_include_threads")]
    pub include_threads: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TopFunctionsRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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

    #[schemars(description = "Include matching thread rows in each group (default: true).")]
    #[serde(default = "default_include_threads")]
    pub include_threads: bool,
}

fn default_sort_by() -> String {
    "self".to_string()
}

fn default_c2c_sort_by() -> String {
    "hitm".to_string()
}

fn default_c2c_access_site_sort_by() -> String {
    "hitm".to_string()
}

fn default_c2c_callchain_limit() -> usize {
    3
}

fn default_c2c_cacheline_detail_limit() -> usize {
    200
}

fn default_limit() -> usize {
    20
}

fn default_include_threads() -> bool {
    true
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CallTreeRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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

    #[schemars(
        description = "Thread name prefix to aggregate. A trailing '*' is accepted, e.g. bench-feature-* matches names starting with bench-feature-."
    )]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Thread name prefixes to aggregate. A trailing '*' is accepted for prefix-style globs."
    )]
    #[serde(default)]
    pub thread_name_prefixes: Vec<String>,

    #[schemars(
        description = "Optional full function name or substring. If set, reroot the call tree at this function."
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

    #[schemars(
        description = "Optional case-insensitive function name include filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub include: Option<String>,

    #[schemars(
        description = "Optional case-insensitive function name exclude filter. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub exclude: Option<String>,

    #[schemars(description = "Optional regex include filter for function names.")]
    #[serde(default)]
    pub include_regex: Option<String>,

    #[schemars(description = "Optional regex exclude filter for function names.")]
    #[serde(default)]
    pub exclude_regex: Option<String>,

    #[schemars(description = "Include matching thread rows in the result (default: false).")]
    #[serde(default)]
    pub include_threads: bool,
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

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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
pub struct ContextSwitchesRequest {
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
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

    #[schemars(
        description = "Maximum number of longest off-CPU intervals to return (default: 20, maximum: 200)."
    )]
    #[serde(default = "default_context_switch_limit")]
    pub limit: usize,
}

fn default_context_switch_limit() -> usize {
    20
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FlamegraphRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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
        description = "Thread name prefix to aggregate. A trailing '*' is accepted, e.g. chunk-worker*."
    )]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Thread name prefixes to aggregate. A trailing '*' is accepted for prefix-style globs."
    )]
    #[serde(default)]
    pub thread_name_prefixes: Vec<String>,

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

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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

    #[schemars(
        description = "Thread name prefix to aggregate before focusing. A trailing '*' is accepted, e.g. bench-feature-*."
    )]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Thread name prefixes to aggregate before focusing. A trailing '*' is accepted for prefix-style globs."
    )]
    #[serde(default)]
    pub thread_name_prefixes: Vec<String>,

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

    #[schemars(
        description = "Optional case-insensitive function name include filter for rendered descendants. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub include: Option<String>,

    #[schemars(
        description = "Optional case-insensitive function name exclude filter for rendered descendants. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub exclude: Option<String>,

    #[schemars(
        description = "Optional regex include filter for rendered descendant function names."
    )]
    #[serde(default)]
    pub include_regex: Option<String>,

    #[schemars(
        description = "Optional regex exclude filter for rendered descendant function names."
    )]
    #[serde(default)]
    pub exclude_regex: Option<String>,

    #[schemars(description = "Include matching thread rows in the result (default: false).")]
    #[serde(default)]
    pub include_threads: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FunctionSourceRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

    #[schemars(
        description = "Full function name or substring whose exclusive samples should be analyzed"
    )]
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

    #[schemars(
        description = "Thread name prefix to aggregate before grouping exclusive samples. A trailing '*' is accepted."
    )]
    #[serde(default)]
    pub thread_name_prefix: Option<String>,

    #[schemars(
        description = "Thread name prefixes to aggregate before grouping exclusive samples."
    )]
    #[serde(default)]
    pub thread_name_prefixes: Vec<String>,

    #[schemars(
        description = "Maximum instruction rows and source-line rows to return (default: 50, maximum: 500)."
    )]
    #[serde(default = "default_source_limit")]
    pub limit: usize,

    #[schemars(description = "Include matching thread rows in the result (default: true).")]
    #[serde(default = "default_include_threads")]
    pub include_threads: bool,
}

fn default_source_limit() -> usize {
    50
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FunctionUnderCallerRequest {
    #[schemars(description = "Path to the profile JSON file (or .json.gz)")]
    pub path: String,

    #[schemars(
        description = "Optional inclusive analysis-window start in profile-relative milliseconds; 0 is the first observed sample."
    )]
    #[serde(default)]
    pub start_time_ms: Option<f64>,

    #[schemars(
        description = "Optional inclusive analysis-window end in profile-relative milliseconds."
    )]
    #[serde(default)]
    pub end_time_ms: Option<f64>,

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

    #[schemars(
        description = "Optional case-insensitive function name include filter for rendered descendants. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub include: Option<String>,

    #[schemars(
        description = "Optional case-insensitive function name exclude filter for rendered descendants. Use '|' to separate alternatives."
    )]
    #[serde(default)]
    pub exclude: Option<String>,

    #[schemars(
        description = "Optional regex include filter for rendered descendant function names."
    )]
    #[serde(default)]
    pub include_regex: Option<String>,

    #[schemars(
        description = "Optional regex exclude filter for rendered descendant function names."
    )]
    #[serde(default)]
    pub exclude_regex: Option<String>,

    #[schemars(description = "Include matching thread rows in the result (default: true).")]
    #[serde(default = "default_include_threads")]
    pub include_threads: bool,
}

fn default_caller_mode() -> String {
    "ancestor".to_string()
}

// ── Response types ──

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EffectiveTimeRange {
    /// Inclusive profile-relative start in milliseconds.
    pub start_time_ms: f64,
    /// Inclusive profile-relative end in milliseconds.
    pub end_time_ms: f64,
    pub duration_ms: f64,
}

fn effective_time_range(range: &AnalysisRange) -> EffectiveTimeRange {
    EffectiveTimeRange {
        start_time_ms: range.start_time_ms,
        end_time_ms: range.end_time_ms,
        duration_ms: range.duration_ms(),
    }
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProfileInfoResult {
    pub product: String,
    /// Earliest observed sample timestamp in the profile's original clock domain.
    pub observed_start_time_ms: f64,
    pub duration_ms: f64,
    pub total_samples: usize,
    pub thread_count: usize,
    pub interval_ms: f64,
    pub categories: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cProfileSummary {
    pub arch: Option<String>,
    pub cpu_description: Option<String>,
    pub perf_version: Option<String>,
    pub event_names: Vec<String>,
    pub cacheline_size: u64,
    pub duration_ms: f64,
    /// All PERF_RECORD_SAMPLE records, including events without PERF_SAMPLE_DATA_SRC.
    pub total_sample_records: usize,
    /// Sample records whose event format contains PERF_SAMPLE_DATA_SRC, including records
    /// later excluded for a missing or zero data address.
    pub total_memory_samples: usize,
    /// Memory sample records retained for analysis after requiring a nonzero data address.
    pub usable_memory_samples: usize,
    /// Address attribution currently uses the exact PERF_SAMPLE_IP value without adjustment.
    pub instruction_ip_policy: String,
    /// Capture-wide aggregate over every usable memory sample, before request filters.
    pub global_stats: C2cCachelineStats,
    /// Capture-wide aggregate grouped by the decoded PERF_SAMPLE_DATA_SRC memory level.
    pub global_memory_levels: Vec<C2cMemoryLevelRow>,
    pub samples_with_callchains: usize,
    pub matched_memory_samples: usize,
    pub skipped_non_memory_samples: usize,
    pub missing_data_address_samples: usize,
    pub missing_physical_address_samples: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cMemoryLevelRow {
    pub memory_level: String,
    pub stats: C2cCachelineStats,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cRawDataSourceRow {
    /// Exact, unmodified PERF_SAMPLE_DATA_SRC value from the capture.
    pub raw_data_source: String,
    pub operation: String,
    pub memory_level: String,
    pub stats: C2cCachelineStats,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cCachelineRow {
    pub cacheline_address: String,
    pub physical_cacheline_addresses: Vec<String>,
    pub samples: usize,
    pub loads: usize,
    pub stores: usize,
    pub total_hitm: usize,
    pub local_hitm: usize,
    pub remote_hitm: usize,
    pub hitm_percent: f64,
    pub total_peer: usize,
    pub local_peer: usize,
    pub remote_peer: usize,
    pub locked: usize,
    pub average_weight: f64,
    pub average_instruction_latency: Option<f64>,
    pub cpus: Vec<u32>,
    pub pids: Vec<i32>,
    pub tids: Vec<i32>,
    pub thread_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cTopCachelinesResult {
    pub profile: C2cProfileSummary,
    pub sort_by: String,
    pub matched_stats: C2cCachelineStats,
    pub matched_memory_levels: Vec<C2cMemoryLevelRow>,
    pub total_matched_hitm: usize,
    pub total_matched_peer: usize,
    pub cachelines: Vec<C2cCachelineRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cInlineFrame {
    pub function_name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cResolvedCallchainFrame {
    pub instruction_address: String,
    pub relative_instruction_address: Option<String>,
    pub function_name: Option<String>,
    pub dso: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub inline_frames: Vec<C2cInlineFrame>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cCallchainRow {
    pub samples: usize,
    pub total_hitm: usize,
    pub locked: usize,
    pub frames: Vec<C2cResolvedCallchainFrame>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cTopAccessSiteRow {
    pub site_id: String,
    pub instruction_address: String,
    pub instruction_addresses: Vec<String>,
    /// Exact, unmodified PERF_SAMPLE_IP values represented by this site.
    pub raw_sampled_ips: Vec<String>,
    /// Exact PERF_SAMPLE_DATA_SRC values and their decoded aggregate statistics.
    pub raw_data_sources: Vec<C2cRawDataSourceRow>,
    pub relative_instruction_address: Option<String>,
    pub function_name: Option<String>,
    pub dso: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub inline_frames: Vec<C2cInlineFrame>,
    pub grouped_callchain: Vec<C2cResolvedCallchainFrame>,
    pub top_callchains: Vec<C2cCallchainRow>,
    pub samples: usize,
    pub loads: usize,
    pub stores: usize,
    pub total_hitm: usize,
    pub local_hitm: usize,
    pub remote_hitm: usize,
    pub total_peer: usize,
    pub local_peer: usize,
    pub remote_peer: usize,
    pub locked: usize,
    pub exact_ip_samples: usize,
    pub non_exact_ip_samples: usize,
    pub non_unit_weight_samples: usize,
    pub instruction_latency_samples: usize,
    pub average_weight: f64,
    pub average_instruction_latency: Option<f64>,
    pub distinct_virtual_cachelines: usize,
    pub distinct_hitm_cachelines: usize,
    pub distinct_physical_cachelines: usize,
    pub cpus: Vec<u32>,
    pub pids: Vec<i32>,
    pub tids: Vec<i32>,
    pub thread_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cTopAccessSitesResult {
    pub profile: C2cProfileSummary,
    pub sort_by: String,
    pub matched_stats: C2cCachelineStats,
    pub matched_memory_levels: Vec<C2cMemoryLevelRow>,
    pub grouped_by_callchain: bool,
    pub total_access_sites: usize,
    pub access_sites: Vec<C2cTopAccessSiteRow>,
    pub symbolication_warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cOffsetRow {
    pub offset: u64,
    pub stats: C2cCachelineStats,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cAccessedCachelineRow {
    pub pid: i32,
    pub cacheline_address: String,
    pub physical_cacheline_addresses: Vec<String>,
    /// Recorded MMAP/MMAP2 regions containing sampled data addresses on this line.
    pub data_mappings: Vec<C2cDataMappingRow>,
    pub stats: C2cCachelineStats,
    pub offsets: Vec<C2cOffsetRow>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cDataMappingRow {
    pub path: String,
    pub mapping_start: String,
    pub mapping_end: String,
    pub page_offset: String,
    pub build_id: Option<String>,
    pub stats: C2cCachelineStats,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cMappedDataAddress {
    pub path: String,
    pub mapping_start: String,
    pub mapping_end: String,
    pub page_offset: String,
    pub mapping_offset: String,
    pub file_offset: String,
    pub build_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cRelatedAccessSiteRow {
    pub site_id: String,
    pub instruction_address: String,
    pub relative_instruction_address: Option<String>,
    pub function_name: Option<String>,
    pub dso: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub inline_frames: Vec<C2cInlineFrame>,
    pub stats: C2cCachelineStats,
    pub shared_cachelines: usize,
    pub cpus: Vec<u32>,
    pub pids: Vec<i32>,
    pub tids: Vec<i32>,
    pub thread_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cThreadBreakdownRow {
    pub pid: i32,
    pub tid: i32,
    pub thread_name: String,
    pub stats: C2cCachelineStats,
    pub distinct_virtual_cachelines: usize,
    pub cpus: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cCpuBreakdownRow {
    pub cpu: u32,
    pub stats: C2cCachelineStats,
    pub distinct_virtual_cachelines: usize,
    pub tids: Vec<i32>,
    pub thread_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cAccessSiteDetailResult {
    pub profile: C2cProfileSummary,
    pub site_id: String,
    pub instruction_address: String,
    pub instruction_addresses: Vec<String>,
    /// Exact, unmodified PERF_SAMPLE_IP values represented by this site.
    pub raw_sampled_ips: Vec<String>,
    /// Exact PERF_SAMPLE_DATA_SRC values and their decoded aggregate statistics.
    pub raw_data_sources: Vec<C2cRawDataSourceRow>,
    pub relative_instruction_address: Option<String>,
    pub function_name: Option<String>,
    pub dso: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub inline_frames: Vec<C2cInlineFrame>,
    pub stats: C2cCachelineStats,
    pub distinct_virtual_cachelines: usize,
    pub distinct_physical_cachelines: usize,
    pub cacheline_offset: usize,
    pub returned_cachelines: usize,
    pub cachelines_truncated: bool,
    pub next_cacheline_offset: Option<usize>,
    pub cachelines: Vec<C2cAccessedCachelineRow>,
    pub offset_distribution: Vec<C2cOffsetRow>,
    pub related_access_sites: Vec<C2cRelatedAccessSiteRow>,
    pub per_thread: Vec<C2cThreadBreakdownRow>,
    pub per_cpu: Vec<C2cCpuBreakdownRow>,
    pub callchains: Vec<C2cCallchainRow>,
    pub symbolication_warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cAccessSiteRow {
    pub offset: u64,
    pub data_address: String,
    pub instruction_address: String,
    /// Exact, unmodified PERF_SAMPLE_IP value. This is an explicit alias for
    /// instruction_address for consumers that must distinguish raw and resolved addresses.
    pub raw_sampled_ip: String,
    /// Whether PERF_RECORD_MISC_EXACT_IP was set on these samples.
    pub exact_ip: bool,
    /// Recorded mapping containing this data address, when perf captured one.
    pub data_mapping: Option<C2cMappedDataAddress>,
    pub function_name: Option<String>,
    pub dso: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub inline_frames: Vec<C2cInlineFrame>,
    pub pid: i32,
    pub tid: i32,
    pub thread_name: String,
    pub cpu: u32,
    pub operation: String,
    pub memory_level: String,
    pub data_source: String,
    /// Exact PERF_SAMPLE_DATA_SRC value. This is an explicit alias for data_source.
    pub raw_data_source: String,
    pub samples: usize,
    pub total_hitm: usize,
    pub local_hitm: usize,
    pub remote_hitm: usize,
    pub total_peer: usize,
    pub local_peer: usize,
    pub remote_peer: usize,
    pub locked: usize,
    pub average_weight: f64,
    pub average_instruction_latency: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cCachelineDetailResult {
    pub profile: C2cProfileSummary,
    pub cacheline_address: String,
    pub physical_cacheline_addresses: Vec<String>,
    pub data_mappings: Vec<C2cDataMappingRow>,
    pub stats: C2cCachelineStats,
    pub access_sites: Vec<C2cAccessSiteRow>,
    pub symbolication_warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct C2cCachelineStats {
    pub samples: usize,
    pub loads: usize,
    pub stores: usize,
    pub total_hitm: usize,
    pub local_hitm: usize,
    pub remote_hitm: usize,
    pub total_peer: usize,
    pub local_peer: usize,
    pub remote_peer: usize,
    pub locked: usize,
    pub exact_ip_samples: usize,
    pub non_exact_ip_samples: usize,
    pub non_unit_weight_samples: usize,
    pub average_weight: f64,
    pub instruction_latency_samples: usize,
    pub average_instruction_latency: Option<f64>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadInfo {
    pub index: usize,
    pub name: String,
    pub pid: String,
    pub tid: String,
    pub sample_count: usize,
    pub duration_ms: f64,
    pub wall_time_ms: f64,
    pub cpu_sample_time_ms: f64,
    pub cpu_sample_percent_of_wall: f64,
    pub samples_per_second: f64,
    pub is_main: bool,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProfileThreadsResult {
    pub effective_range: EffectiveTimeRange,
    pub threads: Vec<ThreadInfo>,
    pub groups: Vec<ThreadSummaryGroup>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadSummaryGroup {
    pub name_prefix: String,
    pub thread_count: usize,
    pub sample_count: usize,
    pub wall_time_ms: f64,
    pub cpu_sample_time_ms: f64,
    pub cpu_sample_percent_of_wall: f64,
    pub samples_per_second: f64,
    pub max_thread_duration_ms: f64,
    pub main_thread_count: usize,
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
    pub effective_range: EffectiveTimeRange,
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub sort_by: String,
    pub functions: Vec<FunctionRow>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadGroupTopFunctionsResult {
    pub effective_range: EffectiveTimeRange,
    pub groups: Vec<ThreadGroupTopFunctionsGroup>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ThreadGroupTopFunctionsGroup {
    pub thread_name_prefix: String,
    pub normalized_thread_name_prefix: String,
    pub thread_count: usize,
    pub sample_count: usize,
    pub total_time_ms: f64,
    pub wall_time_ms: f64,
    pub cpu_sample_time_ms: f64,
    pub cpu_sample_percent_of_wall: f64,
    pub samples_per_second: f64,
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
    pub effective_range: EffectiveTimeRange,
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
    pub effective_range: EffectiveTimeRange,
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
    pub effective_range: EffectiveTimeRange,
    pub scope: String,
    pub thread: Option<String>,
    pub tid: Option<String>,
    pub thread_index: Option<usize>,
    pub thread_count: usize,
    pub sample_count: usize,
    pub wall_time_ms: f64,
    pub cpu_sample_time_ms: f64,
    pub cpu_sample_percent_of_wall: f64,
    pub samples_per_second: f64,
    pub threads: Vec<ThreadInfo>,
    pub focus_function: Option<String>,
    pub focus_function_id: Option<String>,
    pub focus_display_name: Option<String>,
    pub matched_samples: Option<usize>,
    pub focused_time_ms: Option<f64>,
    pub focused_percent: Option<f64>,
    pub tree: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MarkerInfo {
    pub name: String,
    pub start_time: Option<f64>,
    pub end_time: Option<f64>,
    pub phase: Option<u8>,
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
pub struct ContextSwitchCpuUsage {
    pub cpu: String,
    pub interval_count: usize,
    pub on_cpu_time_ms: f64,
    pub on_cpu_percent: f64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContextSwitchReasonSummary {
    pub reason: String,
    pub switch_count: usize,
    pub observed_off_cpu_time_ms: f64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OffCpuIntervalInfo {
    pub start_time_ms: f64,
    pub end_time_ms: f64,
    pub duration_ms: f64,
    pub reason: String,
    pub previous_cpu: String,
    pub next_cpu: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ContextSwitchesResult {
    pub effective_range: EffectiveTimeRange,
    pub thread: String,
    pub tid: String,
    pub thread_index: usize,
    pub observed_start_time_ms: f64,
    pub observed_end_time_ms: f64,
    pub observed_duration_ms: f64,
    pub on_cpu_time_ms: f64,
    pub off_cpu_time_ms: f64,
    pub on_cpu_percent: f64,
    pub off_cpu_percent: f64,
    pub on_cpu_interval_count: usize,
    pub switch_out_count: usize,
    pub cpus: Vec<ContextSwitchCpuUsage>,
    pub switch_out_reasons: Vec<ContextSwitchReasonSummary>,
    pub longest_off_cpu_intervals: Vec<OffCpuIntervalInfo>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FlamegraphResult {
    pub effective_range: EffectiveTimeRange,
    pub scope: String,
    pub thread: Option<String>,
    pub tid: Option<String>,
    pub thread_index: Option<usize>,
    pub thread_count: usize,
    pub threads: Vec<ThreadInfo>,
    pub focus_function: Option<String>,
    pub focus_function_id: Option<String>,
    pub focus_display_name: Option<String>,
    pub collapsed_stacks: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InlineSourceFrameInfo {
    pub inline_depth: usize,
    pub function_id: String,
    pub function_name: String,
    pub display_name: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InstructionSourceRow {
    /// Library-relative instruction address, formatted as hexadecimal.
    pub instruction_address: Option<String>,
    pub library: Option<String>,
    pub library_debug_id: Option<String>,
    pub symbol_name: Option<String>,
    pub symbol_start_address: Option<String>,
    pub symbol_offset: Option<String>,
    pub symbol_size: Option<u64>,
    pub focus_file: Option<String>,
    pub focus_line: Option<u32>,
    pub focus_source: Option<String>,
    /// `dwarf`, `sidecar`, `profile`, or `unresolved`.
    pub source_origin: String,
    /// Frames are ordered from the outer function to the deepest inline frame.
    pub inline_frames: Vec<InlineSourceFrameInfo>,
    pub sample_count: usize,
    pub cpu_sample_time_ms: f64,
    pub percent_of_exclusive: f64,
    pub percent_of_scope: f64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DwarfResolutionInfo {
    pub attempted_library_count: usize,
    pub loaded_library_count: usize,
    pub identity_verified_library_count: usize,
    pub attempted_instruction_count: usize,
    pub resolved_instruction_count: usize,
    pub resolved_sample_count: usize,
    pub binary_paths: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionSourceLineRow {
    pub library: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub source: Option<String>,
    pub instruction_count: usize,
    pub instruction_addresses: Vec<String>,
    pub sample_count: usize,
    pub cpu_sample_time_ms: f64,
    pub percent_of_exclusive: f64,
    pub percent_of_scope: f64,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionSourceResult {
    pub effective_range: EffectiveTimeRange,
    pub scope: String,
    pub thread: Option<String>,
    pub tid: Option<String>,
    pub thread_index: Option<usize>,
    pub thread_count: usize,
    pub threads: Vec<ThreadInfo>,
    pub function_id: String,
    pub function_name: String,
    pub display_name: String,
    pub symbol_sidecar_loaded: bool,
    pub dwarf_resolution: DwarfResolutionInfo,
    pub exclusive_samples: usize,
    pub exclusive_time_ms: f64,
    pub exclusive_percent_of_scope: f64,
    pub total_scope_samples: usize,
    pub scope_time_ms: f64,
    pub instruction_resolved_samples: usize,
    pub source_resolved_samples: usize,
    pub sidecar_symbolicated_samples: usize,
    pub instruction_count: usize,
    pub returned_instruction_count: usize,
    pub source_line_count: usize,
    pub returned_source_line_count: usize,
    pub instructions: Vec<InstructionSourceRow>,
    pub source_lines: Vec<FunctionSourceLineRow>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FocusFunctionResult {
    pub effective_range: EffectiveTimeRange,
    pub scope: String,
    pub thread: Option<String>,
    pub tid: Option<String>,
    pub thread_index: Option<usize>,
    pub thread_count: usize,
    pub threads: Vec<ThreadInfo>,
    pub function_id: String,
    pub function_name: String,
    pub display_name: String,
    pub matched_samples: usize,
    pub total_thread_samples: usize,
    pub total_scope_samples: usize,
    pub wall_time_ms: f64,
    pub cpu_sample_time_ms: f64,
    pub cpu_sample_percent_of_wall: f64,
    pub samples_per_second: f64,
    pub focused_percent: f64,
    pub focused_time_ms: f64,
    pub tree: String,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FunctionUnderCallerResult {
    pub effective_range: EffectiveTimeRange,
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
    pub wall_time_ms: f64,
    pub cpu_sample_time_ms: f64,
    pub cpu_sample_percent_of_wall: f64,
    pub samples_per_second: f64,
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
        description = "Get profile metadata: duration, raw observed sample-clock start, sample count, thread count, sampling interval, and categories"
    )]
    fn profile_info(
        &self,
        Parameters(req): Parameters<ProfileInfoRequest>,
    ) -> Result<Json<ProfileInfoResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let profile = &cached.profile;

        Ok(Json(ProfileInfoResult {
            product: profile.product.clone(),
            observed_start_time_ms: profile.observed_start_time_ms,
            duration_ms: profile.duration_ms,
            total_samples: profile.total_sample_count,
            thread_count: profile.threads.len(),
            interval_ms: profile.interval_ms,
            categories: profile.categories.clone(),
        }))
    }

    #[tool(
        description = "Rank contended cachelines from a perf.data file recorded with perf c2c record. Reports HITM, peer, load/store, latency, CPU, process, and thread aggregates without invoking the perf command-line report"
    )]
    fn c2c_top_cachelines(
        &self,
        Parameters(req): Parameters<C2cTopCachelinesRequest>,
    ) -> Result<Json<C2cTopCachelinesResult>, String> {
        let sort_by = req.sort_by.to_ascii_lowercase();
        if !matches!(sort_by.as_str(), "hitm" | "peer" | "samples" | "weight") {
            return Err("sort_by must be 'hitm', 'peer', 'samples', or 'weight'".to_string());
        }

        let profile = self.get_c2c_profile(&req.path)?;
        let filter = C2cFilter {
            pid: req.pid,
            tid: req.tid,
            thread_name_prefix: req.thread_name_prefix.as_deref(),
            start_time_ms: req.start_time_ms,
            end_time_ms: req.end_time_ms,
        };
        filter.validate()?;

        let mut cachelines: HashMap<u64, C2cCachelineAccum> = HashMap::new();
        let mut totals = C2cStats::default();
        let mut memory_levels: BTreeMap<&'static str, C2cStats> = BTreeMap::new();
        let mut matched_memory_samples = 0;
        for sample in profile
            .samples
            .iter()
            .filter(|sample| filter.matches(&profile, sample))
        {
            matched_memory_samples += 1;
            totals.add_sample(sample);
            memory_levels
                .entry(sample.data_source.level())
                .or_default()
                .add_sample(sample);
            let address = align_cacheline(sample.data_address, profile.cacheline_size);
            cachelines
                .entry(address)
                .or_default()
                .add_sample(sample, profile.cacheline_size);
        }

        let total_hitm = totals.total_hitm();
        let total_peer = totals.total_peer();
        let mut cachelines: Vec<_> = cachelines.into_iter().collect();
        cachelines.sort_unstable_by(|(left_address, left), (right_address, right)| {
            let metric = |line: &C2cCachelineAccum| match sort_by.as_str() {
                "hitm" => line.stats.total_hitm() as u128,
                "peer" => line.stats.total_peer() as u128,
                "samples" => line.stats.samples as u128,
                "weight" => line.stats.weight_sum,
                _ => unreachable!("sort_by was validated"),
            };
            metric(right)
                .cmp(&metric(left))
                .then_with(|| right.stats.samples.cmp(&left.stats.samples))
                .then_with(|| left_address.cmp(right_address))
        });
        cachelines.truncate(req.limit.min(1_000));

        let cachelines = cachelines
            .into_iter()
            .map(|(address, line)| C2cCachelineRow {
                cacheline_address: format_address(address),
                physical_cacheline_addresses: line
                    .physical_addresses
                    .into_iter()
                    .map(format_address)
                    .collect(),
                samples: line.stats.samples,
                loads: line.stats.loads,
                stores: line.stats.stores,
                total_hitm: line.stats.total_hitm(),
                local_hitm: line.stats.local_hitm,
                remote_hitm: line.stats.remote_hitm,
                hitm_percent: percent(line.stats.total_hitm() as f64, total_hitm as f64),
                total_peer: line.stats.total_peer(),
                local_peer: line.stats.local_peer,
                remote_peer: line.stats.remote_peer,
                locked: line.stats.locked,
                average_weight: line.stats.average_weight(),
                average_instruction_latency: line.stats.average_instruction_latency(),
                cpus: line.cpus.into_iter().collect(),
                pids: line.pids.into_iter().collect(),
                tids: line.tids.into_iter().collect(),
                thread_names: line.thread_names.into_iter().collect(),
            })
            .collect();

        Ok(Json(C2cTopCachelinesResult {
            profile: c2c_profile_summary(&profile, matched_memory_samples),
            sort_by,
            matched_stats: c2c_stats_result(&totals),
            matched_memory_levels: c2c_memory_level_rows(&memory_levels),
            total_matched_hitm: total_hitm,
            total_matched_peer: total_peer,
            cachelines,
        }))
    }

    #[tool(
        description = "Rank memory access instructions across every cacheline they touched in a perf c2c capture. This exposes one lock or field access fragmented across many heap allocations; rows include stable site IDs, source and inline frames, HITM/peer/lock/latency statistics, distinct virtual and physical cacheline counts, and optional recorded callchains"
    )]
    fn c2c_top_access_sites(
        &self,
        Parameters(req): Parameters<C2cTopAccessSitesRequest>,
    ) -> Result<Json<C2cTopAccessSitesResult>, String> {
        let sort_by = req.sort_by.to_ascii_lowercase();
        if !matches!(
            sort_by.as_str(),
            "hitm" | "locked" | "samples" | "weight" | "latency"
        ) {
            return Err(
                "sort_by must be 'hitm', 'locked', 'samples', 'weight', or 'latency'".to_string(),
            );
        }

        let profile = self.get_c2c_profile(&req.path)?;
        let filter = C2cFilter {
            pid: req.pid,
            tid: req.tid,
            thread_name_prefix: req.thread_name_prefix.as_deref(),
            start_time_ms: req.start_time_ms,
            end_time_ms: req.end_time_ms,
        };
        filter.validate()?;

        let include_callchains = req.include_callchains || req.group_by_callchain;
        let mut sites: HashMap<C2cSiteKey, C2cSiteAccum> = HashMap::new();
        let mut totals = C2cStats::default();
        let mut memory_levels: BTreeMap<&'static str, C2cStats> = BTreeMap::new();
        let mut matched_memory_samples = 0;
        for sample in profile
            .samples
            .iter()
            .filter(|sample| filter.matches(&profile, sample))
        {
            matched_memory_samples += 1;
            totals.add_sample(sample);
            memory_levels
                .entry(sample.data_source.level())
                .or_default()
                .add_sample(sample);
            let key = C2cSiteKey::for_sample(sample, req.group_by_callchain);
            let grouped_callchain = req
                .group_by_callchain
                .then(|| Arc::clone(&sample.callchain));
            sites
                .entry(key.clone())
                .or_insert_with(|| C2cSiteAccum::new(key, grouped_callchain))
                .add_sample(sample, profile.cacheline_size, include_callchains);
        }

        validate_c2c_latency_sort(&sort_by, matched_memory_samples, &totals)?;

        let total_access_sites = sites.len();
        let mut sites: Vec<_> = sites.into_values().collect();
        sites.sort_unstable_by(|left, right| {
            let ordering = match sort_by.as_str() {
                "hitm" => right.stats.total_hitm().cmp(&left.stats.total_hitm()),
                "locked" => right.stats.locked.cmp(&left.stats.locked),
                "samples" => right.stats.samples.cmp(&left.stats.samples),
                "weight" => right.stats.weight_sum.cmp(&left.stats.weight_sum),
                "latency" => right
                    .stats
                    .average_instruction_latency()
                    .unwrap_or(0.0)
                    .total_cmp(&left.stats.average_instruction_latency().unwrap_or(0.0)),
                _ => unreachable!("sort_by was validated"),
            };
            ordering
                .then_with(|| right.stats.total_hitm().cmp(&left.stats.total_hitm()))
                .then_with(|| right.stats.samples.cmp(&left.stats.samples))
                .then_with(|| c2c_site_id(&left.key).cmp(&c2c_site_id(&right.key)))
        });
        sites.truncate(req.limit.min(1_000));

        let mut resolvers = HashMap::new();
        let mut resolution_failures = HashMap::new();
        let access_sites = sites
            .into_iter()
            .map(|site| {
                let site_id = c2c_site_id(&site.key);
                let mapped = site.key.instruction.mapped.as_ref();
                let resolved =
                    resolve_c2c_instruction(mapped, &mut resolvers, &mut resolution_failures);
                let distinct_hitm_cachelines = site.hitm_cacheline_count();
                let instruction_addresses: Vec<_> = site
                    .instruction_addresses
                    .into_iter()
                    .map(format_address)
                    .collect();
                let instruction_address = instruction_addresses
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format_address(site.key.instruction.raw_address));
                let raw_sampled_ips = instruction_addresses.clone();
                let grouped_callchain =
                    site.grouped_callchain
                        .as_deref()
                        .map_or_else(Vec::new, |frames| {
                            resolve_c2c_callchain(frames, &mut resolvers, &mut resolution_failures)
                        });
                let top_callchains = if include_callchains {
                    render_c2c_callchains(
                        site.callchains.into_values().collect(),
                        req.callchain_limit,
                        &mut resolvers,
                        &mut resolution_failures,
                    )
                } else {
                    Vec::new()
                };
                C2cTopAccessSiteRow {
                    site_id,
                    instruction_address,
                    instruction_addresses,
                    raw_sampled_ips,
                    raw_data_sources: c2c_raw_data_source_rows(site.data_sources),
                    relative_instruction_address: mapped
                        .map(|mapped| format_address(mapped.relative_address)),
                    function_name: resolved.function_name,
                    dso: mapped.map(|mapped| mapped.path.to_string()),
                    file: resolved.file,
                    line: resolved.line,
                    inline_frames: resolved.inline_frames,
                    grouped_callchain,
                    top_callchains,
                    samples: site.stats.samples,
                    loads: site.stats.loads,
                    stores: site.stats.stores,
                    total_hitm: site.stats.total_hitm(),
                    local_hitm: site.stats.local_hitm,
                    remote_hitm: site.stats.remote_hitm,
                    total_peer: site.stats.total_peer(),
                    local_peer: site.stats.local_peer,
                    remote_peer: site.stats.remote_peer,
                    locked: site.stats.locked,
                    exact_ip_samples: site.stats.exact_ip_samples,
                    non_exact_ip_samples: site
                        .stats
                        .samples
                        .saturating_sub(site.stats.exact_ip_samples),
                    non_unit_weight_samples: site.stats.non_unit_weight_samples,
                    instruction_latency_samples: site.stats.instruction_latency_samples,
                    average_weight: site.stats.average_weight(),
                    average_instruction_latency: site.stats.average_instruction_latency(),
                    distinct_virtual_cachelines: site.virtual_cachelines.len(),
                    distinct_hitm_cachelines,
                    distinct_physical_cachelines: site.physical_cachelines.len(),
                    cpus: site.cpus.into_iter().collect(),
                    pids: site.pids.into_iter().collect(),
                    tids: site.tids.into_iter().collect(),
                    thread_names: site.thread_names.into_iter().collect(),
                }
            })
            .collect();

        Ok(Json(C2cTopAccessSitesResult {
            profile: c2c_profile_summary(&profile, matched_memory_samples),
            sort_by,
            matched_stats: c2c_stats_result(&totals),
            matched_memory_levels: c2c_memory_level_rows(&memory_levels),
            grouped_by_callchain: req.group_by_callchain,
            total_access_sites,
            access_sites,
            symbolication_warnings: c2c_symbolication_warnings(resolution_failures),
        }))
    }

    #[tool(
        description = "Explain one cross-cacheline access site selected by instruction_address or stable site_id. Returns every matching cacheline up to cacheline_limit, offset distribution, other instructions and threads accessing those lines, recorded callchains, and per-thread/per-CPU breakdowns"
    )]
    fn c2c_access_site_detail(
        &self,
        Parameters(req): Parameters<C2cAccessSiteDetailRequest>,
    ) -> Result<Json<C2cAccessSiteDetailResult>, String> {
        if req.instruction_address.is_some() == req.site_id.is_some() {
            return Err(
                "provide exactly one of instruction_address or site_id from c2c_top_access_sites"
                    .to_string(),
            );
        }
        let requested_address = req
            .instruction_address
            .as_deref()
            .map(parse_address)
            .transpose()?;
        let requested_site_id = req.site_id.as_deref();
        let profile = self.get_c2c_profile(&req.path)?;
        let filter = C2cFilter {
            pid: req.pid,
            tid: req.tid,
            thread_name_prefix: req.thread_name_prefix.as_deref(),
            start_time_ms: req.start_time_ms,
            end_time_ms: req.end_time_ms,
        };
        filter.validate()?;

        let mut site: Option<C2cSiteAccum> = None;
        let mut cachelines: HashMap<(i32, u64), C2cDetailedCachelineAccum> = HashMap::new();
        let mut offsets: HashMap<u64, C2cStats> = HashMap::new();
        let mut threads: HashMap<(i32, i32, Arc<str>), C2cThreadBreakdownAccum> = HashMap::new();
        let mut cpus: HashMap<u32, C2cCpuBreakdownAccum> = HashMap::new();

        for sample in profile
            .samples
            .iter()
            .filter(|sample| filter.matches(&profile, sample))
        {
            let Some(matched_key) =
                select_c2c_site_key(sample, requested_address, requested_site_id)
            else {
                continue;
            };
            let line_address = align_cacheline(sample.data_address, profile.cacheline_size);
            let line_key = (sample.pid, line_address);
            let grouped_callchain = matched_key
                .callchain
                .is_some()
                .then(|| Arc::clone(&sample.callchain));
            site.get_or_insert_with(|| C2cSiteAccum::new(matched_key, grouped_callchain))
                .add_sample(sample, profile.cacheline_size, true);
            cachelines
                .entry(line_key)
                .or_default()
                .add_sample(sample, profile.cacheline_size);
            offsets
                .entry(sample.data_address - line_address)
                .or_default()
                .add_sample(sample);

            let thread = threads
                .entry((sample.pid, sample.tid, Arc::clone(&sample.thread_name)))
                .or_default();
            thread.stats.add_sample(sample);
            thread.cachelines.insert(line_key);
            thread.cpus.insert(sample.cpu);

            let cpu = cpus.entry(sample.cpu).or_default();
            cpu.stats.add_sample(sample);
            cpu.cachelines.insert(line_key);
            cpu.tids.insert(sample.tid);
            cpu.thread_names.insert(sample.thread_name.to_string());
        }

        let Some(site) = site else {
            return Err(
                "no memory samples matched the requested access site and filters".to_string(),
            );
        };

        let target_cachelines: BTreeSet<_> = site.virtual_cachelines.keys().copied().collect();
        let mut related: HashMap<C2cInstructionIdentity, C2cRelatedSiteAccum> = HashMap::new();
        for sample in profile
            .samples
            .iter()
            .filter(|sample| filter.matches(&profile, sample))
        {
            let line_key = (
                sample.pid,
                align_cacheline(sample.data_address, profile.cacheline_size),
            );
            if !target_cachelines.contains(&line_key)
                || select_c2c_site_key(sample, requested_address, requested_site_id).is_some()
            {
                continue;
            }
            let identity = C2cInstructionIdentity::new(
                sample.instruction_address,
                sample.mapped_instruction.as_ref(),
            );
            related
                .entry(identity.clone())
                .or_insert_with(|| C2cRelatedSiteAccum::new(identity))
                .add_sample(sample, profile.cacheline_size);
        }

        let mut cachelines: Vec<_> = cachelines.into_iter().collect();
        cachelines.sort_unstable_by(|(left_key, left), (right_key, right)| {
            right
                .stats
                .total_hitm()
                .cmp(&left.stats.total_hitm())
                .then_with(|| right.stats.locked.cmp(&left.stats.locked))
                .then_with(|| right.stats.samples.cmp(&left.stats.samples))
                .then_with(|| left_key.cmp(right_key))
        });
        let distinct_virtual_cachelines = cachelines.len();
        let cacheline_offset = req.cacheline_offset.min(distinct_virtual_cachelines);
        let cacheline_limit = req.cacheline_limit.min(10_000);
        let cachelines = cachelines
            .into_iter()
            .skip(cacheline_offset)
            .take(cacheline_limit)
            .map(|((pid, address), line)| {
                let mut line_offsets: Vec<_> = line.offsets.into_iter().collect();
                line_offsets.sort_unstable_by(|(left_offset, left), (right_offset, right)| {
                    right
                        .total_hitm()
                        .cmp(&left.total_hitm())
                        .then_with(|| right.locked.cmp(&left.locked))
                        .then_with(|| right.samples.cmp(&left.samples))
                        .then_with(|| left_offset.cmp(right_offset))
                });
                C2cAccessedCachelineRow {
                    pid,
                    cacheline_address: format_address(address),
                    physical_cacheline_addresses: line
                        .physical_cachelines
                        .into_iter()
                        .map(format_address)
                        .collect(),
                    data_mappings: c2c_data_mapping_rows(line.data_mappings),
                    stats: c2c_stats_result(&line.stats),
                    offsets: line_offsets
                        .into_iter()
                        .map(|(offset, stats)| C2cOffsetRow {
                            offset,
                            stats: c2c_stats_result(&stats),
                        })
                        .collect(),
                }
            })
            .collect::<Vec<_>>();

        let mut offsets: Vec<_> = offsets.into_iter().collect();
        offsets.sort_unstable_by(|(left_offset, left), (right_offset, right)| {
            right
                .total_hitm()
                .cmp(&left.total_hitm())
                .then_with(|| right.locked.cmp(&left.locked))
                .then_with(|| right.samples.cmp(&left.samples))
                .then_with(|| left_offset.cmp(right_offset))
        });
        let offset_distribution = offsets
            .into_iter()
            .map(|(offset, stats)| C2cOffsetRow {
                offset,
                stats: c2c_stats_result(&stats),
            })
            .collect();

        let mut resolvers = HashMap::new();
        let mut resolution_failures = HashMap::new();
        let mapped = site.key.instruction.mapped.as_ref();
        let resolved = resolve_c2c_instruction(mapped, &mut resolvers, &mut resolution_failures);

        let mut related: Vec<_> = related.into_values().collect();
        related.sort_unstable_by(|left, right| {
            right
                .stats
                .total_hitm()
                .cmp(&left.stats.total_hitm())
                .then_with(|| right.stats.locked.cmp(&left.stats.locked))
                .then_with(|| right.stats.samples.cmp(&left.stats.samples))
        });
        related.truncate(req.related_limit.min(1_000));
        let related_access_sites = related
            .into_iter()
            .map(|related| {
                let mapped = related.identity.mapped.as_ref();
                let resolved =
                    resolve_c2c_instruction(mapped, &mut resolvers, &mut resolution_failures);
                let key = C2cSiteKey {
                    instruction: related.identity.clone(),
                    callchain: None,
                };
                C2cRelatedAccessSiteRow {
                    site_id: c2c_site_id(&key),
                    instruction_address: related
                        .instruction_addresses
                        .first()
                        .copied()
                        .map(format_address)
                        .unwrap_or_else(|| format_address(key.instruction.raw_address)),
                    relative_instruction_address: mapped
                        .map(|mapped| format_address(mapped.relative_address)),
                    function_name: resolved.function_name,
                    dso: mapped.map(|mapped| mapped.path.to_string()),
                    file: resolved.file,
                    line: resolved.line,
                    inline_frames: resolved.inline_frames,
                    stats: c2c_stats_result(&related.stats),
                    shared_cachelines: related.cachelines.len(),
                    cpus: related.cpus.into_iter().collect(),
                    pids: related.pids.into_iter().collect(),
                    tids: related.tids.into_iter().collect(),
                    thread_names: related.thread_names.into_iter().collect(),
                }
            })
            .collect();

        let mut threads: Vec<_> = threads.into_iter().collect();
        threads.sort_unstable_by(|(_, left), (_, right)| {
            right
                .stats
                .total_hitm()
                .cmp(&left.stats.total_hitm())
                .then_with(|| right.stats.locked.cmp(&left.stats.locked))
                .then_with(|| right.stats.samples.cmp(&left.stats.samples))
        });
        threads.truncate(req.related_limit.min(1_000));
        let per_thread = threads
            .into_iter()
            .map(|((pid, tid, thread_name), thread)| C2cThreadBreakdownRow {
                pid,
                tid,
                thread_name: thread_name.to_string(),
                stats: c2c_stats_result(&thread.stats),
                distinct_virtual_cachelines: thread.cachelines.len(),
                cpus: thread.cpus.into_iter().collect(),
            })
            .collect();

        let mut cpus: Vec<_> = cpus.into_iter().collect();
        cpus.sort_unstable_by(|(left_cpu, left), (right_cpu, right)| {
            right
                .stats
                .total_hitm()
                .cmp(&left.stats.total_hitm())
                .then_with(|| right.stats.locked.cmp(&left.stats.locked))
                .then_with(|| right.stats.samples.cmp(&left.stats.samples))
                .then_with(|| left_cpu.cmp(right_cpu))
        });
        cpus.truncate(req.related_limit.min(1_000));
        let per_cpu = cpus
            .into_iter()
            .map(|(cpu, breakdown)| C2cCpuBreakdownRow {
                cpu,
                stats: c2c_stats_result(&breakdown.stats),
                distinct_virtual_cachelines: breakdown.cachelines.len(),
                tids: breakdown.tids.into_iter().collect(),
                thread_names: breakdown.thread_names.into_iter().collect(),
            })
            .collect();

        let callchains = render_c2c_callchains(
            site.callchains.into_values().collect(),
            req.related_limit,
            &mut resolvers,
            &mut resolution_failures,
        );
        let site_id = c2c_site_id(&site.key);
        let instruction_addresses: Vec<_> = site
            .instruction_addresses
            .into_iter()
            .map(format_address)
            .collect();
        let instruction_address = instruction_addresses
            .first()
            .cloned()
            .unwrap_or_else(|| format_address(site.key.instruction.raw_address));
        let raw_sampled_ips = instruction_addresses.clone();
        let returned_cachelines = cachelines.len();
        let next_cacheline_offset = (cacheline_offset + returned_cachelines
            < distinct_virtual_cachelines)
            .then_some(cacheline_offset + returned_cachelines);

        Ok(Json(C2cAccessSiteDetailResult {
            profile: c2c_profile_summary(&profile, site.stats.samples),
            site_id,
            instruction_address,
            instruction_addresses,
            raw_sampled_ips,
            raw_data_sources: c2c_raw_data_source_rows(site.data_sources),
            relative_instruction_address: mapped
                .map(|mapped| format_address(mapped.relative_address)),
            function_name: resolved.function_name,
            dso: mapped.map(|mapped| mapped.path.to_string()),
            file: resolved.file,
            line: resolved.line,
            inline_frames: resolved.inline_frames,
            stats: c2c_stats_result(&site.stats),
            distinct_virtual_cachelines,
            distinct_physical_cachelines: site.physical_cachelines.len(),
            cacheline_offset,
            returned_cachelines,
            cachelines_truncated: next_cacheline_offset.is_some(),
            next_cacheline_offset,
            cachelines,
            offset_distribution,
            related_access_sites,
            per_thread,
            per_cpu,
            callchains,
            symbolication_warnings: c2c_symbolication_warnings(resolution_failures),
        }))
    }

    #[tool(
        description = "Explain one cacheline returned by c2c_top_cachelines. Groups its accesses by instruction, thread, CPU, offset, and memory-source classification, and resolves recorded instructions through matching local binaries when possible"
    )]
    fn c2c_cacheline_detail(
        &self,
        Parameters(req): Parameters<C2cCachelineDetailRequest>,
    ) -> Result<Json<C2cCachelineDetailResult>, String> {
        let profile = self.get_c2c_profile(&req.path)?;
        let cacheline_address = parse_address(&req.cacheline_address)?;
        let aligned_address = align_cacheline(cacheline_address, profile.cacheline_size);
        if cacheline_address != aligned_address {
            return Err(format!(
                "cacheline_address must be {}-byte aligned; use {}",
                profile.cacheline_size,
                format_address(aligned_address)
            ));
        }
        let filter = C2cFilter {
            pid: req.pid,
            tid: req.tid,
            thread_name_prefix: req.thread_name_prefix.as_deref(),
            start_time_ms: req.start_time_ms,
            end_time_ms: req.end_time_ms,
        };
        filter.validate()?;

        let mut stats = C2cStats::default();
        let mut physical_addresses = BTreeSet::new();
        let mut data_mappings: HashMap<C2cDataMappingKey, C2cStats> = HashMap::new();
        let mut access_sites: HashMap<C2cAccessKey, C2cAccessAccum> = HashMap::new();
        for sample in profile.samples.iter().filter(|sample| {
            filter.matches(&profile, sample)
                && align_cacheline(sample.data_address, profile.cacheline_size) == cacheline_address
        }) {
            stats.add_sample(sample);
            if let Some(address) = sample.physical_address {
                physical_addresses.insert(align_cacheline(address, profile.cacheline_size));
            }
            if let Some(mapped) = &sample.mapped_data_address {
                data_mappings
                    .entry(mapped.into())
                    .or_default()
                    .add_sample(sample);
            }
            let key = C2cAccessKey {
                offset: sample.data_address - cacheline_address,
                pid: sample.pid,
                tid: sample.tid,
                cpu: sample.cpu,
                thread_name: Arc::clone(&sample.thread_name),
                instruction_address: sample.instruction_address,
                exact_ip: sample.exact_ip,
                data_source: sample.data_source,
                mapped_data_address: sample.mapped_data_address.clone(),
                mapped_instruction: sample.mapped_instruction.clone(),
            };
            access_sites
                .entry(key.clone())
                .or_insert_with(|| C2cAccessAccum {
                    key,
                    stats: C2cStats::default(),
                })
                .stats
                .add_sample(sample);
        }
        if stats.samples == 0 {
            return Err(format!(
                "no memory samples matched cacheline {} and the requested filters",
                format_address(cacheline_address)
            ));
        }

        let mut access_sites: Vec<_> = access_sites.into_values().collect();
        access_sites.sort_unstable_by(|left, right| {
            right
                .stats
                .total_hitm()
                .cmp(&left.stats.total_hitm())
                .then_with(|| right.stats.total_peer().cmp(&left.stats.total_peer()))
                .then_with(|| right.stats.samples.cmp(&left.stats.samples))
                .then_with(|| right.stats.weight_sum.cmp(&left.stats.weight_sum))
                .then_with(|| {
                    left.key
                        .instruction_address
                        .cmp(&right.key.instruction_address)
                })
        });
        access_sites.truncate(req.limit.min(1_000));

        let mut resolvers = HashMap::new();
        let mut resolution_failures = HashMap::new();
        let access_sites = access_sites
            .into_iter()
            .map(|access| {
                let key = access.key;
                let resolved = resolve_c2c_instruction(
                    key.mapped_instruction.as_ref(),
                    &mut resolvers,
                    &mut resolution_failures,
                );
                C2cAccessSiteRow {
                    offset: key.offset,
                    data_address: format_address(cacheline_address + key.offset),
                    instruction_address: format_address(key.instruction_address),
                    raw_sampled_ip: format_address(key.instruction_address),
                    exact_ip: key.exact_ip,
                    data_mapping: key.mapped_data_address.map(c2c_mapped_data_address),
                    function_name: resolved.function_name,
                    dso: key
                        .mapped_instruction
                        .as_ref()
                        .map(|mapped| mapped.path.to_string()),
                    file: resolved.file,
                    line: resolved.line,
                    inline_frames: resolved.inline_frames,
                    pid: key.pid,
                    tid: key.tid,
                    thread_name: key.thread_name.to_string(),
                    cpu: key.cpu,
                    operation: key.data_source.operation().to_string(),
                    memory_level: key.data_source.level().to_string(),
                    data_source: format!("0x{:x}", key.data_source.raw),
                    raw_data_source: format!("0x{:x}", key.data_source.raw),
                    samples: access.stats.samples,
                    total_hitm: access.stats.total_hitm(),
                    local_hitm: access.stats.local_hitm,
                    remote_hitm: access.stats.remote_hitm,
                    total_peer: access.stats.total_peer(),
                    local_peer: access.stats.local_peer,
                    remote_peer: access.stats.remote_peer,
                    locked: access.stats.locked,
                    average_weight: access.stats.average_weight(),
                    average_instruction_latency: access.stats.average_instruction_latency(),
                }
            })
            .collect();
        let mut symbolication_warnings: Vec<_> = resolution_failures
            .into_iter()
            .map(|(path, error)| format!("{path}: {error}"))
            .collect();
        symbolication_warnings.sort_unstable();

        Ok(Json(C2cCachelineDetailResult {
            profile: c2c_profile_summary(&profile, stats.samples),
            cacheline_address: format_address(cacheline_address),
            physical_cacheline_addresses: physical_addresses
                .into_iter()
                .map(format_address)
                .collect(),
            data_mappings: c2c_data_mapping_rows(data_mappings),
            stats: c2c_stats_result(&stats),
            access_sites,
            symbolication_warnings,
        }))
    }

    #[tool(
        description = "List threads with optional prefix/regex/sample/duration filters, CPU-sample vs wall-time summaries, and optional compact groups by name prefix"
    )]
    fn profile_threads(
        &self,
        Parameters(req): Parameters<ProfileThreadsRequest>,
    ) -> Result<Json<ProfileThreadsResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let profile = &cached.profile;
        let range = AnalysisRange::resolve(profile, req.start_time_ms, req.end_time_ms)?;
        let prefixes =
            requested_thread_prefixes(&req.thread_name_prefix, &req.thread_name_prefixes);
        let thread_name_regex = compile_optional_regex(&req.thread_name_regex, "thread_name")?;

        let thread_indices: Vec<usize> = profile
            .threads
            .iter()
            .enumerate()
            .filter(|(_, thread)| {
                if !prefixes.is_empty()
                    && !prefixes
                        .iter()
                        .any(|prefix| thread_name_matches_prefix(&thread.name, prefix))
                {
                    return false;
                }

                if let Some(regex) = &thread_name_regex
                    && !regex.is_match(&thread.name)
                {
                    return false;
                }

                if let Some(min_samples) = req.min_samples
                    && samples::sample_count(thread, Some(&range)) < min_samples
                {
                    return false;
                }

                if let Some(min_duration_ms) = req.min_duration_ms
                    && samples::thread_wall_time_ms(thread, Some(&range)) < min_duration_ms
                {
                    return false;
                }

                true
            })
            .map(|(index, _)| index)
            .collect();
        let groups = if req.group_by_name_prefix {
            thread_summary_groups(profile, &thread_indices, Some(&range))
        } else {
            Vec::new()
        };
        let threads = if req.include_threads {
            thread_infos(profile, &thread_indices, Some(&range))
        } else {
            Vec::new()
        };

        Ok(Json(ProfileThreadsResult {
            effective_range: effective_time_range(&range),
            threads,
            groups,
        }))
    }

    #[tool(
        description = "Get top N functions by self-time or total-time for a thread. Use sort_by='self' for CPU hotspots, sort_by='total' for functions dominating the call tree."
    )]
    fn profile_top_functions(
        &self,
        Parameters(req): Parameters<TopFunctionsRequest>,
    ) -> Result<Json<TopFunctionsResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;
        let selected = select_sample_thread(
            &cached.profile,
            &req.thread,
            &req.tid,
            req.thread_index,
            &range,
        )?;
        let thread = selected.thread;

        let mut stats = function_stats_for_thread(&cached, selected.index, &range);

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
            effective_range: effective_time_range(&range),
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
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;
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
                .filter(|(_, thread)| {
                    thread.name.starts_with(&normalized_prefix)
                        && samples::sample_count(thread, Some(&range)) > 0
                })
                .map(|(index, _)| index)
                .collect();

            if !thread_indices.is_empty() {
                matched_any = true;
            }

            let (mut stats, total_time_ms, sample_count) =
                aggregate_function_stats(&cached, &thread_indices, &range);
            sort_function_stats(&mut stats, &req.sort_by);
            let summary = thread_sample_summary(&cached.profile, &thread_indices, Some(&range));

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
                wall_time_ms: round2(summary.wall_time_ms),
                cpu_sample_time_ms: round2(summary.cpu_sample_time_ms),
                cpu_sample_percent_of_wall: round2(summary.cpu_sample_percent_of_wall),
                samples_per_second: round2(summary.samples_per_second),
                sort_by: req.sort_by.clone(),
                threads: if req.include_threads {
                    thread_infos(&cached.profile, &thread_indices, Some(&range))
                } else {
                    Vec::new()
                },
                functions,
            });
        }

        if !matched_any {
            return Err("No threads matched the requested prefix group(s)".to_string());
        }

        Ok(Json(ThreadGroupTopFunctionsResult {
            effective_range: effective_time_range(&range),
            groups,
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
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;

        let selected = if req.thread.is_some() || req.tid.is_some() || req.thread_index.is_some() {
            Some(select_sample_thread(
                &cached.profile,
                &req.thread,
                &req.tid,
                req.thread_index,
                &range,
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

            if samples::sample_count(thread, Some(&range)) == 0 {
                continue;
            }
            let stats = function_stats_for_thread(&cached, index, &range);

            for stat in &stats {
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
            effective_range: effective_time_range(&range),
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
        let range = AnalysisRange::resolve(profile, req.start_time_ms, req.end_time_ms)?;
        let thread_indices: Vec<usize> = profile
            .threads
            .iter()
            .enumerate()
            .filter(|(_, thread)| samples::sample_count(thread, Some(&range)) > 0)
            .map(|(index, _)| index)
            .collect();
        let stats_by_thread = function_stats_for_threads(&cached, &thread_indices, &range);
        let target = resolve_function_name(
            &stats_by_thread,
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
        let mut total_samples = 0usize;
        let mut library = None;
        let mut file = None;
        let mut line = None;
        let mut callers: HashMap<String, usize> = HashMap::new();
        let mut callees: HashMap<String, usize> = HashMap::new();
        let mut found_threads = Vec::new();

        for (thread_index, thread) in profile.threads.iter().enumerate() {
            // Check function stats
            if let Some(stats) = stats_by_thread.get(thread_index)
                && let Some(s) = stats.iter().find(|s| s.name == target)
            {
                total_self_time += s.self_time_ms;
                total_total_time += s.total_time_ms;
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
            for sample in thread
                .samples
                .iter()
                .filter(|sample| range.contains(sample))
            {
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
        let scope_time_ms = scope_total_time_ms(profile, &thread_indices, Some(&range));

        Ok(Json(FunctionDetailResult {
            effective_range: effective_time_range(&range),
            function_id: symbols::function_id(&target),
            display_name: symbols::compact_function_name(&target),
            function_name: target,
            self_time_ms: round2(total_self_time),
            total_time_ms: round2(total_total_time),
            self_percent: round2(percent(total_self_time, scope_time_ms)),
            total_percent: round2(percent(total_total_time, scope_time_ms)),
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
        description = "Get a hierarchical call tree showing where time is spent, with optional thread-prefix aggregation and focused rerooting"
    )]
    fn profile_call_tree(
        &self,
        Parameters(req): Parameters<CallTreeRequest>,
    ) -> Result<Json<CallTreeResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;
        let selection = select_thread_indices_for_single_or_prefix_scope(
            &cached.profile,
            &req.thread,
            &req.tid,
            req.thread_index,
            &req.thread_name_prefix,
            &req.thread_name_prefixes,
            &range,
        )?;
        let thread_refs: Vec<&ResolvedThread> = selection
            .thread_indices
            .iter()
            .filter_map(|index| cached.profile.threads.get(*index))
            .collect();

        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let frame_filter = FrameNameFilter::new(
            &req.include,
            &req.exclude,
            &req.include_regex,
            &req.exclude_regex,
            exclude_framework,
        )?;
        let stats_by_thread =
            function_stats_for_threads(&cached, &selection.thread_indices, &range);
        let focus_function = if req.focus_function.is_some() || req.focus_function_id.is_some() {
            Some(
                resolve_function_name_in_threads(
                    &stats_by_thread,
                    req.focus_function.as_deref(),
                    req.focus_function_id.as_deref(),
                    &req.match_mode,
                    Some(&selection.thread_indices),
                )
                .ok_or_else(|| {
                    "Focus function not found in selected thread scope. Provide focus_function_id or focus_function; try profile_search_functions first.".to_string()
                })?,
            )
        } else {
            None
        };

        let (text, matched_samples, focused_time_ms, focused_percent) =
            if let Some(function_name) = &focus_function {
                let focused = call_tree::build_focused_call_tree_for_threads_with_filter(
                    &thread_refs,
                    cached.profile.interval_ms,
                    Some(&range),
                    function_name,
                    req.max_depth,
                    req.min_percent,
                    |name| frame_filter.includes(name),
                )
                .ok_or_else(|| {
                    format!(
                        "Function '{}' did not appear in any samples in scope {}",
                        function_name, selection.scope
                    )
                })?;
                (
                    focused
                        .tree
                        .render_text_with_options(req.max_depth, req.short_names, true),
                    Some(focused.sample_count),
                    Some(round2(focused.focused_time_ms)),
                    Some(round2(focused.focused_percent)),
                )
            } else {
                let tree = call_tree::build_call_tree_for_threads_with_filter(
                    &thread_refs,
                    cached.profile.interval_ms,
                    Some(&range),
                    req.max_depth,
                    req.min_percent,
                    |name| frame_filter.includes(name),
                );
                (
                    tree.render_text_with_options(req.max_depth, req.short_names, false),
                    None,
                    None,
                    None,
                )
            };
        let focus_function_id = focus_function
            .as_ref()
            .map(|function_name| symbols::function_id(function_name));
        let focus_display_name = focus_function
            .as_ref()
            .map(|function_name| symbols::compact_function_name(function_name));
        let summary =
            thread_sample_summary(&cached.profile, &selection.thread_indices, Some(&range));
        let (thread, tid, thread_index) = if let Some(selected_thread) = &selection.selected_thread
        {
            (
                Some(selected_thread.thread.name.clone()),
                Some(selected_thread.thread.tid.clone()),
                Some(selected_thread.index),
            )
        } else {
            (None, None, None)
        };

        Ok(Json(CallTreeResult {
            effective_range: effective_time_range(&range),
            scope: selection.scope,
            thread,
            tid,
            thread_index,
            thread_count: selection.thread_indices.len(),
            sample_count: summary.sample_count,
            wall_time_ms: round2(summary.wall_time_ms),
            cpu_sample_time_ms: round2(summary.cpu_sample_time_ms),
            cpu_sample_percent_of_wall: round2(summary.cpu_sample_percent_of_wall),
            samples_per_second: round2(summary.samples_per_second),
            threads: if req.include_threads {
                thread_infos(&cached.profile, &selection.thread_indices, Some(&range))
            } else {
                Vec::new()
            },
            focus_function,
            focus_function_id,
            focus_display_name,
            matched_samples,
            focused_time_ms,
            focused_percent,
            tree: text,
        }))
    }

    #[tool(
        description = "Focus on a function by full name or substring. Reroots stacks at the matched function for one thread or a thread-name-prefix scope."
    )]
    fn profile_focus_function(
        &self,
        Parameters(req): Parameters<FocusFunctionRequest>,
    ) -> Result<Json<FocusFunctionResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;
        let selection = select_thread_indices_for_single_or_prefix_scope(
            &cached.profile,
            &req.thread,
            &req.tid,
            req.thread_index,
            &req.thread_name_prefix,
            &req.thread_name_prefixes,
            &range,
        )?;
        let thread_refs: Vec<&ResolvedThread> = selection
            .thread_indices
            .iter()
            .filter_map(|index| cached.profile.threads.get(*index))
            .collect();

        let stats_by_thread =
            function_stats_for_threads(&cached, &selection.thread_indices, &range);
        let function_name = resolve_function_name_in_threads(
            &stats_by_thread,
            req.query.as_deref(),
            req.function_id.as_deref(),
            &req.match_mode,
            Some(&selection.thread_indices),
        )
        .ok_or_else(|| {
            format!(
                "Function not found in scope {}. Provide function_id or query; try profile_search_functions first.",
                selection.scope
            )
        })?;

        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let frame_filter = FrameNameFilter::new(
            &req.include,
            &req.exclude,
            &req.include_regex,
            &req.exclude_regex,
            exclude_framework,
        )?;
        let focused = call_tree::build_focused_call_tree_for_threads_with_filter(
            &thread_refs,
            cached.profile.interval_ms,
            Some(&range),
            &function_name,
            req.max_depth,
            req.min_percent,
            |name| frame_filter.includes(name),
        )
        .ok_or_else(|| {
            format!(
                "Function '{}' did not appear in any samples in scope {}",
                function_name, selection.scope
            )
        })?;
        let text = focused
            .tree
            .render_text_with_options(req.max_depth, req.short_names, true);
        let summary =
            thread_sample_summary(&cached.profile, &selection.thread_indices, Some(&range));
        let (thread, tid, thread_index) = if let Some(selected_thread) = &selection.selected_thread
        {
            (
                Some(selected_thread.thread.name.clone()),
                Some(selected_thread.thread.tid.clone()),
                Some(selected_thread.index),
            )
        } else {
            (None, None, None)
        };

        Ok(Json(FocusFunctionResult {
            effective_range: effective_time_range(&range),
            scope: selection.scope,
            thread,
            tid,
            thread_index,
            thread_count: selection.thread_indices.len(),
            threads: if req.include_threads {
                thread_infos(&cached.profile, &selection.thread_indices, Some(&range))
            } else {
                Vec::new()
            },
            function_id: symbols::function_id(&function_name),
            display_name: symbols::compact_function_name(&function_name),
            function_name,
            matched_samples: focused.sample_count,
            total_thread_samples: focused.total_samples,
            total_scope_samples: focused.total_samples,
            wall_time_ms: round2(summary.wall_time_ms),
            cpu_sample_time_ms: round2(summary.cpu_sample_time_ms),
            cpu_sample_percent_of_wall: round2(summary.cpu_sample_percent_of_wall),
            samples_per_second: round2(summary.samples_per_second),
            focused_percent: round2(focused.focused_percent),
            focused_time_ms: round2(focused.focused_time_ms),
            tree: text,
        }))
    }

    #[tool(
        description = "Break down a function's exclusive/self samples by library-relative instruction address and focused source line. Resolves every sampled PC from matching recorded-binary DWARF when available, with companion .syms.json and profile data as fallbacks. Returns outer-to-inner inline frames and supports profile-relative time ranges and thread-name-prefix aggregation."
    )]
    fn profile_function_source(
        &self,
        Parameters(req): Parameters<FunctionSourceRequest>,
    ) -> Result<Json<FunctionSourceResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;
        let selection = select_thread_indices_for_single_or_prefix_scope(
            &cached.profile,
            &req.thread,
            &req.tid,
            req.thread_index,
            &req.thread_name_prefix,
            &req.thread_name_prefixes,
            &range,
        )?;
        let stats_by_thread =
            function_stats_for_threads(&cached, &selection.thread_indices, &range);
        let function_name = resolve_function_name_in_threads(
            &stats_by_thread,
            req.query.as_deref(),
            req.function_id.as_deref(),
            &req.match_mode,
            Some(&selection.thread_indices),
        )
        .ok_or_else(|| {
            format!(
                "Function not found in scope {}. Provide function_id or query; try profile_search_functions first.",
                selection.scope
            )
        })?;

        let mut breakdown = source::exclusive_source_breakdown(
            &cached.profile,
            &selection.thread_indices,
            &range,
            &function_name,
        );
        if breakdown.exclusive_sample_count == 0 {
            return Err(format!(
                "Function '{}' has no exclusive/self samples in scope {} and the selected time range",
                function_name, selection.scope
            ));
        }

        let dwarf = source::resolve_dwarf_sources(&cached.profile, &function_name, &mut breakdown);

        let instruction_count = breakdown.instructions.len();
        let source_line_count = breakdown.source_lines.len();
        let limit = req.limit.min(500);
        breakdown.instructions.truncate(limit);
        breakdown.source_lines.truncate(limit);

        let instructions: Vec<InstructionSourceRow> = breakdown
            .instructions
            .into_iter()
            .map(|instruction| {
                let symbol_offset = instruction
                    .address
                    .zip(instruction.symbol_start_address)
                    .and_then(|(address, start)| address.checked_sub(start))
                    .map(hex_address);
                let inline_frames = instruction
                    .inline_frames
                    .into_iter()
                    .enumerate()
                    .map(|(inline_depth, frame)| InlineSourceFrameInfo {
                        inline_depth,
                        function_id: symbols::function_id(&frame.function_name),
                        display_name: symbols::compact_function_name(&frame.function_name),
                        source: source_location(&frame.file, frame.line),
                        function_name: frame.function_name,
                        file: frame.file,
                        line: frame.line,
                    })
                    .collect();

                InstructionSourceRow {
                    instruction_address: instruction.address.map(hex_address),
                    library: instruction.library,
                    library_debug_id: instruction.library_debug_id,
                    symbol_name: instruction.symbol_name,
                    symbol_start_address: instruction.symbol_start_address.map(hex_address),
                    symbol_offset,
                    symbol_size: instruction.symbol_size,
                    focus_source: source_location(&instruction.focus_file, instruction.focus_line),
                    focus_file: instruction.focus_file,
                    focus_line: instruction.focus_line,
                    source_origin: instruction.source_origin.to_string(),
                    inline_frames,
                    sample_count: instruction.sample_count,
                    cpu_sample_time_ms: round2(instruction.cpu_sample_time_ms),
                    percent_of_exclusive: round2(percent(
                        instruction.cpu_sample_time_ms,
                        breakdown.exclusive_time_ms,
                    )),
                    percent_of_scope: round2(percent(
                        instruction.cpu_sample_time_ms,
                        breakdown.scope_time_ms,
                    )),
                }
            })
            .collect();
        let source_lines: Vec<FunctionSourceLineRow> = breakdown
            .source_lines
            .into_iter()
            .map(|line| FunctionSourceLineRow {
                library: line.library,
                source: source_location(&line.file, line.line),
                file: line.file,
                line: line.line,
                instruction_count: line.instruction_addresses.len(),
                instruction_addresses: line
                    .instruction_addresses
                    .into_iter()
                    .map(hex_address)
                    .collect(),
                sample_count: line.sample_count,
                cpu_sample_time_ms: round2(line.cpu_sample_time_ms),
                percent_of_exclusive: round2(percent(
                    line.cpu_sample_time_ms,
                    breakdown.exclusive_time_ms,
                )),
                percent_of_scope: round2(percent(line.cpu_sample_time_ms, breakdown.scope_time_ms)),
            })
            .collect();
        let (thread, tid, thread_index) = if let Some(selected_thread) = &selection.selected_thread
        {
            (
                Some(selected_thread.thread.name.clone()),
                Some(selected_thread.thread.tid.clone()),
                Some(selected_thread.index),
            )
        } else {
            (None, None, None)
        };

        Ok(Json(FunctionSourceResult {
            effective_range: effective_time_range(&range),
            scope: selection.scope,
            thread,
            tid,
            thread_index,
            thread_count: selection.thread_indices.len(),
            threads: if req.include_threads {
                thread_infos(&cached.profile, &selection.thread_indices, Some(&range))
            } else {
                Vec::new()
            },
            function_id: symbols::function_id(&function_name),
            display_name: symbols::compact_function_name(&function_name),
            function_name,
            symbol_sidecar_loaded: cached.fingerprint.symbols.is_some(),
            dwarf_resolution: DwarfResolutionInfo {
                attempted_library_count: dwarf.attempted_library_count,
                loaded_library_count: dwarf.loaded_library_count,
                identity_verified_library_count: dwarf.identity_verified_library_count,
                attempted_instruction_count: dwarf.attempted_instruction_count,
                resolved_instruction_count: dwarf.resolved_instruction_count,
                resolved_sample_count: dwarf.resolved_sample_count,
                binary_paths: dwarf.binary_paths,
                warnings: dwarf.warnings,
            },
            exclusive_samples: breakdown.exclusive_sample_count,
            exclusive_time_ms: round2(breakdown.exclusive_time_ms),
            exclusive_percent_of_scope: round2(percent(
                breakdown.exclusive_time_ms,
                breakdown.scope_time_ms,
            )),
            total_scope_samples: breakdown.scope_sample_count,
            scope_time_ms: round2(breakdown.scope_time_ms),
            instruction_resolved_samples: breakdown.instruction_resolved_samples,
            source_resolved_samples: breakdown.source_resolved_samples,
            sidecar_symbolicated_samples: breakdown.sidecar_symbolicated_samples,
            instruction_count,
            returned_instruction_count: instructions.len(),
            source_line_count,
            returned_source_line_count: source_lines.len(),
            instructions,
            source_lines,
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
        let range = AnalysisRange::resolve(profile, req.start_time_ms, req.end_time_ms)?;
        let (scope, thread_indices) = select_thread_indices_for_scope(
            profile,
            &req.thread,
            &req.tid,
            req.thread_index,
            &req.thread_name_prefix,
            &req.thread_name_prefixes,
            &range,
        )?;
        let caller_relationship = parse_caller_relationship(&req.caller_mode)?;
        let stats_by_thread = function_stats_for_threads(&cached, &thread_indices, &range);

        let function_name = resolve_function_name_in_threads(
            &stats_by_thread,
            req.function_name.as_deref(),
            req.function_id.as_deref(),
            &req.match_mode,
            Some(&thread_indices),
        )
        .ok_or_else(|| {
            "Function not found in selected thread scope. Provide function_id or function_name; try profile_search_functions first.".to_string()
        })?;

        let caller_name = resolve_function_name_in_threads(
            &stats_by_thread,
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
            &range,
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
        let frame_filter = FrameNameFilter::new(
            &req.include,
            &req.exclude,
            &req.include_regex,
            &req.exclude_regex,
            exclude_framework,
        )?;
        let focused = call_tree::build_focused_call_tree_under_caller_with_filter(
            &thread_refs,
            profile.interval_ms,
            Some(&range),
            &function_name,
            &caller_name,
            caller_relationship,
            req.max_depth,
            req.min_percent,
            |name| frame_filter.includes(name),
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
        let summary = thread_sample_summary(profile, &thread_indices, Some(&range));

        Ok(Json(FunctionUnderCallerResult {
            effective_range: effective_time_range(&range),
            scope,
            thread_count: thread_indices.len(),
            threads: if req.include_threads {
                thread_infos(profile, &thread_indices, Some(&range))
            } else {
                Vec::new()
            },
            matched_threads: if req.include_threads {
                thread_infos(profile, &metrics.matched_thread_indices, Some(&range))
            } else {
                Vec::new()
            },
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
            wall_time_ms: round2(summary.wall_time_ms),
            cpu_sample_time_ms: round2(summary.cpu_sample_time_ms),
            cpu_sample_percent_of_wall: round2(summary.cpu_sample_percent_of_wall),
            samples_per_second: round2(summary.samples_per_second),
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
                phase: m.phase,
                category: m.category.clone(),
                data: m.data_value(),
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
        description = "Analyze Samply context-switch markers for one thread: on/off-CPU time, CPU migration, blocked/preempted switch-outs, and the longest observed off-CPU intervals. Record with --per-cpu-threads --cswitch-markers."
    )]
    fn profile_context_switches(
        &self,
        Parameters(req): Parameters<ContextSwitchesRequest>,
    ) -> Result<Json<ContextSwitchesResult>, String> {
        let cached = self.get_profile(&req.path)?;
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;
        let selected = select_thread(&cached.profile, &req.thread, &req.tid, req.thread_index)?;
        let thread = selected.thread;
        let analysis = context_switch::analyze_context_switches(
            thread,
            Some(range.raw_start_time_ms()),
            Some(range.raw_end_time_ms()),
            req.limit.min(200),
        )
        .ok_or_else(|| {
            format!(
                "No usable OnCpu context-switch intervals found for {}. Record the profile with `samply record --per-cpu-threads --cswitch-markers ...` and select an application thread.",
                thread_label(selected.index, thread)
            )
        })?;

        let observed_duration_ms = analysis.observed_duration_ms;
        let cpus = analysis
            .cpus
            .into_iter()
            .map(|cpu| ContextSwitchCpuUsage {
                cpu: cpu.cpu,
                interval_count: cpu.interval_count,
                on_cpu_time_ms: round2(cpu.on_cpu_time_ms),
                on_cpu_percent: round2(percent(cpu.on_cpu_time_ms, observed_duration_ms)),
            })
            .collect();
        let switch_out_reasons = analysis
            .switch_out_reasons
            .into_iter()
            .map(|reason| ContextSwitchReasonSummary {
                reason: reason.reason,
                switch_count: reason.switch_count,
                observed_off_cpu_time_ms: round2(reason.observed_off_cpu_time_ms),
            })
            .collect();
        let longest_off_cpu_intervals = analysis
            .longest_off_cpu_intervals
            .into_iter()
            .map(|interval| OffCpuIntervalInfo {
                start_time_ms: round2(range.relative_time_ms(interval.start_time_ms)),
                end_time_ms: round2(range.relative_time_ms(interval.end_time_ms)),
                duration_ms: round2(interval.duration_ms),
                reason: interval.reason,
                previous_cpu: interval.previous_cpu,
                next_cpu: interval.next_cpu,
            })
            .collect();

        Ok(Json(ContextSwitchesResult {
            effective_range: effective_time_range(&range),
            thread: thread.name.clone(),
            tid: thread.tid.clone(),
            thread_index: selected.index,
            observed_start_time_ms: round2(range.relative_time_ms(analysis.observed_start_time_ms)),
            observed_end_time_ms: round2(range.relative_time_ms(analysis.observed_end_time_ms)),
            observed_duration_ms: round2(observed_duration_ms),
            on_cpu_time_ms: round2(analysis.on_cpu_time_ms),
            off_cpu_time_ms: round2(analysis.off_cpu_time_ms),
            on_cpu_percent: round2(percent(analysis.on_cpu_time_ms, observed_duration_ms)),
            off_cpu_percent: round2(percent(analysis.off_cpu_time_ms, observed_duration_ms)),
            on_cpu_interval_count: analysis.on_cpu_interval_count,
            switch_out_count: analysis.switch_out_count,
            cpus,
            switch_out_reasons,
            longest_off_cpu_intervals,
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
        let range = AnalysisRange::resolve(&cached.profile, req.start_time_ms, req.end_time_ms)?;
        let selection = select_thread_indices_for_single_or_prefix_scope(
            &cached.profile,
            &req.thread,
            &req.tid,
            req.thread_index,
            &req.thread_name_prefix,
            &req.thread_name_prefixes,
            &range,
        )?;
        let thread_refs: Vec<&ResolvedThread> = selection
            .thread_indices
            .iter()
            .filter_map(|index| cached.profile.threads.get(*index))
            .collect();
        let stats_by_thread =
            function_stats_for_threads(&cached, &selection.thread_indices, &range);

        let focus_function = if req.focus_function.is_some() || req.focus_function_id.is_some() {
            Some(
                resolve_function_name_in_threads(
                    &stats_by_thread,
                    req.focus_function.as_deref(),
                    req.focus_function_id.as_deref(),
                    &req.match_mode,
                    Some(&selection.thread_indices),
                )
                .ok_or_else(|| {
                    format!(
                        "Focus function not found in scope {}. Try profile_search_functions first.",
                        selection.scope
                    )
                })?,
            )
        } else {
            None
        };

        let exclude_framework =
            exclude_framework_enabled(req.exclude_framework, req.user_code_only);
        let stacks = flamegraph::collapsed_stacks_for_threads_with_options(
            &thread_refs,
            Some(&range),
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
        let (thread, tid, thread_index) = if let Some(selected_thread) = &selection.selected_thread
        {
            (
                Some(selected_thread.thread.name.clone()),
                Some(selected_thread.thread.tid.clone()),
                Some(selected_thread.index),
            )
        } else {
            (None, None, None)
        };

        Ok(Json(FlamegraphResult {
            effective_range: effective_time_range(&range),
            scope: selection.scope,
            thread,
            tid,
            thread_index,
            thread_count: selection.thread_indices.len(),
            threads: thread_infos(&cached.profile, &selection.thread_indices, Some(&range)),
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
                "Samply profiler and Linux perf c2c analysis tools. Every tool requires a \
                 `path` parameter. The profile_* tools accept a profile JSON file (or .json.gz); \
                 c2c_top_cachelines, c2c_cacheline_detail, c2c_top_access_sites, and \
                 c2c_access_site_detail accept native perf.data files produced by perf c2c \
                 record. Use profile_info for metadata \
                 overview and profile_threads to list threads. Prefer `thread_index` or `tid` \
                 from profile_threads when selecting a thread, because thread names can repeat. \
                 Use profile_top_functions to find CPU hotspots, profile_search_functions to \
                 find full Rust symbol names and stable function_id values from short substrings, \
                 profile_thread_group_top_functions to aggregate hotspots across thread name \
                 prefixes such as rayon-gen-* or chunk-worker, \
                 profile_focus_function to reroot stacks at a function with percentages scaled \
                 to matching samples, profile_function_source to break exclusive samples down \
                 by instruction address and source line with inline frames, \
                 profile_function_under_caller for exclusive/descendant \
                 time when a function appears under a specific caller/ancestor, \
                 profile_call_tree for full hierarchical call analysis, \
                 profile_function_detail for callers/callees, profile_markers for timeline \
                 events, profile_context_switches for on/off-CPU and scheduling analysis, \
                 and profile_flamegraph for collapsed stack output, including aggregation by \
                 thread_name_prefix. For cache-to-cache analysis, use c2c_top_cachelines to rank \
                 contended lines, then pass a returned cacheline_address to \
                 c2c_cacheline_detail for per-instruction, thread, CPU, latency, and source \
                 attribution. Use c2c_top_access_sites when one instruction touches many \
                 different lines, then pass its stable site_id to c2c_access_site_detail for \
                 cacheline, offset, co-accessor, callchain, thread, and CPU breakdowns. Prefer \
                 exclude_framework=true or user_code_only=true for Rust/Criterion profiles. \
                 Result rows include display_name for compact Rust symbols and source when \
                 file/line data is present. Sample-based tools accept inclusive `start_time_ms` \
                 and `end_time_ms` bounds relative to profile start and return `effective_range`. \
                 Concurrent requests for one profile share its load; requests for different \
                 paths are serialized to bound memory. Focused trees show both focus and thread \
                 percentages."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

fn hex_address(address: u64) -> String {
    format!("0x{address:x}")
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
    use crate::profile::resolved::{ResolvedSample, SampleWeightType};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn sample() -> ResolvedSample {
        ResolvedSample {
            timestamp_ms: 0.0,
            weight: 1,
            cpu_delta_us: None,
            stack: Default::default(),
        }
    }

    fn thread(name: &str, tid: &str, is_main: bool, sample_count: usize) -> ResolvedThread {
        ResolvedThread {
            name: name.to_string(),
            pid: "1".to_string(),
            tid: tid.to_string(),
            is_main,
            sample_weight_type: SampleWeightType::Samples,
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
            libraries: vec![],
            product: "test".to_string(),
            interval_ms: 1.0,
            categories: vec![],
            observed_start_time_ms: 0.0,
            duration_ms: 100.0,
            total_sample_count: 155,
        }
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("samply-mcp-{name}-{}-{now}", std::process::id()))
    }

    fn profile_json(thread_name: &str) -> String {
        format!(
            r#"{{
                "meta": {{
                    "categories": [{{ "name": "Other", "color": "grey", "subcategories": [] }}],
                    "interval": 1,
                    "product": "test"
                }},
                "libs": [],
                "threads": [{{
                    "name": "{thread_name}",
                    "isMainThread": true,
                    "pid": 1,
                    "tid": 1,
                    "unregisterTime": null,
                    "frameTable": {{ "length": 1, "func": [0], "category": [0] }},
                    "funcTable": {{ "length": 1, "name": [0] }},
                    "stackTable": {{ "length": 1, "prefix": [null], "frame": [0] }},
                    "samples": {{
                        "length": 2,
                        "stack": [0, 0],
                        "time": [0, 1],
                        "weight": [1, 1]
                    }},
                    "resourceTable": {{ "length": 0 }},
                    "nativeSymbols": {{ "length": 0 }},
                    "stringArray": ["root_function"]
                }}]
            }}"#
        )
    }

    fn context_switch_profile_json() -> String {
        r#"{
            "meta": {
                "categories": [{ "name": "Other", "color": "grey", "subcategories": [] }],
                "interval": 1,
                "product": "test",
                "markerSchema": [{
                    "name": "OnCpu",
                    "display": ["marker-chart", "marker-table"],
                    "data": [
                        {"key": "cpu", "label": "CPU", "format": "unique-string"},
                        {"key": "outwhy", "label": "Switch-out reason", "format": "unique-string"}
                    ]
                }]
            },
            "libs": [],
            "threads": [{
                "name": "worker",
                "isMainThread": true,
                "pid": 1,
                "tid": 2,
                "unregisterTime": null,
                "frameTable": { "length": 1, "func": [0], "category": [0] },
                "funcTable": { "length": 1, "name": [0] },
                "stackTable": { "length": 1, "prefix": [null], "frame": [0] },
                "samples": { "length": 2, "stack": [0, 0], "time": [0, 20], "weight": [1, 1] },
                "markers": {
                    "length": 3,
                    "name": [1, 1, 1],
                    "startTime": [0, 10, 15],
                    "endTime": [4, 13, 20],
                    "phase": [1, 1, 1],
                    "category": [0, 0, 0],
                    "data": [
                        {"type": "OnCpu", "cpu": 2, "outwhy": 3},
                        {"type": "OnCpu", "cpu": 4, "outwhy": 5},
                        {"type": "OnCpu", "cpu": 2, "outwhy": 3}
                    ]
                },
                "resourceTable": { "length": 0 },
                "nativeSymbols": { "length": 0 },
                "stringArray": [
                    "root_function", "Running on CPU", "CPU 0", "blocked", "CPU 1", "preempted"
                ]
            }]
        }"#
        .to_string()
    }

    fn ranged_profile_json() -> String {
        r#"{
            "meta": {
                "categories": [{ "name": "Other", "color": "grey", "subcategories": [] }],
                "interval": 2,
                "product": "range-test"
            },
            "libs": [],
            "threads": [{
                "name": "main-worker",
                "isMainThread": true,
                "pid": 1,
                "tid": 2,
                "unregisterTime": null,
                "frameTable": {
                    "length": 6,
                    "func": [0, 1, 2, 3, 4, 5],
                    "category": [0, 0, 0, 0, 0, 0]
                },
                "funcTable": { "length": 6, "name": [0, 1, 2, 3, 4, 5] },
                "stackTable": {
                    "length": 6,
                    "prefix": [null, null, 1, 2, 3, 3],
                    "frame": [0, 1, 2, 3, 4, 5]
                },
                "samples": {
                    "length": 7,
                    "stack": [0, 4, 4, 4, 5, 5, 5],
                    "time": [35198474, 35222714, 35222716, 35243472, 35258584, 35258586, 35274854],
                    "weight": [1, 1, 1, 1, 1, 1, 1],
                    "weightType": "samples"
                },
                "resourceTable": { "length": 0 },
                "nativeSymbols": { "length": 0 },
                "stringArray": [
                    "idle", "root", "caller", "tick_game", "before_kill", "after_kill"
                ]
            }]
        }"#
        .to_string()
    }

    fn source_profile_json() -> String {
        r#"{
            "meta": {
                "categories": [{ "name": "Other", "color": "grey", "subcategories": [] }],
                "interval": 2,
                "product": "source-test"
            },
            "libs": [{
                "name": "source-test",
                "debugName": "source-test",
                "breakpadId": "ABCD0"
            }],
            "threads": [{
                "name": "chunk-worker-0",
                "isMainThread": true,
                "pid": 1,
                "tid": 10,
                "unregisterTime": null,
                "frameTable": {
                    "length": 3,
                    "func": [0, 1, 1],
                    "category": [0, 0, 0],
                    "address": [-1, 260, 264]
                },
                "funcTable": {
                    "length": 2,
                    "name": [0, 1],
                    "resource": [-1, 0]
                },
                "stackTable": {
                    "length": 3,
                    "prefix": [null, 0, 0],
                    "frame": [0, 1, 2]
                },
                "samples": {
                    "length": 3,
                    "stack": [1, 1, 2],
                    "time": [1000, 1002, 1010],
                    "weight": [1, 1, 1],
                    "weightType": "samples"
                },
                "resourceTable": { "length": 1, "lib": [0] },
                "nativeSymbols": { "length": 0 },
                "stringArray": ["root", "0x100"]
            }, {
                "name": "chunk-worker-1",
                "isMainThread": false,
                "pid": 1,
                "tid": 11,
                "unregisterTime": null,
                "frameTable": {
                    "length": 2,
                    "func": [0, 1],
                    "category": [0, 0],
                    "address": [-1, 264]
                },
                "funcTable": {
                    "length": 2,
                    "name": [0, 1],
                    "resource": [-1, 0]
                },
                "stackTable": {
                    "length": 2,
                    "prefix": [null, 0],
                    "frame": [0, 1]
                },
                "samples": {
                    "length": 1,
                    "stack": [1],
                    "time": [1004],
                    "weight": [1],
                    "weightType": "samples"
                },
                "resourceTable": { "length": 1, "lib": [0] },
                "nativeSymbols": { "length": 0 },
                "stringArray": ["root", "0x104"]
            }]
        }"#
        .to_string()
    }

    fn source_sidecar_json() -> String {
        r#"{
            "string_table": [
                "ChunkMap::tick_game",
                "inlined_helper",
                "src/chunk_map.rs",
                "src/helper.rs"
            ],
            "data": [{
                "debug_name": "source-test",
                "debug_id": "AB-CD-00",
                "code_id": "",
                "symbol_table": [{
                    "rva": 256,
                    "size": 32,
                    "symbol": 0,
                    "frames": [
                        {"function": 1, "file": 3, "line": 20},
                        {"function": 0, "file": 2, "line": 100}
                    ]
                }, {
                    "rva": 256,
                    "size": 32,
                    "symbol": 0,
                    "frames": [
                        {"function": 1, "file": 3, "line": 21},
                        {"function": 0, "file": 2, "line": 101}
                    ]
                }],
                "known_addresses": [[260, 0], [264, 1]]
            }]
        }"#
        .to_string()
    }

    fn write_profile(path: &Path, thread_name: &str) {
        std::fs::write(path, profile_json(thread_name)).unwrap();
    }

    fn rewrite_after_mtime_change(path: &Path, contents: impl Fn() -> String) {
        let before = std::fs::metadata(path).unwrap().modified().unwrap();

        for _ in 0..30 {
            std::thread::sleep(Duration::from_millis(50));
            std::fs::write(path, contents()).unwrap();

            let after = std::fs::metadata(path).unwrap().modified().unwrap();
            if after != before {
                return;
            }
        }

        panic!("file mtime did not change for {}", path.display());
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

    #[test]
    fn duplicate_thread_names_are_selected_after_range_filtering() {
        let mut profile = profile();
        for sample in &mut profile.threads[1].samples {
            sample.timestamp_ms = 50.0;
        }
        let range = AnalysisRange::resolve(&profile, Some(0.0), Some(10.0)).unwrap();

        let selected =
            select_sample_thread(&profile, &Some("app".to_string()), &None, None, &range).unwrap();

        assert_eq!(selected.index, 0);
        assert_eq!(samples::sample_count(selected.thread, Some(&range)), 5);
    }

    #[test]
    fn get_profile_reloads_when_profile_file_mtime_changes() {
        let dir = unique_test_dir("cache-reload");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("profile.json");
        write_profile(&path, "first");

        let server = ProfileServer::new();
        let first = server.get_profile(path.to_str().unwrap()).unwrap();
        assert_eq!(first.profile.threads[0].name, "first");
        drop(first);

        rewrite_after_mtime_change(&path, || profile_json("second"));

        let second = server.get_profile(path.to_str().unwrap()).unwrap();
        assert_eq!(second.profile.threads[0].name, "second");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn repeated_sample_stacks_share_one_resolved_allocation() {
        let dir = unique_test_dir("shared-stacks");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("profile.json");
        write_profile(&path, "shared");

        let server = ProfileServer::new();
        let cached = server.get_profile(path.to_str().unwrap()).unwrap();
        let samples = &cached.profile.threads[0].samples;

        assert_eq!(samples.len(), 2);
        assert!(crate::profile::resolved::ResolvedStack::ptr_eq(
            &samples[0].stack,
            &samples[1].stack
        ));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn metadata_queries_do_not_build_function_statistics() {
        let dir = unique_test_dir("lazy-analysis-cache");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("profile.json");
        write_profile(&path, "lazy");
        let path = path.to_string_lossy().into_owned();

        let server = ProfileServer::new();
        let cached = server.get_profile(&path).unwrap();
        assert!(cached.cache.function_stats[0].get().is_none());

        server
            .profile_info(Parameters(ProfileInfoRequest { path: path.clone() }))
            .unwrap();
        assert!(cached.cache.function_stats[0].get().is_none());

        let range = AnalysisRange::resolve(&cached.profile, None, None).unwrap();
        let stats = function_stats_for_thread(&cached, 0, &range);
        assert!(!stats.is_empty());
        assert!(cached.cache.function_stats[0].get().is_some());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn same_path_requests_share_one_cached_profile() {
        use std::sync::Barrier;

        let dir = unique_test_dir("single-flight");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("profile.json");
        write_profile(&path, "shared");

        let server = Arc::new(ProfileServer::new());
        let start = Arc::new(Barrier::new(9));
        let release = Arc::new(Barrier::new(9));
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut workers = Vec::new();

        for _ in 0..8 {
            let server = Arc::clone(&server);
            let path = path.clone();
            let start = Arc::clone(&start);
            let release = Arc::clone(&release);
            let sender = sender.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                let cached = server.get_profile(path.to_str().unwrap()).unwrap();
                sender.send(Arc::as_ptr(&cached.cached) as usize).unwrap();
                release.wait();
            }));
        }
        drop(sender);

        start.wait();
        let pointers: Vec<usize> = receiver.iter().take(8).collect();
        assert_eq!(pointers.len(), 8);
        assert!(pointers.iter().all(|pointer| *pointer == pointers[0]));
        let state = server.profiles.state.lock().unwrap();
        assert_eq!(state.active_requests, 8);
        assert_eq!(state.loads_started, 1);
        drop(state);

        release.wait();
        for worker in workers {
            worker.join().unwrap();
        }

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn different_profile_paths_wait_for_the_active_profile() {
        let dir = unique_test_dir("profile-serialization");
        std::fs::create_dir(&dir).unwrap();
        let first_path = dir.join("first.json");
        let second_path = dir.join("second.json");
        write_profile(&first_path, "first");
        write_profile(&second_path, "second");

        let server = Arc::new(ProfileServer::new());
        let first = server.get_profile(first_path.to_str().unwrap()).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_server = Arc::clone(&server);
        let worker = std::thread::spawn(move || {
            let second = worker_server
                .get_profile(second_path.to_str().unwrap())
                .unwrap();
            sender.send(second.profile.threads[0].name.clone()).unwrap();
        });

        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            "second"
        );
        worker.join().unwrap();

        let state = server.profiles.state.lock().unwrap();
        assert_eq!(
            state.entry.as_ref().unwrap().path.file_name().unwrap(),
            "second.json"
        );
        assert_eq!(state.loads_started, 2);
        drop(state);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn profile_fingerprint_includes_syms_sidecar_mtime() {
        let dir = unique_test_dir("sidecar-cache");
        std::fs::create_dir(&dir).unwrap();
        let profile_path = dir.join("profile.json");
        let syms_path = dir.join("profile.json.syms.json");
        write_profile(&profile_path, "profile");
        std::fs::write(&syms_path, "{}").unwrap();

        let first = ProfileFingerprint::read(&profile_path).unwrap();
        rewrite_after_mtime_change(&syms_path, || "{\"changed\":true}".to_string());
        let second = ProfileFingerprint::read(&profile_path).unwrap();

        assert_ne!(first, second);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn profile_context_switches_resolves_marker_strings_and_summarizes_intervals() {
        let dir = unique_test_dir("context-switches");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("profile.json");
        std::fs::write(&path, context_switch_profile_json()).unwrap();

        let server = ProfileServer::new();
        let cached = server.get_profile(path.to_str().unwrap()).unwrap();
        let first_marker = &cached.profile.threads[0].markers[0];
        assert_eq!(first_marker.phase, Some(1));
        let first_marker_data = first_marker.data_value().unwrap();
        assert_eq!(first_marker_data["cpu"], "CPU 0");
        assert_eq!(first_marker_data["outwhy"], "blocked");

        let Json(result) = server
            .profile_context_switches(Parameters(ContextSwitchesRequest {
                path: path.to_string_lossy().into_owned(),
                thread: None,
                tid: None,
                thread_index: Some(0),
                start_time_ms: None,
                end_time_ms: None,
                limit: 10,
            }))
            .unwrap();

        assert_eq!(result.thread, "worker");
        assert_eq!(result.on_cpu_time_ms, 12.0);
        assert_eq!(result.off_cpu_time_ms, 8.0);
        assert_eq!(result.cpus[0].cpu, "CPU 0");
        assert_eq!(result.longest_off_cpu_intervals[0].reason, "blocked");
        assert_eq!(result.longest_off_cpu_intervals[0].duration_ms, 6.0);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sample_analysis_tools_use_disjoint_profile_relative_ranges() {
        let dir = unique_test_dir("analysis-ranges");
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("profile.json");
        std::fs::write(&path, ranged_profile_json()).unwrap();
        let path = path.to_string_lossy().into_owned();
        let server = ProfileServer::new();

        let Json(info) = server
            .profile_info(Parameters(ProfileInfoRequest { path: path.clone() }))
            .unwrap();
        assert_eq!(info.observed_start_time_ms, 35_198_474.0);

        let first_top: TopFunctionsRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_index": 0,
            "start_time_ms": 24240,
            "end_time_ms": 45000
        }))
        .unwrap();
        let Json(first_top) = server.profile_top_functions(Parameters(first_top)).unwrap();
        assert_eq!(first_top.effective_range.start_time_ms, 24_240.0);
        assert!(
            first_top
                .functions
                .iter()
                .any(|row| row.name == "before_kill")
        );
        assert!(
            !first_top
                .functions
                .iter()
                .any(|row| row.name == "after_kill")
        );

        let second_top: TopFunctionsRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_index": 0,
            "start_time_ms": 60110,
            "end_time_ms": 76380
        }))
        .unwrap();
        let Json(second_top) = server
            .profile_top_functions(Parameters(second_top))
            .unwrap();
        assert!(
            second_top
                .functions
                .iter()
                .any(|row| row.name == "after_kill")
        );
        assert!(
            !second_top
                .functions
                .iter()
                .any(|row| row.name == "before_kill")
        );

        let first_focus: FocusFunctionRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_index": 0,
            "query": "tick_game",
            "match_mode": "exact",
            "start_time_ms": 24240,
            "end_time_ms": 45000
        }))
        .unwrap();
        let Json(first_focus) = server
            .profile_focus_function(Parameters(first_focus))
            .unwrap();
        assert_eq!(first_focus.matched_samples, 3);
        assert_eq!(first_focus.total_scope_samples, 3);
        assert_eq!(first_focus.focused_time_ms, 6.0);
        assert_eq!(first_focus.focused_percent, 100.0);
        assert!(first_focus.tree.contains("before_kill"));
        assert!(!first_focus.tree.contains("after_kill"));

        let second_focus: FocusFunctionRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_index": 0,
            "query": "tick_game",
            "match_mode": "exact",
            "start_time_ms": 60110,
            "end_time_ms": 76380
        }))
        .unwrap();
        let Json(second_focus) = server
            .profile_focus_function(Parameters(second_focus))
            .unwrap();
        assert_eq!(second_focus.matched_samples, 3);
        assert_eq!(second_focus.total_scope_samples, 3);
        assert_eq!(second_focus.focused_time_ms, 6.0);
        assert!(second_focus.tree.contains("after_kill"));
        assert!(!second_focus.tree.contains("before_kill"));

        let call_tree: CallTreeRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_index": 0,
            "start_time_ms": 24240,
            "end_time_ms": 45000,
            "min_percent": 0
        }))
        .unwrap();
        let Json(call_tree) = server.profile_call_tree(Parameters(call_tree)).unwrap();
        assert_eq!(call_tree.sample_count, 3);
        assert!(call_tree.tree.contains("before_kill"));
        assert!(!call_tree.tree.contains("after_kill"));

        let flamegraph: FlamegraphRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_index": 0,
            "start_time_ms": 60110,
            "end_time_ms": 76380
        }))
        .unwrap();
        let Json(flamegraph) = server.profile_flamegraph(Parameters(flamegraph)).unwrap();
        assert!(flamegraph.collapsed_stacks.contains("after_kill 3"));
        assert!(!flamegraph.collapsed_stacks.contains("before_kill"));

        let under_caller: FunctionUnderCallerRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_index": 0,
            "function_name": "tick_game",
            "function_id": null,
            "caller_name": "caller",
            "caller_function_id": null,
            "match_mode": "exact",
            "caller_match_mode": "exact",
            "start_time_ms": 24240,
            "end_time_ms": 45000
        }))
        .unwrap();
        let Json(under_caller) = server
            .profile_function_under_caller(Parameters(under_caller))
            .unwrap();
        assert_eq!(under_caller.descendant_samples, 3);
        assert_eq!(under_caller.total_scope_samples, 3);
        assert_eq!(under_caller.descendant_time_ms, 6.0);

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn source_breakdown_and_flamegraph_aggregate_thread_prefixes_in_range() {
        let dir = unique_test_dir("function-source");
        std::fs::create_dir(&dir).unwrap();
        let profile_path = dir.join("profile.json");
        let sidecar_path = dir.join("profile.json.syms.json");
        std::fs::write(&profile_path, source_profile_json()).unwrap();
        std::fs::write(&sidecar_path, source_sidecar_json()).unwrap();
        let path = profile_path.to_string_lossy().into_owned();
        let server = ProfileServer::new();

        let source_request: FunctionSourceRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "query": "ChunkMap::tick_game",
            "match_mode": "exact",
            "thread_name_prefix": "chunk-worker-*",
            "start_time_ms": 0,
            "end_time_ms": 5,
            "limit": 10
        }))
        .unwrap();
        let Json(source) = server
            .profile_function_source(Parameters(source_request))
            .unwrap();

        assert_eq!(source.effective_range.start_time_ms, 0.0);
        assert_eq!(source.effective_range.end_time_ms, 5.0);
        assert_eq!(source.thread_count, 2);
        assert_eq!(source.exclusive_samples, 3);
        assert_eq!(source.exclusive_time_ms, 6.0);
        assert_eq!(source.instruction_count, 2);
        assert_eq!(source.source_line_count, 2);
        assert_eq!(source.sidecar_symbolicated_samples, 3);
        assert_eq!(source.dwarf_resolution.attempted_library_count, 1);
        assert_eq!(source.dwarf_resolution.attempted_instruction_count, 2);
        assert_eq!(source.dwarf_resolution.loaded_library_count, 0);
        assert!(!source.dwarf_resolution.warnings.is_empty());
        assert_eq!(
            source.instructions[0].instruction_address.as_deref(),
            Some("0x104")
        );
        assert_eq!(source.instructions[0].sample_count, 2);
        assert_eq!(source.instructions[0].focus_line, Some(100));
        assert_eq!(source.instructions[0].inline_frames.len(), 2);
        assert_eq!(
            source.instructions[0].inline_frames[1].function_name,
            "inlined_helper"
        );
        assert_eq!(source.source_lines[0].line, Some(100));

        let flamegraph_request: FlamegraphRequest = serde_json::from_value(serde_json::json!({
            "path": path,
            "thread_name_prefix": "chunk-worker-*",
            "start_time_ms": 0,
            "end_time_ms": 5
        }))
        .unwrap();
        let Json(flamegraph) = server
            .profile_flamegraph(Parameters(flamegraph_request))
            .unwrap();

        assert_eq!(flamegraph.thread_count, 2);
        assert!(flamegraph.thread.is_none());
        assert!(
            flamegraph
                .collapsed_stacks
                .contains("root;ChunkMap::tick_game 3")
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn c2c_access_sites_aggregate_distinct_cachelines_and_stable_ids() {
        let sample = |data_address, physical_address, tid, cpu| C2cSample {
            timestamp_ns: Some(1_000_000),
            pid: 42,
            tid,
            cpu,
            thread_name: Arc::from("worker"),
            instruction_address: 0x1234,
            exact_ip: true,
            data_address,
            mapped_data_address: None,
            physical_address: Some(physical_address),
            weight: 100,
            instruction_latency: Some(120),
            data_source: crate::c2c::MemoryDataSource {
                raw: 0x836_2980_8042,
            },
            mapped_instruction: None,
            callchain: Arc::from([C2cCallchainFrame {
                instruction_address: 0x1200,
                mapped_instruction: None,
            }]),
        };
        let samples = [
            sample(0x1004, 0xa004, 7, 1),
            sample(0x2008, 0xb008, 8, 2),
            sample(0x100c, 0xa00c, 7, 3),
        ];
        let key = C2cSiteKey::for_sample(&samples[0], false);
        let site_id = c2c_site_id(&key);
        let mut site = C2cSiteAccum::new(key.clone(), None);
        for sample in &samples {
            site.add_sample(sample, 64, true);
        }

        assert_eq!(site.stats.samples, 3);
        assert_eq!(site.stats.remote_hitm, 3);
        assert_eq!(site.virtual_cachelines.len(), 2);
        assert_eq!(site.hitm_cacheline_count(), 2);
        assert_eq!(site.physical_cachelines.len(), 2);
        assert_eq!(site.callchains.len(), 1);
        assert_eq!(site.data_sources.len(), 1);
        let data_source_rows = c2c_raw_data_source_rows(site.data_sources.clone());
        assert_eq!(data_source_rows[0].raw_data_source, "0x83629808042");
        assert_eq!(data_source_rows[0].stats.samples, 3);
        assert_eq!(data_source_rows[0].stats.remote_hitm, 3);
        assert_eq!(c2c_site_id(&key), site_id);
        assert_ne!(
            c2c_site_id(&C2cSiteKey::for_sample(&samples[0], true)),
            site_id
        );
        assert!(select_c2c_site_key(&samples[0], None, Some(&site_id)).is_some());
    }

    #[test]
    fn c2c_latency_sort_requires_latency_samples() {
        let stats = C2cStats {
            samples: 42,
            ..C2cStats::default()
        };
        assert_eq!(
            validate_c2c_latency_sort("latency", 42, &stats).unwrap_err(),
            "cannot sort by latency: none of the 42 memory samples matched by the requested filters contains instruction-latency data"
        );
        assert!(validate_c2c_latency_sort("hitm", 42, &stats).is_ok());

        let stats = C2cStats {
            instruction_latency_samples: 1,
            ..stats
        };
        assert!(validate_c2c_latency_sort("latency", 42, &stats).is_ok());
    }
}
