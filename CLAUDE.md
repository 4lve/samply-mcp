# samply-mcp

MCP server for analyzing samply profiler output. Parses Firefox Profiler "Processed Profile" JSON format and exposes agent-friendly analysis tools.

## Build & Test

```bash
cargo fmt
cargo clippy --all-features --all-targets -- -D warnings
cargo test
```

Both `cargo fmt --check` and `cargo clippy -- -D warnings` must pass with zero warnings before any commit.

## Architecture

```
src/
├── main.rs              # Entry point, CLI dispatch (tokio async)
├── cli.rs               # Clap command definitions
├── mcp.rs               # MCP server (rmcp), tool router, all tool handlers
├── profile/
│   ├── types.rs         # Serde types for Firefox Profiler JSON
│   ├── parse.rs         # Gzip decompression + JSON deserialization
│   └── resolved.rs      # Denormalized profile with resolved index references
└── analysis/
    ├── symbols.rs      # Rust symbol IDs, compact display names, framework filters
    ├── functions.rs     # Per-function self-time / total-time aggregation
    ├── call_tree.rs     # Call tree construction + text rendering
    └── flamegraph.rs    # Brendan Gregg collapsed stack format
```

## MCP Tools

All tools require a `path` parameter pointing to a profile file. Profiles are loaded on-demand and cached in memory.

- `profile_info` — metadata: duration, sample count, thread count, interval, categories (params: path)
- `profile_threads` — list threads with stable `thread_index`/`tid`, names, sample counts, time ranges (params: path)
- `profile_top_functions` — top N functions by self/total time with `function_id`, compact `display_name`, and source when available (params: path, thread/tid/thread_index, sort_by, limit, include, exclude, exclude_framework/user_code_only)
- `profile_thread_group_top_functions` — top functions aggregated across thread name prefixes such as `rayon-gen-*` or `chunk-worker` (params: path, thread_name_prefix or thread_name_prefixes, sort_by, limit, include, exclude, exclude_framework/user_code_only)
- `profile_search_functions` — find full symbol names and `function_id` values by substring (params: path, query, thread/tid/thread_index, match_mode, sort_by, limit, exclude_framework/user_code_only)
- `profile_focus_function` — reroot stacks at one function and show both focus/thread percentages (params: path, query or function_id, thread/tid/thread_index, max_depth, min_percent, exclude_framework/user_code_only, short_names)
- `profile_function_under_caller` — exclusive/descendant time for a function only under a specific caller/ancestor, optionally aggregated by thread name prefix (params: path, function_name/function_id, caller_name/caller_function_id, caller_mode, thread/tid/thread_index or thread_name_prefix, max_depth, min_percent, exclude_framework/user_code_only, short_names)
- `profile_call_tree` — hierarchical call tree with time % and optional framework pruning (params: path, thread/tid/thread_index, max_depth, min_percent, exclude_framework/user_code_only, short_names)
- `profile_function_detail` — callers/callees/source for one function, substring, or `function_id` (params: path, function_name or function_id, match_mode)
- `profile_markers` — timeline markers/events (params: path, thread/tid/thread_index, limit)
- `profile_context_switches` — on/off-CPU time, CPU migration, blocked/preempted switch-outs, and longest off-CPU intervals from profiles recorded with `--per-cpu-threads --cswitch-markers` (params: path, thread/tid/thread_index, start_time_ms/end_time_ms, limit)
- `profile_flamegraph` — collapsed stack format text, optionally focused (params: path, thread/tid/thread_index, focus_function)

Prefer `thread_index` or `tid` from `profile_threads` when selecting one thread; profile thread names can repeat. Use `profile_thread_group_top_functions` when CPU work is split across thread pools. Prefixes are starts-with matches, with a trailing `*` accepted for convenience. Prefer `function_id` from search/top-function rows for follow-up calls with large Rust symbols. For Rust/Criterion profiles, use `exclude_framework: true` or `user_code_only: true` to prune criterion/std/core/alloc/libc/startup frames.

## Usage

```bash
samply-mcp mcp
```

Starts an MCP server on stdio. Profiles are loaded on-demand when tools are called with a `path` parameter, and cached in memory for subsequent requests.

## Test Fixtures

`tests/fixtures/profile.json.gz` is a real samply profile of a simple Rust binary (gen_profile.rs), tracked with git LFS. It contains symbolicated function names like `gen_profile::hot_function`.

To regenerate:
```bash
rustc -g tests/fixtures/gen_profile.rs -o /tmp/gen_profile
samply record --save-only --unstable-presymbolicate -o tests/fixtures/profile.json.gz -- /tmp/gen_profile
# Then merge symbols from the .syms.json sidecar into the profile
```
