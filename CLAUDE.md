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
├── mcp.rs               # MCP server (rmcp), tool router, all 7 tool handlers
├── profile/
│   ├── types.rs         # Serde types for Firefox Profiler JSON
│   ├── parse.rs         # Gzip decompression + JSON deserialization
│   └── resolved.rs      # Denormalized profile with resolved index references
└── analysis/
    ├── functions.rs     # Per-function self-time / total-time aggregation
    ├── call_tree.rs     # Call tree construction + text rendering
    └── flamegraph.rs    # Brendan Gregg collapsed stack format
```

## MCP Tools

All tools require a `path` parameter pointing to a profile file. Profiles are loaded on-demand and cached in memory.

- `profile_info` — metadata: duration, sample count, thread count, interval, categories (params: path)
- `profile_threads` — list threads with names, sample counts, time ranges (params: path)
- `profile_top_functions` — top N functions by self/total time (params: path, thread, sort_by, limit)
- `profile_call_tree` — hierarchical call tree with time % (params: path, thread, depth, min_percent)
- `profile_function_detail` — callers/callees/source for one function (params: path, function_name)
- `profile_markers` — timeline markers/events (params: path, thread, limit)
- `profile_flamegraph` — collapsed stack format text (params: path, thread)

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
