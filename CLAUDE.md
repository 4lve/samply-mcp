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

- `profile_info` — metadata: duration, sample count, thread count, interval, categories
- `profile_threads` — list threads with names, sample counts, time ranges
- `profile_top_functions` — top N functions by self/total time (params: thread, sort_by, limit)
- `profile_call_tree` — hierarchical call tree with time % (params: thread, depth, min_percent)
- `profile_function_detail` — callers/callees/source for one function (params: function_name)
- `profile_markers` — timeline markers/events (params: thread, limit)
- `profile_flamegraph` — collapsed stack format text (params: thread)

## Usage

```bash
samply-mcp mcp <profile.json.gz>
```

Starts an MCP server on stdio. The profile is parsed and analyzed on startup; all tools query the in-memory resolved profile.

## Test Fixtures

`tests/fixtures/profile.json.gz` is a real samply profile of a simple Rust binary (gen_profile.rs), tracked with git LFS. It contains symbolicated function names like `gen_profile::hot_function`.

To regenerate:
```bash
rustc -g tests/fixtures/gen_profile.rs -o /tmp/gen_profile
samply record --save-only --unstable-presymbolicate -o tests/fixtures/profile.json.gz -- /tmp/gen_profile
# Then merge symbols from the .syms.json sidecar into the profile
```
