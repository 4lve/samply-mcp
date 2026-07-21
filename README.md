# samply-mcp

An MCP server that lets AI assistants analyze [samply](https://github.com/mstange/samply) CPU profiles. Register it once, then ask Claude to analyze any profile by path — find hotspots, explore call trees, and explain what's slow.

## What it does

```
$ samply record --save-only --unstable-presymbolicate -o profile.json.gz -- ./my-program
$ claude mcp add samply /path/to/samply-mcp mcp
```

Then in Claude Code, just ask:

> "What are the top CPU hotspots in /tmp/profile.json.gz?"
> "Show me the call tree for the main thread"
> "What's calling `vec::sort` the most?"

Every tool accepts a `path` parameter, so one server installation works for any profile.

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `profile_info` | Profile metadata: duration, raw observed sample-clock start, sample count, thread count, sampling interval |
| `profile_threads` | List all threads with stable `thread_index`/`tid`, names, sample counts, and time ranges |
| `profile_top_functions` | Top N functions by self-time or total-time, with stable `function_id`, compact `display_name`, and source when available |
| `profile_thread_group_top_functions` | Top functions aggregated across thread name prefixes such as `rayon-gen-*` or `chunk-worker` |
| `profile_search_functions` | Find full symbol names and `function_id` values by substring, with per-thread timing |
| `profile_focus_function` | Reroot stacks at a function and show both focused and thread-level percentages |
| `profile_function_under_caller` | Measure exclusive and descendant time for a function only when it appears under a caller/ancestor |
| `profile_call_tree` | Hierarchical call tree with optional `exclude_framework`/`user_code_only` pruning |
| `profile_function_detail` | Callers, callees, and source locations for a specific function |
| `profile_markers` | Timeline markers and events |
| `profile_context_switches` | On/off-CPU time, CPU migration, switch-out reasons, and longest scheduling gaps |
| `profile_flamegraph` | Collapsed stack format, optionally sliced from a focused function |

All tools require a `path` parameter pointing to a profile `.json` or `.json.gz` file. Profiles are loaded on first use and cached in memory.

Sample-based tools accept optional `start_time_ms` and `end_time_ms` bounds. The bounds are inclusive, measured relative to the first observed sample (`0` is profile start), and are applied before thread selection, totals, percentages, and tree construction. Results include an `effective_range` showing the requested range after it was clamped to the profile. `profile_info.observed_start_time_ms` exposes the first sample's original timestamp so profile-relative results can be aligned with logs that use the host-monotonic clock.

CPU time is sample-equivalent time: `samples` weights multiply the profile's configured interval, while `tracing-ms` weights are already milliseconds. Sparse logical-thread samples therefore do not absorb wall-clock gaps or off-CPU time.

Thread names can repeat in multi-process profiles. Prefer `thread_index` or `tid` from `profile_threads` when calling thread-scoped tools. Function-focused tools accept short substrings, and search/top-function rows return a stable `function_id` so follow-up calls do not need to pass huge monomorphized Rust symbols.

Use `profile_thread_group_top_functions` when work is spread across thread pools. `thread_name_prefix: "rayon-gen-*"` matches all names starting with `rayon-gen-`, and `thread_name_prefixes: ["rayon-gen-*", "chunk-worker"]` returns one aggregate group per prefix. Use `profile_function_under_caller` for scoped questions like `WaterFluid::tick` only under `finish_generation_status`; `caller_mode: "ancestor"` is the default, and `caller_mode: "immediate"` requires the direct caller.

For Rust or Criterion profiles, pass `exclude_framework: true` or `user_code_only: true` to prune common runtime/framework frames such as `criterion`, `std`, `core`, `alloc`, `libc`, raw addresses, and startup frames. Focused call trees report nodes as `X% focus / Y% thread` to avoid mistaking a small focused subset for a large whole-profile cost.

## Recording a Profile

Install [samply](https://github.com/mstange/samply):

```bash
cargo install samply
```

Record your program. The `--unstable-presymbolicate` flag writes a `.syms.json` sidecar that samply-mcp uses to resolve function names automatically:

```bash
samply record --save-only --unstable-presymbolicate -o profile.json.gz -- ./target/profiling/my-program

```

This produces `profile.json.gz` (and `profile.json.syms.json` alongside it). samply-mcp picks up the sidecar automatically — no manual symbolication needed.

For scheduler and blocking analysis, record context-switch markers and per-CPU tracks together:

```bash
samply record --save-only --per-cpu-threads --cswitch-markers \
  --unstable-presymbolicate -o profile.json.gz -- ./target/profiling/my-program
```

Then use `profile_context_switches` on an application thread. It reports observed on/off-CPU time, CPU usage and migration, `blocked` versus `preempted` switch-outs, and the longest off-CPU intervals. Off-CPU time following `blocked` includes the application's wait plus any delay before it runs again; context-switch markers alone cannot separate those two portions.

## Installation

Requires Rust 1.85+.

```bash
git clone https://github.com/protortyp/samply-mcp
cd samply-mcp
cargo build --release
# Binary is at target/release/samply-mcp
```

## MCP Server Setup

### Claude Code (CLI)

```bash
claude mcp add samply /path/to/samply-mcp mcp
```

No profile path needed — profiles are loaded on-demand when tools are called.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "samply": {
      "command": "/path/to/samply-mcp",
      "args": ["mcp"]
    }
  }
}
```

## Example Workflow

```bash
# 1. Build your program (with debug info for best results)
cargo build

# 2. Record a profile
samply record --save-only --unstable-presymbolicate \
  -o /tmp/profile.json.gz -- ./target/debug/my-program

# 3. Register the MCP server (once, globally or per-project)
claude mcp add samply ~/path/to/samply-mcp mcp

# 4. Open Claude Code and ask it to analyze by path
```
