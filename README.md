# samply-mcp

An MCP server that lets AI assistants analyze [samply](https://crates.io/crates/samply) CPU profiles. Register it once, then ask your assistant to analyze any profile by path — find hotspots, explore call trees, and explain what's slow.

## What it does

```
$ cargo samply --samply-args="--save-only --unstable-presymbolicate --cswitch-markers --rate 500 --per-cpu-threads"
```

Then, from an AI assistant connected to this MCP server, just ask:

> "What are the top CPU hotspots in /path/to/project/profile.json.gz?"
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
| `profile_function_source` | Break a function's exclusive samples down by instruction address, resolving each PC through matching recorded-binary DWARF with `.syms.json` fallback |
| `profile_function_under_caller` | Measure exclusive and descendant time for a function only when it appears under a caller/ancestor |
| `profile_call_tree` | Hierarchical call tree with optional `exclude_framework`/`user_code_only` pruning |
| `profile_function_detail` | Callers, callees, and source locations for a specific function |
| `profile_markers` | Timeline markers and events |
| `profile_context_switches` | On/off-CPU time, CPU migration, switch-out reasons, and longest scheduling gaps |
| `profile_flamegraph` | Collapsed stack format, optionally focused or aggregated by thread-name prefix |

All tools require a `path` parameter pointing to a profile `.json` or `.json.gz` file. Profiles are loaded on first use and cached in memory.

Sample-based tools accept optional `start_time_ms` and `end_time_ms` bounds. The bounds are inclusive, measured relative to the first observed sample (`0` is profile start), and are applied before thread selection, totals, percentages, and tree construction. Results include an `effective_range` showing the requested range after it was clamped to the profile. `profile_info.observed_start_time_ms` exposes the first sample's original timestamp so profile-relative results can be aligned with logs that use the host-monotonic clock.

CPU time is sample-equivalent time: `samples` weights multiply the profile's configured interval, while `tracing-ms` weights are already milliseconds. Sparse logical-thread samples therefore do not absorb wall-clock gaps or off-CPU time.

Thread names can repeat in multi-process profiles. Prefer `thread_index` or `tid` from `profile_threads` when calling thread-scoped tools. Function-focused tools accept short substrings, and search/top-function rows return a stable `function_id` so follow-up calls do not need to pass huge monomorphized Rust symbols.

Use `profile_thread_group_top_functions` when work is spread across thread pools. `thread_name_prefix: "rayon-gen-*"` matches all names starting with `rayon-gen-`, and `thread_name_prefixes: ["rayon-gen-*", "chunk-worker"]` returns one aggregate group per prefix. Use `profile_function_under_caller` for scoped questions like `WaterFluid::tick` only under `finish_generation_status`; `caller_mode: "ancestor"` is the default, and `caller_mode: "immediate"` requires the direct caller.

Use `profile_function_source` when a hotspot has a large self-time bucket. It groups only the function's exclusive leaf samples by library-relative instruction address and by the focused function's source line, reports sample-equivalent CPU time and percentages, and resolves every sampled PC through the DWARF in the binary/debug path recorded by the profile. On ELF and Mach-O, the recorded code ID is checked before the file is trusted. Results include the full outer-to-inner inline chain plus DWARF coverage, binary paths, identity-verification counts, and warnings. The companion `.syms.json` and already-symbolicated profile remain fallbacks when the recorded binary is unavailable. The tool accepts the same profile-relative time range and `thread_name_prefix`/`thread_name_prefixes` aggregation as the other focused tools. `profile_flamegraph` accepts those prefix selectors as well.

For Rust or Criterion profiles, pass `exclude_framework: true` or `user_code_only: true` to prune common runtime/framework frames such as `criterion`, `std`, `core`, `alloc`, `libc`, raw addresses, and startup frames. Focused call trees report nodes as `X% focus / Y% thread` to avoid mistaking a small focused subset for a large whole-profile cost.

## Recording a Profile

Install [cargo-samply](https://crates.io/crates/cargo-samply) and [samply](https://crates.io/crates/samply):

```bash
cargo install cargo-samply
cargo install samply
```

On Linux, samply may need access to performance events. This removes the running kernel's perf-event restrictions for unprivileged users until the setting is changed again or the system reboots:

```bash
echo '-1' | sudo tee /proc/sys/kernel/perf_event_paranoid
```

From the Rust project you want to profile, run:

```bash
cargo samply --samply-args="--save-only --unstable-presymbolicate --cswitch-markers --rate 500 --per-cpu-threads"
```

`cargo-samply` builds an optimized binary with debug information and runs it under samply. With samply's default output path, the command produces `profile.json.gz` and a `profile.json.syms.json` sidecar in the current directory. samply-mcp picks up the sidecar automatically, so no manual symbolication is needed.

The command above is the full Linux workflow. On macOS, omit `--per-cpu-threads`, which samply does not support there.

The context-switch markers and per-CPU tracks enable `profile_context_switches`. It reports observed on/off-CPU time, CPU usage and migration, `blocked` versus `preempted` switch-outs, and the longest off-CPU intervals. Off-CPU time following `blocked` includes the application's wait plus any delay before it runs again; context-switch markers alone cannot separate those two portions.

## Installation

Requires Rust 1.85+.

```bash
git clone https://github.com/4lve/samply-mcp
cd samply-mcp
cargo build --release
# Binary is at target/release/samply-mcp
```

## MCP Server Setup

### Codex CLI

```bash
codex mcp add samply -- /path/to/samply-mcp/target/release/samply-mcp mcp
```

### Claude Code (CLI)

```bash
claude mcp add samply -- /path/to/samply-mcp/target/release/samply-mcp mcp
```

No profile path needed — profiles are loaded on-demand when tools are called.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "samply": {
      "command": "/path/to/samply-mcp/target/release/samply-mcp",
      "args": ["mcp"]
    }
  }
}
```

## Example Workflow

```bash
# 1. On Linux, allow access to performance events
echo '-1' | sudo tee /proc/sys/kernel/perf_event_paranoid

# 2. Build and record a profile
cargo samply --samply-args="--save-only --unstable-presymbolicate --cswitch-markers --rate 500 --per-cpu-threads"

# 3. Register the MCP server (once, globally or per-project)
codex mcp add samply -- /path/to/samply-mcp/target/release/samply-mcp mcp

# 4. Ask your assistant to analyze /path/to/project/profile.json.gz
```
