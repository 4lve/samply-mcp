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
| `profile_info` | Profile metadata: duration, sample count, thread count, sampling interval |
| `profile_threads` | List all threads with names, sample counts, and time ranges |
| `profile_top_functions` | Top N functions by self-time or total-time |
| `profile_call_tree` | Hierarchical call tree with time percentages |
| `profile_function_detail` | Callers, callees, and source locations for a specific function |
| `profile_markers` | Timeline markers and events |
| `profile_flamegraph` | Collapsed stack format (Brendan Gregg) for generating flamegraphs |

All tools require a `path` parameter pointing to a profile `.json` or `.json.gz` file. Profiles are loaded on first use and cached in memory.

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
