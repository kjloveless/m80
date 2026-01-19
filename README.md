# m80

Windows-native microVM runtime (Zig) with a minimal CLI scaffold.

## Status

Phase 0: repository layout, core stubs, and CLI scaffolding.
Phase 1: WHP backend brings up vCPU loop + guest memory loading (Windows), with shared IO/serial scaffolding across backends.
The VM backend, jailer hardening, mounts, and networking are not implemented yet.

## Supported Platforms

- Windows (primary target)
- POSIX hosts (macOS/Linux) for scaffolding and CLI development

## VM Name Rules

Names must be 1-64 characters and only use letters, numbers, `-`, and `_`.

## CLI

```
# Create a VM record
m80 init <name>

# Start/stop (placeholder VM)
m80 start <name>
m80 stop <name>

# Inspect state
m80 ps
m80 inspect <name>

# Delete
m80 delete <name>
```

## Logging

Set `M80_LOG_LEVEL` to control verbosity:

- `debug`
- `info` (default)
- `warn`
- `error`

## Data Directories

- Windows: `%LOCALAPPDATA%\m80`
- POSIX: `$XDG_DATA_HOME/m80` or `~/.local/share/m80`

## Build

```
zig build
zig build run -- help
zig build test
```
