# Autonomous Mode & Project Guidelines for Vortex

## 1. Autonomous Execution
- Execute all tasks end-to-end without pausing for intermediate approvals.
- Take direct action using available tools (code edits, builds, diagnostics) and report final results at the end.
- Autonomously resolve compilation errors, missing dependencies, and configuration mismatches.
- Never ask clarifying or confirmation questions unless a destructive, irreversible action is required.

## 2. Engineering Standards
- Maintain high-performance, asynchronous Rust paradigms across `vortex-core`, `vortexd`, and `vortex`.
- Ensure zero packet/DNS leakage under all failure scenarios via `nftables` and local resolvers.
- Keep CLI and TUI lightweight, responsive, and ergonomic.
