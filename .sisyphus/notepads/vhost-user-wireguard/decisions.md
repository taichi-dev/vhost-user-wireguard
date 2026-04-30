# Architectural Decisions

## Project: vhost-user-wireguard

## [2026-04-30] Initial decisions from plan

- One process per VM (single-tenant)
- Single Rust binary (lib + bin in one crate)
- Dual MIT OR Apache-2.0 license
- Rust 2024 edition
- Linux x86_64 glibc target only
- MSRV: latest stable (1.85+)
- vhost-user mode: server+client (configurable)
- CLI: typed clap flags with --kebab-case per leaf
- JSON lease persistence (atomic write)
- Text + JSON tracing logs
- boringtun userspace WireGuard
- cargo test for testing (NO tokio-test, NO proptest)
