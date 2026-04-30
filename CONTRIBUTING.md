# Contributing

Thanks for your interest. This document covers everything you need to get a change merged.

---

## Development Setup

### Prerequisites

- Rust (stable, MSRV 1.85+). Install via [rustup](https://rustup.rs):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- [pre-commit](https://pre-commit.com) for local hook enforcement:
  ```bash
  pip install pre-commit
  pre-commit install
  ```

### Build

```bash
cargo build
cargo build --release
```

### Run tests

```bash
cargo test --lib          # unit tests (fast, no root required)
cargo test                # all tests including integration
```

The full suite should pass with 161 lib tests. If you add a feature, add tests first (see TDD below).

### Lint and format

```bash
cargo clippy -- -D warnings
cargo fmt --check
cargo deny check          # license + advisory audit
```

All of these run in CI. Pre-commit runs `fmt` and `clippy` on every commit.

---

## Test Discipline

This project follows TDD. The expected workflow:

1. Write a failing test that captures the desired behaviour.
2. Write the minimum code to make it pass.
3. Refactor, keeping tests green.

Tests live alongside the code they test (`#[cfg(test)]` modules in the same file) or in `tests/` for integration tests. Don't add `#[ignore]` without a comment explaining why and a tracking issue.

---

## Coding Standards

These are enforced by CI and pre-commit. A PR that violates them won't merge.

### SPDX header

Every `*.rs` file must start with:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
```

No exceptions. The pre-commit hook checks this.

### No `unwrap()` or `expect()` in library code

`unwrap()` and `expect()` are only acceptable in:

- `main.rs` during startup (before the daemon is running)
- Test code (`#[cfg(test)]` blocks)
- Cases where a panic is provably impossible, documented with a `// SAFETY:` or `// INVARIANT:` comment explaining why

In all other cases, propagate errors with `?` or convert them to a typed error.

### No `Box<dyn Error>` in library code

Use [thiserror](https://docs.rs/thiserror)-derived error enums. Every module that can fail has its own error variant in `src/error.rs`. This keeps error handling explicit and avoids type erasure.

### No `as` casts between numeric types

Use `try_from` / `try_into` for fallible conversions. The only accepted exceptions are:

- `as RawFd` (file descriptor coercions where the type is already validated)
- `as u8` after an explicit range check with a comment

### No async

The daemon is synchronous by design. Don't add `tokio`, `async-std`, `futures`, or any async runtime. The vhost-user serve loop is blocking; adding async would complicate the privilege-drop and signal-handling sequences without benefit.

### No `Mutex<Tunn>` / `Arc<Tunn>` / `RefCell<Tunn>`

The WireGuard tunnel (`boringtun::Tunn`) is owned by `WgEngine` and accessed only from the serve loop thread. Don't wrap it in shared-state primitives. If you need to access it from another thread, redesign the ownership model and open a discussion first.

### Error messages

Error messages should be lowercase, not end with a period, and not start with "Error:". They're composed by the caller. Example: `"failed to read lease file"` not `"Failed to read lease file."`.

---

## Commit Style

This project uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

Format: `<type>(<scope>): <description>`

Common types:

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `refactor` | Code change that's neither a fix nor a feature |
| `test` | Adding or fixing tests |
| `docs` | Documentation only |
| `chore` | Build system, CI, dependency updates |
| `perf` | Performance improvement |

Scope is optional but encouraged: `feat(dhcp): add static reservation validation`.

Keep the subject line under 72 characters. Use the body for context that doesn't fit on one line.

---

## Pull Request Expectations

Before opening a PR:

- [ ] `cargo test --lib` passes
- [ ] `cargo clippy -- -D warnings` is clean
- [ ] `cargo fmt --check` passes
- [ ] `cargo deny check` passes
- [ ] New code has tests
- [ ] New `*.rs` files have the SPDX header
- [ ] Commit messages follow Conventional Commits

PR description should explain:

1. What problem this solves (or what feature it adds)
2. How you tested it
3. Any trade-offs or alternatives you considered

Small, focused PRs are easier to review than large ones. If you're unsure whether a change is in scope, open an issue first.

### Review process

Expect at least one round of review. Reviewers will focus on correctness, safety, and consistency with the existing codebase. They won't nitpick style that's already enforced by the linter.

---

## Adding a New Feature

Before writing code for a significant feature:

1. Check the [Out of Scope](README.md#out-of-scope) list in the README. If your feature is listed there, open an issue to discuss it first.
2. Open an issue describing the feature, the use case, and a rough design.
3. Wait for a maintainer to acknowledge it before investing significant time.

This avoids the situation where you write a large PR that can't be merged because of a design conflict.

---

## License

By contributing, you agree that your contributions will be licensed under the same dual MIT OR Apache-2.0 terms as the rest of the project.
