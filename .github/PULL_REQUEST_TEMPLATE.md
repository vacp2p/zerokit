## Description

<!-- Provide a clear summary of the changes and motivation behind them. -->
<!-- Link related issues using "Closes #123" or "Related to #456". -->

## Changes

<!-- List the key changes in this PR. -->

-

## Testing

<!-- Describe how the changes were tested. -->
<!-- Include any relevant test commands, scenarios, or edge cases covered. -->

---

## PR Lifecycle

> [!IMPORTANT]
> **Draft PRs** signal that work is still in progress and **will not trigger CI**.
> Only mark your PR as **Ready for review** when you believe it is complete.
> All CI checks **must pass** before requesting a review.

## Code Guidelines

Please keep the following in mind (see [CONTRIBUTING.md](../CONTRIBUTING.md) for full details):

### Commits

- Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) (`feat(rln):`, `fix(utils):`, `chore:`, etc.)
- Use the appropriate scope: `rln`, `rln-cli`, `rln-wasm`, `utils`, `ci`
- GPG-sign your commits

### Error Handling

- **No panics in library code.** Do not use `unwrap()`, `expect()`, or `panic!()`
  in production paths inside `rln/src/` or `utils/src/`.
  The only acceptable exception is an internal invariant that is statically guaranteed - and even then, prefer returning an error.
- Use the project's `thiserror`-based error types (`RLNError`, `ProtocolError`, `UtilsError`, etc.)
  and propagate errors with `?`.
- Provide context in error variants (e.g., `InsufficientData { expected, actual }`).
- `unwrap()` is fine in **tests**.

### Code Style

- Run `cargo make fmt` at the root of the repository to auto-format the entire codebase with rules defined in [`rustfmt.toml`](../rustfmt.toml).
- Run `cargo make fmt_check` to verify formatting (CI enforces this on stable).
- Group imports: std first, then external crates, then local modules (see `rustfmt.toml`).
- Use `pub(crate)` for items that should not be part of the public API.
- Apply `Zeroize` / `ZeroizeOnDrop` to any struct holding secret material.

### Linting (mirrors CI)

CI runs clippy across multiple crate/feature combinations. Run the relevant checks locally before pushing:

```bash
# Default features - workspace root (rln + utils)
cargo clippy --all-targets --tests --release -- -D warnings

# Stateless feature - from rln/
cd rln && cargo clippy --all-targets --tests --release \
  --features=stateless --no-default-features -- -D warnings

# WASM target - from rln-wasm/
cd rln-wasm && cargo clippy --target wasm32-unknown-unknown \
  --tests --release -- -D warnings
```

At minimum, run the default-features check. If your changes touch `stateless` or `rln-wasm`, run those checks as well.

## Checklist

- [ ] My PR title follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format
- [ ] I have linked the related issue(s)
- [ ] I have run `cargo +nightly fmt --all` to apply all `rustfmt.toml` rules (including import grouping)
- [ ] `cargo fmt --all -- --check` produces no changes
- [ ] Clippy passes for all affected crate/feature combinations (see [Linting](#linting-mirrors-ci) above)
- [ ] `make test` passes locally
- [ ] No new `unwrap()` / `expect()` / `panic!()` in library code
- [ ] New code includes appropriate tests (unit / integration / WASM where applicable)
- [ ] I have run the CI coverage report - add the `run-coverage` label to enable it
- [ ] All CI checks pass and the PR is marked **Ready for review**
