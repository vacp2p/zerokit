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

- **No panics in library code.** Do not use `unwrap()`, `expect()`, `panic!()`, or `unreachable!()`
  in production paths inside `rln/src/` or `utils/src/` - return a typed error instead.
- There is no crate-wide error enum: each fallible method returns its narrowest
  `thiserror`-based error type (e.g. `GenerateProofError`, `SerializationError`) and
  propagates with `?`.
- Carry context in error variants, e.g. `PathLengthMismatch(expected, actual)`.
- `unwrap()` is fine in **tests**.

### Code Style

- Run `cargo make fmt` at the repo root to auto-format all crates with the rules in
  [`rustfmt.toml`](../rustfmt.toml) (nightly rustfmt; import grouping is applied automatically).
- Run `cargo make fmt_check` to verify formatting (CI enforces this).
- Use `pub(crate)` for items that should not be part of the public API.
- Apply `Zeroize` / `ZeroizeOnDrop` to any struct holding secret material.

### Linting (mirrors CI)

```bash
# Core crates (rln + utils) and rln-cli - from the repo root
cargo clippy --all-targets --tests --release -- -D warnings

# WASM target - from rln-wasm/
cargo clippy --target wasm32-unknown-unknown --tests --release -- -D warnings
```

At minimum, run the core-crates check. If your changes touch `rln-wasm`, run that check as well.

## Checklist

- [ ] My PR title follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format
- [ ] I have linked the related issue(s)
- [ ] I have verified that `cargo make fmt_check` and `make test` pass locally
- [ ] Clippy passes for all affected crate/feature combinations (see [Linting](#linting-mirrors-ci) above)
- [ ] No new `unwrap()` / `expect()` / `panic!()` / `unreachable!()` in library code
- [ ] New code includes appropriate tests (unit / integration / WASM where applicable)
- [ ] I have added the `run-coverage` label to enable the CI coverage report (Optional)
- [ ] All CI checks pass and the PR is marked **Ready for review**
