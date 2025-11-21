# Contributing to Zerokit

Thank you for your interest in contributing to Zerokit!
This guide will discuss how the Zerokit team handles [Commits](#commits),
[Pull Requests](#pull-requests) and [Merging](#merging).

**Note:** We won't force external contributors to follow this verbatim.
Following these guidelines definitely helps us in accepting your contributions.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b fix/your-bug-fix` or `git checkout -b feat/your-feature-name`
3. Make your changes following our guidelines
4. Ensure relevant tests pass (see [testing guidelines](#building-and-testing))
5. Commit your changes (signed commits are highly encouraged  - see [commit guidelines](#commits))
6. Push and create a Pull Request

## Development Setup

### Prerequisites

Install the required dependencies:

```bash
make installdeps
```

Or use Nix:

```bash
nix develop
```

### Building and Testing

```bash
# Build all crates
make build

# Run standard tests
make test

# Module-specific testing
cd rln && cargo make test_stateless        # Test stateless features
cd rln-wasm && cargo make test_browser     # Test in browser headless mode
cd rln-wasm && cargo make test_parallel    # Test parallel features
```

### Tools

We recommend using the [markdownlint extension](https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint)
for VS Code to maintain consistent documentation formatting.

## Commits

We want to keep our commits small and focused.
This allows for easily reviewing individual commits and/or
splitting up pull requests when they grow too big.
Additionally, this allows us to merge smaller changes quicker and release more often.

**All commits must be GPG signed.**
This ensures the authenticity and integrity of contributions.

### Conventional Commits

When making the commit, write the commit message
following the [Conventional Commits (v1.0.0)](https://www.conventionalcommits.org/en/v1.0.0/) specification.
Following this convention allows us to provide an automated release process
that also generates a detailed Changelog.

As described by the specification, our commit messages should be written as:

```markdown
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Some examples of this pattern include:

```markdown
feat(rln): add parallel witness calculation support
```

```markdown
fix(rln-wasm): resolve memory leak in browser threading
```

```markdown
docs: update RLN protocol flow documentation
```

#### Scopes

Use scopes to improve the Changelog:

- `rln` - Core RLN implementation
- `rln-cli` - Command-line interface
- `rln-wasm` - WebAssembly bindings
- `utils` - Cryptographic utilities (Merkle trees, Poseidon hash)
- `ci` - Continuous integration

#### Breaking Changes

Mark breaking changes by adding `!` after the type:

```markdown
feat(rln)!: change proof generation API
```

## Pull Requests

Before creating a pull request, search for related issues.
If none exist, create an issue describing the problem you're solving.

### CI Flow

Our continuous integration automatically runs when you create a Pull Request:

- **Build verification**: All crates compile successfully
- **Test execution**: Comprehensive testing across all modules and feature combinations
- **Code formatting**: `cargo fmt` compliance
- **Linting**: `cargo clippy` checks
- **Cross-platform builds**: Testing on multiple platforms

Ensure the following commands pass before submitting:

```bash
# Format code
cargo fmt --all

# Check for common mistakes
cargo clippy --all-targets

# Run all tests
make test
```

### Adding Tests

Include tests for new functionality:

- **Unit tests** for specific functions
- **Integration tests** for broader functionality
- **WASM tests** for browser compatibility

### Typos and Small Changes

For minor fixes like typos, please report them as issues instead of opening PRs.
This helps us manage resources effectively and ensures meaningful contributions.

## Merging

We use "squash merging" for all pull requests.
This combines all commits into one commit, so keep pull requests small and focused.

### Requirements

- CI checks must pass
- At least one maintainer review and approval
- All review feedback addressed

### Squash Guidelines

When squashing, update the commit title to be a proper Conventional Commit and
include any other relevant commits in the body:

```markdown
feat(rln): implement parallel witness calculation (#123)

fix(tests): resolve memory leak in test suite
chore(ci): update rust toolchain version
```

## Roadmap Alignment

Please refer to our [project roadmap](https://roadmap.vac.dev/) for current development priorities.
Consider how your changes align with these strategic goals, when contributing.

## Getting Help

- **Issues**: Create a GitHub issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check existing docs and unit tests for examples

## License

By contributing to Zerokit, you agree that your contributions will be licensed under both MIT and
Apache 2.0 licenses, consistent with the project's dual licensing.

## Additional Resources

- [Conventional Commits Guide](https://www.conventionalcommits.org/en/v1.0.0/)
- [Project GitHub Repository](https://github.com/vacp2p/zerokit)
