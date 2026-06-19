# Contributing to StellarID

Thank you for your interest in contributing. This project participates in the [Stellar Wave Program](https://drips.network/wave/stellar) on Drips — contributors earn USDC rewards for resolving issues.

## Prerequisites

- [Rust](https://rustup.rs/) 1.75+
- [Soroban CLI](https://developers.stellar.org/docs/smart-contracts/getting-started/setup)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install WASM target
rustup target add wasm32-unknown-unknown

# Install Soroban CLI
cargo install --locked soroban-cli
```

## Setup

```bash
git clone https://github.com/laugh-tales/stellar-id
cd stellar-id
cargo build
cargo test
```

All tests must pass before you begin working on an issue.

## Workflow

1. Comment on the issue you want to work on — wait to be assigned before starting
2. Fork the repository
3. Create a branch: `git checkout -b fix/your-issue-name`
4. Make your changes
5. Run `make check` (runs fmt + lint + tests)
6. Commit using conventional format (see below)
7. Open a Pull Request against `main`

## Commit Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

| Type | When to use |
|---|---|
| `feat` | New contract function or feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `test` | Adding or updating tests |
| `chore` | Build config, CI, tooling |
| `refactor` | Code restructure without behaviour change |

Examples:
```
feat: add batch credential issuance function
fix: prevent expired credential from returning valid in has_valid_credential
docs: add integration example for DeFi gating
test: add edge case for revoked credential expiry check
```

## Code Standards

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` — all warnings are errors
- Every new public function needs a `///` doc comment
- Every new feature needs at least one test in `#[cfg(test)]`
- Use `persistent()` storage for user data, `instance()` for contract-wide counters

## New to Stellar/Soroban?

- [Soroban Getting Started](https://developers.stellar.org/docs/smart-contracts/getting-started/setup)
- [Soroban SDK Docs](https://docs.rs/soroban-sdk)
- [Stellar Concepts](https://developers.stellar.org/docs/learn/fundamentals)

## Questions

Open a GitHub Discussion or comment on the relevant issue.
