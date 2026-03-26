# Contributing to stealthreq

## Getting started

1. Install Rust with `rustup`.
2. `cd /home/mukund-thiru/Santh/libs/stealthreq`.
3. Run `cargo test` before opening a PR.

## Development expectations

- Add tests for every new behavioral branch.
- Keep randomness deterministic in unit tests using explicit seeds.
- Keep parser logic defensive (safe by default), especially around external input.
- Keep API surface trait-based so downstream clients can opt in without crate lock-in.

## Testing

- `cargo check`
- `cargo test`
- `cargo test -- --nocapture` for debug output in edge cases

## PR checklist

- [ ] New tests included
- [ ] No `unwrap` in production library code unless fully justified
- [ ] Examples updated when API changes
