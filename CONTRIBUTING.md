# Contributing to SentinelWall

## Development Setup

### Prerequisites

- Rust 1.75+ (`rustup install stable`)
- Python 3.12+ with pip
- Node.js 20+ with npm
- nftables (Linux only; dry-run mode works on other platforms)

### Build Everything

```bash
# Rust workspace
cargo build --all

# Python ML service
cd sentinel-ml && pip install -e ".[dev]"

# Web frontend
cd sentinel-web && npm install && npm run dev
```

### Running Tests

```bash
# Rust unit + integration tests (dry-run on non-Linux)
SENTINEL_DRY_RUN=true cargo test --all

# Python tests
cd sentinel-ml && pytest tests/ -v

# Frontend type check
cd sentinel-web && npm run type-check
```

## Code Style

- **Rust**: `cargo fmt --all` + `cargo clippy --all -- -D warnings`
- **Python**: `ruff check` + `ruff format`
- **TypeScript**: ESLint + Prettier (run `npm run lint`)

CI enforces all of these — fix them before opening a PR.

## Pull Request Guidelines

1. Fork and create a feature branch: `git checkout -b feat/my-feature`
2. Make your changes with tests
3. Run the full test suite
4. Open a PR against `main` with a clear description

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add geo-IP blocking for IPv6
fix: prevent duplicate rule insertion on reload
docs: add cluster sync architecture diagram
refactor: extract rate-limiter into separate module
```

## Architecture Decisions

See [ARCHITECTURE.md](ARCHITECTURE.md) before making structural changes. Discuss significant changes in an issue before implementing.

## Security Issues

See [SECURITY.md](SECURITY.md) — do not open public issues for vulnerabilities.
