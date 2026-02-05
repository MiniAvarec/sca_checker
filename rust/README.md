# SCA Checker (Rust)

Rust implementation of the GitLab/local SCA checker. It scans dependency files, builds an inventory, and queries OSV for vulnerabilities.

## Build

```bash
cargo build --release
```

## Run (GitLab group)

```bash
cargo run -- --config ../config.json
```

## Run locally (no GitLab)

```bash
cargo run -- --local --path ..
```

## Output

- Dependency inventory: `output/dependency_inventory.json`
- Vulnerability report: `output/vulnerability_report.json`
- Console output: JSON lines (stdout), grouped by `dependency` + `version`, with fields `dependency`, `version`, `source_files`, `vuln_ids`, `osv_links`, `vuln_count`
- Progress logs go to stderr

## CLI options

- `--config`: path to config (default `config.json`)
- `--local`: scan a local directory instead of GitLab
- `--path`: local path to scan (used with `--local`, default `.`)

## Notes

- Lock files provide exact versions and give the best OSV coverage.
- The Rust version reads the same `config.json` format as the Python script.
