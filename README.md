# GitLab SCA Checker

Scans a GitLab group (or a local folder) for dependency files, builds a dependency inventory (JSON), and checks for known vulnerabilities using OSV.

## Quick start (GitLab group)

1. Create a virtualenv and install requirements:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Create a config file and fill in your GitLab token + group:

```bash
cp config.example.json config.json
```

3. Run the scan:

```bash
python sca_checker.py --config config.json
```

## Local scan (no GitLab)

```bash
python sca_checker.py --local --path .
```

If `config.json` is missing, defaults are used for output paths.

## Rust version

Build:
```bash
cd rust
cargo build --release
```

Run (GitLab group):
```bash
cd rust
cargo run -- --config ../config.json
```

Run locally:
```bash
cd rust
cargo run -- --local --path ..
```

The Rust version reads the same `config.json` and produces the same output files and JSONL format as the Python script.

## CLI options

- `--config`: path to config (default `config.json`)
- `--local`: scan a local directory instead of GitLab
- `--path`: local path to scan (used with `--local`, default `.`)

## Config options

- `gitlab.base_url`: GitLab base URL (default `https://gitlab.com`)
- `gitlab.token`: personal access token
- `gitlab.group`: group path or numeric ID
- `scan.include_subgroups`: include subgroup projects (`true`/`false`)
- `scan.per_page`: GitLab API page size
- `scan.ignore_projects`: list of project IDs, full paths (`group/subgroup/name`), or project names to skip
- `output.inventory_path`: path for dependency inventory JSON
- `output.vulnerability_report_path`: path for OSV report JSON

## Output

- Dependency inventory: `output/dependency_inventory.json`
- Vulnerability report: `output/vulnerability_report.json`
- Console output: JSON lines (stdout), grouped by `dependency` + `version`, with fields `dependency`, `version`, `source_files`, `vuln_ids`, `osv_links`, `vuln_count`
- Progress logs are sent to stderr for easy pipeline parsing.

## Notes

- The scanner prefers lock files for exact versions (where possible) and will skip OSV queries for unresolved versions.
- Add or tune dependency file parsers in `sca_checker.py` as needed.
