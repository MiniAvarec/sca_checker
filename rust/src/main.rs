use clap::Parser;
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;
use toml::Value as TomlValue;
use urlencoding::encode;
use walkdir::WalkDir;

const OSV_API_BASE: &str = "https://api.osv.dev/v1";

static SEMVER_EXACT_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9]+(\.[0-9]+)*([A-Za-z0-9\.\+\-_~]*)?$").unwrap()
});

static RE_REQUIREMENTS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([A-Za-z0-9_.-]+)(\[[^\]]+\])?\s*(==|===|>=|<=|~=|!=|>|<)\s*([^\s]+)").unwrap()
});

static RE_PNPM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s{2,}/(.+?)/([^/]+):\s*$").unwrap()
});

static RE_GRADLE_STRING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"['\"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^'\"]+)['\"]").unwrap()
});

static RE_GRADLE_MAP: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"group:\s*['\"]([^'\"]+)['\"].*?name:\s*['\"]([^'\"]+)['\"].*?version:\s*['\"]([^'\"]+)['\"]").unwrap()
});

static RE_YARN_VERSION_DQ: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s+version\s+\"([^\"]+)\"").unwrap()
});

static RE_YARN_VERSION_SQ: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s+version\s+'([^']+)'"").unwrap()
});

static RE_GEMFILE_LOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)").unwrap()
});

static RE_GEMFILE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*gem\s+['\"]([^'\"]+)['\"]\s*(,\s*['\"]([^'\"]+)['\"])?").unwrap()
});

static LOCAL_IGNORE_DIRS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        ".git",
        ".hg",
        ".svn",
        ".venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "output",
        ".idea",
        ".vscode",
    ]
    .iter()
    .copied()
    .collect()
});

#[derive(Parser, Debug)]
#[command(about = "GitLab group or local SCA checker using OSV")]
struct Cli {
    #[arg(long, default_value = "config.json")]
    config: String,
    #[arg(long)]
    local: bool,
    #[arg(long, default_value = ".")]
    path: String,
}

#[derive(Debug, Deserialize, Default)]
struct Config {
    gitlab: Option<GitlabConfig>,
    scan: Option<ScanConfig>,
    output: Option<OutputConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct GitlabConfig {
    base_url: Option<String>,
    token: Option<String>,
    group: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ScanConfig {
    include_subgroups: Option<bool>,
    per_page: Option<u32>,
    ignore_projects: Option<Vec<Value>>,
}

#[derive(Debug, Deserialize, Default)]
struct OutputConfig {
    inventory_path: Option<String>,
    vulnerability_report_path: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct Dependency {
    project_id: i64,
    project_name: String,
    project_path: String,
    file_path: String,
    name: String,
    ecosystem: String,
    version: Option<String>,
    version_spec: Option<String>,
    package_manager: String,
    dep_type: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct DepFile {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    dependency_count: usize,
}

#[derive(Debug, Serialize, Clone)]
struct InventoryProject {
    id: i64,
    name: String,
    path_with_namespace: String,
    default_branch: Option<String>,
    dependency_files: Vec<DepFile>,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Serialize)]
struct Inventory {
    generated_at: String,
    group: String,
    project_count: usize,
    dependency_count: usize,
    projects: Vec<InventoryProject>,
}

#[derive(Debug, Serialize)]
struct IssueReport {
    generated_at: String,
    issue_count: usize,
    issues: Vec<Value>,
}

#[derive(Debug, Clone)]
struct ParsedDep {
    name: String,
    ecosystem: String,
    version: Option<String>,
    version_spec: Option<String>,
    dep_type: Option<String>,
}

type ParserFn = fn(&str) -> Vec<ParsedDep>;

struct GitLabClient {
    base_url: String,
    token: String,
    per_page: u32,
    client: Client,
}

impl GitLabClient {
    fn new(base_url: String, token: String, per_page: u32) -> Result<Self, String> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "PRIVATE-TOKEN",
            HeaderValue::from_str(&token).map_err(|e| e.to_string())?,
        );
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            per_page,
            client,
        })
    }

    fn request(&self, method: &str, path: &str, params: &Vec<(&str, String)>) -> Result<reqwest::blocking::Response, String> {
        let url = format!("{}/api/v4{}", self.base_url, path);
        for _ in 0..5 {
            let req = match method {
                "GET" => self.client.get(&url).query(params),
                _ => return Err("Unsupported method".to_string()),
            };
            let resp = req.send().map_err(|e| e.to_string())?;
            if resp.status().as_u16() == 429 {
                let retry_after = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(2);
                sleep(Duration::from_secs(retry_after));
                continue;
            }
            return Ok(resp);
        }
        Err("GitLab API rate limited".to_string())
    }

    fn get_paginated(&self, path: &str, params: &Vec<(&str, String)>) -> Result<Vec<Value>, String> {
        let mut results: Vec<Value> = Vec::new();
        let mut page = 1u32;
        loop {
            let mut p = params.clone();
            p.push(("per_page", self.per_page.to_string()));
            p.push(("page", page.to_string()));
            let resp = self.request("GET", path, &p)?;
            if resp.status().as_u16() >= 400 {
                return Err(format!("GitLab API error {}", resp.status()));
            }
            let headers = resp.headers().clone();
            let data: Value = resp.json().map_err(|e| e.to_string())?;
            let arr = data.as_array().ok_or("Unexpected response format")?;
            results.extend(arr.iter().cloned());
            let next_page = headers
                .get("X-Next-Page")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .trim()
                .to_string();
            if next_page.is_empty() {
                break;
            }
            page = next_page.parse::<u32>().unwrap_or(0);
            if page == 0 {
                break;
            }
        }
        Ok(results)
    }

    fn iter_group_projects(&self, group: &str, include_subgroups: bool) -> Result<Vec<Value>, String> {
        let group_enc = encode(group).to_string();
        let params = vec![(
            "include_subgroups",
            if include_subgroups { "true" } else { "false" }.to_string(),
        )];
        self.get_paginated(&format!("/groups/{}/projects", group_enc), &params)
    }

    fn iter_repo_files(&self, project_id: i64, reference: &str) -> Result<Vec<Value>, String> {
        let params = vec![("ref", reference.to_string()), ("recursive", "true".to_string())];
        self.get_paginated(&format!("/projects/{}/repository/tree", project_id), &params)
    }

    fn get_file_raw(&self, project_id: i64, file_path: &str, reference: &str) -> Result<Option<String>, String> {
        let encoded = encode(file_path).to_string();
        let params = vec![("ref", reference.to_string())];
        let resp = self.request(
            "GET",
            &format!("/projects/{}/repository/files/{}/raw", project_id, encoded),
            &params,
        )?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if resp.status().as_u16() >= 400 {
            return Err(format!("GitLab API error {}", resp.status()));
        }
        let text = resp.text().map_err(|e| e.to_string())?;
        Ok(Some(text))
    }
}

fn log(message: &str) {
    eprintln!("{}", message);
}

fn normalize_version_spec(spec: Option<&str>) -> Option<String> {
    let mut s = spec?.trim().to_string();
    if s.is_empty() {
        return None;
    }
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s = s[1..s.len() - 1].to_string();
    }
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn is_exact_version(spec: &str) -> bool {
    let mut s = spec.trim();
    if s.starts_with("==") || s.starts_with("===") {
        s = s.trim_start_matches('=');
    }
    let lower = s.to_lowercase();
    if lower.starts_with("git+")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("file:")
        || lower.starts_with("path:")
        || lower.starts_with("workspace:")
        || lower.starts_with("link:")
        || lower.starts_with("npm:")
        || lower.starts_with("github:")
    {
        return false;
    }
    if s.chars().any(|c| matches!(c, '^' | '~' | '>' | '<' | '*' | '|' | ',')) {
        return false;
    }
    if s.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    if s.ends_with(".tgz") {
        return false;
    }
    if s.starts_with('v') && SEMVER_EXACT_RE.is_match(&s[1..]) {
        return true;
    }
    SEMVER_EXACT_RE.is_match(s)
}

fn normalize_exact_version(spec: Option<&str>) -> Option<String> {
    let mut s = spec?.trim().to_string();
    if s.starts_with("==") || s.starts_with("===") {
        s = s.trim_start_matches('=').to_string();
    }
    if s.starts_with('v') && SEMVER_EXACT_RE.is_match(&s[1..]) {
        s = s[1..].to_string();
    }
    Some(s)
}

fn split_name_and_spec(req: &str) -> (String, Option<String>) {
    let s = req.trim();
    if s.is_empty() {
        return ("".to_string(), None);
    }
    let mut parts = s.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("");
    let name = name.split('[').next().unwrap_or("").to_string();
    let spec = parts.next().map(|s| s.trim().to_string());
    (name, spec)
}

fn get_parser_for_path(path: &str) -> Option<(&'static str, ParserFn)> {
    let base = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if base == "package.json" {
        return Some(("package.json", parse_package_json));
    }
    if base == "package-lock.json" {
        return Some(("package-lock.json", parse_package_lock_json));
    }
    if base == "yarn.lock" {
        return Some(("yarn.lock", parse_yarn_lock));
    }
    if base == "pnpm-lock.yaml" {
        return Some(("pnpm-lock.yaml", parse_pnpm_lock));
    }
    if base.starts_with("requirements") && base.ends_with(".txt") {
        return Some(("requirements.txt", parse_requirements_txt));
    }
    if base == "pipfile.lock" {
        return Some(("pipfile.lock", parse_pipfile_lock));
    }
    if base == "poetry.lock" {
        return Some(("poetry.lock", parse_poetry_lock));
    }
    if base == "pyproject.toml" {
        return Some(("pyproject.toml", parse_pyproject_toml));
    }
    if base == "go.mod" {
        return Some(("go.mod", parse_go_mod));
    }
    if base == "go.sum" {
        return Some(("go.sum", parse_go_sum));
    }
    if base == "pom.xml" {
        return Some(("pom.xml", parse_pom_xml));
    }
    if base == "build.gradle" {
        return Some(("build.gradle", parse_build_gradle));
    }
    if base == "build.gradle.kts" {
        return Some(("build.gradle.kts", parse_build_gradle));
    }
    if base == "gemfile.lock" {
        return Some(("gemfile.lock", parse_gemfile_lock));
    }
    if base == "gemfile" {
        return Some(("gemfile", parse_gemfile));
    }
    if base == "composer.lock" {
        return Some(("composer.lock", parse_composer_lock));
    }
    if base == "composer.json" {
        return Some(("composer.json", parse_composer_json));
    }
    if base == "cargo.lock" {
        return Some(("cargo.lock", parse_cargo_lock));
    }
    if base == "cargo.toml" {
        return Some(("cargo.toml", parse_cargo_toml));
    }
    if base == "packages.config" {
        return Some(("packages.config", parse_packages_config));
    }
    if base.ends_with(".csproj") {
        return Some(("csproj", parse_csproj));
    }
    None
}

fn parse_package_json(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: Value = serde_json::from_str(content).unwrap_or(Value::Null);
    for dep_type in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        if let Some(section) = data.get(dep_type).and_then(|v| v.as_object()) {
            for (name, spec_val) in section {
                let spec = spec_val.as_str().unwrap_or("").to_string();
                let spec_norm = normalize_version_spec(Some(&spec));
                let version = spec_norm
                    .as_deref()
                    .filter(|s| is_exact_version(s))
                    .and_then(|s| normalize_exact_version(Some(s)));
                deps.push(ParsedDep {
                    name: name.to_string(),
                    ecosystem: "npm".to_string(),
                    version,
                    version_spec: spec_norm,
                    dep_type: Some(dep_type.to_string()),
                });
            }
        }
    }
    deps
}

fn parse_package_lock_json(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: Value = serde_json::from_str(content).unwrap_or(Value::Null);
    if let Some(packages) = data.get("packages").and_then(|v| v.as_object()) {
        for (key, info) in packages {
            if key == "" {
                continue;
            }
            let version = info.get("version").and_then(|v| v.as_str());
            if version.is_none() {
                continue;
            }
            let mut name = info
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if name.is_none() {
                if let Some(idx) = key.rfind("node_modules/") {
                    name = Some(key[idx + "node_modules/".len()..].to_string());
                } else {
                    name = Path::new(key)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string());
                }
            }
            if let (Some(name), Some(version)) = (name, version) {
                deps.push(ParsedDep {
                    name,
                    ecosystem: "npm".to_string(),
                    version: Some(version.to_string()),
                    version_spec: Some(version.to_string()),
                    dep_type: Some("lock".to_string()),
                });
            }
        }
        return deps;
    }

    fn walk(dep_dict: &serde_json::Map<String, Value>, deps: &mut Vec<ParsedDep>) {
        for (name, info) in dep_dict {
            if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                deps.push(ParsedDep {
                    name: name.to_string(),
                    ecosystem: "npm".to_string(),
                    version: Some(version.to_string()),
                    version_spec: Some(version.to_string()),
                    dep_type: Some("lock".to_string()),
                });
            }
            if let Some(nested) = info.get("dependencies").and_then(|v| v.as_object()) {
                walk(nested, deps);
            }
        }
    }

    if let Some(deps_obj) = data.get("dependencies").and_then(|v| v.as_object()) {
        walk(deps_obj, &mut deps);
    }

    deps
}

fn parse_yarn_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;

    let mut flush = |deps: &mut Vec<ParsedDep>, names: &mut Vec<String>, version: &mut Option<String>| {
        if let (Some(ver), true) = (version.clone(), !names.is_empty()) {
            for n in names.iter() {
                deps.push(ParsedDep {
                    name: n.to_string(),
                    ecosystem: "npm".to_string(),
                    version: Some(ver.clone()),
                    version_spec: Some(ver.clone()),
                    dep_type: Some("lock".to_string()),
                });
            }
        }
        names.clear();
        *version = None;
    };

    for line in content.lines() {
        if line.trim().is_empty() {
            flush(&mut deps, &mut current_names, &mut current_version);
            continue;
        }
        if !line.starts_with(' ') && line.trim_end().ends_with(':') {
            flush(&mut deps, &mut current_names, &mut current_version);
            let header = line.trim_end_matches(':').trim();
            let selectors = header.split(',');
            let mut names: Vec<String> = Vec::new();
            for sel in selectors {
                let mut s = sel.trim().trim_matches('"').to_string();
                if s.starts_with("workspace:") || s.starts_with("link:") || s.starts_with("file:") {
                    continue;
                }
                if let Some(idx) = s.find("@npm:") {
                    s = s[..idx].to_string();
                } else {
                    let mut parts = s.rsplitn(2, '@');
                    let _ver = parts.next();
                    if let Some(name_part) = parts.next() {
                        s = name_part.to_string();
                    }
                }
                if !s.is_empty() {
                    names.push(s);
                }
            }
            let mut seen = HashSet::new();
            current_names = names.into_iter().filter(|n| seen.insert(n.clone())).collect();
            continue;
        }
        if let Some(cap) = RE_YARN_VERSION_DQ.captures(line) {
            current_version = Some(cap[1].to_string());
        } else if let Some(cap) = RE_YARN_VERSION_SQ.captures(line) {
            current_version = Some(cap[1].to_string());
        }
    }

    flush(&mut deps, &mut current_names, &mut current_version);
    deps
}

fn parse_pnpm_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    for line in content.lines() {
        if let Some(cap) = RE_PNPM.captures(line) {
            let name = cap[1].to_string();
            let mut version = cap[2].to_string();
            if let Some(idx) = version.find('_') {
                version = version[..idx].to_string();
            }
            deps.push(ParsedDep {
                name,
                ecosystem: "npm".to_string(),
                version: Some(version.clone()),
                version_spec: Some(version),
                dep_type: Some("lock".to_string()),
            });
        }
    }
    deps
}

fn parse_requirements_txt(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    for raw in content.lines() {
        let mut line = raw.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-r ")
            || line.starts_with("--")
            || line.starts_with("-e ")
            || line.starts_with("git+")
            || line.starts_with("http://")
            || line.starts_with("https://")
        {
            continue;
        }
        if let Some(idx) = line.find(';') {
            line = line[..idx].trim().to_string();
        }
        if let Some(cap) = RE_REQUIREMENTS.captures(&line) {
            let name = cap[1].to_string();
            let op = cap[3].to_string();
            let ver = cap[4].to_string();
            let spec = format!("{}{}", op, ver);
            let version = if op == "==" || op == "===" {
                normalize_exact_version(Some(&spec))
            } else {
                None
            };
            deps.push(ParsedDep {
                name,
                ecosystem: "PyPI".to_string(),
                version,
                version_spec: Some(spec),
                dep_type: Some("requirements".to_string()),
            });
        }
    }
    deps
}

fn parse_pipfile_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: Value = serde_json::from_str(content).unwrap_or(Value::Null);
    for section_name in ["default", "develop"] {
        if let Some(section) = data.get(section_name).and_then(|v| v.as_object()) {
            for (name, info) in section {
                if let Some(spec) = info.get("version").and_then(|v| v.as_str()) {
                    let spec_norm = normalize_version_spec(Some(spec));
                    let version = spec_norm
                        .as_deref()
                        .filter(|s| is_exact_version(s))
                        .and_then(|s| normalize_exact_version(Some(s)));
                    deps.push(ParsedDep {
                        name: name.to_string(),
                        ecosystem: "PyPI".to_string(),
                        version,
                        version_spec: spec_norm,
                        dep_type: Some(section_name.to_string()),
                    });
                }
            }
        }
    }
    deps
}

fn parse_poetry_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: TomlValue = content.parse().unwrap_or(TomlValue::Table(Default::default()));
    if let Some(packages) = data.get("package").and_then(|v| v.as_array()) {
        for pkg in packages {
            if let (Some(name), Some(version)) = (
                pkg.get("name").and_then(|v| v.as_str()),
                pkg.get("version").and_then(|v| v.as_str()),
            ) {
                deps.push(ParsedDep {
                    name: name.to_string(),
                    ecosystem: "PyPI".to_string(),
                    version: Some(version.to_string()),
                    version_spec: Some(version.to_string()),
                    dep_type: Some("lock".to_string()),
                });
            }
        }
    }
    deps
}

fn spec_from_toml_value(val: &TomlValue) -> Option<String> {
    if let Some(s) = val.as_str() {
        return Some(s.to_string());
    }
    if let Some(tbl) = val.as_table() {
        if let Some(version) = tbl.get("version").and_then(|v| v.as_str()) {
            return Some(version.to_string());
        }
    }
    None
}

fn parse_pyproject_toml(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: TomlValue = content.parse().unwrap_or(TomlValue::Table(Default::default()));

    if let Some(project) = data.get("project").and_then(|v| v.as_table()) {
        if let Some(list) = project.get("dependencies").and_then(|v| v.as_array()) {
            for req in list {
                if let Some(req_str) = req.as_str() {
                    let (name, spec) = split_name_and_spec(req_str);
                    if name.is_empty() {
                        continue;
                    }
                    let spec_norm = normalize_version_spec(spec.as_deref());
                    let version = spec_norm
                        .as_deref()
                        .filter(|s| is_exact_version(s))
                        .and_then(|s| normalize_exact_version(Some(s)));
                    deps.push(ParsedDep {
                        name,
                        ecosystem: "PyPI".to_string(),
                        version,
                        version_spec: spec_norm,
                        dep_type: Some("project".to_string()),
                    });
                }
            }
        }
        if let Some(opt) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            for (_group, items) in opt {
                if let Some(list) = items.as_array() {
                    for req in list {
                        if let Some(req_str) = req.as_str() {
                            let (name, spec) = split_name_and_spec(req_str);
                            if name.is_empty() {
                                continue;
                            }
                            let spec_norm = normalize_version_spec(spec.as_deref());
                            let version = spec_norm
                                .as_deref()
                                .filter(|s| is_exact_version(s))
                                .and_then(|s| normalize_exact_version(Some(s)));
                            deps.push(ParsedDep {
                                name,
                                ecosystem: "PyPI".to_string(),
                                version,
                                version_spec: spec_norm,
                                dep_type: Some("optional".to_string()),
                            });
                        }
                    }
                }
            }
        }
    }

    if let Some(tool) = data.get("tool").and_then(|v| v.as_table()) {
        if let Some(poetry) = tool.get("poetry").and_then(|v| v.as_table()) {
            for dep_section in ["dependencies", "dev-dependencies"] {
                if let Some(section) = poetry.get(dep_section).and_then(|v| v.as_table()) {
                    for (name, spec_val) in section {
                        if name == "python" {
                            continue;
                        }
                        let spec = spec_from_toml_value(spec_val);
                        let spec_norm = normalize_version_spec(spec.as_deref());
                        let version = spec_norm
                            .as_deref()
                            .filter(|s| is_exact_version(s))
                            .and_then(|s| normalize_exact_version(Some(s)));
                        deps.push(ParsedDep {
                            name: name.to_string(),
                            ecosystem: "PyPI".to_string(),
                            version,
                            version_spec: spec_norm,
                            dep_type: Some(dep_section.to_string()),
                        });
                    }
                }
            }
            if let Some(groups) = poetry.get("group").and_then(|v| v.as_table()) {
                for (_group_name, group_val) in groups {
                    if let Some(group_tbl) = group_val.as_table() {
                        if let Some(section) = group_tbl.get("dependencies").and_then(|v| v.as_table()) {
                            for (name, spec_val) in section {
                                if name == "python" {
                                    continue;
                                }
                                let spec = spec_from_toml_value(spec_val);
                                let spec_norm = normalize_version_spec(spec.as_deref());
                                let version = spec_norm
                                    .as_deref()
                                    .filter(|s| is_exact_version(s))
                                    .and_then(|s| normalize_exact_version(Some(s)));
                                deps.push(ParsedDep {
                                    name: name.to_string(),
                                    ecosystem: "PyPI".to_string(),
                                    version,
                                    version_spec: spec_norm,
                                    dep_type: Some("poetry-group".to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    deps
}

fn parse_go_mod(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let mut in_require = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require && line.starts_with(")") {
            in_require = false;
            continue;
        }
        if in_require {
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                deps.push(ParsedDep {
                    name: parts[0].to_string(),
                    ecosystem: "Go".to_string(),
                    version: Some(parts[1].to_string()),
                    version_spec: Some(parts[1].to_string()),
                    dep_type: Some("go.mod".to_string()),
                });
            }
            continue;
        }
        if line.starts_with("require ") {
            let rest = line.trim_start_matches("require ").trim();
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                deps.push(ParsedDep {
                    name: parts[0].to_string(),
                    ecosystem: "Go".to_string(),
                    version: Some(parts[1].to_string()),
                    version_spec: Some(parts[1].to_string()),
                    dep_type: Some("go.mod".to_string()),
                });
            }
        }
    }
    deps
}

fn parse_go_sum(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let mut version = parts[1].to_string();
        if version.ends_with("/go.mod") {
            version = version.replace("/go.mod", "");
        }
        deps.push(ParsedDep {
            name: parts[0].to_string(),
            ecosystem: "Go".to_string(),
            version: Some(version.clone()),
            version_spec: Some(version),
            dep_type: Some("go.sum".to_string()),
        });
    }
    deps
}

fn parse_pom_xml(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let doc = match Document::parse(content) {
        Ok(d) => d,
        Err(_) => return deps,
    };
    let root = doc.root_element();
    let mut props: HashMap<String, String> = HashMap::new();
    let mut project_version: Option<String> = None;

    for child in root.children().filter(|n| n.is_element()) {
        let name = child.tag_name().name();
        if name == "version" {
            if let Some(text) = child.text() {
                project_version = Some(text.trim().to_string());
            }
        }
        if name == "properties" {
            for prop in child.children().filter(|n| n.is_element()) {
                if let Some(text) = prop.text() {
                    props.insert(prop.tag_name().name().to_string(), text.trim().to_string());
                }
            }
        }
    }

    let resolve_version = |ver: Option<String>| -> Option<String> {
        let v = ver?;
        let s = v.trim();
        if s.starts_with("${") && s.ends_with('}') {
            let key = &s[2..s.len() - 1];
            if key == "project.version" {
                return project_version.clone();
            }
            return props.get(key).cloned();
        }
        Some(s.to_string())
    };

    for dep in doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == "dependency") {
        let mut group_id: Option<String> = None;
        let mut artifact_id: Option<String> = None;
        let mut version: Option<String> = None;
        let mut scope: Option<String> = None;
        for child in dep.children().filter(|n| n.is_element()) {
            match child.tag_name().name() {
                "groupId" => group_id = child.text().map(|s| s.trim().to_string()),
                "artifactId" => artifact_id = child.text().map(|s| s.trim().to_string()),
                "version" => version = child.text().map(|s| s.trim().to_string()),
                "scope" => scope = child.text().map(|s| s.trim().to_string()),
                _ => {}
            }
        }
        if let (Some(g), Some(a)) = (group_id, artifact_id) {
            let resolved = resolve_version(version);
            let spec_norm = normalize_version_spec(resolved.as_deref());
            let version_exact = spec_norm
                .as_deref()
                .filter(|s| is_exact_version(s))
                .and_then(|s| normalize_exact_version(Some(s)));
            let name = format!("{}:{}", g, a);
            deps.push(ParsedDep {
                name,
                ecosystem: "Maven".to_string(),
                version: version_exact,
                version_spec: spec_norm,
                dep_type: scope.or_else(|| Some("maven".to_string())),
            });
        }
    }

    deps
}

fn parse_build_gradle(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    for cap in RE_GRADLE_STRING.captures_iter(content) {
        let group_id = cap[1].to_string();
        let artifact_id = cap[2].to_string();
        let version = cap[3].to_string();
        let spec_norm = normalize_version_spec(Some(&version));
        let version_exact = spec_norm
            .as_deref()
            .filter(|s| is_exact_version(s))
            .and_then(|s| normalize_exact_version(Some(s)));
        deps.push(ParsedDep {
            name: format!("{}:{}", group_id, artifact_id),
            ecosystem: "Maven".to_string(),
            version: version_exact,
            version_spec: spec_norm,
            dep_type: Some("gradle".to_string()),
        });
    }
    for cap in RE_GRADLE_MAP.captures_iter(content) {
        let group_id = cap[1].to_string();
        let artifact_id = cap[2].to_string();
        let version = cap[3].to_string();
        let spec_norm = normalize_version_spec(Some(&version));
        let version_exact = spec_norm
            .as_deref()
            .filter(|s| is_exact_version(s))
            .and_then(|s| normalize_exact_version(Some(s)));
        deps.push(ParsedDep {
            name: format!("{}:{}", group_id, artifact_id),
            ecosystem: "Maven".to_string(),
            version: version_exact,
            version_spec: spec_norm,
            dep_type: Some("gradle".to_string()),
        });
    }
    deps
}

fn parse_gemfile_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let mut in_specs = false;
    for line in content.lines() {
        if line.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        if in_specs && line.trim().chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            in_specs = false;
            continue;
        }
        if in_specs {
            if let Some(cap) = RE_GEMFILE_LOCK.captures(line) {
                let name = cap[1].to_string();
                let version = cap[2].to_string();
                deps.push(ParsedDep {
                    name,
                    ecosystem: "RubyGems".to_string(),
                    version: Some(version.clone()),
                    version_spec: Some(version),
                    dep_type: Some("lock".to_string()),
                });
            }
        }
    }
    deps
}

fn parse_gemfile(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    for line in content.lines() {
        if let Some(cap) = RE_GEMFILE.captures(line) {
            let name = cap[1].to_string();
            let spec = cap.get(3).map(|m| m.as_str().to_string());
            let spec_norm = normalize_version_spec(spec.as_deref());
            let version_exact = spec_norm
                .as_deref()
                .filter(|s| is_exact_version(s))
                .and_then(|s| normalize_exact_version(Some(s)));
            deps.push(ParsedDep {
                name,
                ecosystem: "RubyGems".to_string(),
                version: version_exact,
                version_spec: spec_norm,
                dep_type: Some("gemfile".to_string()),
            });
        }
    }
    deps
}

fn parse_composer_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: Value = serde_json::from_str(content).unwrap_or(Value::Null);
    for section_name in ["packages", "packages-dev"] {
        if let Some(list) = data.get(section_name).and_then(|v| v.as_array()) {
            for pkg in list {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|v| v.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    let mut v = version.to_string();
                    if v.starts_with('v') {
                        v = v.trim_start_matches('v').to_string();
                    }
                    deps.push(ParsedDep {
                        name: name.to_string(),
                        ecosystem: "Packagist".to_string(),
                        version: Some(v.clone()),
                        version_spec: Some(v),
                        dep_type: Some("lock".to_string()),
                    });
                }
            }
        }
    }
    deps
}

fn parse_composer_json(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: Value = serde_json::from_str(content).unwrap_or(Value::Null);
    for section_name in ["require", "require-dev"] {
        if let Some(section) = data.get(section_name).and_then(|v| v.as_object()) {
            for (name, spec_val) in section {
                let spec = spec_val.as_str().unwrap_or("").to_string();
                let spec_norm = normalize_version_spec(Some(&spec));
                let version_exact = spec_norm
                    .as_deref()
                    .filter(|s| is_exact_version(s))
                    .and_then(|s| normalize_exact_version(Some(s)));
                deps.push(ParsedDep {
                    name: name.to_string(),
                    ecosystem: "Packagist".to_string(),
                    version: version_exact,
                    version_spec: spec_norm,
                    dep_type: Some(section_name.to_string()),
                });
            }
        }
    }
    deps
}

fn parse_cargo_lock(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: TomlValue = content.parse().unwrap_or(TomlValue::Table(Default::default()));
    if let Some(packages) = data.get("package").and_then(|v| v.as_array()) {
        for pkg in packages {
            if let (Some(name), Some(version)) = (
                pkg.get("name").and_then(|v| v.as_str()),
                pkg.get("version").and_then(|v| v.as_str()),
            ) {
                deps.push(ParsedDep {
                    name: name.to_string(),
                    ecosystem: "crates.io".to_string(),
                    version: Some(version.to_string()),
                    version_spec: Some(version.to_string()),
                    dep_type: Some("lock".to_string()),
                });
            }
        }
    }
    deps
}

fn parse_cargo_dep_table(section: &toml::value::Table, dep_type: &str, deps: &mut Vec<ParsedDep>) {
    for (name, spec_val) in section {
        let spec = spec_from_toml_value(spec_val);
        let spec_norm = normalize_version_spec(spec.as_deref());
        let version_exact = spec_norm
            .as_deref()
            .filter(|s| is_exact_version(s))
            .and_then(|s| normalize_exact_version(Some(s)));
        deps.push(ParsedDep {
            name: name.to_string(),
            ecosystem: "crates.io".to_string(),
            version: version_exact,
            version_spec: spec_norm,
            dep_type: Some(dep_type.to_string()),
        });
    }
}

fn parse_cargo_toml(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let data: TomlValue = content.parse().unwrap_or(TomlValue::Table(Default::default()));
    for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(section) = data.get(key).and_then(|v| v.as_table()) {
            parse_cargo_dep_table(section, key, &mut deps);
        }
    }
    if let Some(targets) = data.get("target").and_then(|v| v.as_table()) {
        for (_target, cfg) in targets {
            if let Some(tbl) = cfg.as_table() {
                for key in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(section) = tbl.get(key).and_then(|v| v.as_table()) {
                        parse_cargo_dep_table(section, &format!("target-{}", key), &mut deps);
                    }
                }
            }
        }
    }
    deps
}

fn parse_csproj(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let doc = match Document::parse(content) {
        Ok(d) => d,
        Err(_) => return deps,
    };
    for node in doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == "PackageReference") {
        let name = node.attribute("Include").or_else(|| node.attribute("Update"));
        let mut version = node.attribute("Version").map(|s| s.to_string());
        if version.is_none() {
            for child in node.children().filter(|n| n.is_element()) {
                if child.tag_name().name() == "Version" {
                    version = child.text().map(|s| s.trim().to_string());
                    break;
                }
            }
        }
        if let (Some(name), Some(version)) = (name, version) {
            let spec_norm = normalize_version_spec(Some(&version));
            let version_exact = spec_norm
                .as_deref()
                .filter(|s| is_exact_version(s))
                .and_then(|s| normalize_exact_version(Some(s)));
            deps.push(ParsedDep {
                name: name.to_string(),
                ecosystem: "NuGet".to_string(),
                version: version_exact,
                version_spec: spec_norm,
                dep_type: Some("csproj".to_string()),
            });
        }
    }
    deps
}

fn parse_packages_config(content: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let doc = match Document::parse(content) {
        Ok(d) => d,
        Err(_) => return deps,
    };
    for node in doc.descendants().filter(|n| n.is_element() && n.tag_name().name() == "package") {
        let name = node.attribute("id");
        let version = node.attribute("version");
        if let (Some(name), Some(version)) = (name, version) {
            deps.push(ParsedDep {
                name: name.to_string(),
                ecosystem: "NuGet".to_string(),
                version: Some(version.to_string()),
                version_spec: Some(version.to_string()),
                dep_type: Some("packages.config".to_string()),
            });
        }
    }
    deps
}

fn read_file_text(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn iter_local_files(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    let walker = WalkDir::new(root).into_iter();
    for entry in walker.filter_entry(|e| {
        let name = e.file_name().to_string_lossy();
        if e.file_type().is_dir() && LOCAL_IGNORE_DIRS.contains(name.as_ref()) {
            return false;
        }
        true
    }) {
        if let Ok(entry) = entry {
            if entry.file_type().is_file() {
                if let Ok(rel) = entry.path().strip_prefix(root) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    files.push(rel_str);
                }
            }
        }
    }
    files
}

fn collect_dependencies<F>(
    project_id: i64,
    project_name: &str,
    project_path: &str,
    file_paths: Vec<String>,
    read_fn: F,
) -> (Vec<DepFile>, Vec<Dependency>)
where
    F: Fn(&str) -> Result<String, String>,
{
    let mut dep_files = Vec::new();
    let mut deps_for_project = Vec::new();

    for file_path in file_paths {
        let (parser_name, parser_fn) = match get_parser_for_path(&file_path) {
            Some(v) => v,
            None => continue,
        };
        let content = match read_fn(&file_path) {
            Ok(c) => c,
            Err(err) => {
                log(&format!("  Failed to read {}: {}", file_path, err));
                continue;
            }
        };
        let parsed = match std::panic::catch_unwind(|| parser_fn(&content)) {
            Ok(v) => v,
            Err(_) => {
                log(&format!("  Failed to parse {}", file_path));
                Vec::new()
            }
        };

        dep_files.push(DepFile {
            path: file_path.clone(),
            kind: parser_name.to_string(),
            dependency_count: parsed.len(),
        });

        for dep in parsed {
            deps_for_project.push(Dependency {
                project_id,
                project_name: project_name.to_string(),
                project_path: project_path.to_string(),
                file_path: file_path.clone(),
                name: dep.name,
                ecosystem: dep.ecosystem,
                version: dep.version,
                version_spec: dep.version_spec,
                package_manager: parser_name.to_string(),
                dep_type: dep.dep_type,
            });
        }
    }

    (dep_files, deps_for_project)
}

fn scan_local(root_path: &str) -> Result<(String, Vec<InventoryProject>, Vec<Dependency>), String> {
    let root = fs::canonicalize(Path::new(root_path)).map_err(|e| e.to_string())?;
    if !root.is_dir() {
        return Err(format!("Local path not found or not a directory: {}", root.display()));
    }
    let project_name = root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("local")
        .to_string();
    let project_path = root.to_string_lossy().to_string();
    log(&format!("Scanning local path: {}", project_path));

    let file_paths = iter_local_files(&root);
    let read_fn = |rel_path: &str| -> Result<String, String> {
        let full = root.join(PathBuf::from(rel_path));
        read_file_text(&full)
    };

    let (dep_files, deps_for_project) = collect_dependencies(0, &project_name, &project_path, file_paths, read_fn);

    let project_entries = vec![InventoryProject {
        id: 0,
        name: project_name,
        path_with_namespace: project_path,
        default_branch: None,
        dependency_files: dep_files,
        dependencies: deps_for_project.clone(),
    }];

    Ok(("local".to_string(), project_entries, deps_for_project))
}

fn scan_gitlab(
    client: &GitLabClient,
    group: &str,
    include_subgroups: bool,
    ignore_projects_raw: &[Value],
) -> Result<(String, Vec<InventoryProject>, Vec<Dependency>), String> {
    log(&format!("Loading projects for group: {}", group));
    let projects = client.iter_group_projects(group, include_subgroups)?;
    log(&format!("Found {} projects", projects.len()));

    let mut ignore_ids = HashSet::new();
    let mut ignore_names = HashSet::new();
    for item in ignore_projects_raw {
        if let Some(id) = item.as_i64() {
            ignore_ids.insert(id);
            continue;
        }
        if let Some(s) = item.as_str() {
            let s = s.trim();
            if !s.is_empty() {
                ignore_names.insert(s.to_lowercase());
            }
        }
    }

    let mut all_deps = Vec::new();
    let mut project_entries = Vec::new();

    for proj in projects {
        let project_id = proj.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
        let project_name = proj
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let project_path = proj
            .get("path_with_namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&project_name)
            .to_string();
        let default_branch = proj
            .get("default_branch")
            .and_then(|v| v.as_str())
            .unwrap_or("main")
            .to_string();

        if project_id == 0 {
            continue;
        }
        if ignore_ids.contains(&project_id) {
            log(&format!("Skipping {} (ignored by id)", project_path));
            continue;
        }
        if ignore_names.contains(&project_path.to_lowercase()) || ignore_names.contains(&project_name.to_lowercase()) {
            log(&format!("Skipping {} (ignored by name/path)", project_path));
            continue;
        }

        log(&format!("Scanning {} ({})", project_path, default_branch));
        let files = match client.iter_repo_files(project_id, &default_branch) {
            Ok(v) => v,
            Err(e) => {
                log(&format!("  Failed to list files: {}", e));
                continue;
            }
        };
        let file_paths: Vec<String> = files
            .iter()
            .filter(|f| f.get("type").and_then(|v| v.as_str()) == Some("blob"))
            .filter_map(|f| f.get("path").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();

        let read_fn = |path: &str| -> Result<String, String> {
            match client.get_file_raw(project_id, path, &default_branch)? {
                Some(text) => Ok(text),
                None => Err("Not found".to_string()),
            }
        };

        let (dep_files, deps_for_project) =
            collect_dependencies(project_id, &project_name, &project_path, file_paths, read_fn);

        all_deps.extend(deps_for_project.clone());

        project_entries.push(InventoryProject {
            id: project_id,
            name: project_name,
            path_with_namespace: project_path,
            default_branch: Some(default_branch),
            dependency_files: dep_files,
            dependencies: deps_for_project,
        });
    }

    Ok((group.to_string(), project_entries, all_deps))
}

fn query_osv(deps: &[Dependency]) -> Result<HashMap<(String, String, String), Vec<Value>>, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;

    let mut queries = Vec::new();
    let mut keys: Vec<(String, String, String)> = Vec::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();

    for dep in deps {
        let version = match dep.version.as_ref() {
            Some(v) => v.clone(),
            None => continue,
        };
        let key = (dep.ecosystem.clone(), dep.name.clone(), version.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key.clone());
        queries.push(json!({
            "package": {"name": dep.name, "ecosystem": dep.ecosystem},
            "version": version
        }));
        keys.push(key);
    }

    let mut key_to_vulns: HashMap<(String, String, String), Vec<Value>> = HashMap::new();

    let chunk_size = 500usize;
    let mut idx = 0usize;
    while idx < queries.len() {
        let end = std::cmp::min(idx + chunk_size, queries.len());
        let chunk = &queries[idx..end];
        let key_chunk = &keys[idx..end];
        let payload = json!({"queries": chunk});
        let resp = client
            .post(&format!("{}/querybatch", OSV_API_BASE))
            .json(&payload)
            .send()
            .map_err(|e| e.to_string())?;
        if resp.status().as_u16() >= 400 {
            return Err(format!("OSV API error {}", resp.status()));
        }
        let data: Value = resp.json().map_err(|e| e.to_string())?;
        let results = data.get("results").and_then(|v| v.as_array()).unwrap_or(&vec![]);
        for (key, result) in key_chunk.iter().zip(results.iter()) {
            let vulns = result.get("vulns").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if !vulns.is_empty() {
                key_to_vulns.insert(key.clone(), vulns);
            }
        }
        idx = end;
    }

    Ok(key_to_vulns)
}

fn compute_severity(vuln: &Value) -> String {
    let mut best_score: Option<f64> = None;
    let mut best_type: Option<String> = None;
    if let Some(severity) = vuln.get("severity").and_then(|v| v.as_array()) {
        for s in severity {
            let score = s
                .get("score")
                .and_then(|v| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse::<f64>().ok())));
            if let Some(score) = score {
                if best_score.map(|b| score > b).unwrap_or(true) {
                    best_score = Some(score);
                    best_type = s.get("type").and_then(|v| v.as_str()).map(|s| s.to_string());
                }
            }
        }
    }
    if let Some(score) = best_score {
        let label = if score >= 9.0 {
            "CRITICAL"
        } else if score >= 7.0 {
            "HIGH"
        } else if score >= 4.0 {
            "MEDIUM"
        } else {
            "LOW"
        };
        if let Some(t) = best_type {
            format!("{} (CVSS {:.1} {})", label, score, t)
        } else {
            format!("{} (CVSS {:.1})", label, score)
        }
    } else {
        "Unknown".to_string()
    }
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let mut config: Config = Config::default();
    if Path::new(&cli.config).exists() {
        let content = fs::read_to_string(&cli.config).map_err(|e| e.to_string())?;
        config = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    } else if !cli.local {
        return Err(format!("Config file not found: {}", cli.config));
    } else {
        log(&format!("Config file not found: {}. Using defaults for local scan.", cli.config));
    }

    let scan_cfg = config.scan.unwrap_or_default();
    let out_cfg = config.output.unwrap_or_default();

    let inventory_path = out_cfg
        .inventory_path
        .unwrap_or_else(|| "output/dependency_inventory.json".to_string());
    let vuln_report_path = out_cfg
        .vulnerability_report_path
        .unwrap_or_else(|| "output/vulnerability_report.json".to_string());

    let (group, project_entries, all_deps) = if cli.local {
        scan_local(&cli.path)?
    } else {
        let gitlab_cfg = config.gitlab.unwrap_or_default();
        let base_url = gitlab_cfg
            .base_url
            .unwrap_or_else(|| "https://gitlab.com".to_string());
        let token = gitlab_cfg
            .token
            .ok_or("Config missing required fields: gitlab.token".to_string())?;
        let group = gitlab_cfg
            .group
            .ok_or("Config missing required fields: gitlab.group".to_string())?;
        let include_subgroups = scan_cfg.include_subgroups.unwrap_or(true);
        let per_page = scan_cfg.per_page.unwrap_or(100);
        let ignore_projects_raw = scan_cfg.ignore_projects.unwrap_or_default();

        let client = GitLabClient::new(base_url, token, per_page)?;
        scan_gitlab(&client, &group, include_subgroups, &ignore_projects_raw)?
    };

    let inventory = Inventory {
        generated_at: format!("{}", Utc::now().to_rfc3339()),
        group,
        project_count: project_entries.len(),
        dependency_count: all_deps.len(),
        projects: project_entries,
    };

    write_json(&inventory_path, &inventory)?;
    log(&format!("Inventory saved to {}", inventory_path));

    if all_deps.is_empty() {
        log("No dependencies found.");
        return Ok(());
    }

    log("Querying OSV...");
    let key_to_vulns = query_osv(&all_deps)?;

    let mut issues: Vec<Value> = Vec::new();
    for dep in &all_deps {
        let version = match dep.version.as_ref() {
            Some(v) => v.clone(),
            None => continue,
        };
        let key = (dep.ecosystem.clone(), dep.name.clone(), version.clone());
        let vulns = key_to_vulns.get(&key).cloned().unwrap_or_default();
        for vuln in vulns {
            let osv_id = vuln.get("id").and_then(|v| v.as_str()).unwrap_or("UNKNOWN");
            let issue = json!({
                "project": dep.project_path,
                "dependency": dep.name,
                "ecosystem": dep.ecosystem,
                "version": version,
                "source_file": dep.file_path,
                "vuln_id": osv_id,
                "osv_id": osv_id,
                "osv_link": format!("https://osv.dev/vulnerability/{}", osv_id),
                "severity": compute_severity(&vuln),
                "summary": vuln.get("summary").and_then(|v| v.as_str()).unwrap_or("").trim(),
            });
            issues.push(issue);
        }
    }

    let report = IssueReport {
        generated_at: format!("{}", Utc::now().to_rfc3339()),
        issue_count: issues.len(),
        issues: issues.clone(),
    };

    write_json(&vuln_report_path, &report)?;

    if issues.is_empty() {
        log("No vulnerabilities found.");
        return Ok(());
    }

    let mut grouped: HashMap<(String, String), HashSet<String>> = HashMap::new();
    let mut grouped_files: HashMap<(String, String), HashSet<String>> = HashMap::new();
    for issue in &issues {
        let dep = issue.get("dependency").and_then(|v| v.as_str()).unwrap_or("");
        let ver = issue.get("version").and_then(|v| v.as_str()).unwrap_or("");
        let key = (dep.to_string(), ver.to_string());
        let vuln_id = issue.get("vuln_id").and_then(|v| v.as_str()).unwrap_or("");
        grouped.entry(key.clone()).or_default().insert(vuln_id.to_string());
        let src = issue.get("source_file").and_then(|v| v.as_str()).unwrap_or("");
        grouped_files.entry(key).or_default().insert(src.to_string());
    }

    log(&format!("Found {} vulnerable dependencies.", grouped.len()));
    let mut keys: Vec<(String, String)> = grouped.keys().cloned().collect();
    keys.sort();
    for key in keys {
        let dep = &key.0;
        let ver = &key.1;
        let mut vuln_ids: Vec<String> = grouped.get(&key).cloned().unwrap_or_default().into_iter().collect();
        vuln_ids.sort();
        let mut source_files: Vec<String> = grouped_files.get(&key).cloned().unwrap_or_default().into_iter().collect();
        source_files.sort();
        let osv_links: Vec<String> = vuln_ids.iter().map(|id| format!("https://osv.dev/vulnerability/{}", id)).collect();
        let output = json!({
            "dependency": dep,
            "version": ver,
            "source_files": source_files,
            "vuln_ids": vuln_ids,
            "osv_links": osv_links,
            "vuln_count": grouped.get(&key).map(|s| s.len()).unwrap_or(0),
        });
        println!("{}", output.to_string());
    }

    Ok(())
}

fn write_json<T: Serialize>(path: &str, payload: &T) -> Result<(), String> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    let text = serde_json::to_string_pretty(payload).map_err(|e| e.to_string())?;
    fs::write(p, text).map_err(|e| e.to_string())?;
    Ok(())
}
