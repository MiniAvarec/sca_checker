#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

try:
    import requests
except ImportError:  # pragma: no cover
    print("Missing dependency: requests. Install with: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)

import xml.etree.ElementTree as ET

OSV_API_BASE = "https://api.osv.dev/v1"

ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
    "cargo": "crates.io",
    "nuget": "NuGet",
}

SEMVER_EXACT_RE = re.compile(r"^[0-9]+(\.[0-9]+)*([A-Za-z0-9\.\+\-_~]*)?$")

LOCAL_IGNORE_DIRS = {
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
}


@dataclass
class Dependency:
    project_id: int
    project_name: str
    project_path: str
    file_path: str
    name: str
    ecosystem: str
    version: Optional[str]
    version_spec: Optional[str]
    package_manager: str
    dep_type: Optional[str]


class GitLabClient:
    def __init__(self, base_url: str, token: str, per_page: int = 100) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.per_page = per_page
        self.session = requests.Session()
        self.session.headers.update({"PRIVATE-TOKEN": token})

    def _request(self, method: str, path: str, params: Optional[dict] = None) -> requests.Response:
        url = f"{self.base_url}/api/v4{path}"
        for _ in range(5):
            resp = self.session.request(method, url, params=params, timeout=30)
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                sleep_for = int(retry_after) if retry_after else 2
                time.sleep(sleep_for)
                continue
            return resp
        return resp

    def get_json(self, path: str, params: Optional[dict] = None) -> dict:
        resp = self._request("GET", path, params=params)
        if resp.status_code >= 400:
            raise RuntimeError(f"GitLab API error {resp.status_code}: {resp.text}")
        return resp.json()

    def get_text(self, path: str, params: Optional[dict] = None) -> str:
        resp = self._request("GET", path, params=params)
        if resp.status_code == 404:
            raise FileNotFoundError(path)
        if resp.status_code >= 400:
            raise RuntimeError(f"GitLab API error {resp.status_code}: {resp.text}")
        return resp.text

    def get_paginated(self, path: str, params: Optional[dict] = None) -> List[dict]:
        params = params or {}
        params["per_page"] = self.per_page
        page = 1
        results: List[dict] = []
        while True:
            params["page"] = page
            resp = self._request("GET", path, params=params)
            if resp.status_code >= 400:
                raise RuntimeError(f"GitLab API error {resp.status_code}: {resp.text}")
            data = resp.json()
            if not isinstance(data, list):
                raise RuntimeError(f"Unexpected response format for {path}")
            results.extend(data)
            next_page = resp.headers.get("X-Next-Page")
            if not next_page:
                break
            page = int(next_page)
        return results

    def iter_group_projects(self, group: str, include_subgroups: bool) -> List[dict]:
        group_enc = quote(group, safe="")
        params = {"include_subgroups": "true" if include_subgroups else "false"}
        return self.get_paginated(f"/groups/{group_enc}/projects", params=params)

    def iter_repo_files(self, project_id: int, ref: str) -> List[dict]:
        params = {"ref": ref, "recursive": "true"}
        return self.get_paginated(f"/projects/{project_id}/repository/tree", params=params)

    def get_file_raw(self, project_id: int, file_path: str, ref: str) -> str:
        encoded = quote(file_path, safe="")
        return self.get_text(f"/projects/{project_id}/repository/files/{encoded}/raw", params={"ref": ref})


# -------------------------
# Parsing helpers
# -------------------------

def normalize_version_spec(spec: Optional[str]) -> Optional[str]:
    if spec is None:
        return None
    spec = str(spec).strip()
    if not spec:
        return None
    if (spec.startswith("\"") and spec.endswith("\"")) or (spec.startswith("'") and spec.endswith("'")):
        spec = spec[1:-1]
    return spec.strip()


def is_exact_version(spec: Optional[str]) -> bool:
    if not spec:
        return False
    s = spec.strip()
    if s.startswith("==") or s.startswith("==="):
        s = s.lstrip("=")
    lower = s.lower()
    if lower.startswith(("git+", "http://", "https://", "file:", "path:", "workspace:", "link:", "npm:", "github:")):
        return False
    if any(ch in s for ch in ["^", "~", ">", "<", "*", "|", ",", " "]):
        return False
    if s.endswith(".tgz"):
        return False
    if s.startswith("v") and SEMVER_EXACT_RE.match(s[1:]):
        return True
    return bool(SEMVER_EXACT_RE.match(s))


def normalize_exact_version(spec: Optional[str]) -> Optional[str]:
    if not spec:
        return None
    s = spec.strip()
    if s.startswith("==") or s.startswith("==="):
        s = s.lstrip("=")
    if s.startswith("v") and SEMVER_EXACT_RE.match(s[1:]):
        s = s[1:]
    return s


def split_name_and_spec(req: str) -> Tuple[str, Optional[str]]:
    s = req.strip()
    if not s:
        return "", None
    parts = re.split(r"\s+", s, maxsplit=1)
    name = parts[0]
    name = name.split("[")[0]
    spec = parts[1].strip() if len(parts) > 1 else None
    return name, spec


# -------------------------
# Parsers
# -------------------------

def parse_package_json(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = json.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for dep_type in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        section = data.get(dep_type, {})
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            spec = normalize_version_spec(str(spec))
            version = normalize_exact_version(spec) if is_exact_version(spec) else None
            deps.append((name, ECOSYSTEMS["npm"], version, spec, dep_type))
    return deps


def parse_package_lock_json(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = json.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []

    if isinstance(data.get("packages"), dict):
        for key, info in data["packages"].items():
            if not isinstance(info, dict):
                continue
            if key == "":
                continue
            version = info.get("version")
            if not version:
                continue
            name = info.get("name")
            if not name:
                if "node_modules/" in key:
                    name = key.split("node_modules/")[-1]
                else:
                    name = os.path.basename(key)
            deps.append((name, ECOSYSTEMS["npm"], str(version), str(version), "lock"))
        return deps

    def walk(dep_dict: dict) -> None:
        for name, info in dep_dict.items():
            if not isinstance(info, dict):
                continue
            version = info.get("version")
            if version:
                deps.append((name, ECOSYSTEMS["npm"], str(version), str(version), "lock"))
            nested = info.get("dependencies")
            if isinstance(nested, dict):
                walk(nested)

    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])

    return deps


def parse_yarn_lock(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    current_names: List[str] = []
    current_version: Optional[str] = None

    def flush() -> None:
        nonlocal current_names, current_version
        if current_version and current_names:
            for n in current_names:
                deps.append((n, ECOSYSTEMS["npm"], current_version, current_version, "lock"))
        current_names = []
        current_version = None

    for line in content.splitlines():
        if not line.strip():
            flush()
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            flush()
            header = line.rstrip(":").strip()
            selectors = [s.strip() for s in header.split(",")]
            names: List[str] = []
            for sel in selectors:
                sel = sel.strip().strip("\"")
                if sel.startswith(("workspace:", "link:", "file:")):
                    continue
                if "@npm:" in sel:
                    name = sel.split("@npm:", 1)[0]
                else:
                    name = sel.rsplit("@", 1)[0]
                name = name.strip()
                if name:
                    names.append(name)
            current_names = list(dict.fromkeys(names))
            continue
        m = re.match(r"\s+version\s+\"([^\"]+)\"", line)
        if not m:
            m = re.match(r"\s+version\s+'([^']+)'", line)
        if m:
            current_version = m.group(1).strip()

    flush()
    return deps


def parse_pnpm_lock(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    in_packages = False
    for line in content.splitlines():
        if line.strip() == "packages:":
            in_packages = True
            continue
        if not in_packages:
            continue
        m = re.match(r"^\s{2,}/(.+?)/([^/]+):\s*$", line)
        if not m:
            continue
        name = m.group(1)
        version = m.group(2)
        if "_" in version:
            version = version.split("_", 1)[0]
        deps.append((name, ECOSYSTEMS["npm"], version, version, "lock"))
    return deps


def parse_requirements_txt(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--", "-e ", "git+", "http://", "https://")):
            continue
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.-]+)(\[[^\]]+\])?\s*(==|===|>=|<=|~=|!=|>|<)\s*([^\s]+)", line)
        if not m:
            continue
        name = m.group(1)
        op = m.group(3)
        ver = m.group(4)
        spec = f"{op}{ver}"
        version = normalize_exact_version(spec) if op in ("==", "===") else None
        deps.append((name, ECOSYSTEMS["pypi"], version, spec, "requirements"))
    return deps


def parse_pipfile_lock(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = json.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for section_name in ["default", "develop"]:
        section = data.get(section_name, {})
        if not isinstance(section, dict):
            continue
        for name, info in section.items():
            if not isinstance(info, dict):
                continue
            spec = info.get("version")
            spec = normalize_version_spec(spec)
            version = normalize_exact_version(spec) if is_exact_version(spec) else None
            deps.append((name, ECOSYSTEMS["pypi"], version, spec, section_name))
    return deps


def parse_poetry_lock(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = tomllib.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append((name, ECOSYSTEMS["pypi"], str(version), str(version), "lock"))
    return deps


def parse_pyproject_toml(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = tomllib.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []

    project = data.get("project", {})
    if isinstance(project, dict):
        for req in project.get("dependencies", []) or []:
            if not isinstance(req, str):
                continue
            name, spec = split_name_and_spec(req)
            spec = normalize_version_spec(spec)
            version = normalize_exact_version(spec) if is_exact_version(spec) else None
            if name:
                deps.append((name, ECOSYSTEMS["pypi"], version, spec, "project"))
        opt = project.get("optional-dependencies", {}) or {}
        if isinstance(opt, dict):
            for _, items in opt.items():
                if not isinstance(items, list):
                    continue
                for req in items:
                    if not isinstance(req, str):
                        continue
                    name, spec = split_name_and_spec(req)
                    spec = normalize_version_spec(spec)
                    version = normalize_exact_version(spec) if is_exact_version(spec) else None
                    if name:
                        deps.append((name, ECOSYSTEMS["pypi"], version, spec, "optional"))

    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
    if isinstance(poetry, dict):
        for dep_section in ["dependencies", "dev-dependencies", "group"]:
            section = poetry.get(dep_section)
            if dep_section == "group" and isinstance(section, dict):
                # Poetry 1.2+ groups
                for _, group_data in section.items():
                    deps_dict = group_data.get("dependencies", {}) if isinstance(group_data, dict) else {}
                    if isinstance(deps_dict, dict):
                        for name, spec in deps_dict.items():
                            if name == "python":
                                continue
                            spec = normalize_version_spec(spec.get("version") if isinstance(spec, dict) else spec)
                            version = normalize_exact_version(spec) if is_exact_version(spec) else None
                            deps.append((name, ECOSYSTEMS["pypi"], version, spec, "poetry-group"))
                continue
            if not isinstance(section, dict):
                continue
            for name, spec in section.items():
                if name == "python":
                    continue
                spec = normalize_version_spec(spec.get("version") if isinstance(spec, dict) else spec)
                version = normalize_exact_version(spec) if is_exact_version(spec) else None
                deps.append((name, ECOSYSTEMS["pypi"], version, spec, dep_section))

    return deps


def parse_go_mod(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    in_require = False
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line.startswith(")"):
            in_require = False
            continue
        if in_require:
            if not line or line.startswith("//"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                deps.append((name, ECOSYSTEMS["go"], version, version, "go.mod"))
            continue
        if line.startswith("require "):
            line = line[len("require ") :]
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                deps.append((name, ECOSYSTEMS["go"], version, version, "go.mod"))
    return deps


def parse_go_sum(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        version = parts[1]
        if version.endswith("/go.mod"):
            version = version.replace("/go.mod", "")
        deps.append((name, ECOSYSTEMS["go"], version, version, "go.sum"))
    return deps


def parse_pom_xml(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return deps

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1]

    props: Dict[str, str] = {}
    project_version = None
    for child in root:
        if strip_ns(child.tag) == "version":
            project_version = child.text
        if strip_ns(child.tag) == "properties":
            for prop in child:
                props[strip_ns(prop.tag)] = (prop.text or "").strip()

    def resolve_version(ver: Optional[str]) -> Optional[str]:
        if not ver:
            return None
        ver = ver.strip()
        if ver.startswith("${") and ver.endswith("}"):
            key = ver[2:-1]
            if key == "project.version" and project_version:
                return project_version
            return props.get(key)
        return ver

    for dep in root.iter():
        if strip_ns(dep.tag) != "dependency":
            continue
        group_id = artifact_id = version = scope = None
        for child in dep:
            tag = strip_ns(child.tag)
            if tag == "groupId":
                group_id = (child.text or "").strip()
            elif tag == "artifactId":
                artifact_id = (child.text or "").strip()
            elif tag == "version":
                version = (child.text or "").strip()
            elif tag == "scope":
                scope = (child.text or "").strip()
        if not group_id or not artifact_id:
            continue
        version = resolve_version(version)
        version = normalize_version_spec(version)
        version_exact = normalize_exact_version(version) if is_exact_version(version) else None
        name = f"{group_id}:{artifact_id}"
        dep_type = scope or "maven"
        deps.append((name, ECOSYSTEMS["maven"], version_exact, version, dep_type))
    return deps


def parse_build_gradle(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    # String notation: group:artifact:version
    for m in re.finditer(r"['\"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([^'\"]+)['\"]", content):
        group_id, artifact_id, version = m.groups()
        name = f"{group_id}:{artifact_id}"
        spec = version.strip()
        version_exact = normalize_exact_version(spec) if is_exact_version(spec) else None
        deps.append((name, ECOSYSTEMS["maven"], version_exact, spec, "gradle"))

    # Map notation: group: 'g', name: 'a', version: 'v'
    for m in re.finditer(r"group:\s*['\"]([^'\"]+)['\"].*?name:\s*['\"]([^'\"]+)['\"].*?version:\s*['\"]([^'\"]+)['\"]", content, re.DOTALL):
        group_id, artifact_id, version = m.groups()
        name = f"{group_id}:{artifact_id}"
        spec = version.strip()
        version_exact = normalize_exact_version(spec) if is_exact_version(spec) else None
        deps.append((name, ECOSYSTEMS["maven"], version_exact, spec, "gradle"))
    return deps


def parse_gemfile_lock(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    in_specs = False
    for line in content.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and re.match(r"^[A-Z]+", line.strip()):
            # next section
            in_specs = False
            continue
        if in_specs:
            m = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)", line)
            if m:
                name, version = m.groups()
                deps.append((name, ECOSYSTEMS["rubygems"], version, version, "lock"))
    return deps


def parse_gemfile(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for line in content.splitlines():
        m = re.match(r"\s*gem\s+['\"]([^'\"]+)['\"]\s*(,\s*['\"]([^'\"]+)['\"])?", line)
        if not m:
            continue
        name = m.group(1)
        spec = normalize_version_spec(m.group(3))
        version_exact = normalize_exact_version(spec) if is_exact_version(spec) else None
        deps.append((name, ECOSYSTEMS["rubygems"], version_exact, spec, "gemfile"))
    return deps


def parse_composer_lock(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = json.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for section_name in ["packages", "packages-dev"]:
        for pkg in data.get(section_name, []) or []:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                deps.append((name, ECOSYSTEMS["packagist"], str(version).lstrip("v"), str(version), "lock"))
    return deps


def parse_composer_json(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = json.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for section_name in ["require", "require-dev"]:
        section = data.get(section_name, {})
        if not isinstance(section, dict):
            continue
        for name, spec in section.items():
            spec = normalize_version_spec(spec)
            version_exact = normalize_exact_version(spec) if is_exact_version(spec) else None
            deps.append((name, ECOSYSTEMS["packagist"], version_exact, spec, section_name))
    return deps


def parse_cargo_lock(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = tomllib.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    for pkg in data.get("package", []):
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            deps.append((name, ECOSYSTEMS["cargo"], str(version), str(version), "lock"))
    return deps


def parse_cargo_toml(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    data = tomllib.loads(content)
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []

    def parse_dep_dict(section: dict, dep_type: str) -> None:
        for name, spec in section.items():
            spec = normalize_version_spec(spec.get("version") if isinstance(spec, dict) else spec)
            version_exact = normalize_exact_version(spec) if is_exact_version(spec) else None
            deps.append((name, ECOSYSTEMS["cargo"], version_exact, spec, dep_type))

    for key in ["dependencies", "dev-dependencies", "build-dependencies"]:
        section = data.get(key)
        if isinstance(section, dict):
            parse_dep_dict(section, key)

    target = data.get("target")
    if isinstance(target, dict):
        for _, target_cfg in target.items():
            if not isinstance(target_cfg, dict):
                continue
            for key in ["dependencies", "dev-dependencies", "build-dependencies"]:
                section = target_cfg.get(key)
                if isinstance(section, dict):
                    parse_dep_dict(section, f"target-{key}")

    return deps


def parse_csproj(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return deps

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1]

    for elem in root.iter():
        if strip_ns(elem.tag) != "PackageReference":
            continue
        name = elem.attrib.get("Include") or elem.attrib.get("Update")
        version = elem.attrib.get("Version")
        if not version:
            for child in elem:
                if strip_ns(child.tag) == "Version":
                    version = (child.text or "").strip()
        if name and version:
            spec = normalize_version_spec(version)
            version_exact = normalize_exact_version(spec) if is_exact_version(spec) else None
            deps.append((name, ECOSYSTEMS["nuget"], version_exact, spec, "csproj"))
    return deps


def parse_packages_config(content: str) -> List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]]:
    deps: List[Tuple[str, str, Optional[str], Optional[str], Optional[str]]] = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return deps
    for pkg in root.iter():
        if pkg.tag != "package":
            continue
        name = pkg.attrib.get("id")
        version = pkg.attrib.get("version")
        if name and version:
            deps.append((name, ECOSYSTEMS["nuget"], version, version, "packages.config"))
    return deps


# -------------------------
# File detection
# -------------------------

def get_parser_for_path(path: str):
    base = os.path.basename(path).lower()
    if base == "package.json":
        return "package.json", parse_package_json
    if base == "package-lock.json":
        return "package-lock.json", parse_package_lock_json
    if base == "yarn.lock":
        return "yarn.lock", parse_yarn_lock
    if base == "pnpm-lock.yaml":
        return "pnpm-lock.yaml", parse_pnpm_lock
    if base.startswith("requirements") and base.endswith(".txt"):
        return "requirements.txt", parse_requirements_txt
    if base == "pipfile.lock":
        return "pipfile.lock", parse_pipfile_lock
    if base == "poetry.lock":
        return "poetry.lock", parse_poetry_lock
    if base == "pyproject.toml":
        return "pyproject.toml", parse_pyproject_toml
    if base == "go.mod":
        return "go.mod", parse_go_mod
    if base == "go.sum":
        return "go.sum", parse_go_sum
    if base == "pom.xml":
        return "pom.xml", parse_pom_xml
    if base in ("build.gradle", "build.gradle.kts"):
        return base, parse_build_gradle
    if base == "gemfile.lock":
        return "gemfile.lock", parse_gemfile_lock
    if base == "gemfile":
        return "gemfile", parse_gemfile
    if base == "composer.lock":
        return "composer.lock", parse_composer_lock
    if base == "composer.json":
        return "composer.json", parse_composer_json
    if base == "cargo.lock":
        return "cargo.lock", parse_cargo_lock
    if base == "cargo.toml":
        return "cargo.toml", parse_cargo_toml
    if base == "packages.config":
        return "packages.config", parse_packages_config
    if base.endswith(".csproj"):
        return "csproj", parse_csproj
    return None, None


# -------------------------
# OSV
# -------------------------

def chunked(items: List[dict], size: int) -> List[List[dict]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _parse_cvss_score(vector: str) -> Optional[float]:
    """Extract base score from a CVSS vector string, or parse as plain float."""
    if not vector:
        return None
    try:
        return float(vector)
    except (TypeError, ValueError):
        pass
    if not vector.upper().startswith("CVSS:"):
        return None
    # Only compute score for CVSS 3.x vectors; v4 uses different formula
    version_part = vector.split("/")[0]  # e.g. "CVSS:3.1"
    if not version_part.upper().startswith("CVSS:3"):
        return None
    metrics: Dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.rsplit(":", 1)
            metrics[k] = v
    av = metrics.get("AV", "N")
    ac = metrics.get("AC", "L")
    pr = metrics.get("PR", "N")
    ui = metrics.get("UI", "N")
    scope = metrics.get("S", "U")
    ci = metrics.get("C", "N")
    ii = metrics.get("I", "N")
    ai = metrics.get("A", "N")
    av_w = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(av, 0.85)
    ac_w = {"L": 0.77, "H": 0.44}.get(ac, 0.77)
    pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    pr_w = (pr_map_c if scope == "C" else pr_map_u).get(pr, 0.85)
    ui_w = {"N": 0.85, "R": 0.62}.get(ui, 0.85)
    impact_map = {"H": 0.56, "L": 0.22, "N": 0.0}
    c_i = impact_map.get(ci, 0.0)
    i_i = impact_map.get(ii, 0.0)
    a_i = impact_map.get(ai, 0.0)
    iss = 1.0 - ((1.0 - c_i) * (1.0 - i_i) * (1.0 - a_i))
    if iss <= 0:
        return 0.0
    exploitability = 8.22 * av_w * ac_w * pr_w * ui_w
    if scope == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    raw = exploitability + impact
    if scope == "C":
        raw = min(raw * 1.08, 10.0)
    else:
        raw = min(raw, 10.0)
    return round(raw * 10) / 10  # round to 1 decimal


def compute_severity(vuln: dict) -> str:
    best_score = None
    best_type = None
    for s in vuln.get("severity", []) or []:
        score = _parse_cvss_score(s.get("score"))
        if score is None:
            continue
        s_type = s.get("type")
        if best_score is None or score > best_score:
            best_score = score
            best_type = s_type
    # Fallback: database_specific.severity (e.g. GitHub advisories)
    if best_score is None:
        db_sev = (vuln.get("database_specific") or {}).get("severity", "")
        if isinstance(db_sev, str) and db_sev:
            upper = db_sev.upper()
            mapping = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                       "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM",
                       "LOW": "LOW"}
            if upper in mapping:
                return mapping[upper]
    if best_score is None:
        return "Unknown"
    label = "LOW"
    if best_score >= 9.0:
        label = "CRITICAL"
    elif best_score >= 7.0:
        label = "HIGH"
    elif best_score >= 4.0:
        label = "MEDIUM"
    return f"{label} (CVSS {best_score:.1f}{' ' + best_type if best_type else ''})"


def choose_cve(vuln: dict) -> str:
    for alias in vuln.get("aliases", []) or []:
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def _fetch_vuln_details(session: requests.Session, vuln_ids: List[str]) -> Dict[str, dict]:
    """Fetch full vulnerability details from OSV for a list of IDs."""
    details: Dict[str, dict] = {}
    for vuln_id in vuln_ids:
        try:
            resp = session.get(f"{OSV_API_BASE}/vulns/{vuln_id}", timeout=30)
            if resp.status_code < 400:
                details[vuln_id] = resp.json()
        except Exception:
            pass
    return details


def query_osv(deps: List[Dependency]) -> Dict[Tuple[str, str, str], List[dict]]:
    session = requests.Session()
    key_to_vulns: Dict[Tuple[str, str, str], List[dict]] = {}

    queries: List[dict] = []
    keys: List[Tuple[str, str, str]] = []
    seen = set()

    for dep in deps:
        if not dep.version:
            continue
        key = (dep.ecosystem, dep.name, dep.version)
        if key in seen:
            continue
        seen.add(key)
        queries.append({"package": {"name": dep.name, "ecosystem": dep.ecosystem}, "version": dep.version})
        keys.append(key)

    # Step 1: querybatch to find which vulns affect each dep
    all_vuln_ids: set = set()
    batch_results: List[Tuple[Tuple[str, str, str], List[dict]]] = []

    for chunk, key_chunk in zip(chunked(queries, 500), chunked(keys, 500)):
        payload = {"queries": chunk}
        resp = session.post(f"{OSV_API_BASE}/querybatch", json=payload, timeout=30)
        if resp.status_code >= 400:
            raise RuntimeError(f"OSV API error {resp.status_code}: {resp.text}")
        data = resp.json()
        results = data.get("results", [])
        for key, result in zip(key_chunk, results):
            vulns = result.get("vulns", []) or []
            if vulns:
                batch_results.append((key, vulns))
                for v in vulns:
                    vid = v.get("id")
                    if vid:
                        all_vuln_ids.add(vid)

    # Step 2: fetch full details for each unique vuln ID
    log(f"Fetching details for {len(all_vuln_ids)} vulnerabilities...")
    vuln_details = _fetch_vuln_details(session, list(all_vuln_ids))

    # Step 3: replace stub entries with full details
    for key, vulns in batch_results:
        full_vulns = []
        for v in vulns:
            vid = v.get("id")
            full = vuln_details.get(vid) if vid else None
            full_vulns.append(full if full else v)
        key_to_vulns[key] = full_vulns

    return key_to_vulns


# -------------------------
# Main
# -------------------------

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, payload: dict) -> None:
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)

def log(message: str) -> None:
    print(message, file=sys.stderr)


def iter_local_files(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in LOCAL_IGNORE_DIRS]
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(full_path, root)
            files.append(rel_path.replace(os.sep, "/"))
    return files


def collect_dependencies(
    project_id: int,
    project_name: str,
    project_path: str,
    file_paths: List[str],
    read_fn,
) -> Tuple[List[dict], List[Dependency]]:
    dep_files: List[dict] = []
    deps_for_project: List[Dependency] = []

    for file_path in file_paths:
        parser_name, parser_fn = get_parser_for_path(file_path)
        if not parser_fn:
            continue
        try:
            content = read_fn(file_path)
        except FileNotFoundError:
            continue
        except Exception as exc:  # noqa: BLE001
            log(f"  Failed to read {file_path}: {exc}")
            continue

        try:
            parsed = parser_fn(content)
        except Exception as exc:  # noqa: BLE001
            log(f"  Failed to parse {file_path}: {exc}")
            parsed = []

        dep_files.append({
            "path": file_path,
            "type": parser_name,
            "dependency_count": len(parsed),
        })

        for name, ecosystem, version, version_spec, dep_type in parsed:
            dep = Dependency(
                project_id=project_id,
                project_name=project_name,
                project_path=project_path,
                file_path=file_path,
                name=name,
                ecosystem=ecosystem,
                version=version,
                version_spec=version_spec,
                package_manager=parser_name,
                dep_type=dep_type,
            )
            deps_for_project.append(dep)

    return dep_files, deps_for_project


def scan_gitlab(
    client: GitLabClient,
    group: str,
    include_subgroups: bool,
    ignore_projects_raw: List[object],
) -> Tuple[str, List[dict], List[Dependency]]:
    log(f"Loading projects for group: {group}")
    projects = client.iter_group_projects(group, include_subgroups)
    log(f"Found {len(projects)} projects")

    ignore_ids = set()
    ignore_names = set()
    for item in ignore_projects_raw:
        if isinstance(item, int):
            ignore_ids.add(item)
            continue
        if isinstance(item, str):
            s = item.strip()
            if not s:
                continue
            ignore_names.add(s.lower())

    all_deps: List[Dependency] = []
    project_entries: List[dict] = []

    for proj in projects:
        project_id = proj.get("id")
        project_name = proj.get("name") or ""
        project_path = proj.get("path_with_namespace") or project_name
        default_branch = proj.get("default_branch") or "main"

        if not project_id:
            continue
        if project_id in ignore_ids:
            log(f"Skipping {project_path} (ignored by id)")
            continue
        if project_path.lower() in ignore_names or project_name.lower() in ignore_names:
            log(f"Skipping {project_path} (ignored by name/path)")
            continue

        log(f"Scanning {project_path} ({default_branch})")
        try:
            files = client.iter_repo_files(project_id, default_branch)
        except Exception as exc:  # noqa: BLE001
            log(f"  Failed to list files: {exc}")
            continue

        file_paths = [f.get("path") for f in files if f.get("type") == "blob" and f.get("path")]

        def read_fn(path: str) -> str:
            return client.get_file_raw(project_id, path, default_branch)

        dep_files, deps_for_project = collect_dependencies(
            project_id,
            project_name,
            project_path,
            file_paths,
            read_fn,
        )

        all_deps.extend(deps_for_project)

        project_entries.append({
            "id": project_id,
            "name": project_name,
            "path_with_namespace": project_path,
            "default_branch": default_branch,
            "dependency_files": dep_files,
            "dependencies": [asdict(d) for d in deps_for_project],
        })

    return group, project_entries, all_deps


def scan_local(root_path: str) -> Tuple[str, List[dict], List[Dependency]]:
    root = os.path.abspath(root_path)
    if not os.path.isdir(root):
        raise RuntimeError(f"Local path not found or not a directory: {root}")

    project_name = os.path.basename(root.rstrip(os.sep)) or root
    project_path = root
    log(f"Scanning local path: {root}")

    file_paths = iter_local_files(root)

    def read_fn(rel_path: str) -> str:
        full_path = os.path.join(root, rel_path)
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()

    dep_files, deps_for_project = collect_dependencies(
        0,
        project_name,
        project_path,
        file_paths,
        read_fn,
    )

    project_entries = [{
        "id": 0,
        "name": project_name,
        "path_with_namespace": project_path,
        "default_branch": None,
        "dependency_files": dep_files,
        "dependencies": [asdict(d) for d in deps_for_project],
    }]

    return "local", project_entries, deps_for_project


def main() -> int:
    parser = argparse.ArgumentParser(description="GitLab group or local SCA checker using OSV")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--local", action="store_true", help="Scan local path without GitLab")
    parser.add_argument("--path", default=".", help="Local path to scan (used with --local)")
    args = parser.parse_args()

    config: dict = {}
    if os.path.exists(args.config):
        config = load_config(args.config)
    elif not args.local:
        print(f"Config file not found: {args.config}", file=sys.stderr)
        return 1
    else:
        log(f"Config file not found: {args.config}. Using defaults for local scan.")

    scan_cfg = config.get("scan", {})
    out_cfg = config.get("output", {})

    inventory_path = out_cfg.get("inventory_path", "output/dependency_inventory.json")
    vuln_report_path = out_cfg.get("vulnerability_report_path", "output/vulnerability_report.json")

    if args.local:
        try:
            group, project_entries, all_deps = scan_local(args.path)
        except Exception as exc:  # noqa: BLE001
            log(str(exc))
            return 1
    else:
        gitlab_cfg = config.get("gitlab", {})
        base_url = gitlab_cfg.get("base_url")
        token = gitlab_cfg.get("token")
        group = gitlab_cfg.get("group")
        include_subgroups = bool(scan_cfg.get("include_subgroups", True))
        per_page = int(scan_cfg.get("per_page", 100))
        ignore_projects_raw = scan_cfg.get("ignore_projects", []) or []

        if not base_url or not token or not group:
            print("Config missing required fields: gitlab.base_url, gitlab.token, gitlab.group", file=sys.stderr)
            return 1

        client = GitLabClient(base_url, token, per_page=per_page)
        group, project_entries, all_deps = scan_gitlab(
            client,
            group,
            include_subgroups,
            ignore_projects_raw,
        )

    inventory = {
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "group": group,
        "project_count": len(project_entries),
        "dependency_count": len(all_deps),
        "projects": project_entries,
    }
    save_json(inventory_path, inventory)
    log(f"Inventory saved to {inventory_path}")

    if not all_deps:
        log("No dependencies found.")
        return 0

    log("Querying OSV...")
    key_to_vulns = query_osv(all_deps)

    issues = []
    for dep in all_deps:
        if not dep.version:
            continue
        key = (dep.ecosystem, dep.name, dep.version)
        vulns = key_to_vulns.get(key, [])
        for vuln in vulns:
            osv_id = vuln.get("id") or "UNKNOWN"
            issue = {
                "project": dep.project_path,
                "dependency": dep.name,
                "ecosystem": dep.ecosystem,
                "version": dep.version,
                "source_file": dep.file_path,
                "vuln_id": osv_id,
                "osv_id": osv_id,
                "osv_link": f"https://osv.dev/vulnerability/{osv_id}",
                "severity": compute_severity(vuln),
                "summary": (vuln.get("summary") or "").strip(),
                "details": (vuln.get("details") or "").strip(),
            }
            issues.append(issue)

    report = {
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "issue_count": len(issues),
        "issues": issues,
    }
    save_json(vuln_report_path, report)

    if not issues:
        log("No vulnerabilities found.")
        return 0

    grouped: Dict[Tuple[str, str], dict] = {}
    for issue in issues:
        key = (issue["dependency"], issue["version"])
        entry = grouped.get(key)
        if not entry:
            entry = {
                "dependency": issue["dependency"],
                "version": issue["version"],
                "source_files": set(),
                "vuln_ids": set(),
                "osv_links": set(),
            }
            grouped[key] = entry
        entry["source_files"].add(issue["source_file"])
        entry["vuln_ids"].add(issue["vuln_id"])
        entry["osv_links"].add(issue["osv_link"])

    log(f"Found {len(grouped)} vulnerable dependencies.")
    for key in sorted(grouped.keys()):
        entry = grouped[key]
        output = {
            "dependency": entry["dependency"],
            "version": entry["version"],
            "source_files": sorted(entry["source_files"]),
            "vuln_ids": sorted(entry["vuln_ids"]),
            "osv_links": sorted(entry["osv_links"]),
            "vuln_count": len(entry["vuln_ids"]),
        }
        print(json.dumps(output, sort_keys=False))

    return 0


if __name__ == "__main__":
    sys.exit(main())
