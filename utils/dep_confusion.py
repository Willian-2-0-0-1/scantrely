#!/usr/bin/env python3
"""
Dependency Confusion Checker
Based on: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

Workflow:
  1. Derive GitHub org names from target domains
  2. Search GitHub for package manifests (package.json, requirements.txt, etc.)
  3. Extract all dependency names
  4. Check each name against public registries (npm, PyPI, RubyGems)
  5. Flag packages NOT found publicly (squattable) or with suspicious metadata

Usage:
  python3 dep_confusion.py hackersec.com
  python3 dep_confusion.py hackersec.com --github-token ghp_xxx
  python3 dep_confusion.py hackersec.com portoseguro.com.br --org hackersec
  python3 dep_confusion.py hackersec.com --json
"""

import argparse
import base64
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ─── Well-known public packages to skip (reduce false-positive noise) ─────────

_SKIP_NPM = {
    "react", "react-dom", "vue", "@vue/core", "angular", "lodash", "lodash-es",
    "express", "axios", "webpack", "webpack-cli", "babel-core", "@babel/core",
    "@babel/preset-env", "typescript", "eslint", "prettier", "jest", "mocha",
    "chai", "moment", "dayjs", "date-fns", "jquery", "bootstrap", "tailwindcss",
    "postcss", "autoprefixer", "sass", "node-sass", "rollup", "vite", "parcel",
    "next", "nuxt", "gatsby", "svelte", "solid-js", "preact", "lit",
    "rxjs", "mobx", "redux", "@reduxjs/toolkit", "zustand", "pinia",
    "react-router", "react-router-dom", "vue-router", "react-query",
    "@tanstack/react-query", "swr", "socket.io", "socket.io-client",
    "nodemon", "ts-node", "dotenv", "cross-env", "concurrently",
    "cors", "helmet", "morgan", "body-parser", "cookie-parser",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "passport-local",
    "mongoose", "sequelize", "typeorm", "prisma", "@prisma/client",
    "mysql2", "pg", "sqlite3", "redis", "ioredis",
    "aws-sdk", "@aws-sdk/client-s3", "firebase", "@firebase/app",
    "uuid", "nanoid", "short-uuid", "crypto-js", "forge",
    "sharp", "multer", "formidable", "busboy",
    "chalk", "colors", "ora", "inquirer", "commander", "yargs",
    "jest-environment-jsdom", "testing-library", "@testing-library/react",
    "vitest", "cypress", "playwright", "puppeteer",
    "storybook", "@storybook/react",
    "html-webpack-plugin", "css-loader", "style-loader", "file-loader",
    "source-map-loader", "ts-loader", "babel-loader",
}

_SKIP_PYPI = {
    "requests", "flask", "django", "fastapi", "uvicorn", "gunicorn",
    "numpy", "pandas", "scipy", "matplotlib", "seaborn", "plotly",
    "scikit-learn", "sklearn", "tensorflow", "torch", "keras",
    "boto3", "botocore", "google-cloud", "azure", "azure-storage-blob",
    "sqlalchemy", "alembic", "psycopg2", "psycopg2-binary", "pymysql",
    "pymongo", "redis", "celery", "kombu", "pika",
    "pytest", "unittest", "mock", "coverage", "black", "flake8", "mypy",
    "pydantic", "marshmallow", "attrs", "dataclasses",
    "pillow", "opencv-python", "imageio",
    "cryptography", "pycryptodome", "paramiko", "fabric",
    "click", "typer", "argparse", "rich", "colorama", "tqdm",
    "aiohttp", "httpx", "urllib3", "certifi", "charset-normalizer",
    "setuptools", "wheel", "pip", "virtualenv", "poetry",
    "jinja2", "markupsafe", "werkzeug", "itsdangerous",
    "python-dotenv", "pyyaml", "toml", "tomli",
    "lxml", "beautifulsoup4", "scrapy", "selenium",
    "arrow", "pendulum", "python-dateutil", "pytz",
    "loguru", "structlog", "sentry-sdk",
}

_SKIP_RUBY = {
    "rails", "activerecord", "activesupport", "actionview", "actionpack",
    "bundler", "rake", "puma", "unicorn", "thin",
    "rspec", "minitest", "capybara", "factory_bot",
    "devise", "omniauth", "pundit", "cancancan",
    "sidekiq", "resque", "delayed_job",
    "nokogiri", "httparty", "faraday", "rest-client",
    "pg", "mysql2", "sqlite3", "redis",
    "jwt", "bcrypt", "dotenv",
    "rubocop", "brakeman", "reek",
}

# ─── HTTP helpers ──────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict | None = None, timeout: int = 10) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        from utils.circuit_breaker import CircuitOpen, guarded_urlopen
    except ImportError:
        CircuitOpen = ()  # type: ignore
        guarded_urlopen = None
    try:
        opener = guarded_urlopen or urllib.request.urlopen
        kwargs = {"timeout": timeout}
        with opener(req, **kwargs) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, b""
    except CircuitOpen:
        return 0, b""
    except Exception:
        return 0, b""


def _gh_get(path: str, token: str) -> tuple[int, dict | list | None]:
    url = f"https://api.github.com{path}"
    hdrs = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ASM-DepConfusion-Checker/1.0",
    }
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    status, body = _http_get(url, headers=hdrs, timeout=15)
    if status == 200 and body:
        try:
            return status, json.loads(body)
        except Exception:
            pass
    return status, None


# ─── Registry checks ──────────────────────────────────────────────────────────

def check_npm(pkg: str) -> dict:
    """Check if a package exists on npm registry."""
    encoded = urllib.request.quote(pkg, safe="@/")
    status, body = _http_get(
        f"https://registry.npmjs.org/{encoded}",
        headers={"User-Agent": "ASM-DepConfusion/1.0"},
        timeout=10,
    )
    if status != 200 or not body:
        return {"exists": False, "version": "", "author": "", "published": ""}
    try:
        data = json.loads(body)
        latest = data.get("dist-tags", {}).get("latest", "")
        ver_data = data.get("versions", {}).get(latest, {})
        author = ver_data.get("author", {})
        if isinstance(author, dict):
            author = author.get("name", "")
        times = data.get("time", {})
        published = times.get(latest, times.get("created", ""))
        return {
            "exists": True,
            "version": latest,
            "author": str(author),
            "published": published[:10] if published else "",
            "description": data.get("description", ""),
            "downloads": data.get("downloads", 0),
        }
    except Exception:
        return {"exists": True, "version": "?", "author": "", "published": ""}


def check_pypi(pkg: str) -> dict:
    """Check if a package exists on PyPI."""
    status, body = _http_get(
        f"https://pypi.org/pypi/{urllib.request.quote(pkg)}/json",
        headers={"User-Agent": "ASM-DepConfusion/1.0"},
        timeout=10,
    )
    if status != 200 or not body:
        return {"exists": False, "version": "", "author": "", "published": ""}
    try:
        data = json.loads(body)
        info = data.get("info", {})
        releases = data.get("releases", {})
        latest = info.get("version", "")
        published = ""
        if latest and releases.get(latest):
            upload_time = releases[latest][0].get("upload_time", "")
            published = upload_time[:10] if upload_time else ""
        return {
            "exists": True,
            "version": latest,
            "author": info.get("author", ""),
            "published": published,
            "description": info.get("summary", ""),
            "downloads": 0,
        }
    except Exception:
        return {"exists": True, "version": "?", "author": "", "published": ""}


def check_rubygems(pkg: str) -> dict:
    """Check if a gem exists on RubyGems."""
    status, body = _http_get(
        f"https://rubygems.org/api/v1/gems/{urllib.request.quote(pkg)}.json",
        headers={"User-Agent": "ASM-DepConfusion/1.0"},
        timeout=10,
    )
    if status != 200 or not body:
        return {"exists": False, "version": "", "author": "", "published": ""}
    try:
        data = json.loads(body)
        return {
            "exists": True,
            "version": data.get("version", ""),
            "author": data.get("authors", ""),
            "published": "",
            "description": data.get("info", ""),
            "downloads": data.get("downloads", 0),
        }
    except Exception:
        return {"exists": True, "version": "?", "author": "", "published": ""}


# ── GAP 8: New registries (NuGet, Packagist/Composer, Cargo, Hex.pm) ──

def check_nuget(pkg: str) -> dict:
    """Check if a package exists on NuGet (.NET)."""
    status, body = _http_get(
        f"https://api.nuget.org/v3/registration5-semver1/{urllib.request.quote(pkg.lower())}/index.json",
        headers={"User-Agent": "ASM-DepConfusion/1.0"},
        timeout=10,
    )
    if status != 200 or not body:
        return {"exists": False, "version": "", "author": "", "published": ""}
    try:
        data = json.loads(body)
        items = data.get("items", [])
        latest_version = ""
        description = ""
        if items and isinstance(items, list):
            last_item = items[-1]
            entries = last_item.get("items", [])
            if entries:
                catalog = entries[-1].get("catalogEntry", {})
                latest_version = catalog.get("version", "")
                description = catalog.get("description", "")
        return {"exists": True, "version": latest_version, "author": "",
                "published": "", "description": description, "downloads": 0}
    except Exception:
        return {"exists": True, "version": "?", "author": "", "published": ""}


def check_packagist(pkg: str) -> dict:
    """Check if a package exists on Packagist/Composer (PHP)."""
    status, body = _http_get(
        f"https://repo.packagist.org/p2/{urllib.request.quote(pkg.lower())}.json",
        headers={"User-Agent": "ASM-DepConfusion/1.0"},
        timeout=10,
    )
    if status != 200 or not body:
        return {"exists": False, "version": "", "author": "", "published": ""}
    try:
        data = json.loads(body)
        packages = data.get("packages", {})
        pkg_key = list(packages.keys())[0] if packages else pkg
        versions = packages.get(pkg_key, [])
        latest_version = versions[0].get("version", "") if versions else ""
        description = versions[0].get("description", "") if versions else ""
        published = versions[0].get("time", "") if versions else ""
        return {"exists": True, "version": latest_version, "author": "",
                "published": published[:10], "description": description, "downloads": 0}
    except Exception:
        return {"exists": True, "version": "?", "author": "", "published": ""}


def check_cargo(pkg: str) -> dict:
    """Check if a crate exists on crates.io (Rust/Cargo)."""
    status, body = _http_get(
        f"https://crates.io/api/v1/crates/{urllib.request.quote(pkg.lower())}",
        headers={"User-Agent": "ASM-DepConfusion/1.0"},
        timeout=10,
    )
    if status != 200 or not body:
        return {"exists": False, "version": "", "author": "", "published": ""}
    try:
        data = json.loads(body)
        crate = data.get("crate", {})
        return {"exists": True, "version": crate.get("max_stable_version", crate.get("newest_version", "")),
                "author": "", "published": crate.get("updated_at", "")[:10],
                "description": crate.get("description", ""), "downloads": crate.get("downloads", 0)}
    except Exception:
        return {"exists": True, "version": "?", "author": "", "published": ""}


def check_hex(pkg: str) -> dict:
    """Check if a package exists on Hex.pm (Elixir)."""
    status, body = _http_get(
        f"https://hex.pm/api/packages/{urllib.request.quote(pkg.lower())}",
        headers={"User-Agent": "ASM-DepConfusion/1.0"},
        timeout=10,
    )
    if status != 200 or not body:
        return {"exists": False, "version": "", "author": "", "published": ""}
    try:
        data = json.loads(body)
        return {"exists": True,
                "version": data.get("latest_stable_version", data.get("latest_version", "")),
                "author": data.get("meta", {}).get("maintainers", []),
                "published": data.get("updated_at", "")[:10],
                "description": data.get("meta", {}).get("description", ""),
                "downloads": data.get("downloads", {}).get("all", 0)}
    except Exception:
        return {"exists": True, "version": "?", "author": "", "published": ""}


# ── Well-known packages to skip per new registry ──

_SKIP_NUGET = {
    "newtonsoft.json", "system.text.json", "entityframework", "dapper",
    "automapper", "serilog", "nlog", "log4net", "moq", "nunit", "xunit",
    "fluentassertions", "swashbuckle", "mediatr", "fluentvalidation",
    "polly", "identitymodel", "microsoft.extensions.dependencyinjection",
    "microsoft.extensions.logging", "microsoft.extensions.configuration",
    "microsoft.aspnetcore", "microsoft.entityframeworkcore",
    "restsharp", "refit", "microsoft.azure", "azure.storage.blobs",
    "aws.sdk", "mongodb.driver", "npgsql", "mysql.data", "mysqlconnector",
    "dapper.contrib", "serilog.aspnetcore", "hangfire",
    "microsoft.applicationinsights", "microsoft.identity.client",
}

_SKIP_PACKAGIST = {
    "laravel/framework", "symfony/console", "symfony/http-foundation",
    "symfony/routing", "symfony/cache", "symfony/process",
    "doctrine/orm", "doctrine/dbal", "monolog/monolog", "phpunit/phpunit",
    "guzzlehttp/guzzle", "nesbot/carbon", "fakerphp/faker",
    "phpstan/phpstan", "friendsofphp/php-cs-fixer", "psy/psysh",
    "barryvdh/laravel-debugbar", "spatie/laravel-permission",
    "league/flysystem", "vlucas/phpdotenv", "ramsey/uuid",
    "swiftmailer/swiftmailer", "phpseclib/phpseclib",
    "sensiolabs/security-checker", "twig/twig", "laravel/tinker",
}

_SKIP_CARGO = {
    "serde", "tokio", "reqwest", "actix-web", "axum", "warp", "rocket",
    "clap", "structopt", "anyhow", "thiserror", "log", "env_logger",
    "chrono", "regex", "rand", "itertools", "rayon", "crossbeam",
    "hyper", "tonic", "prost", "diesel", "sqlx", "rusqlite", "redis",
    "lapin", "uuid", "base64", "sha2", "hmac", "jwt", "jsonwebtoken",
    "tera", "askama", "handlebars", "lettre", "reqwest-middleware",
    "tower", "tower-http", "tracing", "opentelemetry", "sentry",
}

_SKIP_HEX = {
    "phoenix", "ecto", "ecto_sql", "postgrex", "myxql", "jason",
    "plug", "cowboy", "bandit", "telemetry", "phoenix_live_view",
    "phoenix_live_dashboard", "phoenix_html", "phoenix_pubsub",
    "phoenix_ecto", "absinthe", "credo", "dialyxir", "ex_doc",
    "bypass", "mox", "wallaby", "hound", "floki", "httpoison",
    "tesla", "finch", "mint", "castore", "req", "oban", "broadway",
    "swoosh", "bamboo", "nimble_csv", "nimble_parsec", "nimble_pool",
    "nimble_options", "comeonin", "bcrypt_elixir", "argon2_elixir",
    "guardian", "ueberauth", "cors_plug", "corsica",
}


# ─── Risk assessment ──────────────────────────────────────────────────────────

def _parse_version(v: str) -> int:
    """Return major version number, or 0 if unparseable."""
    m = re.match(r"(\d+)", v or "0")
    return int(m.group(1)) if m else 0


def assess_risk(pkg: str, registry: str, info: dict, company_name: str) -> tuple[str, str]:
    """Return (risk_level, reason)."""
    if not info["exists"]:
        return "high", f"Package not found on {registry} — internal name can be squatted"

    version = info.get("version", "")
    major = _parse_version(version)
    description = (info.get("description") or "").lower()
    author = (info.get("author") or "").lower()
    published = info.get("published", "")

    # Squatting indicators: absurdly high version
    if major >= 9000:
        return "critical", f"Version {version} on {registry} is suspiciously high — possible active squatting"

    if major >= 100:
        return "high", f"Version {version} on {registry} unusually high — may indicate squatting attempt"

    # Check if description/author looks like attacker bait
    if any(kw in description for kw in ["bug bounty", "proof of concept", "dependency confusion",
                                         "internal package", "placeholder", "reserved"]):
        return "high", f"Public package on {registry} has suspicious description — possible squatting"

    # Very recently published with company name in it
    co_slug = re.sub(r"[^a-z0-9]", "", company_name.lower())
    pkg_clean = re.sub(r"[^a-z0-9]", "", pkg.lower())
    if co_slug and co_slug in pkg_clean:
        if published:
            try:
                pub_date = datetime.strptime(published, "%Y-%m-%d")
                days_old = (datetime.now() - pub_date).days
                if days_old < 30:
                    return "medium", (f"Package contains company name and was published {days_old}d ago "
                                      f"on {registry} — verify ownership")
            except Exception:
                pass
        return "low", f"Package with company name exists on {registry} — verify it is yours"

    return "info", f"Package exists on {registry} (v{version})"


# ─── Manifest parsers ─────────────────────────────────────────────────────────

def parse_package_json(content: str) -> list[tuple[str, str]]:
    """Extract (package_name, registry='npm') pairs from package.json."""
    try:
        data = json.loads(content)
    except Exception:
        return []
    pkgs = []
    for key in ("dependencies", "devDependencies", "peerDependencies",
                 "optionalDependencies", "bundledDependencies"):
        deps = data.get(key) or {}
        if isinstance(deps, dict):
            for name in deps:
                pkgs.append((name, "npm"))
        elif isinstance(deps, list):
            for name in deps:
                pkgs.append((str(name), "npm"))
    return pkgs


def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # strip version specifiers: pkg>=1.0, pkg==1.0, pkg[extras]
        name = re.split(r"[>=<!;\[\s]", line)[0].strip()
        if name and re.match(r"^[a-zA-Z0-9_.-]+$", name):
            pkgs.append((name, "pypi"))
    return pkgs


def parse_setup_py(content: str) -> list[tuple[str, str]]:
    pkgs = []
    for m in re.finditer(r"""install_requires\s*=\s*\[([^\]]+)\]""", content, re.DOTALL):
        for pkg in re.findall(r"""['"]([a-zA-Z0-9_.-]+)[>=<!;'"\s]""", m.group(1)):
            pkgs.append((pkg, "pypi"))
    return pkgs


def parse_pyproject_toml(content: str) -> list[tuple[str, str]]:
    pkgs = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("[tool.poetry.dependencies]", "[project]",
                        "[tool.poetry.dev-dependencies]", "[project.optional-dependencies]"):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
        if in_deps:
            m = re.match(r'^([a-zA-Z0-9_.-]+)\s*[=\^~<>!]', stripped)
            if m and m.group(1).lower() not in ("python", "python_requires"):
                pkgs.append((m.group(1), "pypi"))
    return pkgs


def parse_gemfile(content: str) -> list[tuple[str, str]]:
    pkgs = []
    for m in re.finditer(r"""gem\s+['"]([a-zA-Z0-9_.-]+)['"]""", content):
        pkgs.append((m.group(1), "rubygems"))
    return pkgs


def parse_pom_xml(content: str) -> list[tuple[str, str]]:
    """Extract groupId:artifactId pairs from pom.xml — reported as info only."""
    pkgs = []
    artifacts = re.findall(
        r"<artifactId>\s*([a-zA-Z0-9_.-]+)\s*</artifactId>", content
    )
    for a in artifacts:
        pkgs.append((a, "maven"))
    return pkgs


# ── GAP 8: New manifest parsers ──

def parse_packages_config(content: str) -> list[tuple[str, str]]:
    """Extract package IDs from packages.config (NuGet)."""
    pkgs = []
    for m in re.finditer(r'<package\s+id="([^"]+)"', content, re.I):
        pkgs.append((m.group(1), "nuget"))
    return pkgs


def parse_csproj(content: str) -> list[tuple[str, str]]:
    """Extract PackageReference from csproj/fsproj (NuGet)."""
    pkgs = []
    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"', content, re.I):
        pkgs.append((m.group(1), "nuget"))
    return pkgs


def parse_composer_json(content: str) -> list[tuple[str, str]]:
    """Extract dependencies from composer.json (Packagist/PHP)."""
    pkgs = []
    try:
        data = json.loads(content)
        for section in ("require", "require-dev", "suggest"):
            for pkg_name in data.get(section, {}):
                pkgs.append((pkg_name, "packagist"))
    except Exception:
        pass
    return pkgs


def parse_cargo_toml(content: str) -> list[tuple[str, str]]:
    """Extract dependencies from Cargo.toml (Rust/Cargo)."""
    pkgs = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[dependencies]" or line == "[build-dependencies]" or line == "[dev-dependencies]":
            in_deps = True
            continue
        if line.startswith("[") and line != "[dependencies]":
            in_deps = False
            continue
        if in_deps and "=" in line and not line.startswith("#"):
            name = line.split("=")[0].strip().strip('"')
            if name:
                pkgs.append((name, "cargo"))
    return pkgs


def parse_mix_exs(content: str) -> list[tuple[str, str]]:
    """Extract dependencies from mix.exs (Elixir/Hex)."""
    pkgs = []
    for m in re.finditer(r'\{:(\w[\w_-]*)\s*,', content):
        name = m.group(1)
        if name not in ("path", "git", "github", "in_umbrella", "only", "optional",
                         "runtime", "system_env", "env", "manager", "override",
                         "compile", "app", "mod", "elixir", "erlang", "true", "false"):
            pkgs.append((name, "hex"))
    return pkgs


MANIFEST_PARSERS = {
    "package.json":         parse_package_json,
    "requirements.txt":     parse_requirements_txt,
    "requirements-dev.txt": parse_requirements_txt,
    "requirements-test.txt": parse_requirements_txt,
    "setup.py":             parse_setup_py,
    "pyproject.toml":       parse_pyproject_toml,
    "Gemfile":              parse_gemfile,
    "pom.xml":              parse_pom_xml,
    "packages.config":      parse_packages_config,
    "composer.json":        parse_composer_json,
    "Cargo.toml":           parse_cargo_toml,
    "mix.exs":              parse_mix_exs,
}

REGISTRY_SKIP = {
    "npm": _SKIP_NPM,
    "pypi": _SKIP_PYPI,
    "rubygems": _SKIP_RUBY,
    "maven": set(),
    "nuget": _SKIP_NUGET,
    "packagist": _SKIP_PACKAGIST,
    "cargo": _SKIP_CARGO,
    "hex": _SKIP_HEX,
}

REGISTRY_CHECKERS = {
    "npm":      check_npm,
    "pypi":     check_pypi,
    "rubygems": check_rubygems,
    "nuget":    check_nuget,
    "packagist": check_packagist,
    "cargo":    check_cargo,
    "hex":      check_hex,
}


# ─── GitHub helpers ───────────────────────────────────────────────────────────

def derive_org_names(domains: list[str]) -> list[str]:
    """Guess GitHub org names from domain names."""
    orgs = []
    seen = set()
    for domain in domains:
        # Strip TLD(s): hackersec.com → hackersec; porto-seguro.com.br → porto-seguro
        base = domain.lower()
        base = re.sub(r"\.(com|net|org|io|br|co|uk|de|fr|es|pt|mx|ar|cl|co)(\.br|\.uk|\.au)?$", "", base)
        base = re.sub(r"\.(com|net|org|io)$", "", base)
        parts = base.split(".")
        for p in parts:
            candidates = [p, p.replace("-", ""), p.replace("_", "-")]
            for c in candidates:
                if c and c not in seen and len(c) > 2:
                    orgs.append(c)
                    seen.add(c)
    return orgs


def verify_github_org(org: str, token: str) -> bool:
    status, _ = _gh_get(f"/orgs/{org}", token)
    if status == 200:
        return True
    # also check as user
    status2, _ = _gh_get(f"/users/{org}", token)
    return status2 == 200


def search_manifests_in_org(org: str, filename: str, token: str) -> list[dict]:
    """Search GitHub code for a specific manifest filename in an org."""
    # GitHub search API: q=filename:package.json+org:hackersec
    q = urllib.request.quote(f"filename:{filename} org:{org}")
    status, data = _gh_get(f"/search/code?q={q}&per_page=30", token)
    if status != 200 or not data:
        return []
    return data.get("items", [])


def fetch_file_content(owner: str, repo: str, path: str, token: str) -> str:
    """Fetch raw file content from GitHub."""
    status, data = _gh_get(f"/repos/{owner}/{repo}/contents/{path}", token)
    if status != 200 or not data or not isinstance(data, dict):
        return ""
    encoding = data.get("encoding", "")
    content = data.get("content", "")
    if encoding == "base64":
        try:
            return base64.b64decode(content.replace("\n", "")).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return content


# ─── Main checker ─────────────────────────────────────────────────────────────

class DepConfusionChecker:
    def __init__(self, github_token: str = "", verbose: bool = False):
        self.token = github_token
        self.verbose = verbose
        self._registry_cache: dict[str, dict] = {}

    def _log(self, msg: str):
        if self.verbose:
            print(msg, file=sys.stderr, flush=True)

    def _check_registry_cached(self, pkg: str, registry: str) -> dict:
        key = f"{registry}:{pkg.lower()}"
        if key not in self._registry_cache:
            checker = REGISTRY_CHECKERS.get(registry)
            if checker:
                self._registry_cache[key] = checker(pkg)
                time.sleep(0.15)  # gentle rate limit
            else:
                self._registry_cache[key] = {"exists": None, "version": "", "author": "", "published": ""}
        return self._registry_cache[key]

    def run(self, company_name: str, domains: list[str],
            extra_orgs: list[str] | None = None) -> dict:
        started = time.time()
        results = {
            "company": company_name,
            "domains": domains,
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "orgs_checked": [],
            "repos_scanned": 0,
            "manifests_found": 0,
            "packages_checked": 0,
            "findings": [],
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "errors": [],
        }

        # 1. Derive org candidates
        org_candidates = derive_org_names(domains)
        if extra_orgs:
            org_candidates = list(dict.fromkeys(extra_orgs + org_candidates))

        confirmed_orgs = []
        for org in org_candidates:
            self._log(f"[~] Checking GitHub org: {org}")
            if verify_github_org(org, self.token):
                confirmed_orgs.append(org)
                self._log(f"[+] Found org: {org}")
            time.sleep(0.2)

        results["orgs_checked"] = confirmed_orgs

        if not confirmed_orgs:
            results["errors"].append(
                "No GitHub org found for the given domains. "
                "Try --org <org-name> to specify manually."
            )
            # Still try with unconfirmed orgs if no token (avoid rate-limit false negatives)
            if not self.token and org_candidates:
                confirmed_orgs = org_candidates[:2]
                self._log(f"[!] No token — trying unverified orgs: {confirmed_orgs}")

        # 2. Search manifests across all orgs
        seen_pkgs: dict[tuple, str] = {}  # (name, registry) → source

        for org in confirmed_orgs:
            for filename in MANIFEST_PARSERS:
                self._log(f"[~] Searching {org} for {filename}")
                items = search_manifests_in_org(org, filename, self.token)
                time.sleep(0.5)

                for item in items:
                    repo = item.get("repository", {}).get("full_name", "")
                    path = item.get("path", "")
                    self._log(f"    → {repo}/{path}")

                    content = fetch_file_content(
                        item.get("repository", {}).get("owner", {}).get("login", ""),
                        item.get("repository", {}).get("name", ""),
                        path, self.token
                    )
                    time.sleep(0.3)

                    if not content:
                        continue

                    results["repos_scanned"] += 1
                    results["manifests_found"] += 1

                    parser = MANIFEST_PARSERS[filename]
                    deps = parser(content)
                    source_ref = f"{repo}/{path}"

                    for pkg_name, registry in deps:
                        key = (pkg_name.lower(), registry)
                        if key not in seen_pkgs:
                            seen_pkgs[key] = source_ref

        # 3. Check each unique package against its registry
        self._log(f"\n[*] Checking {len(seen_pkgs)} unique packages across registries...")

        for (pkg_name, registry), source_ref in sorted(seen_pkgs.items()):
            # Skip well-known packages
            skip_set = REGISTRY_SKIP.get(registry, set())
            if pkg_name.lower() in skip_set:
                continue
            # Skip scoped npm packages from well-known orgs
            if registry == "npm" and pkg_name.startswith("@"):
                scope = pkg_name.split("/")[0][1:]  # e.g. "@babel/core" → "babel"
                if scope in {"babel", "types", "angular", "vue", "storybook",
                              "testing-library", "jest", "aws-sdk", "google-cloud",
                              "firebase", "mui", "chakra-ui", "radix-ui", "tailwindcss",
                              "rollup", "vitejs", "swc", "nestjs", "prisma"}:
                    continue

            # maven — just report as info, no public registry check
            if registry == "maven":
                results["findings"].append({
                    "package": pkg_name,
                    "registry": "maven",
                    "risk": "info",
                    "reason": "Maven dependency — manual check recommended for internal artifacts",
                    "source": source_ref,
                    "registry_info": {},
                })
                results["summary"]["info"] += 1
                results["packages_checked"] += 1
                continue

            self._log(f"  checking {registry}:{pkg_name}")
            info = self._check_registry_cached(pkg_name, registry)
            risk, reason = assess_risk(pkg_name, registry, info, company_name)
            results["packages_checked"] += 1

            # Only report packages that are not clearly public and low-risk
            if risk in ("critical", "high", "medium") or not info.get("exists"):
                results["findings"].append({
                    "package": pkg_name,
                    "registry": registry,
                    "risk": risk,
                    "reason": reason,
                    "source": source_ref,
                    "registry_info": {
                        "exists": info.get("exists"),
                        "version": info.get("version", ""),
                        "author": info.get("author", ""),
                        "published": info.get("published", ""),
                        "description": (info.get("description") or "")[:120],
                    },
                })
                results["summary"][risk] = results["summary"].get(risk, 0) + 1

        results["duration_s"] = round(time.time() - started, 1)
        # Sort findings: critical → high → medium → low → info
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results["findings"].sort(key=lambda f: order.get(f["risk"], 5))
        return results


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Dependency Confusion Checker — find squattable internal package names"
    )
    ap.add_argument("domains", nargs="+", help="Target domain(s), e.g. hackersec.com portoseguro.com.br")
    ap.add_argument("--company", "-c", default="", help="Company name (for risk assessment)")
    ap.add_argument("--org", "-o", action="append", default=[], dest="orgs",
                    help="Explicit GitHub org(s) to search (can repeat)")
    ap.add_argument("--github-token", "-t", default="",
                    help="GitHub token for higher rate limits (or set GITHUB_TOKEN env var)")
    ap.add_argument("--json", action="store_true", help="Output raw JSON")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    import os
    token = args.github_token or os.environ.get("GITHUB_TOKEN", "")

    # Try to load from settings.json in same directory
    settings_path = Path(__file__).parent / "settings.json"
    if not token and settings_path.exists():
        try:
            cfg = json.loads(settings_path.read_text())
            token = cfg.get("github_token", "")
        except Exception:
            pass

    company_name = args.company or args.domains[0].split(".")[0].title()

    checker = DepConfusionChecker(github_token=token, verbose=args.verbose)
    results = checker.run(company_name, args.domains, extra_orgs=args.orgs or None)

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    # ── Pretty output ──────────────────────────────────────────────────────────
    RISK_COLOR = {
        "critical": "\033[91m", "high": "\033[33m",
        "medium": "\033[36m",   "low": "\033[37m", "info": "\033[90m",
    }
    RESET = "\033[0m"

    print(f"\n{'─'*60}")
    print(f"  Dependency Confusion Check — {company_name}")
    print(f"  Domains : {', '.join(results['domains'])}")
    print(f"  GitHub orgs found : {', '.join(results['orgs_checked']) or 'none'}")
    print(f"  Manifests scanned : {results['manifests_found']}")
    print(f"  Packages checked  : {results['packages_checked']}")
    print(f"{'─'*60}")

    s = results["summary"]
    print(f"  Summary: "
          f"\033[91m{s.get('critical',0)} critical\033[0m  "
          f"\033[33m{s.get('high',0)} high\033[0m  "
          f"\033[36m{s.get('medium',0)} medium\033[0m  "
          f"\033[37m{s.get('low',0)} low\033[0m\n")

    if results["errors"]:
        for e in results["errors"]:
            print(f"  \033[33m[!]\033[0m {e}")
        print()

    if not results["findings"]:
        print("  \033[92m[✓]\033[0m No squattable packages found.")
    else:
        for f in results["findings"]:
            c = RISK_COLOR.get(f["risk"], "")
            exists = f["registry_info"].get("exists")
            exists_str = "NOT on registry" if exists is False else f"v{f['registry_info'].get('version','?')}"
            print(f"  {c}[{f['risk'].upper():8}]{RESET} {f['registry']}:{f['package']}")
            print(f"             {f['reason']}")
            print(f"             Source : {f['source']}")
            if exists is not False:
                print(f"             Public : {exists_str} by {f['registry_info'].get('author','?')}")
            print()

    print(f"  Scan took {results['duration_s']}s")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
