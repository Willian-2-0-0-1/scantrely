#!/usr/bin/env python3
"""ASM Tool Registry — unified interface for CLI tools + API-based recon modules."""

import json, subprocess as _subprocess_real, time, os, sys, shutil, re as _re, threading, platform, tempfile, urllib.request, zipfile
import logging as _logging
_log = _logging.getLogger('scantrely.tools')
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable
from utils.tool_gate import gate_for as _gate_for

import re
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


class _GatedSubprocess:
    """Transparent stand-in for subprocess in the tool registry.

    Most production tool execution goes through utils.command_runner, which is
    already gated. A few install/version/probe paths in this file still call
    subprocess.run/check_output directly; route those through ToolGate too so
    every external process is covered by the global cap.
    """

    def __getattr__(self, name):
        return getattr(_subprocess_real, name)

    @staticmethod
    def _tool(cmd) -> str:
        try:
            first = cmd[0] if isinstance(cmd, (list, tuple)) and cmd else str(cmd).split()[0]
            return os.path.basename(str(first)) or "tool"
        except Exception:
            return "tool"

    def run(self, cmd, **kw):
        if "timeout" not in kw:
            kw["timeout"] = 300
        with _gate_for(self._tool(cmd)).slot():
            return _subprocess_real.run(cmd, **kw)

    def check_output(self, cmd, **kw):
        with _gate_for(self._tool(cmd)).slot():
            return _subprocess_real.check_output(cmd, **kw)


subprocess = _GatedSubprocess()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENUMS AND DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class ToolCategory(str, Enum):
    SUBDOMAIN = "subdomain"
    PORT_SCAN = "port_scan"
    HTTP      = "http"
    DNS       = "dns"
    VULN      = "vuln"
    OSINT     = "osint"
    SECRETS   = "secrets"
    API_INTEL = "api_intel"
    CLOUD     = "cloud"
    UTIL      = "util"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class Finding:
    type:     str
    value:    str
    host:     str = ""
    ip:       str = ""
    port:     int = 0
    severity: str = Severity.INFO
    source:   str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class ToolResult:
    tool:     str
    target:   str
    status:   str = "done"
    reason:   str = ""
    findings: list = field(default_factory=list)
    error:    str | None = None
    duration: float = 0.0
    raw_stdout: str = ""
    raw_stderr: str = ""
    metrics:  dict = field(default_factory=dict)
    artifacts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "tool": self.tool, "target": self.target,
            "status": self.status,
            "reason": self.reason,
            "findings": [{"type": f.type, "value": f.value, "host": f.host,
                          "ip": f.ip, "port": f.port, "severity": f.severity,
                          "source": f.source, "metadata": f.metadata}
                          for f in self.findings],
            "error": self.error, "duration": self.duration,
            "metrics": self.metrics or {},
            "artifacts": self.artifacts or {},
        }
        if hasattr(self, "data") and isinstance(self.data, dict):
            d.update(self.data)
        return d


# ═══════════════════════════════════════════════════════════════════════════════
#  BASE TOOL CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class BaseTool:
    name:         str = ""
    category:     ToolCategory = ToolCategory.UTIL
    description:  str = ""
    install_cmd:  str = ""
    requires_key: str | None = None
    timeout:      int = 120

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "1.0"

    def _get_key(self, key_name: str, opts: dict | None) -> str | None:
        if opts is None:
            opts = {}
        return opts.get("settings", {}).get(key_name) or opts.get(key_name) or ""

    def _http_open(self, url: str, *, headers: dict | None = None, timeout: int = 15,
                   name: str | None = None):
        """GET via ``guarded_urlopen`` (per-host circuit breaker + timeout)."""
        from urllib.request import Request
        from utils.circuit_breaker import guarded_urlopen
        req = Request(url, headers=headers or {"User-Agent": "ASM-Platform/1.0"})
        return guarded_urlopen(req, timeout=timeout, name=name)

    def _resolve_binary(self, name: str) -> str | None:
        """Resolve a tool binary from project bin/, PATH, or common Go/Python install locations."""
        gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
        gobin = os.environ.get("GOBIN")
        project_bin = Path(__file__).resolve().parent.parent / "bin"
        candidates = [project_bin / name]
        if gobin:
            candidates.append(Path(gobin) / name)
        candidates.append(Path(gopath) / "bin" / name)
        candidates.append(Path.home() / ".local" / "bin" / name)
        candidates.append(Path("/mnt/compartilhada/go/bin") / name)

        for candidate in candidates:
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)
        return shutil.which(name)

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        raise NotImplementedError


class CommandTool(BaseTool):
    """CLI tool wrapper."""
    def command(self, target: str, opts: dict) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        raise NotImplementedError

    def available(self) -> bool:
        return self._resolve_binary(self.name) is not None

    def version(self) -> str:
        try:
            binary = self._resolve_binary(self.name) or self.name
            out = subprocess.check_output([binary, "--version"], stderr=subprocess.STDOUT, timeout=5)
            return out.decode().strip().split("\n")[0][:60]
        except Exception:
            return "unknown"

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        from utils import rate_limiter as _rl
        from utils.command_runner import CommandContext, run as run_command
        _rl.wait()
        opts = opts or {}
        result = ToolResult(tool=self.name, target=target)
        t0 = time.time()
        try:
            cmd = self.command(target, opts)
            if cmd:
                resolved = self._resolve_binary(cmd[0])
                if resolved:
                    cmd = [resolved, *cmd[1:]]
            proc = run_command(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                context=CommandContext(
                    company_id=opts.get("company_id", ""),
                    module=opts.get("module", self.name),
                    db=opts.get("db"),
                ),
            )
            result.raw_stdout = proc.stdout
            result.raw_stderr = proc.stderr
            # Some tools (theHarvester, asnmap) exit 1 even with valid output.
            # Only treat as error if returncode != 0 AND no stdout.
            if proc.returncode != 0:
                if proc.stdout.strip():
                    # Got output — parse it normally despite non-zero exit
                    result.findings = self.parse(proc.stdout, proc.stderr, target)
                    result.status = "done"
                    result.reason = f"exit {proc.returncode} with output"
                else:
                    stderr = proc.stderr.strip()[:300]
                    reason = stderr or f"Exit code {proc.returncode}"
                    result.error = reason
                    result.reason = reason
                    if "timeout" in reason.lower():
                        result.status = "timeout"
                    elif "binary not found" in reason.lower():
                        result.status = "unsupported"
                    else:
                        result.status = "error"
            else:
                result.findings = self.parse(proc.stdout, proc.stderr, target)
                result.status = "done"
        except subprocess.TimeoutExpired:
            result.status = "timeout"
            result.reason = f"Timeout ({self.timeout}s)"
            result.error = result.reason
        except FileNotFoundError:
            result.status = "unsupported"
            result.reason = f"Binary not found: {self.name}"
            result.error = result.reason
        except Exception as e:
            err = str(e)[:300]
            result.error = err
            result.reason = err
            if "not found" in err.lower() or "not in registry" in err.lower():
                result.status = "unsupported"
            elif "timeout" in err.lower():
                result.status = "timeout"
            else:
                result.status = "error"
        result.duration = time.time() - t0
        result.metrics = {
            "findings": len(result.findings or []),
        }
        return result


class ApiTool(BaseTool):
    """API-based tool wrapper."""
    def run_api(self, target: str, opts: dict) -> list[Finding]:
        raise NotImplementedError

    def available(self) -> bool:
        key = self.requires_key
        if not key:
            return True
        return True

    def version(self) -> str:
        return "API v2"

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        opts = opts or {}
        result = ToolResult(tool=self.name, target=target)
        t0 = time.time()
        if self.requires_key:
            key = self._get_key(self.requires_key, opts)
            if not key:
                result.status = "skipped"
                result.reason = f"{self.requires_key} not configured"
                result.error = result.reason
                result.duration = 0.0
                result.metrics = {"findings": 0}
                return result
        from utils.circuit_breaker import CircuitOpen, breaker_for
        br = breaker_for(f"api:{self.name}")
        if not br.allow():
            result.status = "error"
            result.reason = f"circuit open ({self.name})"
            result.error = result.reason
            result.duration = 0.0
            result.metrics = {"findings": 0}
            return result
        for attempt in range(3):
            if attempt and not br.allow():
                result.status = "error"
                result.reason = f"circuit open ({self.name})"
                result.error = result.reason
                break
            try:
                result.findings = self.run_api(target, opts)
                result.status = "done"
                result.reason = ""
                br.success()
                break
            except CircuitOpen as e:
                result.status = "error"
                result.reason = str(e)
                result.error = result.reason
                break
            except Exception as e:
                err_str = str(e).lower()
                if "429" in err_str or "rate limit" in err_str or "too many" in err_str:
                    br.failure()
                    wait = 2 ** attempt + 1
                    time.sleep(wait)
                    continue
                if attempt < 2 and ("timeout" in err_str or "connection" in err_str or "temporary" in err_str):
                    br.failure()
                    time.sleep(2 ** attempt + 1)
                    continue
                br.failure()
                result.error = str(e)[:300]
                result.reason = result.error
                if "timeout" in err_str or "connection" in err_str or "temporary" in err_str:
                    result.status = "timeout"
                elif "not configured" in err_str or "missing key" in err_str:
                    result.status = "skipped"
                else:
                    result.status = "error"
                break
        result.duration = time.time() - t0
        result.metrics = {
            "findings": len(result.findings or []),
        }
        return result


# ═══════════════════════════════════════════════════════════════════════════════
#  TOOL REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, BaseTool] = {}
        self._by_category: dict[ToolCategory, list[BaseTool]] = {}

    def register(self, tool_cls: type):
        tool = tool_cls()
        self._tools[tool.name] = tool
        self._by_category.setdefault(tool.category, []).append(tool)
        return tool_cls

    def get(self, name: str) -> BaseTool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[BaseTool]:
        return list(self._tools.values())

    def status(self) -> list[dict]:
        results = []
        for name, t in sorted(self._tools.items()):
            try:
                avail = t.available()
            except Exception:
                avail = False
            results.append({
                "name": name, "category": t.category,
                "description": t.description,
                "available": avail,
                "version": t.version() if avail and isinstance(t, CommandTool) else ("key_set" if avail else "no_key"),
                "install_cmd": t.install_cmd,
                "requires_key": t.requires_key,
                "type": "api" if isinstance(t, ApiTool) else "cli",
            })
        return results

    def run(self, name: str, target: str, opts: dict | None = None) -> ToolResult:
        tool = self._tools.get(name)
        if not tool:
            r = ToolResult(tool=name, target=target)
            r.error = f"Unknown tool: {name}"
            return r
        return tool.run(target, opts)


registry = ToolRegistry()


# ═══════════════════════════════════════════════════════════════════════════════
#  WORDLIST LOADER
# ═══════════════════════════════════════════════════════════════════════════════

_WORDLIST_BASE = Path(__file__).parent / "wordlists"


def _wordlist(category: str, mode: str = "large") -> str | None:
    """Find the best wordlist for a category.
    
    Priority chain:
      1. wordlists/<category>/tiered/<mode>.txt (optimized for speed/quality)
      2. wordlists/<category>/tiered/full.txt (full merged + deduplicated)
      3. wordlists/<category>/ <largest .txt file> (raw source)
      
    Mode mapping:
      "small"  → small-10k.txt  or smallest file
      "medium" → medium-100k.txt or medium file  
      "large"  → full.txt       or largest file
    """
    base = _WORDLIST_BASE / category
    if not base.exists():
        return None
    
    # Tier 1: optimized tiered wordlists
    tiered = base / "tiered"
    if tiered.exists():
        mode_map = {"small": "small-10k.txt", "medium": "medium-100k.txt", "large": "full.txt"}
        fname = mode_map.get(mode, "full.txt")
        tiered_file = tiered / fname
        if tiered_file.exists() and tiered_file.stat().st_size > 100:
            return str(tiered_file)
        # Fallback: any tiered file
        candidates = sorted(tiered.glob("*.txt"), key=lambda p: p.stat().st_size, reverse=True)
        if candidates:
            return str(candidates[0])
    
    # Tier 2: raw wordlist files
    candidates = sorted(base.glob("*.txt"), key=lambda p: p.stat().st_size, reverse=True)
    if not candidates:
        return None
    
    if mode == "small":
        return str(candidates[-1])
    return str(candidates[0])


def load_wordlist(category: str, mode: str = "large", count: int = 50000) -> list[str]:
    path = _wordlist(category, mode)
    if not path:
        return []
    items = []
    try:
        with open(path, "rb") as f:
            while len(items) < count:
                chunk = f.read(65536)
                if not chunk:
                    break
                for line in chunk.split(b"\n"):
                    stripped = line.strip()
                    if stripped and not stripped.startswith(b"#"):
                        try:
                            items.append(stripped.decode("utf-8", errors="ignore"))
                        except Exception:
                            _log.debug('tools.py:454 erro ignorado', exc_info=True)
                    if len(items) >= count:
                        break
    except Exception:
        _log.debug('tools.py:458 erro ignorado', exc_info=True)
    return items


# ═══════════════════════════════════════════════════════════════════════════════
#  SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class SubfinderTool(CommandTool):
    name        = "subfinder"
    category    = ToolCategory.SUBDOMAIN
    description = "Fast passive subdomain enumeration"
    install_cmd = "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    timeout     = 240

    def command(self, target: str, opts: dict) -> list[str]:
        # Hard caps: subfinder defaults to -max-time 10 MINUTES per domain, which
        # makes bulk sweeps unusable when a single source stalls. Cap aggressively.
        cmd = ["subfinder", "-d", target, "-silent", "-timeout", "8", "-max-time", "2"]
        settings = opts.get("settings", {})
        providers = {}
        if settings:
            import yaml
            providers = {
                "binaryedge":    [settings.get("binaryedge_key")] if settings.get("binaryedge_key") else [],
                "censys":        [f"{settings.get('censys_api_id')}:{settings.get('censys_api_secret')}"] if settings.get("censys_api_id") and settings.get("censys_api_secret") else [],
                "chaos":         [settings.get("chaos_key")] if settings.get("chaos_key") else [],
                "fofa":          [f"{settings.get('fofa_email')}:{settings.get('fofa_key')}"] if settings.get("fofa_email") and settings.get("fofa_key") else [],
                "fullhunt":      [settings.get("fullhunt_key")] if settings.get("fullhunt_key") else [],
                "github":        [settings.get("github_token")] if settings.get("github_token") else [],
                "intelx":        [settings.get("intelx_key")] if settings.get("intelx_key") else [],
                "leakix":        [settings.get("leakix_key")] if settings.get("leakix_key") else [],
                "netlas":        [settings.get("netlas_key")] if settings.get("netlas_key") else [],
                "securitytrails":[settings.get("securitytrails_key")] if settings.get("securitytrails_key") else [],
                "shodan":        [settings.get("shodan_key")] if settings.get("shodan_key") else [],
                "virustotal":    [settings.get("virustotal_key")] if settings.get("virustotal_key") else [],
            }
            providers = {k: v for k, v in providers.items() if v}

        # -all: medido em 15/10/2026, todas as fontes levam ~10s por domínio e
        # incluem fontes sem chave que a lista fixa deixava de fora (thc, shodanct, hudsonrock…).
        # crtsh fica de fora: oscila de 1s a 2min e o módulo certs já consulta crt.sh/certspotter/Shodan CT
        cmd.extend(["-all", "-es", "crtsh"])
        if providers:
            cfg_path = f"/tmp/subfinder_cfg_{target.replace('.','_')}.yaml"
            fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # tem chaves de API
            with os.fdopen(fd, "w") as f:
                import yaml
                yaml.dump(providers, f)
            self._tmp_cfg = cfg_path
            cmd.extend(["-pc", cfg_path])
        return cmd

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        res = super().run(target, opts)
        if hasattr(self, "_tmp_cfg") and os.path.exists(self._tmp_cfg):
            try: os.unlink(self._tmp_cfg)
            except:
                _log.debug('tools.py:526 erro ignorado', exc_info=True)
        return res

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        target_lower = target.lower()
        for line in stdout.strip().splitlines():
            sub = line.strip().lower()
            if sub and (sub.endswith(f".{target_lower}") or sub == target_lower):
                findings.append(Finding(type="subdomain", value=sub, host=sub))
        return findings


@registry.register
class AmassTool(CommandTool):
    name        = "amass"
    category    = ToolCategory.SUBDOMAIN
    description = "In-depth attack surface mapping and subdomain enumeration"
    install_cmd = "snap install amass  # or: go install github.com/owasp-amass/amass/v4/...@master"
    timeout     = 300

    def command(self, target: str, opts: dict) -> list[str]:
        from utils.resolvers import resolvers_file
        # antes: lista pública baixada do GitHub — recusada atrás de VPN com firewall estrito
        return ["amass", "enum", "-passive", "-d", target, "-timeout", "20", "-rf", resolvers_file()]
        return cmd

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        for line in stdout.strip().splitlines():
            sub = line.strip().lower()
            if sub and "." in sub:
                findings.append(Finding(type="subdomain", value=sub, host=sub))
        return findings


@registry.register
class AssetfinderTool(CommandTool):
    """Assetfinder reads the target domain from stdin, not as a CLI arg."""
    name        = "assetfinder"
    category    = ToolCategory.SUBDOMAIN
    description = "Fast subdomain enumeration from public sources"
    install_cmd = "go install github.com/tomnomnom/assetfinder@latest"
    timeout     = 120

    def command(self, target: str, opts: dict) -> list[str]:
        return ["assetfinder", "--subs-only"]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        target_lower = target.lower()
        for line in stdout.strip().splitlines():
            sub = line.strip().lower()
            if sub and (sub.endswith(f".{target_lower}") or sub == target_lower):
                findings.append(Finding(type="subdomain", value=sub, host=sub))
        return findings

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        from utils import rate_limiter as _rl
        _rl.wait()
        opts = opts or {}
        result = ToolResult(tool=self.name, target=target)
        t0 = time.time()
        try:
            proc = subprocess.run(
                self.command(target, opts),
                input=target,
                capture_output=True, text=True,
                timeout=self.timeout,
            )
            result.raw_stdout = proc.stdout
            result.raw_stderr = proc.stderr
            result.findings = self.parse(proc.stdout, proc.stderr, target)
        except subprocess.TimeoutExpired:
            result.error = f"Timeout ({self.timeout}s)"
        except FileNotFoundError:
            result.error = f"Binary not found: {self.name}"
        except Exception as e:
            result.error = str(e)[:300]
        result.duration = time.time() - t0
        return result


@registry.register
class DnsxTool(CommandTool):
    name        = "dnsx"
    category    = ToolCategory.DNS
    description = "Fast multi-purpose DNS query, resolution and brute-force toolkit"
    install_cmd = "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    timeout     = 240

    _QUERY_FLAGS = {
        "a": "-a",
        "aaaa": "-aaaa",
        "cname": "-cname",
        "ns": "-ns",
        "txt": "-txt",
        "srv": "-srv",
        "ptr": "-ptr",
        "mx": "-mx",
        "soa": "-soa",
        "any": "-any",
        "caa": "-caa",
        "axfr": "-axfr",
    }

    def _csv_items(self, value) -> list[str]:
        if not value:
            return []
        if isinstance(value, (list, tuple, set)):
            items = [str(v).strip() for v in value]
        else:
            items = [v.strip() for v in str(value).split(",")]
        return [v.lower() for v in items if v]

    def _looks_like_ip_or_cidr(self, value: str) -> bool:
        import ipaddress
        try:
            if "/" in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
            return True
        except Exception:
            return False

    def command(self, target: str, opts: dict) -> list[str]:
        settings = opts.get("settings", {}) or {}
        mode = str(opts.get("mode") or settings.get("dnsx_mode") or "resolve").lower()
        record_types = self._csv_items(opts.get("record_types") or settings.get("dnsx_record_types") or "")
        if not (resolver_file := opts.get("resolvers") or settings.get("dnsx_resolvers") or ""):
            from utils.resolvers import resolvers_file
            resolver_file = resolvers_file()
        wildcard_domain = opts.get("wildcard_domain") or settings.get("dnsx_wildcard_domain") or ""

        cmd = ["dnsx", "-silent", "-duc"]

        if opts.get("json") or settings.get("dnsx_json"):
            cmd.append("-json")
        if opts.get("no_color", True):
            cmd.append("-nc")
        if opts.get("hostsfile") or settings.get("dnsx_hostsfile"):
            cmd.append("-hf")
        if opts.get("trace") or settings.get("dnsx_trace"):
            cmd.append("-trace")

        if resolver_file:
            cmd += ["-r", str(resolver_file)]
        if opts.get("retry") is not None:
            cmd += ["-retry", str(opts.get("retry"))]
        elif settings.get("dnsx_retry"):
            cmd += ["-retry", str(settings.get("dnsx_retry"))]
        if opts.get("threads") is not None:
            cmd += ["-t", str(opts.get("threads"))]
        elif settings.get("dnsx_threads"):
            cmd += ["-t", str(settings.get("dnsx_threads"))]
        if opts.get("rcode"):
            cmd += ["-rcode", str(opts["rcode"])]
        if opts.get("exclude_type"):
            cmd += ["-e", str(opts["exclude_type"])]
        if opts.get("resp") or settings.get("dnsx_resp"):
            cmd.append("-resp")
        if opts.get("resp_only") or settings.get("dnsx_resp_only"):
            cmd.append("-resp-only")
        if opts.get("cdn") or settings.get("dnsx_cdn"):
            cmd.append("-cdn")
        if opts.get("asn") or settings.get("dnsx_asn"):
            cmd.append("-asn")
        if opts.get("axfr") or settings.get("dnsx_axfr"):
            cmd.append("-axfr")
        if opts.get("stream") or settings.get("dnsx_stream"):
            cmd.append("-stream")
        if opts.get("auto_wildcard") or settings.get("dnsx_auto_wildcard"):
            cmd.append("-auto-wildcard")
        elif wildcard_domain:
            cmd += ["-wd", str(wildcard_domain)]
            wt = opts.get("wildcard_threshold") or settings.get("dnsx_wildcard_threshold")
            if wt not in (None, ""):
                cmd += ["-wt", str(wt)]

        target = str(target).strip()
        if mode == "reverse" or opts.get("ptr") or self._looks_like_ip_or_cidr(target):
            cmd += ["-l", target, "-ptr"]
        elif opts.get("wordlist"):
            cmd += ["-d", target, "-w", str(opts["wordlist"])]
        elif Path(target).exists() and Path(target).is_file():
            cmd += ["-l", target]
        else:
            cmd += ["-d", target]

        if opts.get("recon") or mode == "recon" or "recon" in record_types or "all" in record_types:
            cmd.append("-recon")
        else:
            if not record_types:
                record_types = ["a"]
            for rt in record_types:
                flag = self._QUERY_FLAGS.get(rt)
                if flag and flag not in cmd:
                    cmd.append(flag)
        return cmd

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        ansi_re = _re.compile(r"\x1b\[[0-9;]*m")

        for raw in stdout.splitlines():
            line = ansi_re.sub("", raw).strip()
            if not line:
                continue
            if line.startswith("{") and line.endswith("}"):
                try:
                    item = json.loads(line)
                    host = str(item.get("host") or item.get("name") or item.get("input") or "").strip().rstrip(".")
                    value = str(item.get("data") or item.get("response") or item.get("answer") or line).strip()
                    if host:
                        findings.append(Finding(
                            type="dns_record",
                            value=host,
                            host=host,
                            severity=Severity.INFO,
                            source="dnsx",
                            metadata={k: item.get(k) for k in ("rcode", "type", "asn", "cdn") if item.get(k) is not None}
                        ))
                    else:
                        findings.append(Finding(
                            type="dns_response",
                            value=value,
                            host=target,
                            severity=Severity.INFO,
                            source="dnsx",
                            metadata=item,
                        ))
                except Exception:
                    findings.append(Finding(type="dns_response", value=line, host=target, source="dnsx"))
                continue

            m = _re.match(r"^(?P<host>\S+)\s+\[(?P<body>.*)\]$", line)
            if m:
                host = m.group("host").strip().rstrip(".")
                body = m.group("body").strip()
                meta: dict = {"response": body}
                typ = "dns_record"
                if body:
                    upper = body.upper()
                    if upper in {"NOERROR", "SERVFAIL", "REFUSED", "NXDOMAIN", "FORMERR", "NOTIMP", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"}:
                        meta["rcode"] = upper
                        typ = "dns_rcode"
                    elif body.startswith("AS"):
                        meta["asn"] = body
                        typ = "dns_asn"
                    elif body.startswith("CLOUDFLARE") or body.startswith("GOOGLE") or body.startswith("AWS") or body.startswith("AKAMAI"):
                        meta["cdn"] = body
                        typ = "dns_cdn"
                    elif _IP_RE.match(body):
                        typ = "dns_record"
                findings.append(Finding(
                    type=typ,
                    value=host or body,
                    host=host or target,
                    severity=Severity.INFO,
                    source="dnsx",
                    metadata=meta,
                ))
                continue

            findings.append(Finding(
                type="dns_response",
                value=line,
                host=target,
                severity=Severity.INFO,
                source="dnsx",
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  NVD CVE LOOKUP
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class NvdTool(ApiTool):
    name         = "nvd"
    category     = ToolCategory.VULN
    description  = "NVD CVE database — search CVEs by technology/product keyword"
    install_cmd  = "API only — free key at nvd.nist.gov/developers/request-an-api-key"
    requires_key = "nvd_key"

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "NVD API v2" if self._get_key("nvd_key", {}) else "NVD API v2 (no key — rate limited)"

    def run_api(self, target: str, opts: dict) -> list[Finding]:
        from urllib.parse import urlencode
        key = self._get_key("nvd_key", opts)
        headers = {"User-Agent": "ASM-Platform/1.0"}
        if key:
            headers["apiKey"] = key
        params = {"keywordSearch": target, "resultsPerPage": "20"}
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urlencode(params)
        with self._http_open(url, headers=headers, timeout=15) as r:
            data = json.loads(r.read())
        _sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                    "medium": Severity.MEDIUM, "low": Severity.LOW}
        findings = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:300]
            metrics = cve.get("metrics", {})
            score, severity, vector = 0.0, "low", ""
            for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = metrics.get(ver, [])
                if ms:
                    cvss = ms[0].get("cvssData", {})
                    score = cvss.get("baseScore", 0.0)
                    severity = (cvss.get("baseSeverity") or ms[0].get("baseSeverity", "")).lower()
                    vector = cvss.get("vectorString", "")
                    break
            sev_str = severity or ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low")
            findings.append(Finding(
                type="cve", value=cve_id, host=target,
                severity=_sev_map.get(sev_str, Severity.LOW),
                metadata={"score": score, "vector": vector, "desc": desc,
                          "published": cve.get("published", "")[:10],
                          "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
            ))
        return sorted(findings, key=lambda f: -f.metadata.get("score", 0))


# ═══════════════════════════════════════════════════════════════════════════════
#  BROWSER DEEP RECON — CHROMIUM HEADLESS
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class BrowserReconTool(ApiTool):
    name         = "browser_recon"
    category     = ToolCategory.HTTP
    description  = "Deep Browser Recon — APIs, secrets, source maps, Shadow IT (Chromium headless via CDP)"
    install_cmd  = "chromium (system) — no additional install required"
    requires_key = None

    def available(self) -> bool:
        return shutil.which("chromium") is not None

    def version(self) -> str:
        try:
            out = subprocess.check_output(["chromium", "--version"], stderr=subprocess.STDOUT, timeout=5)
            ver = out.decode().strip().split()[-1][:8]
            return f"Chromium CDP v{ver}"
        except Exception:
            return "Chromium CDP (unknown)"

    def run_api(self, target: str, opts: dict) -> list[Finding]:
        try:
            from recon import run_browser_recon
        except ImportError:
            return []
        data = run_browser_recon(target, screenshot_dir="/tmp", timeout=opts.get("timeout", 25))
        findings = []
        for ep in data.get("api_endpoints", []):
            findings.append(Finding(type="api_endpoint", value=ep.get("url", ""), host=target,
                                    severity=Severity.INFO,
                                    metadata={"method": ep.get("method"), "type": ep.get("type", "xhr")}))
        for s in data.get("secrets_found", []):
            findings.append(Finding(type="secret",
                                    value=f"{s.get('key','')}:{s.get('value_hint','')}",
                                    host=target, severity=Severity.CRITICAL,
                                    metadata={"source": s.get("source", ""), "type": s.get("key", "")}))
        for sm in data.get("source_maps", []):
            findings.append(Finding(type="source_map", value=sm, host=target, severity=Severity.MEDIUM, metadata={}))
        for p in data.get("exposed_paths", []):
            findings.append(Finding(type="exposed_path", value=p.get("path", ""), host=target,
                                    severity=Severity.HIGH if p.get("status") == 200 else Severity.INFO,
                                    metadata={"status": p.get("status")}))
        for obs in data.get("observations", []):
            findings.append(Finding(type="observation", value=obs[:200], host=target,
                                    severity=Severity.INFO, metadata={"category": "browser_recon"}))
        for tech in data.get("technologies", []):
            findings.append(Finding(type="technology", value=tech, host=target, severity=Severity.INFO, metadata={}))
        for svc in data.get("third_party_services", []):
            findings.append(Finding(type="third_party", value=svc, host=target, severity=Severity.INFO, metadata={}))

        # JS deep analysis
        js = data.get("js_analysis", {})
        if js.get("webpack_modules", 0) > 0:
            findings.append(Finding(type="js_webpack", value=f"{js['webpack_modules']} modules",
                                    host=target, severity=Severity.MEDIUM,
                                    metadata={"chunks": js.get("webpack_chunks", [])}))
        for g in js.get("global_variables", [])[:15]:
            findings.append(Finding(type="js_global", value=g, host=target, severity=Severity.INFO, metadata={}))
        for route in js.get("framework_routes", [])[:15]:
            findings.append(Finding(type="js_component", value=route, host=target, severity=Severity.INFO, metadata={}))
        for k in js.get("storage_keys", {}).get("localStorage", [])[:10]:
            findings.append(Finding(type="ls_key", value=k, host=target, severity=Severity.MEDIUM,
                                    metadata={"storage": "localStorage"}))
        for k in js.get("storage_keys", {}).get("sessionStorage", [])[:10]:
            findings.append(Finding(type="ss_key", value=k, host=target, severity=Severity.MEDIUM,
                                    metadata={"storage": "sessionStorage"}))
        for sw in js.get("service_workers", []):
            findings.append(Finding(type="service_worker", value=sw.get("scope", ""), host=target,
                                    severity=Severity.INFO,
                                    metadata={"scriptURL": sw.get("scriptURL", "")}))
        if js.get("inline_event_handlers", 0) > 3:
            findings.append(Finding(type="js_inline_handlers", value=f"{js['inline_event_handlers']} handlers",
                                    host=target, severity=Severity.LOW, metadata={}))

        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  SUPPLY CHAIN — JS LIBRARY CVE SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class SupplyChainTool(ApiTool):
    name         = "supply_chain"
    category     = ToolCategory.VULN
    description  = "JS Supply Chain Scan — client-side library CVEs via NVD"
    install_cmd  = "API only — uses nvd_key from Settings"
    requires_key = "nvd_key"

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "NVD API v2 (supply chain)"

    def run_api(self, target: str, opts: dict) -> list[Finding]:
        try:
            from recon import run_supply_chain_scan
        except ImportError:
            return []
        key = self._get_key("nvd_key", opts)
        hosts = opts.get("hosts", [{"host": target, "technologies": []}])
        data = run_supply_chain_scan(hosts, key or "")
        findings = []
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                   "medium": Severity.MEDIUM, "low": Severity.LOW}
        for f in data.get("findings", []):
            findings.append(Finding(
                type="supply_chain", value=f.get("cve_id", ""),
                host=f.get("affected_hosts", [target])[0] if f.get("affected_hosts") else target,
                severity=sev_map.get(f.get("severity", "low"), Severity.LOW),
                metadata={"library": f.get("library", ""), "version": f.get("version", ""),
                          "score": f.get("score", 0), "desc": f.get("desc", ""),
                          "url": f.get("url", "")},
            ))
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  ASNMAP — ASN range mapping
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class AsnmapTool(CommandTool):
    name        = "asnmap"
    category    = ToolCategory.OSINT
    description = "Maps organization network ranges using ASN information"
    install_cmd = "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    timeout     = 120

    def command(self, target: str, opts: dict) -> list[str]:
        # -duc avoids the updater hitting asn.projectdiscovery.io on startup,
        # which is a common source of DNS/network noise in constrained labs.
        return ["asnmap", "-d", target, "-json", "-silent", "-duc"]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, Exception):
            return findings
        for item in (data if isinstance(data, list) else [data]):
            asn = item.get("asn", "") or item.get("ASN", "")
            cidr = item.get("cidr", "") or item.get("CIDR", "") or item.get("range", "")
            org = item.get("org", "") or item.get("organization", "")
            value = item.get("input", "") or target
            if asn:
                findings.append(Finding(type="asn", value=str(asn), host=target,
                                        severity=Severity.INFO,
                                        metadata={"org": org, "cidr": str(cidr) if cidr else ""}))
            if cidr:
                findings.append(Finding(type="asn_range", value=str(cidr), host=target,
                                        severity=Severity.INFO,
                                        metadata={"asn": str(asn) if asn else "", "org": org}))
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  URLFINDER — URL discovery
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class UrlfinderTool(CommandTool):
    name        = "urlfinder"
    category    = ToolCategory.HTTP
    description = "Discovers associated URLs for a domain"
    install_cmd = "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
    timeout     = 180

    def command(self, target: str, opts: dict) -> list[str]:
        return ["urlfinder", "-d", target]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        for line in stdout.strip().splitlines():
            url = line.strip()
            if url and (url.startswith("http://") or url.startswith("https://")):
                findings.append(Finding(type="url", value=url, host=target,
                                        severity=Severity.INFO))
        return findings

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        opts = opts or {}
        result = ToolResult(tool=self.name, target=target)
        t0 = time.time()
        try:
            cmd = self.command(target, opts)
            proc = subprocess.run(cmd, capture_output=True, timeout=self.timeout)
            stdout = proc.stdout.decode("utf-8", errors="replace") if isinstance(proc.stdout, (bytes, bytearray)) else str(proc.stdout or "")
            stderr = proc.stderr.decode("utf-8", errors="replace") if isinstance(proc.stderr, (bytes, bytearray)) else str(proc.stderr or "")
            result.raw_stdout = stdout
            result.raw_stderr = stderr
            if proc.returncode != 0 and not stdout.strip():
                result.error = stderr.strip()[:300] or f"Exit code {proc.returncode}"
            else:
                urls = []
                findings = []
                for line in stdout.strip().splitlines():
                    url = line.strip()
                    m = _re.search(r"https?://[^\s\"'<>]+", url)
                    if m:
                        url = m.group(0).rstrip(").,;]}>\"'\uFFFD")
                    if url and (url.startswith("http://") or url.startswith("https://")):
                        urls.append(url)
                        findings.append(Finding(type="url", value=url, host=target,
                                                severity=Severity.INFO))
                result.findings = findings
                result.data = {"urls": urls}
        except subprocess.TimeoutExpired:
            result.error = f"Timeout ({self.timeout}s)"
        except FileNotFoundError:
            result.error = f"Binary not found: {self.name}"
        except Exception as e:
            result.error = str(e)[:300]
        result.duration = time.time() - t0
        return result


@registry.register
class CrtShTool(BaseTool):
    name        = "crtsh"
    category    = ToolCategory.OSINT
    description = "Certificate Transparency discovery via crt.sh"
    install_cmd = "HTTP-only tool — no install required"
    timeout     = 90

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return "crt.sh"

    def _normalize_name(self, value: str) -> str:
        return (value or "").strip().lower().lstrip("*.")

    def _matches_target(self, name: str, target: str) -> bool:
        name = self._normalize_name(name)
        target = self._normalize_name(target)
        if not name or not target:
            return False
        return name == target or name.endswith(f".{target}")

    def _fetch(self, query: str) -> list[dict]:
        from utils.circuit_breaker import CircuitOpen, breaker_for
        url = f"https://crt.sh/?{query}&output=json&deduplicate=Y"
        try:
            with self._http_open(url, timeout=20, name="crt.sh") as resp:
                raw = resp.read()
        except CircuitOpen:
            return []
        except Exception:
            return []
        if not raw or raw[:1] == b"<":
            breaker_for("crt.sh").failure()
            return []
        data = json.loads(raw)
        return data if isinstance(data, list) else []

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        opts = opts or {}
        result = ToolResult(tool=self.name, target=target)
        t0 = time.time()
        query_org = (opts.get("organization") or opts.get("org") or "").strip()
        limit = int(opts.get("limit", 500) or 500)
        limit = max(1, min(limit, 2000))
        certs: list[dict] = []
        subdomains: list[str] = []
        seen_subs: set[str] = set()
        seen_certs: set[tuple] = set()

        try:
            queries = []
            if query_org:
                from urllib.parse import quote as _quote
                queries.append(f"o={_quote(query_org)}")
            else:
                from urllib.parse import quote as _quote
                queries.extend([f"q=%25.{_quote(target)}", f"q={_quote(target)}"])

            for query in queries:
                try:
                    data = self._fetch(query)
                except Exception:
                    continue
                for item in data[:limit]:
                    name_value = str(item.get("name_value", "") or "")
                    common_name = str(item.get("common_name", "") or "")
                    issuer_name = str(item.get("issuer_name", "") or "")
                    cert_id = item.get("id")
                    not_before = str(item.get("not_before", "") or "")[:19]
                    not_after = str(item.get("not_after", "") or "")[:19]
                    names = []
                    for raw_name in name_value.replace("\\n", "\n").splitlines():
                        nm = self._normalize_name(raw_name)
                        if nm and self._matches_target(nm, target):
                            names.append(nm)
                            if nm not in seen_subs:
                                seen_subs.add(nm)
                                subdomains.append(nm)
                    cert_key = (common_name, not_after, cert_id)
                    if cert_key not in seen_certs:
                        seen_certs.add(cert_key)
                        certs.append({
                            "id": cert_id,
                            "common_name": common_name,
                            "issuer_name": issuer_name,
                            "not_before": not_before,
                            "not_after": not_after,
                            "name_value": name_value,
                            "names": names,
                            "source": "crt.sh",
                        })
                if certs:
                    break
        except Exception as exc:
            result.status = "error"
            result.error = str(exc)[:300]
            result.reason = result.error

        result.data = {
            "certs": certs,
            "ct_subdomains": sorted(subdomains),
            "total_certs": len(certs),
            "source": "crt.sh",
        }
        result.findings = [
            Finding(type="subdomain", value=sub, host=sub, severity=Severity.INFO, source="crt.sh")
            for sub in subdomains
        ]
        if not result.error:
            result.status = "done" if certs or subdomains else "skipped"
            result.reason = "" if result.status == "done" else "No crt.sh certificates found"
        result.duration = time.time() - t0
        result.metrics = {"findings": len(result.findings)}
        return result


# ═══════════════════════════════════════════════════════════════════════════════
#  ARJUN — HTTP parameter discovery
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class ArjunTool(CommandTool):
    name        = "arjun"
    category    = ToolCategory.HTTP
    description = "HTTP parameter discovery suite"
    install_cmd = "pip install arjun"
    timeout     = 300  # arjun needs time; silently returns empty on timeout

    def command(self, target: str, opts: dict) -> list[str]:
        url = target if target.startswith("http") else f"https://{target}"
        return [
            "arjun", "-u", url, "-oJ", "/tmp/arjun_output.json",
            "-t", "3", "-T", "8", "--stable", "-q",
        ]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        try:
            with open("/tmp/arjun_output.json") as f:
                data = json.load(f)
        except Exception:
            return findings
        params = data.get("results", []) if isinstance(data, dict) else []
        for p in params:
            if isinstance(p, dict):
                name = p.get("param", "") or p.get("parameter", "") or p.get("name", "")
                if name:
                    findings.append(Finding(type="parameter", value=name, host=target,
                                            severity=Severity.INFO,
                                            metadata={"url": p.get("url", target)}))
            elif isinstance(p, str):
                findings.append(Finding(type="parameter", value=p, host=target,
                                        severity=Severity.INFO))
        return findings

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        # Explicit override ensures CommandTool base class is NOT invoked
        from utils import rate_limiter as _rl
        _rl.wait()
        opts = opts or {}
        result = ToolResult(tool=self.name, target=target)
        t0 = time.time()
        try:
            cmd = self.command(target, opts)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            result.raw_stdout = proc.stdout
            result.raw_stderr = proc.stderr
            result.findings = self.parse(proc.stdout, proc.stderr, target)
        except subprocess.TimeoutExpired:
            result.findings = []  # timeout is normal for WAF-protected targets
        except FileNotFoundError:
            result.error = f"Binary not found: {self.name}"
        except Exception as e:
            result.error = str(e)[:300]
        result.duration = time.time() - t0
        if os.path.exists("/tmp/arjun_output.json"):
            try: os.unlink("/tmp/arjun_output.json")
            except:
                _log.debug('tools.py:1269 erro ignorado', exc_info=True)
        return result


# ═══════════════════════════════════════════════════════════════════════════════
#  CLOUDLIST — cloud asset listing
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class CloudlistTool(CommandTool):
    name        = "cloudlist"
    category    = ToolCategory.CLOUD
    description = "Lists assets from multiple cloud providers"
    install_cmd = "Auto-bootstrap from the official GitHub release ZIP (preferred over go install)"
    timeout     = 120

    def _release_asset_name(self) -> str:
        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "aarch64": "arm64",
            "arm64": "arm64",
            "armv7l": "arm",
            "armv6l": "arm",
        }
        arch = arch_map.get(platform.machine().lower(), "amd64")
        return f"cloudlist_{{version}}_linux_{arch}.zip"

    def _latest_release(self) -> dict | None:
        from utils.circuit_breaker import CircuitOpen
        url = "https://api.github.com/repos/projectdiscovery/cloudlist/releases/latest"
        try:
            with self._http_open(
                url,
                headers={"Accept": "application/vnd.github+json", "User-Agent": "asm-tool-bootstrap"},
                timeout=20,
                name="api.github.com",
            ) as resp:
                payload = json.load(resp)
        except CircuitOpen:
            return None
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    def _bootstrap_binary(self) -> bool:
        binary = self._resolve_binary(self.name)
        if binary:
            return True
        try:
            release = self._latest_release()
            if not release:
                return False
            tag = str(release.get("tag_name") or "").lstrip("v")
            version = tag or "latest"
            asset_name = self._release_asset_name().format(version=version)
            assets = release.get("assets") or []
            asset = next((a for a in assets if a.get("name") == asset_name), None)
            if not asset:
                return False
            download_url = asset.get("browser_download_url")
            if not download_url:
                return False

            target_dir = Path("/mnt/compartilhada/go/bin")
            target_dir.mkdir(parents=True, exist_ok=True)
            target_bin = target_dir / self.name

            with tempfile.TemporaryDirectory(prefix="cloudlist-bootstrap-") as tmpdir:
                zip_path = Path(tmpdir) / asset_name
                req = urllib.request.Request(download_url, headers={"User-Agent": "asm-tool-bootstrap"})
                from utils.circuit_breaker import guarded_urlopen
                with guarded_urlopen(req, timeout=60) as resp, open(zip_path, "wb") as fp:
                    shutil.copyfileobj(resp, fp)
                with zipfile.ZipFile(zip_path) as zf:
                    member = next((n for n in zf.namelist() if n.endswith("/cloudlist") or n == "cloudlist"), None)
                    if not member:
                        return False
                    zf.extract(member, tmpdir)
                    extracted = Path(tmpdir) / member
                    if not extracted.exists():
                        return False
                    shutil.copy2(extracted, target_bin)
            target_bin.chmod(0o755)
            return True
        except Exception:
            return False

    def available(self) -> bool:
        return self._resolve_binary(self.name) is not None or self._bootstrap_binary()

    def command(self, target: str, opts: dict) -> list[str]:
        return ["cloudlist", "-host", "-silent"]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        for line in stdout.strip().splitlines():
            host = line.strip()
            if host and "." in host:
                findings.append(Finding(type="cloud_asset", value=host, host=host,
                                        severity=Severity.INFO,
                                        metadata={"provider": "cloud"}))

            elif host:
                findings.append(Finding(type="cloud_ip", value=host, host=host,
                                        severity=Severity.INFO))
        return findings

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        opts = opts or {}
        result = ToolResult(tool=self.name, target=target)
        t0 = time.time()
        try:
            if not self.available():
                result.status = "unsupported"
                result.reason = "cloudlist binary unavailable and bootstrap failed"
                result.error = result.reason
                return result
            cmd = self.command(target, opts)
            resolved = self._resolve_binary(cmd[0])
            if resolved:
                cmd = [resolved, *cmd[1:]]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            result.raw_stdout = proc.stdout
            result.raw_stderr = proc.stderr
            if proc.returncode != 0 and not proc.stdout.strip():
                if "invalid provider" in proc.stderr.lower() or "could not create runner" in proc.stderr.lower():
                    pass  # no cloud creds — return empty, not an error
                else:
                    result.error = proc.stderr.strip()[:300] or f"Exit code {proc.returncode}"
            else:
                result.findings = self.parse(proc.stdout, proc.stderr, target)
        except subprocess.TimeoutExpired:
            pass  # timeout with no cloud providers — not a fatal error
        except FileNotFoundError:
            result.error = f"Binary not found: {self.name}"
        except Exception as e:
            result.error = str(e)[:300]
        result.duration = time.time() - t0
        return result


# ═══════════════════════════════════════════════════════════════════════════════
#  SUBJACK — subdomain takeover checker
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class SubjackTool(CommandTool):
    name        = "subjack"
    category    = ToolCategory.VULN
    description = "Subdomain takeover vulnerability scanner"
    install_cmd = "go install github.com/haccer/subjack@latest"
    timeout     = 120

    def _ensure_resolvers(self) -> Path | None:
        # antes: 1.1.1.1/8.8.8.8 fixos — atrás de VPN com firewall estrito o subjack não resolvia nada
        from utils.resolvers import resolvers_file
        return Path(resolvers_file())

    def command(self, target: str, opts: dict) -> list[str]:
        output_file = f"/tmp/subjack_{target.replace('.','_')}.json"
        cmd = ["subjack", "-d", target, "-o", output_file, "-ssl", "-t", "2", "-timeout", "3"]
        hosts = opts.get("hosts", [])
        if hosts:
            hosts_file = f"/tmp/subjack_hosts_{target.replace('.','_')}.txt"
            with open(hosts_file, "w") as f:
                for h in hosts:
                    hostname = h.get("host", "") if isinstance(h, dict) else str(h)
                    if hostname:
                        f.write(hostname + "\n")
            cmd.extend(["-w", hosts_file])
        resolver_file = opts.get("resolvers") or self._ensure_resolvers()
        if resolver_file:
            cmd.extend(["-r", str(resolver_file)])
        self._output_file = output_file
        return cmd

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        output_file = getattr(self, "_output_file", f"/tmp/subjack_{target.replace('.','_')}.json")
        try:
            with open(output_file) as f:
                data = json.load(f)
        except Exception:
            return findings
        for item in (data if isinstance(data, list) else [data]):
            subdomain = item.get("subdomain", "")
            vulnerable = item.get("vulnerable", False)
            service = item.get("service", "") or item.get("provider", "")
            if subdomain:
                sev = Severity.HIGH if vulnerable else Severity.INFO
                findings.append(Finding(type="takeover", value=subdomain, host=subdomain,
                                        severity=sev,
                                        metadata={"vulnerable": vulnerable, "service": service}))
        return findings

    def run(self, target: str, opts: dict | None = None) -> ToolResult:
        result = super().run(target, opts)
        output_file = getattr(self, "_output_file", f"/tmp/subjack_{target.replace('.','_')}.json")
        if os.path.exists(output_file):
            try: os.unlink(output_file)
            except:
                _log.debug('tools.py:1485 erro ignorado', exc_info=True)
        return result


# ═══════════════════════════════════════════════════════════════════════════════
#  CLOUD ENUM — multi-cloud OSINT enumeration
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class CloudEnumTool(CommandTool):
    name        = "cloud_enum"
    category    = ToolCategory.CLOUD
    description = "Multi-cloud OSINT enumeration (AWS, Azure, GCP)"
    install_cmd = "git clone https://github.com/initstring/cloud_enum.git"
    timeout     = 300

    def available(self) -> bool:
        binary = self._resolve_binary(self.name)
        if not binary:
            return False
        enum_dir = Path(binary).resolve().parent / "enum_tools"
        if enum_dir.is_dir():
            return True
        try:
            proc = _subprocess_real.run(
                [binary, "--help"], capture_output=True, text=True, timeout=8,
            )
            blob = (proc.stderr or "") + (proc.stdout or "")
            if "No module named" in blob or "ModuleNotFoundError" in blob:
                return False
            return True
        except Exception:
            return False

    def command(self, target: str, opts: dict) -> list[str]:
        # Ensure we run cloud_enum directly (it has a shebang) so bash resolves PATH
        return ["cloud_enum", "-k", target, "-qs", "-t", "5"]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            if "open" in line.lower() or "found" in line.lower() or "bucket" in line.lower():
                findings.append(Finding(type="cloud_finding", value=line[:300], host=target,
                                        severity=Severity.MEDIUM))
            elif "elb" in line.lower() or "app" in line.lower():
                if "://" in line:
                    findings.append(Finding(type="cloud_url", value=line[:300], host=target,
                                            severity=Severity.INFO))
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  FAVICON HASH — Shodan favicon hash lookup
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class FaviconHashTool(ApiTool):
    name         = "favicon_hash"
    category     = ToolCategory.API_INTEL
    description  = "Favicon Hash → Origin IP lookup via Shodan"
    install_cmd  = "API only — requires shodan_key in Settings"
    requires_key = "shodan_key"

    def available(self) -> bool:
        return True

    def version(self) -> str:
        key = self._get_key("shodan_key", {})
        return "Shodan API (key set)" if key else "Shodan API (no key)"

    def run_api(self, target: str, opts: dict) -> list[Finding]:
        domain = target
        shodan_key = self._get_key("shodan_key", opts)
        if not shodan_key:
            raise RuntimeError("Shodan API key not configured")

        findings = []
        from urllib.parse import quote
        from utils.circuit_breaker import CircuitOpen

        favicon_data = None
        for scheme in ("https", "http"):
            try:
                with self._http_open(
                    f"{scheme}://{domain}/favicon.ico",
                    headers={"User-Agent": "Mozilla/5.0"},
                    timeout=10,
                ) as r:
                    if r.status == 200:
                        favicon_data = r.read()
                        break
            except CircuitOpen:
                break
            except Exception:
                continue

        if not favicon_data:
            return []

        import base64
        favicon_b64 = base64.b64encode(favicon_data).decode()
        favicon_hash = None
        try:
            import mmh3
            favicon_hash = mmh3.hash(favicon_b64)
        except ImportError:
            import hashlib
            favicon_hash = int(hashlib.md5(favicon_data).hexdigest()[:8], 16)

        try:
            query = f"http.favicon.hash:{favicon_hash}"
            url = f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query={quote(query)}"
            with self._http_open(url, timeout=15) as r:
                data = json.loads(r.read())
        except CircuitOpen:
            raise
        except Exception as e:
            raise RuntimeError(f"Shodan API error: {e}")

        for match in data.get("matches", [])[:50]:
            ip = match.get("ip_str", "")
            org = match.get("org", "")
            hostnames = match.get("hostnames", [])
            ports = match.get("ports", [])
            for hn in hostnames:
                findings.append(Finding(type="favicon_origin", value=f"{hn} ({ip})",
                                        host=domain, ip=ip,
                                        severity=Severity.MEDIUM,
                                        metadata={"org": org, "ports": ports,
                                                  "hash": str(favicon_hash)}))
        if not findings and data.get("matches"):
            for match in data.get("matches", [])[:10]:
                ip = match.get("ip_str", "")
                org = match.get("org", "")
                findings.append(Finding(type="favicon_origin_ip", value=ip,
                                        host=domain, ip=ip,
                                        severity=Severity.MEDIUM,
                                        metadata={"org": org, "hash": str(favicon_hash)}))

        findings.append(Finding(type="favicon_hash", value=str(favicon_hash),
                                host=domain, severity=Severity.INFO,
                                metadata={"domain": domain}))
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  OSINT / EMAIL / SUBDOMAIN ENUMERATION (API-BASED)
# ═══════════════════════════════════════════════════════════════════════════════

@registry.register
class TheHarvesterTool(CommandTool):
    name        = "theHarvester"
    category    = ToolCategory.OSINT
    description = "Email + subdomain + IP harvesting from public sources"
    install_cmd = "pip install theHarvester"
    timeout     = 180

    _DEFAULT_SOURCES = [
        "crtsh",
        "certspotter",
        "commoncrawl",
        "duckduckgo",
        "hackertarget",
        "otx",
        "rapiddns",
        "urlscan",
        "waybackarchive",
    ]

    def command(self, target: str, opts: dict) -> list[str]:
        sources = opts.get("sources") or self._DEFAULT_SOURCES
        if isinstance(sources, str):
            sources = [s.strip() for s in sources.split(",") if s.strip()]
        sources = [s for s in sources if s]
        limit = int(opts.get("limit", 100) or 100)
        return ["theHarvester", "-q", "-l", str(limit), "-d", target, "-b", ",".join(sources)]

    def parse(self, stdout: str, stderr: str, target: str) -> list[Finding]:
        findings = []
        section = None
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[*]") or line.startswith("["):
                if "emails" in line.lower():
                    section = "email"
                elif "hosts" in line.lower() or "subdomains" in line.lower():
                    section = "host"
                elif "ips" in line.lower():
                    section = "ip"
                else:
                    section = None
                continue
            if section == "email" and "@" in line:
                findings.append(Finding(type="email", value=line, host=target, severity=Severity.INFO))
            elif section == "host":
                sub = line.lower()
                if sub.endswith(f".{target}") or sub == target:
                    findings.append(Finding(type="subdomain", value=sub, host=sub))
            elif section == "ip":
                findings.append(Finding(type="ip", value=line, host=target, severity=Severity.INFO))
        return findings


@registry.register
class HunterIOTool(ApiTool):
    name         = "hunterio"
    category     = ToolCategory.OSINT
    description  = "Hunter.io email discovery — find corporate email addresses"
    install_cmd  = "API only — free key at hunter.io"
    requires_key = "hunter_key"

    def run_api(self, target: str, opts: dict) -> list[Finding]:
        key = self._get_key("hunter_key", opts)
        if not key:
            return []
        findings = []
        url = f"https://api.hunter.io/v2/domain-search?domain={target}&api_key={key}&limit=100"
        with self._http_open(url, timeout=20) as r:
            data = json.loads(r.read())
        for entry in data.get("data", {}).get("emails", []):
            findings.append(Finding(
                type="email",
                value=entry.get("value", ""),
                host=target,
                severity=Severity.INFO,
                metadata={
                    "first_name": entry.get("first_name", ""),
                    "last_name": entry.get("last_name", ""),
                    "position": entry.get("position", ""),
                    "confidence": entry.get("confidence", 0),
                    "sources": len(entry.get("sources", [])),
                }
            ))
        return findings


@registry.register
class HackerTargetTool(ApiTool):
    name        = "hackertarget"
    category    = ToolCategory.SUBDOMAIN
    description = "Free subdomain lookup via HackerTarget API"
    install_cmd = "API only — free, no key required"

    def run_api(self, target: str, opts: dict) -> list[Finding]:
        findings = []
        url = f"https://api.hackertarget.com/hostsearch/?q={target}"
        with self._http_open(url, timeout=20) as r:
            text = r.read().decode(errors="replace")
        for line in text.strip().splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lower()
                if sub and (sub.endswith(f".{target}") or sub == target):
                    ip = parts[1].strip() if len(parts) > 1 else ""
                    findings.append(Finding(type="subdomain", value=sub, host=sub, ip=ip))
        return findings


@registry.register
class AlienvaultOtxTool(ApiTool):
    name        = "alienvault_otx"
    category    = ToolCategory.SUBDOMAIN
    description = "AlienVault OTX passive DNS subdomain enumeration"
    install_cmd = "API only — free key at otx.alienvault.com"

    def run_api(self, target: str, opts: dict) -> list[Finding]:
        findings = []
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns"
        with self._http_open(
            url,
            headers={"User-Agent": "ASM-Platform/1.0",
                     "X-OTX-API-KEY": opts.get("otx_key") or (opts.get("settings") or {}).get("otx_key", "")},
            timeout=20,
        ) as r:
            data = json.loads(r.read())
        seen = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname", "").strip().lower()
            if hostname and hostname not in seen and (hostname.endswith(f".{target}") or hostname == target):
                seen.add(hostname)
                findings.append(Finding(type="subdomain", value=hostname, host=hostname,
                                        ip=entry.get("address", ""),
                                        metadata={"record_type": entry.get("record_type", ""),
                                                   "first": entry.get("first", ""),
                                                   "last": entry.get("last", "")}))
        return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="ASM Tool Registry")
    sub = ap.add_subparsers(dest="cmd")

    p_st = sub.add_parser("status", help="Show all tools and their availability")
    p_st.add_argument("--json", action="store_true")
    p_st.add_argument("--category", help="Filter by category")

    p_run = sub.add_parser("run", help="Run a tool against a target")
    p_run.add_argument("tool", help="Tool name")
    p_run.add_argument("target", help="Target domain or IP")
    p_run.add_argument("--json", action="store_true", help="Output JSON")
    p_run.add_argument("--opts", help="JSON options dict", default="{}")

    args = ap.parse_args()

    if args.cmd == "status":
        data = registry.status()
        if args.category:
            data = [d for d in data if d["category"] == args.category]
        if getattr(args, "json", False):
            print(json.dumps(data, indent=2))
        else:
            cat = ""
            for t in data:
                if t["category"] != cat:
                    cat = t["category"]
                    print(f"\n  [{cat}]")
                status_icon = "✓" if t["available"] else "✗"
                print(f"  {status_icon} {t['name']:20s} {t['description'][:60]}")

    else:
        opts = json.loads(args.opts) if args.opts else {}
        result = registry.run(args.tool, args.target, opts)
        if getattr(args, "json", False):
            print(json.dumps(result.to_dict(), indent=2))
        else:
            if result.error:
                print(f"[ERROR] {result.error}")
            else:
                print(f"[{args.tool}] {len(result.findings)} findings for {args.target} ({result.duration:.1f}s)")
                for f in result.findings:
                    sev = f"[{f.severity.upper()}]" if f.severity != "info" else ""
                    print(f"  {sev} {f.type:15s} {f.value[:80]}")
