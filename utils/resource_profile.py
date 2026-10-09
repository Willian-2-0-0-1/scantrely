#!/usr/bin/env python3
"""Adaptive resource profile for ASM deployments.

The platform is often moved between laptops, small VPSes, and larger boxes.
This module turns local CPU/RAM/swap into conservative defaults for workers,
tool gates, and watchdog thresholds. Explicit environment variables still win.
"""

from __future__ import annotations

import os
import logging as _logging
_log = _logging.getLogger('scantrely.resource_profile')


def _meminfo_mb() -> dict[str, int]:
    out: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                key, value = line.split(":", 1)
                out[key] = int(value.strip().split()[0]) // 1024
    except Exception:
        _log.debug('resource_profile.py:21 erro ignorado', exc_info=True)
    return out


def _env_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return max(1, int(default))


def detect_resources() -> dict[str, int | str]:
    mem = _meminfo_mb()
    cpu = os.cpu_count() or 1
    ram_mb = int(mem.get("MemTotal", 0) or 0)
    swap_mb = int(mem.get("SwapTotal", 0) or 0)

    if cpu <= 2 or ram_mb < 4096:
        size = "tiny"
    elif cpu <= 4 or ram_mb < 8192:
        size = "small"
    elif cpu <= 8 or ram_mb < 16384:
        size = "medium"
    elif cpu <= 16 or ram_mb < 32768:
        size = "large"
    else:
        size = "xlarge"

    return {"cpu": cpu, "ram_mb": ram_mb, "swap_mb": swap_mb, "size": size}


def recommended_limits() -> dict[str, int | str]:
    r = detect_resources()
    size = str(r["size"])

    presets: dict[str, dict[str, int]] = {
        "tiny": {
            "ASM_JOB_WORKERS": 1,
            "ASM_GLOBAL_PROC_LIMIT": 4,
            "ASM_DOMAIN_FANOUT_WORKERS": 2,
            "ASM_GATE_DEFAULT": 2,
            "ASM_GATE_SUBFINDER": 2,
            "ASM_GATE_ASSETFINDER": 2,
            "ASM_GATE_HTTPX": 2,
            "ASM_GATE_AMASS": 1,
            "ASM_GATE_NUCLEI": 1,
            "ASM_GATE_NAABU": 1,
            "ASM_GATE_GOWITNESS": 1,
            "ASM_GATE_WPSCAN": 1,
            "ASM_GATE_FFUF": 1,
            "ASM_HTTPX_THREADS": 10,
            "ASM_HTTPX_RATE_LIMIT": 20,
        },
        "small": {
            "ASM_JOB_WORKERS": 1,
            "ASM_GLOBAL_PROC_LIMIT": 6,
            "ASM_DOMAIN_FANOUT_WORKERS": 3,
            "ASM_GATE_DEFAULT": 3,
            "ASM_GATE_SUBFINDER": 3,
            "ASM_GATE_ASSETFINDER": 3,
            "ASM_GATE_HTTPX": 3,
            "ASM_GATE_AMASS": 1,
            "ASM_GATE_NUCLEI": 1,
            "ASM_GATE_NAABU": 1,
            "ASM_GATE_GOWITNESS": 1,
            "ASM_GATE_WPSCAN": 1,
            "ASM_GATE_FFUF": 1,
            "ASM_HTTPX_THREADS": 15,
            "ASM_HTTPX_RATE_LIMIT": 30,
        },
        "medium": {
            "ASM_JOB_WORKERS": 2,
            "ASM_GLOBAL_PROC_LIMIT": 10,
            "ASM_DOMAIN_FANOUT_WORKERS": 4,
            "ASM_GATE_DEFAULT": 4,
            "ASM_GATE_SUBFINDER": 4,
            "ASM_GATE_ASSETFINDER": 4,
            "ASM_GATE_HTTPX": 4,
            "ASM_GATE_AMASS": 1,
            "ASM_GATE_NUCLEI": 1,
            "ASM_GATE_NAABU": 1,
            "ASM_GATE_GOWITNESS": 1,
            "ASM_GATE_WPSCAN": 1,
            "ASM_GATE_FFUF": 1,
            "ASM_HTTPX_THREADS": 25,
            "ASM_HTTPX_RATE_LIMIT": 50,
        },
        "large": {
            "ASM_JOB_WORKERS": 3,
            "ASM_GLOBAL_PROC_LIMIT": 14,
            "ASM_DOMAIN_FANOUT_WORKERS": 5,
            "ASM_GATE_DEFAULT": 5,
            "ASM_GATE_SUBFINDER": 5,
            "ASM_GATE_ASSETFINDER": 5,
            "ASM_GATE_HTTPX": 5,
            "ASM_GATE_AMASS": 1,
            "ASM_GATE_NUCLEI": 2,
            "ASM_GATE_NAABU": 2,
            "ASM_GATE_GOWITNESS": 2,
            "ASM_GATE_WPSCAN": 1,
            "ASM_GATE_FFUF": 2,
            "ASM_HTTPX_THREADS": 35,
            "ASM_HTTPX_RATE_LIMIT": 75,
        },
        "xlarge": {
            "ASM_JOB_WORKERS": 4,
            "ASM_GLOBAL_PROC_LIMIT": 20,
            "ASM_DOMAIN_FANOUT_WORKERS": 6,
            "ASM_GATE_DEFAULT": 6,
            "ASM_GATE_SUBFINDER": 6,
            "ASM_GATE_ASSETFINDER": 6,
            "ASM_GATE_HTTPX": 6,
            "ASM_GATE_AMASS": 1,
            "ASM_GATE_NUCLEI": 2,
            "ASM_GATE_NAABU": 2,
            "ASM_GATE_GOWITNESS": 2,
            "ASM_GATE_WPSCAN": 1,
            "ASM_GATE_FFUF": 2,
            "ASM_HTTPX_THREADS": 50,
            "ASM_HTTPX_RATE_LIMIT": 100,
        },
    }

    limits: dict[str, int | str] = dict(presets[size])
    limits.update(r)

    cpu = int(r["cpu"])
    ram_mb = int(r["ram_mb"] or 2048)
    limits["ASM_WATCHDOG_MAX_LOAD"] = max(2, min(cpu, int(cpu * 0.85) or 1))
    limits["ASM_WATCHDOG_MIN_MEM_MB"] = max(768, min(4096, int(ram_mb * 0.12)))
    limits["ASM_WATCHDOG_MAX_RECON_PROCS"] = int(limits["ASM_GLOBAL_PROC_LIMIT"]) + 4
    return limits


def shell_exports() -> str:
    limits = recommended_limits()
    lines = [
        f"# ASM auto profile: size={limits['size']} cpu={limits['cpu']} ram_mb={limits['ram_mb']} swap_mb={limits['swap_mb']}"
    ]
    for key in sorted(k for k in limits if k.startswith("ASM_")):
        lines.append(f'export {key}="${{{key}:-{limits[key]}}}"')
    return "\n".join(lines)


if __name__ == "__main__":
    print(shell_exports())
