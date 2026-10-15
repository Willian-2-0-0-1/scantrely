"""Resolvedores DNS para ferramentas que, sem configuração, usam resolvedores públicos próprios
(dnsx, subjack, amass).

Com VPN de firewall estrito (ex.: Mullvad), DNS para 1.1.1.1/8.8.8.8 é recusado e essas
ferramentas não resolvem nada — em silêncio. O resolvedor do sistema segue a VPN.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_FALLBACK = "127.0.0.53"


def system_resolvers(resolv_conf: str = "/etc/resolv.conf") -> list[str]:
    servers: list[str] = []
    try:
        for line in Path(resolv_conf).read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver" and parts[1] not in servers:
                servers.append(parts[1])
    except OSError:
        pass
    return servers or [_FALLBACK]


def resolvers_file() -> str:
    """Arquivo (um IP por linha) com os resolvedores do sistema, para -r/-rf."""
    path = Path(tempfile.gettempdir()) / f"scantrely_resolvers_{os.getuid()}.txt"
    content = "\n".join(system_resolvers()) + "\n"
    try:
        if not path.exists() or path.read_text() != content:
            path.write_text(content)
    except OSError:
        pass
    return str(path)
