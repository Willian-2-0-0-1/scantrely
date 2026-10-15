"""Filtros de log do servidor."""
import logging
import re

# A tela consulta estas rotas a cada 1–2s durante um scan: eram 98% do server.log
# (467 mil de 498 mil linhas). Sucessos saem do log; erros e qualquer outro método ficam.
# ASM_LOG_POLLING=1 desliga o filtro.
QUIET_GET_RE = re.compile(
    r'"GET (?:/api/recon/[^/ ]+/(?:pipeline|tool-logs)|/api/live-output/|/api/jobs(?:/summary)?|/api/data/ts|/health)'
    r'[^"]*" (?:2\d\d|304) '
)


class QuietPollingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return not QUIET_GET_RE.search(record.getMessage())
        except Exception:
            return True
