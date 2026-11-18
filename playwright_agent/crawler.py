from __future__ import annotations

from collections import deque
from pathlib import Path

from .input_surface import collect_input_surface
from .models import PageSnapshot
from .network import normalize_endpoint_from_response
from .url_utils import extract_surface, in_scope, normalize_url


def crawl(runtime, target_url: str, scope: list[str], max_pages: int = 50, max_depth: int = 3, allow_external: bool = False, evidence_dir: str | Path = "evidence", screenshot: bool = True) -> list[PageSnapshot]:
    evidence_dir = Path(evidence_dir)
    pages_dir = evidence_dir / "pages"
    pages_dir.mkdir(parents=True, exist_ok=True)
    queue = deque([(normalize_url(target_url), 0)])
    seen: set[str] = set()
    snapshots: list[PageSnapshot] = []

    while queue and len(seen) < max_pages:
        url, depth = queue.popleft()
        norm = normalize_url(url)
        if norm in seen:
            continue
        if not in_scope(norm, scope, allow_external=allow_external):
            continue
        seen.add(norm)
        try:
            # Gentle inter-page delay to avoid triggering rate limits
            if len(seen) > 1:
                import time as _time
                _time.sleep(1.5)
            response = runtime.goto(norm)
            runtime.page.wait_for_timeout(500)
            runtime.harvest_agent_events()  # drena rotas SPA + fetch/XHR in-page
            html = runtime.page.content()
            title = runtime.page.title()
            current_url = normalize_url(runtime.page.url)
            surface = extract_surface(html, current_url)
            inputs = collect_input_surface(html, current_url)
            page_snapshot = PageSnapshot(
                url=current_url,
                depth=depth,
                title=title,
                status=response.status if response else None,
                html_path=str(_save_html(pages_dir, current_url, html)),
                screenshot_path=str(_save_screenshot(runtime, pages_dir, current_url) or "") if screenshot else "",
                links=surface["links"],
                forms=surface["forms"],
                scripts=surface["scripts"],
                inputs=inputs,
                endpoints=[normalize_endpoint_from_response(response, source_page=current_url)] if response else [],
                console=[],
                js=[],  # JS é analisado uma vez no nível da sessão (evita O(páginas×js))
                notes=[],
            )
            snapshots.append(page_snapshot)
            if depth < max_depth:
                discovered = list(surface["links"])
                if runtime.spa_routes:
                    discovered.extend(runtime.spa_routes)
                    runtime.spa_routes.clear()
                for link in discovered:
                    if in_scope(link, scope, allow_external=allow_external):
                        queue.append((normalize_url(link), depth + 1))
        except Exception as exc:
            snapshots.append(PageSnapshot(url=norm, depth=depth, notes=[f"crawl_error: {exc}"]))
    return snapshots


def _save_html(pages_dir: Path, url: str, html: str) -> Path:
    from .file_utils import atomic_write_text, slugify_filename

    path = pages_dir / f"{slugify_filename(url)}.html"
    atomic_write_text(path, html)
    return path


def _save_screenshot(runtime, pages_dir: Path, url: str) -> Path | None:
    from .file_utils import slugify_filename

    path = pages_dir / f"{slugify_filename(url)}.png"
    try:
        runtime.page.screenshot(path=str(path), full_page=True)
    except Exception:
        return None
    return path
