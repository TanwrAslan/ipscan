"""Sonuc bicimlendirme: terminal tablosu, JSON, CSV, ndjson."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

from .engine import OPEN, Result, Stats

_COLORS = {
    "open": "\033[32m",
    "closed": "\033[90m",
    "filtered": "\033[33m",
    "unreachable": "\033[35m",
    "error": "\033[31m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

_TR = {
    "open": "ACIK",
    "closed": "kapali",
    "filtered": "filtreli",
    "unreachable": "erisilemez",
    "error": "hata",
}


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def colorize(text: str, key: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['reset']}"


def state_label(state: str) -> str:
    return _TR.get(state, state)


def format_line(result: Result, color: bool = False) -> str:
    """Tek satirlik canli cikti."""
    host = f"{result.host}:{result.port}"
    label = state_label(result.state)
    line = f"{host:<46} {label:<11} {result.latency_ms:7.1f} ms"
    if result.banner:
        line += f"  {result.banner[:60]}"
    elif result.detail and result.state != OPEN:
        line += f"  {result.detail}"
    return colorize(line, result.state, color)


def sort_key(result: Result):
    import ipaddress
    try:
        return (0, int(ipaddress.ip_address(result.host)), result.port)
    except ValueError:
        return (1, result.host, result.port)


def render_table(results: list[Result], color: bool = False) -> str:
    """Ozet tablo (yalnizca verilen sonuclar)."""
    if not results:
        return "Gosterilecek sonuc yok."
    rows = sorted(results, key=sort_key)
    width = max(len(f"{r.host}:{r.port}") for r in rows) + 2
    out = io.StringIO()
    header = f"{'HEDEF':<{width}} {'DURUM':<11} {'SURE':>10}   AYRINTI"
    out.write(colorize(header, "bold", color) + "\n")
    out.write(colorize("-" * (width + 40), "dim", color) + "\n")
    for r in rows:
        target = f"{r.host}:{r.port}"
        extra = r.banner or r.detail or ""
        line = (f"{target:<{width}} {state_label(r.state):<11} "
                f"{r.latency_ms:7.1f} ms   {extra[:70]}")
        out.write(colorize(line, r.state, color) + "\n")
    return out.getvalue().rstrip("\n")


def render_summary(stats: Stats, color: bool = False) -> str:
    parts = [
        colorize(f"{stats.open} acik", "open", color),
        colorize(f"{stats.closed} kapali", "closed", color),
        colorize(f"{stats.filtered} filtreli", "filtered", color),
    ]
    if stats.unreachable:
        parts.append(colorize(f"{stats.unreachable} erisilemez", "unreachable", color))
    if stats.error:
        parts.append(colorize(f"{stats.error} hata", "error", color))
    body = " | ".join(parts)
    tail = (f"{stats.done}/{stats.total} prob, {stats.elapsed:.2f} sn, "
            f"{stats.rate:,.0f} prob/sn")
    return f"{body}\n{colorize(tail, 'dim', color)}"


def to_json(results: list[Result], stats: Stats, meta: dict | None = None) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "meta": meta or {},
        "stats": stats.to_dict(),
        "results": [r.to_dict() for r in sorted(results, key=sort_key)],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


# Excel/LibreOffice bu karakterlerle baslayan hucreleri formul olarak yorumlar.
_CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value) -> str:
    """CSV formul enjeksiyonuna karsi hucreyi notrler.

    Banner metni uzak sunucudan gelir; '=cmd|...' ile baslayan bir banner
    elektronik tabloda acildiginda komut calistirabilir. Basina tirnak
    koyarak metin olarak kalmasini garanti ederiz.
    """
    text = "" if value is None else str(value)
    if text.startswith(_CSV_INJECTION_PREFIXES):
        return "'" + text
    return text


def to_csv(results: list[Result]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(["host", "port", "state", "latency_ms", "detail", "banner"])
    for r in sorted(results, key=sort_key):
        writer.writerow([r.host, r.port, r.state, f"{r.latency_ms:.1f}",
                         csv_safe(r.detail), csv_safe(r.banner)])
    return buf.getvalue()


def to_ndjson(result: Result) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False)


def write_file(path: str, content: str) -> None:
    """Cikti dosyasini yalnizca sahibin okuyabilecegi izinlerle yazar."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
