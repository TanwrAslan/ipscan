"""Sistem kaynak limitleri: dosya tanimlayici butcesi ve guvenli es zamanlilik.

Amac: tarayicinin hizli olmasi ama makineyi (ve agi) bogmamasi. Es zamanli
soket sayisi her zaman acilabilir fd sayisinin altinda tutulur.
"""

from __future__ import annotations

import os
import sys

try:
    import resource  # POSIX
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

# Uygulamanin kendi kullanimi (stdio, log, HTTP baglantilari) icin ayrilan pay.
FD_HEADROOM = 256
# Otomatik tavan: ephemeral port havuzu ve TIME_WAIT birikimini korumak icin.
AUTO_CONCURRENCY_CAP = 8192
# Kullanici acikca istese bile asilmayan tavan (yerel ephemeral port havuzu
# ~28k civari; ustune cikmak EADDRNOTAVAIL hatasi uretir).
HARD_CONCURRENCY_CAP = 32_768
DEFAULT_CONCURRENCY = 1024
MIN_CONCURRENCY = 16


def fd_soft_limit() -> int:
    """Mevcut (gerekirse yukseltilmis) soft fd limitini dondurur."""
    if resource is None:
        return 512
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < hard:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
            soft = hard
        except (ValueError, OSError):
            pass
    if soft in (resource.RLIM_INFINITY, -1):
        return AUTO_CONCURRENCY_CAP + FD_HEADROOM
    return int(soft)


def fd_budget() -> int:
    """Tarama icin guvenle kullanilabilecek es zamanli soket sayisi."""
    return max(MIN_CONCURRENCY, fd_soft_limit() - FD_HEADROOM)


def safe_concurrency(requested: int | None, total_probes: int | None = None
                     ) -> tuple[int, str | None]:
    """Istenen es zamanlilik degerini guvenli araliga sikistirir.

    Donen ikinci deger, degeri dusurmek zorunda kaldiysak kullaniciya
    gosterilecek aciklamadir.
    """
    note = None
    value = DEFAULT_CONCURRENCY if requested is None else int(requested)
    if value < 1:
        raise ValueError("Es zamanlilik en az 1 olmali.")

    budget = min(fd_budget(), HARD_CONCURRENCY_CAP)
    if value > budget:
        note = (f"Es zamanlilik {value} -> {budget} dusuruldu "
                f"(fd limiti {fd_soft_limit()}, tavan {HARD_CONCURRENCY_CAP}).")
        value = budget

    if requested is None and value > AUTO_CONCURRENCY_CAP:
        value = AUTO_CONCURRENCY_CAP

    if total_probes is not None and value > total_probes:
        value = max(1, total_probes)

    return max(1, value), note


def describe_limits() -> dict[str, int | str]:
    """Arayuzde gosterilecek ozet."""
    return {
        "platform": sys.platform,
        "pid": os.getpid(),
        "fd_soft_limit": fd_soft_limit(),
        "fd_budget": fd_budget(),
        "max_concurrency": min(fd_budget(), HARD_CONCURRENCY_CAP),
        "default_concurrency": DEFAULT_CONCURRENCY,
        "auto_cap": AUTO_CONCURRENCY_CAP,
    }
