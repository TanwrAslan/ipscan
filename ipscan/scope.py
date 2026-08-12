"""Kapsam (scope) denetimi: yalnizca izin verilen aglara tarama.

Yanlislikla yetkisiz bir agi taramayi engellemek icin, hedeflerin bir
izin listesi (scope dosyasi) icinde olmasi sart kosulabilir.

Modlar:
  auto   - scope dosyasi varsa zorunlu kilar, yoksa uyarip devam eder (varsayilan)
  strict - scope dosyasi zorunlu; yoksa veya hedef disaridaysa tarama baslamaz
  off    - kapsam denetimi kapali (yalnizca bilgilendirici uyarilar)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SCOPE_FILES = ("scope.txt", "ipscan-scope.txt")
MODES = ("auto", "strict", "off")


class ScopeError(PermissionError):
    """Hedef izin verilen kapsamin disinda."""


@dataclass
class Scope:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=list)
    source: str | None = None
    mode: str = "auto"

    @property
    def active(self) -> bool:
        """Kapsam kurallari gercekten uygulanacak mi?"""
        return self.mode != "off" and bool(self.networks)

    def contains(self, ip_text: str) -> bool:
        addr = ipaddress.ip_address(ip_text)
        return any(addr in net for net in self.networks)

    def describe(self) -> str:
        if self.mode == "off":
            return "kapsam denetimi kapali"
        if not self.networks:
            return "kapsam dosyasi yok"
        return f"{len(self.networks)} ag ({self.source})"


def load_scope(path: str | None = None, mode: str = "auto",
               base_dir: str | Path = ".") -> Scope:
    """Scope dosyasini yukler. path verilmezse varsayilan adlar aranir."""
    if mode not in MODES:
        raise ValueError(f"Gecersiz kapsam modu: {mode!r} (secenekler: {MODES})")

    scope = Scope(mode=mode)
    candidate: Path | None = None

    if path:
        candidate = Path(path).expanduser()
        if not candidate.is_file():
            raise ScopeError(f"Kapsam dosyasi bulunamadi: {candidate}")
    else:
        for name in DEFAULT_SCOPE_FILES:
            probe = Path(base_dir) / name
            if probe.is_file():
                candidate = probe
                break

    if candidate is None:
        if mode == "strict":
            raise ScopeError(
                "strict modda kapsam dosyasi zorunlu. Ornek: scope.txt olustur "
                "veya --scope ile yol ver."
            )
        return scope

    scope.source = str(candidate)
    text = candidate.read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            scope.networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError as exc:
            raise ScopeError(
                f"{candidate}:{lineno} gecersiz ag tanimi: {line!r} ({exc})"
            ) from exc

    if not scope.networks and mode == "strict":
        raise ScopeError(f"{candidate} bos: strict modda en az bir ag gerekli.")
    return scope


def enforce(scope: Scope, hosts: list[str]) -> list[str]:
    """Kapsam disi hedefleri denetler.

    Kapsam etkinse ihlalde ScopeError firlatir; degilse yalnizca uyari doner.
    """
    if scope.mode == "off":
        return []

    if not scope.networks:
        return [
            "Kapsam dosyasi yok: tarama kisitlanmadan calisacak. "
            "Yalnizca yetkili oldugunuz adresleri taradiginizdan emin olun."
        ]

    outside = [h for h in hosts if not scope.contains(h)]
    if outside:
        preview = ", ".join(outside[:5])
        more = f" (+{len(outside) - 5} adet daha)" if len(outside) > 5 else ""
        raise ScopeError(
            f"{len(outside)} hedef kapsam disinda: {preview}{more}. "
            f"Kapsam kaynagi: {scope.source}"
        )
    return []


def public_targets(hosts: list[str]) -> list[str]:
    """Ozel/lokal olmayan (internete acik) hedefleri dondurur."""
    out = []
    for h in hosts:
        try:
            addr = ipaddress.ip_address(h)
        except ValueError:
            continue
        if addr.is_global:
            out.append(h)
    return out
