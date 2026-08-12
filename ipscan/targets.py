"""Hedef (IP/CIDR/aralik/hostname) ve port ayristirma + dogrulama.

Buradaki tek is: kullanicidan gelen serbest metni, guvenli sekilde
dogrulanmis IP adresi ve port listelerine cevirmek. Hicbir kabuk komutu
calistirilmaz, hicbir girdi eval edilmez.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

# Kaynak tuketimini sinirlamak icin ust sinirlar (sistem "sikinti cikarmasin").
MAX_TARGETS = 65_536
MAX_PORTS = 65_535
MAX_PAIRS = 5_000_000  # hedef x port toplam kombinasyon tavani
MAX_INPUT_CHARS = 256 * 1024

# En sik kullanilan portlar (nmap top-N listelerinden turetilmis kisa setler).
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 53, 67, 68, 69, 80, 81, 88, 106, 110, 111, 113,
    119, 123, 135, 137, 138, 139, 143, 144, 161, 179, 199, 389, 427, 443, 444,
    445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873, 990,
    993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723, 1755,
    1900, 2000, 2001, 2049, 2121, 2181, 2375, 2376, 2717, 3000, 3128, 3268,
    3306, 3389, 3690, 3986, 4444, 4899, 5000, 5009, 5060, 5101, 5190, 5357,
    5432, 5631, 5666, 5672, 5800, 5900, 5985, 6000, 6379, 6646, 7070, 8000,
    8008, 8009, 8080, 8081, 8443, 8888, 9090, 9100, 9200, 9300, 11211, 27017,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

WEB_PORTS = [80, 81, 443, 591, 3000, 3128, 4443, 5000, 8000, 8008, 8080, 8081,
             8088, 8443, 8888, 9000, 9090, 9443]

DB_PORTS = [1433, 1521, 3050, 3306, 5000, 5432, 5984, 6379, 7000, 7199, 8086,
            9042, 9200, 11211, 27017, 27018, 28017, 50000]

REMOTE_PORTS = [22, 23, 3389, 5432, 5800, 5900, 5901, 5985, 5986, 623, 902]

NAMED_PORT_SETS = {
    "top100": TOP_100_PORTS,
    "web": WEB_PORTS,
    "db": DB_PORTS,
    "remote": REMOTE_PORTS,
    "all": list(range(1, 65536)),
    "-": list(range(1, 65536)),
}

# RFC 1123 hostname; yalnizca harf/rakam/tire/nokta kabul edilir.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class TargetError(ValueError):
    """Gecersiz veya guvenli olmayan hedef/port girdisi."""


@dataclass
class TargetSet:
    """Ayristirilmis hedefler ve ayristirma sirasinda olusan uyarilar."""

    hosts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    resolved: dict[str, str] = field(default_factory=dict)  # hostname -> ip

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.hosts)


def _split_tokens(raw: str | list[str]) -> list[str]:
    """Virgul, bosluk, noktali virgul ve satir sonlarina gore boler."""
    if isinstance(raw, (list, tuple)):
        raw = "\n".join(str(x) for x in raw)
    if len(raw) > MAX_INPUT_CHARS:
        raise TargetError(
            f"Girdi cok buyuk ({len(raw)} karakter, sinir {MAX_INPUT_CHARS})."
        )
    # Yorum satirlarini at
    lines = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0]
        lines.append(line)
    tokens = re.split(r"[\s,;]+", "\n".join(lines))
    return [t.strip() for t in tokens if t.strip()]


# ---------------------------------------------------------------- portlar ---

def parse_ports(spec: str | list[str]) -> list[int]:
    """'22,80,443,8000-8100' veya 'top100' gibi ifadeleri port listesine cevirir.

    Sonuc siralanmis ve tekillestirilmistir.
    """
    tokens = _split_tokens(spec)
    if not tokens:
        raise TargetError("Port belirtilmedi.")

    ports: set[int] = set()
    for token in tokens:
        low = token.lower()
        if low in NAMED_PORT_SETS:
            ports.update(NAMED_PORT_SETS[low])
            continue
        if "-" in low:  # tek basina "-" yukarida named set olarak yakalandi
            start_s, _, end_s = low.partition("-")
            if not start_s:
                start_s = "1"
            if not end_s:
                end_s = "65535"
            start, end = _port_int(start_s), _port_int(end_s)
            if start > end:
                start, end = end, start
            if end - start + 1 > MAX_PORTS:
                raise TargetError(f"Port araligi cok genis: {token}")
            ports.update(range(start, end + 1))
            continue
        ports.add(_port_int(low))

    if not ports:
        raise TargetError("Gecerli port bulunamadi.")
    if len(ports) > MAX_PORTS:
        raise TargetError(f"Cok fazla port ({len(ports)} > {MAX_PORTS}).")
    return sorted(ports)


def _port_int(text: str) -> int:
    if not text.isdigit():
        raise TargetError(f"Gecersiz port: {text!r}")
    value = int(text)
    if not 1 <= value <= 65535:
        raise TargetError(f"Port araligi disinda: {value} (1-65535 olmali)")
    return value


# --------------------------------------------------------------- hedefler ---

def parse_targets(
    spec: str | list[str],
    *,
    resolve: bool = False,
    max_targets: int = MAX_TARGETS,
) -> TargetSet:
    """Hedef ifadelerini dogrulanmis IP adresi listesine cevirir.

    Desteklenen bicimler:
      * 192.168.1.10                    tek IP (IPv4/IPv6)
      * 192.168.1.0/24                  CIDR
      * 192.168.1.10-20                 son oktet araligi
      * 192.168.1.10-192.168.1.40       tam IP araligi
      * example.com                     (yalnizca resolve=True ise)
    """
    tokens = _split_tokens(spec)
    if not tokens:
        raise TargetError("Hedef belirtilmedi.")

    result = TargetSet()
    seen: set[str] = set()

    def add(ip_text: str) -> None:
        if ip_text in seen:
            return
        if len(seen) >= max_targets:
            raise TargetError(
                f"Cok fazla hedef (sinir {max_targets}). "
                f"--max-targets ile artirabilirsiniz."
            )
        seen.add(ip_text)
        result.hosts.append(ip_text)

    for token in tokens:
        for ip_text, warn in _expand_token(token, resolve=resolve,
                                           remaining=max_targets - len(seen),
                                           resolved=result.resolved):
            if warn:
                result.warnings.append(warn)
            add(ip_text)

    if not result.hosts:
        raise TargetError("Gecerli hedef bulunamadi.")
    return result


def _expand_token(token: str, *, resolve: bool, remaining: int,
                  resolved: dict[str, str]):
    """Tek bir hedef ifadesini (ip, uyari) ciftlerine acar."""
    # 1) CIDR
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise TargetError(f"Gecersiz CIDR: {token!r} ({exc})") from exc
        count = net.num_addresses
        hosts_iter = net.hosts() if count > 2 else iter(net)
        usable = count - 2 if count > 2 else count
        if usable > remaining:
            raise TargetError(
                f"{token} icinde {usable} adres var, kalan kota {remaining}. "
                f"Daha dar bir aralik verin veya --max-targets kullanin."
            )
        for addr in hosts_iter:
            yield str(addr), None
        return

    # 2) Aralik: a.b.c.d-e  veya  a.b.c.d-a.b.c.e
    if "-" in token and not _looks_like_ipv6(token):
        start_s, _, end_s = token.partition("-")
        try:
            start = ipaddress.ip_address(start_s)
        except ValueError as exc:
            raise TargetError(f"Gecersiz aralik baslangici: {start_s!r}") from exc
        if end_s.isdigit() and isinstance(start, ipaddress.IPv4Address):
            octets = start_s.split(".")
            end = ipaddress.ip_address(".".join(octets[:3] + [end_s]))
        else:
            try:
                end = ipaddress.ip_address(end_s)
            except ValueError as exc:
                raise TargetError(f"Gecersiz aralik sonu: {end_s!r}") from exc
        if start.version != end.version:
            raise TargetError(f"Aralikta IP surumleri uyusmuyor: {token!r}")
        lo, hi = int(start), int(end)
        if lo > hi:
            lo, hi = hi, lo
        span = hi - lo + 1
        if span > remaining:
            raise TargetError(
                f"{token} araliginda {span} adres var, kalan kota {remaining}."
            )
        for value in range(lo, hi + 1):
            yield str(ipaddress.ip_address(value)), None
        return

    # 3) Duz IP
    try:
        yield str(ipaddress.ip_address(token)), None
        return
    except ValueError:
        pass

    # 4) Hostname
    # Yalnizca rakam ve noktadan olusuyorsa bu bozuk bir IP'dir, alan adi degil.
    if all(ch.isdigit() or ch == "." for ch in token):
        raise TargetError(f"Gecersiz IP adresi: {token!r}")
    if not _HOSTNAME_RE.match(token):
        raise TargetError(f"Gecersiz hedef: {token!r}")
    if not resolve:
        raise TargetError(
            f"{token!r} bir alan adi. DNS cozumlemesi kapali "
            f"(CLI: --resolve, web arayuzu: 'DNS cozumle' kutusu)."
        )
    addresses = _resolve_hostname(token)
    if not addresses:
        raise TargetError(f"DNS cozumlenemedi: {token!r}")
    resolved[token] = addresses[0]
    warn = None
    if len(addresses) > 1:
        warn = f"{token} -> {len(addresses)} adres cozumlendi: {', '.join(addresses)}"
    for addr in addresses:
        yield addr, warn
        warn = None


def _looks_like_ipv6(token: str) -> bool:
    return token.count(":") >= 2


def _resolve_hostname(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out


def check_pair_budget(host_count: int, port_count: int,
                      max_pairs: int = MAX_PAIRS) -> int:
    """Toplam prob sayisini dogrular ve dondurur."""
    total = host_count * port_count
    if total > max_pairs:
        raise TargetError(
            f"Toplam {total:,} prob istendi, sinir {max_pairs:,}. "
            f"Hedef veya port sayisini azaltin."
        )
    return total


def iter_pairs(hosts: list[str], ports: list[int]):
    """(host, port) ciftlerini port-major sirayla uretir.

    Port-major sira, ayni ana surekli ust uste baglanti acmak yerine yuku
    hedefler arasina yayar; bu hem daha kibar hem de daha az paket kaybi demek.
    """
    for port in ports:
        for host in hosts:
            yield host, port
