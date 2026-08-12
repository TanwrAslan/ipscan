"""Asenkron TCP connect tarama motoru.

Tasarim notlari
---------------
* Ham soket (SYN) taramasi yok -> root/CAP_NET_RAW gerekmez, ayricalik yukseltme
  yuzeyi olusmaz. Sadece standart TCP connect denemesi yapilir.
* Isler sinirli sayida worker tarafindan tuketilir; hedef listesi tembel
  uretilir, boylece 5 milyon prob bile sabit bellekte calisir.
* Basarili baglantilar SO_LINGER=0 ile kapatilir: kernel RST gonderir ve
  binlerce TIME_WAIT soketi birikmez (yerel sistemi korur).
* Opsiyonel token-bucket hiz limiti ile saniyedeki prob sayisi sinirlanabilir.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import socket
import struct
import time
from dataclasses import dataclass, asdict
from typing import AsyncIterator, Callable, Iterable, Iterator

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
UNREACHABLE = "unreachable"
ERROR = "error"

STATES = (OPEN, CLOSED, FILTERED, UNREACHABLE, ERROR)

# errno -> durum eslesmesi
_ERRNO_STATE = {
    errno.ECONNREFUSED: CLOSED,
    errno.ECONNRESET: CLOSED,
    errno.EHOSTUNREACH: UNREACHABLE,
    errno.ENETUNREACH: UNREACHABLE,
    errno.EHOSTDOWN: UNREACHABLE,
    errno.ENETDOWN: UNREACHABLE,
    errno.ETIMEDOUT: FILTERED,
    errno.EACCES: FILTERED,
    errno.EPERM: FILTERED,
}

_FD_ERRNOS = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM}

# Banner okuma icin ust sinirlar (bellek guvenligi).
BANNER_MAX_BYTES = 256
BANNER_TIMEOUT = 0.6

_LINGER_OFF = struct.pack("ii", 1, 0)  # onoff=1, linger=0 -> kapatirken RST


@dataclass(slots=True)
class Result:
    """Tek bir host:port probunun sonucu."""

    host: str
    port: int
    state: str
    latency_ms: float
    detail: str = ""
    banner: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class Stats:
    total: int = 0
    done: int = 0
    open: int = 0
    closed: int = 0
    filtered: int = 0
    unreachable: int = 0
    error: int = 0
    fd_exhausted: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    def record(self, result: Result) -> None:
        self.done += 1
        setattr(self, result.state, getattr(self, result.state) + 1)

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.monotonic()
        return max(0.0, end - self.started_at) if self.started_at else 0.0

    @property
    def rate(self) -> float:
        return self.done / self.elapsed if self.elapsed > 0 else 0.0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["elapsed"] = round(self.elapsed, 3)
        data["rate"] = round(self.rate, 1)
        return data


class RateLimiter:
    """Basit token-bucket. rate=None ise limit yok."""

    def __init__(self, rate: float | None, burst: float | None = None):
        self.rate = rate
        self.capacity = burst if burst is not None else (rate or 0)
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if not self.rate:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


def _family_for(host: str) -> int:
    try:
        return (socket.AF_INET6
                if ipaddress.ip_address(host).version == 6 else socket.AF_INET)
    except ValueError:
        return socket.AF_INET


async def probe(host: str, port: int, timeout: float, *,
                family: int | None = None, banner: bool = False) -> Result:
    """Tek bir TCP connect denemesi yapar ve sonucu dondurur."""
    loop = asyncio.get_running_loop()
    fam = family if family is not None else _family_for(host)
    start = time.perf_counter()
    sock: socket.socket | None = None
    try:
        sock = socket.socket(fam, socket.SOCK_STREAM)
    except OSError as exc:
        return Result(host, port, ERROR, 0.0,
                      detail=f"soket acilamadi: {exc.strerror or exc}")

    try:
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout)
        except asyncio.TimeoutError:
            return Result(host, port, FILTERED,
                          round((time.perf_counter() - start) * 1000, 3),
                          detail=f"{timeout:.2f}s icinde yanit yok")
        except ConnectionRefusedError:
            return Result(host, port, CLOSED,
                          round((time.perf_counter() - start) * 1000, 3),
                          detail="baglanti reddedildi")
        except OSError as exc:
            code = exc.errno or 0
            state = _ERRNO_STATE.get(code, ERROR)
            detail = exc.strerror or str(exc)
            if code in _FD_ERRNOS:
                detail = f"kaynak yetersiz ({detail})"
            return Result(host, port, state,
                          round((time.perf_counter() - start) * 1000, 3),
                          detail=detail)

        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
        text = None
        if banner:
            text = await _read_banner(loop, sock)
        # Basarili baglantiyi RST ile kapat: TIME_WAIT birikmesin.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_OFF)
        except OSError:
            pass
        return Result(host, port, OPEN, elapsed_ms, banner=text)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


async def _read_banner(loop: asyncio.AbstractEventLoop,
                       sock: socket.socket) -> str | None:
    """Servisin kendiliginden gonderdigi ilk baytlari okur (pasif)."""
    try:
        data = await asyncio.wait_for(
            loop.sock_recv(sock, BANNER_MAX_BYTES), BANNER_TIMEOUT)
    except (asyncio.TimeoutError, OSError):
        return None
    if not data:
        return None
    return data.decode("utf-8", "replace").replace("\r", " ").replace(
        "\n", " ").strip()[:BANNER_MAX_BYTES] or None


class Scanner:
    """Sinirli worker havuzuyla calisan tarayici."""

    def __init__(
        self,
        *,
        concurrency: int = 1024,
        timeout: float = 1.0,
        retries: int = 1,
        rate: float | None = None,
        banner: bool = False,
    ):
        if concurrency < 1:
            raise ValueError("concurrency >= 1 olmali")
        if timeout <= 0:
            raise ValueError("timeout > 0 olmali")
        if retries < 0:
            raise ValueError("retries >= 0 olmali")
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.banner = banner
        self._limiter = RateLimiter(rate, burst=max(rate or 0, concurrency))
        self.stats = Stats()

    async def run(
        self,
        pairs: Iterable[tuple[str, int]] | Iterator[tuple[str, int]],
        *,
        total: int = 0,
        cancel: asyncio.Event | None = None,
    ) -> AsyncIterator[Result]:
        """Sonuclari tamamlandikca (streaming) uretir."""
        self.stats = Stats(total=total, started_at=time.monotonic())
        cancel = cancel or asyncio.Event()

        work: asyncio.Queue = asyncio.Queue(maxsize=self.concurrency * 2)
        out: asyncio.Queue = asyncio.Queue(maxsize=self.concurrency * 4)
        sentinel = object()

        async def producer() -> None:
            try:
                for pair in pairs:
                    if cancel.is_set():
                        break
                    await work.put(pair)
            finally:
                for _ in range(self.concurrency):
                    await work.put(sentinel)

        async def worker() -> None:
            while True:
                item = await work.get()
                if item is sentinel:
                    await out.put(sentinel)
                    return
                if cancel.is_set():
                    continue
                host, port = item
                await self._limiter.acquire()
                result = await probe(host, port, self.timeout, banner=self.banner)
                # Yalnizca "filtered" sonuclar yeniden denenir: paket kaybi
                # yuzunden yanlis pozitif olmasin.
                attempts = 0
                while (result.state == FILTERED and attempts < self.retries
                       and not cancel.is_set()):
                    attempts += 1
                    await self._limiter.acquire()
                    result = await probe(host, port, self.timeout,
                                         banner=self.banner)
                await out.put(result)

        tasks = [asyncio.create_task(producer())]
        tasks += [asyncio.create_task(worker()) for _ in range(self.concurrency)]

        finished = 0
        try:
            while finished < self.concurrency:
                item = await out.get()
                if item is sentinel:
                    finished += 1
                    continue
                self.stats.record(item)
                if item.state == ERROR and "kaynak yetersiz" in item.detail:
                    self.stats.fd_exhausted += 1
                yield item
        finally:
            self.stats.finished_at = time.monotonic()
            cancel.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def scan(
    hosts: list[str],
    ports: list[int],
    *,
    concurrency: int = 1024,
    timeout: float = 1.0,
    retries: int = 1,
    rate: float | None = None,
    banner: bool = False,
    on_result: Callable[[Result], None] | None = None,
    cancel: asyncio.Event | None = None,
) -> tuple[list[Result], Stats]:
    """Kolaylik fonksiyonu: taramayi calistirir, tum sonuclari toplar."""
    from .targets import iter_pairs

    scanner = Scanner(concurrency=concurrency, timeout=timeout,
                      retries=retries, rate=rate, banner=banner)
    total = len(hosts) * len(ports)
    results: list[Result] = []
    async for result in scanner.run(iter_pairs(hosts, ports), total=total,
                                    cancel=cancel):
        results.append(result)
        if on_result:
            on_result(result)
    return results, scanner.stats
