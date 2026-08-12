"""Yerel web arayuzu (varsayilan: http://127.0.0.1:8787).

Guvenlik onlemleri
------------------
* Yalnizca loopback'e baglanir; disari acmak icin acik onay (IPSCAN_ALLOW_REMOTE)
  ve --host parametresi gerekir.
* Her calistirmada rastgele oturum jetonu uretilir; jeton URL ile bir kez
  verilir, sonra HttpOnly + SameSite=Strict cerezde tutulur.
* Host basligi allowlist'e karsi dogrulanir -> DNS rebinding engellenir.
* API istekleri Sec-Fetch-Site / Origin denetiminden gecer -> CSRF engellenir.
* Sert CSP; hicbir harici kaynak yuklenmez, satir ici script yok.
* Istek govdesi ve is sayisi sinirlidir; hicbir girdi shell'e verilmez.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import mimetypes
import os
import queue
import secrets
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, limits, report, scope as scope_mod
from .engine import OPEN, Result, Scanner
from .targets import (MAX_TARGETS, TargetError, check_pair_budget, iter_pairs,
                      parse_ports, parse_targets)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_ROUTES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/app.js": "app.js",
    "/style.css": "style.css",
}

MAX_BODY = 256 * 1024          # 256 KB istek govdesi
MAX_ACTIVE_JOBS = 2            # es zamanli tarama isi
MAX_JOBS_KEPT = 20             # bellekte tutulan is gecmisi
MAX_RETAINED_OPEN = 200_000    # bellekte tutulan acik port sonucu
MAX_RETAINED_ALL = 100_000     # tum durumlarin tutuldugu esik
MAX_SSE_CLIENTS = 8
JOB_TTL = 3600.0               # 1 saat sonra eski isler temizlenir

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
       "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")


# --------------------------------------------------------------------- is ---

@dataclass
class Job:
    id: str
    hosts: list[str]
    ports: list[int]
    options: dict
    state: str = "queued"          # queued | running | done | cancelled | error
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    results: list[Result] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    keep_all: bool = False
    _subscribers: list[queue.Queue] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    cancel_event: asyncio.Event | None = None

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=4096)
        with self._lock:
            if len(self._subscribers) >= MAX_SSE_CLIENTS:
                raise RuntimeError("cok fazla acik baglanti")
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event: str, data: dict) -> None:
        payload = (event, data)
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(payload)
            except queue.Full:
                pass  # yavas istemci: olay dusurulur, tarama yavaslamaz

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "state": self.state,
            "error": self.error,
            "stats": self.stats,
            "options": self.options,
            "hosts": len(self.hosts),
            "ports": len(self.ports),
            "created_at": self.created_at,
        }


class JobManager:
    """Arka planda tek bir asyncio dongusunde isleri yurutur."""

    def __init__(self, scope: scope_mod.Scope):
        self.scope = scope
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True,
                                        name="ipscan-engine")
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _gc(self) -> None:
        now = time.time()
        stale = [jid for jid, job in self.jobs.items()
                 if job.state in ("done", "cancelled", "error")
                 and now - job.created_at > JOB_TTL]
        for jid in stale:
            self.jobs.pop(jid, None)
        while len(self.jobs) > MAX_JOBS_KEPT:
            oldest = min(self.jobs.values(), key=lambda j: j.created_at)
            if oldest.state == "running":
                break
            self.jobs.pop(oldest.id, None)

    def active_count(self) -> int:
        return sum(1 for j in self.jobs.values()
                   if j.state in ("queued", "running"))

    def submit(self, hosts: list[str], ports: list[int], options: dict) -> Job:
        with self._lock:
            self._gc()
            if self.active_count() >= MAX_ACTIVE_JOBS:
                raise RuntimeError(
                    f"Ayni anda en fazla {MAX_ACTIVE_JOBS} tarama calisabilir.")
            job = Job(id=uuid.uuid4().hex, hosts=hosts, ports=ports,
                      options=options)
            job.keep_all = len(hosts) * len(ports) <= MAX_RETAINED_ALL
            self.jobs[job.id] = job
        asyncio.run_coroutine_threadsafe(self._execute(job), self._loop)
        return job

    def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        if not job or job.state not in ("queued", "running"):
            return False
        event = job.cancel_event
        if event is not None:
            self._loop.call_soon_threadsafe(event.set)
        job.state = "cancelled"
        return True

    async def _execute(self, job: Job) -> None:
        opts = job.options
        job.cancel_event = asyncio.Event()
        job.state = "running"
        job.publish("state", job.snapshot())

        scanner = Scanner(
            concurrency=opts["concurrency"], timeout=opts["timeout"],
            retries=opts["retries"], rate=opts.get("rate"),
            banner=opts.get("banner", False),
        )
        total = len(job.hosts) * len(job.ports)
        stream_all = opts.get("streamAll", False) and job.keep_all
        last_push = 0.0

        try:
            async for result in scanner.run(iter_pairs(job.hosts, job.ports),
                                            total=total,
                                            cancel=job.cancel_event):
                is_open = result.state == OPEN
                if is_open:
                    if len(job.results) < MAX_RETAINED_OPEN:
                        job.results.append(result)
                elif job.keep_all:
                    job.results.append(result)

                if is_open or stream_all:
                    job.publish("result", result.to_dict())

                now = time.monotonic()
                if now - last_push > 0.15:
                    last_push = now
                    job.stats = scanner.stats.to_dict()
                    job.publish("progress", job.stats)

            job.stats = scanner.stats.to_dict()
            if job.state != "cancelled":
                job.state = "done"
        except Exception as exc:  # pragma: no cover - beklenmeyen motor hatasi
            job.state = "error"
            job.error = f"{type(exc).__name__}: {exc}"
        finally:
            job.publish("progress", job.stats)
            job.publish("done", job.snapshot())


# ------------------------------------------------------------------ HTTP ---

class Handler(BaseHTTPRequestHandler):
    server_version = f"ipscan/{__version__}"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    # Yavas istemcinin (slowloris) is parcaciklarini tutmasini engeller.
    # SSE akisi 15 sn'de bir ping yazdigi icin bu sureden etkilenmez.
    timeout = 60

    # ---- yardimcilar ----
    def log_message(self, fmt: str, *args) -> None:  # daha sessiz erisim logu
        if os.environ.get("IPSCAN_HTTP_LOG"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _base_headers(self) -> None:
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Permissions-Policy",
                         "geolocation=(), microphone=(), camera=()")

    def _send(self, status: int, body: bytes, content_type: str,
              extra: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self._base_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    # ---- guvenlik denetimleri ----
    def _netloc_ok(self, netloc: str) -> bool:
        netloc = netloc.lower()
        if netloc in self.server.allowed_hosts:  # type: ignore[attr-defined]
            return True
        # Loopback disi (acikca izin verilmis) baglamada makinenin adi/IP'si
        # onceden bilinemez; port eslesmesi ve jeton denetimi yeterlidir.
        if self.server.any_host:  # type: ignore[attr-defined]
            _, sep, port = netloc.rpartition(":")
            return bool(sep) and port == str(self.server.server_address[1])
        return False

    def _host_ok(self) -> bool:
        """DNS rebinding'i engeller: Host basligi beklenen degerlerden biri mi?"""
        return self._netloc_ok(self.headers.get("Host") or "")

    def _token_from_cookie(self) -> str | None:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "ipscan_session":
                return value
        return None

    def _authed(self) -> bool:
        token = self._token_from_cookie() or ""
        return hmac.compare_digest(token, self.server.token)  # type: ignore

    def _same_origin(self) -> bool:
        """Tarayici kaynakli CSRF'i engeller."""
        site = self.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return False
        origin = self.headers.get("Origin")
        if origin and not self._netloc_ok(urlparse(origin).netloc):
            return False
        return True

    def _read_body(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "Gecersiz Content-Length")
            return None
        if length <= 0:
            return {}
        if length > MAX_BODY:
            # Govdeyi okumadan reddediyoruz; okunmamis baytlar ayni baglantida
            # yeni bir istek gibi yorumlanmasin diye baglantiyi kapatiyoruz
            # (HTTP desenkronizasyonu / request smuggling onlemi).
            self.close_connection = True
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        f"Istek govdesi cok buyuk (sinir {MAX_BODY} bayt)")
            return None
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "Gecersiz JSON")
            return None
        if not isinstance(data, dict):
            self._error(HTTPStatus.BAD_REQUEST, "JSON nesnesi bekleniyordu")
            return None
        return data

    # ---- yonlendirme ----
    def do_GET(self) -> None:
        if not self._host_ok():
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "Gecersiz Host basligi")
            return
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path in STATIC_ROUTES:
            self._serve_static(path, params)
            return
        if not self._authed() or not self._same_origin():
            self._error(HTTPStatus.UNAUTHORIZED, "Yetkisiz istek")
            return
        if path == "/api/config":
            self._api_config()
        elif path == "/api/stream":
            self._api_stream(params)
        elif path == "/api/job":
            self._api_job(params)
        elif path == "/api/export":
            self._api_export(params)
        else:
            self._error(HTTPStatus.NOT_FOUND, "Bulunamadi")

    def do_HEAD(self) -> None:
        # /api/stream sonsuz bir akistir; HEAD ile acilirsa is parcacigi asili
        # kalir. HEAD yalnizca statik yollarda desteklenir.
        if urlparse(self.path).path not in STATIC_ROUTES:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "HEAD desteklenmiyor")
            return
        self.do_GET()

    def do_POST(self) -> None:
        if not self._host_ok():
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "Gecersiz Host basligi")
            return
        if not self._authed() or not self._same_origin():
            self._error(HTTPStatus.UNAUTHORIZED, "Yetkisiz istek")
            return
        if self.headers.get("X-Requested-With") != "ipscan":
            self._error(HTTPStatus.FORBIDDEN, "Eksik istek basligi")
            return
        path = urlparse(self.path).path
        if path == "/api/scan":
            self._api_scan()
        elif path == "/api/cancel":
            self._api_cancel()
        else:
            self._error(HTTPStatus.NOT_FOUND, "Bulunamadi")

    # ---- statik ----
    def _serve_static(self, path: str, params: dict) -> None:
        token_param = (params.get("t") or [""])[0]
        authed = self._authed()
        extra: list[tuple[str, str]] = []

        if not authed:
            if not hmac.compare_digest(token_param, self.server.token):  # type: ignore
                self._send(HTTPStatus.UNAUTHORIZED,
                           b"Yetkisiz. Sunucunun yazdirdigi baglantiyi kullanin.",
                           "text/plain; charset=utf-8")
                return
            extra.append(("Set-Cookie",
                          f"ipscan_session={self.server.token}; Path=/; "  # type: ignore
                          f"HttpOnly; SameSite=Strict; Max-Age=86400"))

        name = STATIC_ROUTES[path]
        file_path = STATIC_DIR / name
        try:
            body = file_path.read_bytes()
        except OSError:
            self._error(HTTPStatus.NOT_FOUND, "Dosya yok")
            return
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        self._send(HTTPStatus.OK, body, f"{ctype}; charset=utf-8", extra)

    # ---- API ----
    def _api_config(self) -> None:
        scope = self.server.jobs.scope  # type: ignore[attr-defined]
        self._json(HTTPStatus.OK, {
            "version": __version__,
            "limits": limits.describe_limits(),
            "scope": {
                "mode": scope.mode,
                "source": scope.source,
                "networks": [str(n) for n in scope.networks],
                "active": scope.active,
                "describe": scope.describe(),
            },
            "maxTargets": MAX_TARGETS,
            "maxActiveJobs": MAX_ACTIVE_JOBS,
        })

    def _api_scan(self) -> None:
        data = self._read_body()
        if data is None:
            return
        manager: JobManager = self.server.jobs  # type: ignore[attr-defined]

        try:
            targets_raw = str(data.get("targets", ""))
            ports_raw = str(data.get("ports", ""))
            resolve = bool(data.get("resolve", False))
            target_set = parse_targets(targets_raw, resolve=resolve,
                                       max_targets=MAX_TARGETS)
            ports = parse_ports(ports_raw)
            total = check_pair_budget(len(target_set.hosts), len(ports))
        except TargetError as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
            return

        warnings = list(target_set.warnings)
        try:
            warnings += scope_mod.enforce(manager.scope, target_set.hosts)
        except scope_mod.ScopeError as exc:
            self._error(HTTPStatus.FORBIDDEN, f"Kapsam ihlali: {exc}")
            return

        public = scope_mod.public_targets(target_set.hosts)
        if public and not manager.scope.active:
            warnings.append(
                f"{len(public)} hedef internete acik adres. Yalnizca yetkili "
                f"oldugunuz sistemleri tarayin.")

        try:
            timeout = _clamp(float(data.get("timeout", 1.0)), 0.05, 15.0)
            retries = int(_clamp(int(data.get("retries", 1)), 0, 3))
            rate = data.get("rate")
            rate = float(rate) if rate else None
            if rate is not None:
                rate = _clamp(rate, 1.0, 500_000.0)
            requested_c = data.get("concurrency")
            requested_c = int(requested_c) if requested_c else None
        except (TypeError, ValueError):
            self._error(HTTPStatus.BAD_REQUEST, "Gecersiz sayisal parametre")
            return

        concurrency, note = limits.safe_concurrency(requested_c, total)
        if note:
            warnings.append(note)

        options = {
            "timeout": timeout, "retries": retries, "rate": rate,
            "concurrency": concurrency, "banner": bool(data.get("banner", False)),
            "streamAll": bool(data.get("streamAll", False)),
            "total": total, "resolve": resolve,
        }

        try:
            job = manager.submit(target_set.hosts, ports, options)
        except RuntimeError as exc:
            self._error(HTTPStatus.TOO_MANY_REQUESTS, str(exc))
            return

        self._json(HTTPStatus.OK, {
            "jobId": job.id, "total": total, "hosts": len(target_set.hosts),
            "ports": len(ports), "options": options, "warnings": warnings,
            "keepAll": job.keep_all,
        })

    def _api_cancel(self) -> None:
        data = self._read_body()
        if data is None:
            return
        job_id = str(data.get("jobId", ""))
        ok = self.server.jobs.cancel(job_id)  # type: ignore[attr-defined]
        self._json(HTTPStatus.OK, {"cancelled": ok})

    def _get_job(self, params: dict) -> Job | None:
        job_id = (params.get("job") or [""])[0]
        job = self.server.jobs.jobs.get(job_id)  # type: ignore[attr-defined]
        if job is None:
            self._error(HTTPStatus.NOT_FOUND, "Is bulunamadi")
            return None
        return job

    def _api_job(self, params: dict) -> None:
        job = self._get_job(params)
        if job:
            self._json(HTTPStatus.OK, job.snapshot())

    def _api_export(self, params: dict) -> None:
        job = self._get_job(params)
        if not job:
            return
        fmt = (params.get("fmt") or ["json"])[0]
        open_only = (params.get("open") or ["0"])[0] == "1"
        rows = [r for r in job.results if r.state == OPEN] if open_only \
            else list(job.results)

        from .engine import Stats
        stats = Stats(**{k: v for k, v in job.stats.items()
                         if k in Stats.__slots__}) if job.stats else Stats()

        if fmt == "csv":
            body = report.to_csv(rows).encode("utf-8")
            ctype = "text/csv; charset=utf-8"
            name = f"ipscan-{job.id[:8]}.csv"
        else:
            body = report.to_json(rows, stats, job.options).encode("utf-8")
            ctype = "application/json; charset=utf-8"
            name = f"ipscan-{job.id[:8]}.json"
        self._send(HTTPStatus.OK, body, ctype,
                   [("Content-Disposition", f'attachment; filename="{name}"')])

    def _api_stream(self, params: dict) -> None:
        job = self._get_job(params)
        if not job:
            return
        try:
            q = job.subscribe()
        except RuntimeError as exc:
            self._error(HTTPStatus.TOO_MANY_REQUESTS, str(exc))
            return

        self.send_response(HTTPStatus.OK)
        self._base_headers()
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()

        try:
            self._sse(":ok\n\n")
            # Baglanti gec kuruldu ise mevcut acik sonuclari da gonder.
            for result in list(job.results)[:5000]:
                if result.state == OPEN:
                    self._sse_event("result", result.to_dict())
            self._sse_event("state", job.snapshot())

            while True:
                try:
                    event, data = q.get(timeout=15.0)
                except queue.Empty:
                    self._sse(": ping\n\n")
                    if job.state in ("done", "cancelled", "error"):
                        break
                    continue
                self._sse_event(event, data)
                if event == "done":
                    break
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            job.unsubscribe(q)

    def _sse(self, text: str) -> None:
        self.wfile.write(text.encode("utf-8"))
        self.wfile.flush()

    def _sse_event(self, event: str, data: dict) -> None:
        payload = json.dumps(data, ensure_ascii=False)
        self._sse(f"event: {event}\ndata: {payload}\n\n")


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, token: str, jobs: JobManager,
                 allowed_hosts: set[str], any_host: bool = False):
        super().__init__(addr, handler)
        self.token = token
        self.jobs = jobs
        self.allowed_hosts = allowed_hosts
        # any_host yalnizca loopback disi baglamada (IPSCAN_ALLOW_REMOTE=1) acilir.
        self.any_host = any_host


def serve(*, host: str = "127.0.0.1", port: int = 8787,
          scope_path: str | None = None, scope_mode: str = "auto",
          open_browser: bool = True) -> int:
    """Web arayuzunu baslatir. Ctrl-C ile durur."""
    loopback = host in ("127.0.0.1", "::1", "localhost")
    if not loopback and os.environ.get("IPSCAN_ALLOW_REMOTE") != "1":
        print("hata: loopback disi adrese baglanmak icin IPSCAN_ALLOW_REMOTE=1 "
              "ortam degiskeni gerekli. Arayuz kimlik dogrulamasi tek jetona "
              "dayanir; ag uzerinde acmak onerilmez.", file=sys.stderr)
        return 2

    try:
        scope = scope_mod.load_scope(scope_path, scope_mode)
    except scope_mod.ScopeError as exc:
        print(f"hata: {exc}", file=sys.stderr)
        return 3

    token = secrets.token_urlsafe(32)
    manager = JobManager(scope)
    allowed = {f"{host}:{port}", f"localhost:{port}", f"127.0.0.1:{port}",
               f"[::1]:{port}"}

    try:
        server = Server((host, port), Handler, token=token, jobs=manager,
                        allowed_hosts=allowed, any_host=not loopback)
    except OSError as exc:
        print(f"hata: {host}:{port} dinlenemedi ({exc})", file=sys.stderr)
        return 2

    url = f"http://{host}:{port}/?t={token}"
    print(f"ipscan {__version__} web arayuzu hazir")
    print(f"  adres : {url}")
    print(f"  kapsam: {scope.describe()}")
    print(f"  limit : es zamanlilik tavani {limits.fd_budget()}, "
          f"es zamanli is {MAX_ACTIVE_JOBS}")
    print("  (jeton oturuma ozeldir; baglantiyi paylasmayin. Durdurmak: Ctrl-C)",
          flush=True)

    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever(poll_interval=0.3)
    except KeyboardInterrupt:
        print("\nkapatiliyor...")
    finally:
        server.shutdown()
        server.server_close()
    return 0
