"""Komut satiri arayuzu.

Ornekler:
    python3 -m ipscan 192.168.1.0/24 -p 22,80,443
    python3 -m ipscan -f hedefler.txt -p top100 --json sonuc.json
    python3 -m ipscan web
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from pathlib import Path

from . import __version__, limits, report, scope as scope_mod
from .engine import OPEN, Result, Scanner
from .targets import (MAX_TARGETS, TargetError, check_pair_budget, iter_pairs,
                      parse_ports, parse_targets)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_SCOPE = 3
EXIT_INTERRUPT = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipscan",
        description="Hizli ve guvenli TCP connect port tarayici.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""ornekler:
  ipscan 10.0.0.1 -p 22,80,443
  ipscan 192.168.1.0/24 -p top100 --open-only
  ipscan 10.0.0.1-50 -p 1-65535 -c 2000 --timeout 0.7
  ipscan -f hedefler.txt -p web --json rapor.json --csv rapor.csv
  ipscan web --port 8787
""",
    )
    parser.add_argument("targets", nargs="*",
                        help="IP, CIDR, aralik veya alan adi (--resolve ile)")
    parser.add_argument("-f", "--targets-file", metavar="DOSYA",
                        help="Hedefleri dosyadan oku (satir/virgul ayrilmis)")
    parser.add_argument("-p", "--ports", default="top100",
                        help="Portlar: 22,80,443 | 1-1024 | top100 | web | db | "
                             "remote | all  (varsayilan: top100)")
    parser.add_argument("-c", "--concurrency", type=int, default=None,
                        help="Es zamanli soket sayisi (varsayilan: otomatik)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Baglanti zaman asimi, saniye (varsayilan: 1.0)")
    parser.add_argument("-r", "--retries", type=int, default=1,
                        help="Filtreli sonuclar icin ek deneme (varsayilan: 1)")
    parser.add_argument("--rate", type=float, default=None,
                        help="Saniyedeki azami prob sayisi (varsayilan: sinirsiz)")
    parser.add_argument("--banner", action="store_true",
                        help="Acik portlarda pasif banner oku")
    parser.add_argument("--resolve", action="store_true",
                        help="Alan adlarinin DNS cozumlemesine izin ver")
    parser.add_argument("--max-targets", type=int, default=MAX_TARGETS,
                        help=f"Azami hedef IP sayisi (varsayilan: {MAX_TARGETS})")

    grp = parser.add_argument_group("kapsam / guvenlik")
    grp.add_argument("--scope", metavar="DOSYA",
                     help="Izin verilen ag listesi (varsayilan: ./scope.txt)")
    grp.add_argument("--scope-mode", choices=scope_mod.MODES, default="auto",
                     help="auto: dosya varsa zorunlu | strict: dosya sart | "
                          "off: denetim yok (varsayilan: auto)")

    out = parser.add_argument_group("cikti")
    out.add_argument("--open-only", action="store_true",
                     help="Yalnizca acik portlari goster")
    out.add_argument("--json", metavar="DOSYA", help="JSON raporu yaz")
    out.add_argument("--csv", metavar="DOSYA", help="CSV raporu yaz")
    out.add_argument("--ndjson", action="store_true",
                     help="Sonuclari stdout'a satir satir JSON olarak bas")
    out.add_argument("-q", "--quiet", action="store_true",
                     help="Ilerleme ve canli ciktiyi kapat")
    out.add_argument("--no-color", action="store_true", help="Renkleri kapat")
    parser.add_argument("-V", "--version", action="version",
                        version=f"ipscan {__version__}")
    return parser


def build_web_parser() -> argparse.ArgumentParser:
    """`ipscan web` alt komutu (ayri parser: hedef pozisyonu ile cakismasin)."""
    web = argparse.ArgumentParser(
        prog="ipscan web", description="Yerel web arayuzunu baslatir.")
    web.add_argument("--host", default="127.0.0.1",
                     help="Dinlenecek adres (varsayilan: 127.0.0.1)")
    web.add_argument("--port", type=int, default=8787,
                     help="Dinlenecek port (varsayilan: 8787)")
    web.add_argument("--scope", metavar="DOSYA", help="Izin verilen ag listesi")
    web.add_argument("--scope-mode", choices=scope_mod.MODES, default="auto",
                     help="auto | strict | off (varsayilan: auto)")
    web.add_argument("--no-browser", action="store_true",
                     help="Tarayiciyi otomatik acma")
    return web


def _err(message: str) -> None:
    print(f"hata: {message}", file=sys.stderr)


def _warn(message: str) -> None:
    print(f"uyari: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] == "web":
        args = build_web_parser().parse_args(argv[1:])
        from .webapp import serve
        return serve(host=args.host, port=args.port, scope_path=args.scope,
                     scope_mode=args.scope_mode, open_browser=not args.no_browser)

    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.targets and not args.targets_file:
        parser.print_help()
        return EXIT_USAGE

    color = not args.no_color and report.use_color()

    # ---------------------------------------------------------- girdiler ---
    try:
        raw_targets = list(args.targets)
        if args.targets_file:
            path = Path(args.targets_file).expanduser()
            if not path.is_file():
                _err(f"hedef dosyasi bulunamadi: {path}")
                return EXIT_USAGE
            raw_targets.append(path.read_text(encoding="utf-8", errors="replace"))

        target_set = parse_targets(raw_targets, resolve=args.resolve,
                                   max_targets=args.max_targets)
        ports = parse_ports(args.ports)
        total = check_pair_budget(len(target_set.hosts), len(ports))
    except TargetError as exc:
        _err(str(exc))
        return EXIT_USAGE

    for warning in target_set.warnings:
        _warn(warning)

    # ------------------------------------------------------------ kapsam ---
    try:
        scope = scope_mod.load_scope(args.scope, args.scope_mode)
        for warning in scope_mod.enforce(scope, target_set.hosts):
            _warn(warning)
    except scope_mod.ScopeError as exc:
        _err(f"kapsam ihlali: {exc}")
        return EXIT_SCOPE

    public = scope_mod.public_targets(target_set.hosts)
    if public and not scope.active:
        _warn(f"{len(public)} hedef internete acik adres ({public[0]}...). "
              f"Yalnizca yetkiniz olan sistemleri tarayin.")

    # ------------------------------------------------------------ limitler ---
    concurrency, note = limits.safe_concurrency(args.concurrency, total)
    if note and not args.quiet:
        _warn(note)

    if not args.quiet:
        print(f"{len(target_set.hosts)} hedef x {len(ports)} port = "
              f"{total:,} prob | es zamanlilik {concurrency} | "
              f"zaman asimi {args.timeout}s | kapsam: {scope.describe()}",
              file=sys.stderr)

    try:
        results, stats, interrupted = asyncio.run(_run(
            target_set.hosts, ports, args, concurrency, color))
    except KeyboardInterrupt:  # pragma: no cover
        return EXIT_INTERRUPT

    # ------------------------------------------------------------- rapor ---
    shown = [r for r in results if r.state == OPEN] if args.open_only else results
    meta = {
        "hosts": len(target_set.hosts),
        "ports": len(ports),
        "timeout": args.timeout,
        "concurrency": concurrency,
        "retries": args.retries,
        "scope": scope.describe(),
        "interrupted": interrupted,
    }
    if args.json:
        report.write_file(args.json, report.to_json(shown, stats, meta))
        if not args.quiet:
            print(f"JSON yazildi: {args.json}", file=sys.stderr)
    if args.csv:
        report.write_file(args.csv, report.to_csv(shown))
        if not args.quiet:
            print(f"CSV yazildi: {args.csv}", file=sys.stderr)

    if not args.ndjson and not args.quiet:
        open_results = [r for r in results if r.state == OPEN]
        print()
        if open_results:
            print(report.colorize("ACIK PORTLAR", "bold", color))
            print(report.render_table(open_results, color))
        else:
            print("Acik port bulunamadi.")
        print()
        print(report.render_summary(stats, color))
        if stats.fd_exhausted:
            _warn(f"{stats.fd_exhausted} prob kaynak yetersizliginden basarisiz. "
                  f"-c degerini dusurun.")
        if interrupted:
            _warn("Tarama kullanici tarafindan yarida kesildi.")

    return EXIT_INTERRUPT if interrupted else EXIT_OK


async def _run(hosts, ports, args, concurrency, color):
    """Asenkron tarama + canli ilerleme."""
    scanner = Scanner(concurrency=concurrency, timeout=args.timeout,
                      retries=args.retries, rate=args.rate, banner=args.banner)
    cancel = asyncio.Event()
    interrupted = False

    loop = asyncio.get_running_loop()

    def _on_signal() -> None:
        nonlocal interrupted
        interrupted = True
        cancel.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass

    total = len(hosts) * len(ports)
    results: list[Result] = []
    show_progress = not args.quiet and not args.ndjson and sys.stderr.isatty()
    last_draw = 0.0

    async for result in scanner.run(iter_pairs(hosts, ports), total=total,
                                    cancel=cancel):
        results.append(result)

        if args.ndjson:
            if not args.open_only or result.state == OPEN:
                print(report.to_ndjson(result), flush=True)
        elif result.state == OPEN and not args.quiet:
            if show_progress:
                sys.stderr.write("\r\033[K")
                sys.stderr.flush()
            print(report.format_line(result, color), flush=True)

        if show_progress:
            import time as _time
            now = _time.monotonic()
            if now - last_draw > 0.1 or scanner.stats.done == total:
                last_draw = now
                _draw_progress(scanner.stats)

    if show_progress:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()

    return results, scanner.stats, interrupted


def _draw_progress(stats) -> None:
    pct = (stats.done / stats.total * 100) if stats.total else 100.0
    filled = int(pct / 100 * 24)
    bar = "#" * filled + "." * (24 - filled)
    eta = ""
    if stats.rate > 0 and stats.total > stats.done:
        remaining = (stats.total - stats.done) / stats.rate
        eta = f" kalan ~{remaining:5.1f}s"
    sys.stderr.write(
        f"\r\033[K[{bar}] {pct:5.1f}%  {stats.done:,}/{stats.total:,}  "
        f"{stats.open} acik  {stats.rate:,.0f}/sn{eta}")
    sys.stderr.flush()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
