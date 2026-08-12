"""Motor testleri: gercek loopback soketleri uzerinde calisir (ag trafigi yok)."""

import asyncio
import socket
import unittest

from ipscan.engine import CLOSED, FILTERED, OPEN, RateLimiter, Scanner, probe, scan
from ipscan.targets import iter_pairs


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ListenerMixin:
    def start_listener(self, backlog: int = 64) -> int:
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(backlog)
        self.addCleanup(sock.close)
        return sock.getsockname()[1]


class ProbeTests(unittest.IsolatedAsyncioTestCase, ListenerMixin):
    async def test_open_port(self):
        port = self.start_listener()
        result = await probe("127.0.0.1", port, 1.0)
        self.assertEqual(result.state, OPEN)
        self.assertGreaterEqual(result.latency_ms, 0.0)

    async def test_closed_port(self):
        port = free_port()
        result = await probe("127.0.0.1", port, 1.0)
        self.assertEqual(result.state, CLOSED)

    async def test_filtered_on_timeout(self):
        # TEST-NET-1 (RFC 5737): yonlendirilemez, yanit gelmez.
        result = await probe("192.0.2.1", 80, 0.25)
        self.assertIn(result.state, (FILTERED, "unreachable"))

    async def test_ipv6_loopback(self):
        sock = socket.socket(socket.AF_INET6)
        sock.bind(("::1", 0))
        sock.listen(8)
        self.addCleanup(sock.close)
        port = sock.getsockname()[1]
        result = await probe("::1", port, 1.0)
        self.assertEqual(result.state, OPEN)


class ScannerTests(unittest.IsolatedAsyncioTestCase, ListenerMixin):
    async def test_finds_open_among_closed(self):
        open_port = self.start_listener()
        ports = sorted({open_port, free_port(), free_port()})
        results, stats = await scan(["127.0.0.1"], ports, timeout=1.0,
                                    concurrency=16, retries=0)
        self.assertEqual(len(results), len(ports))
        self.assertEqual(stats.done, len(ports))
        opened = [r.port for r in results if r.state == OPEN]
        self.assertEqual(opened, [open_port])

    async def test_all_probes_accounted_for(self):
        ports = [free_port() for _ in range(50)]
        results, stats = await scan(["127.0.0.1"], ports, timeout=0.5,
                                    concurrency=32, retries=0)
        self.assertEqual(stats.total, 50)
        self.assertEqual(stats.done, 50)
        self.assertEqual(len(results), 50)
        self.assertEqual(stats.open + stats.closed + stats.filtered
                         + stats.unreachable + stats.error, 50)

    async def test_cancel_stops_early(self):
        scanner = Scanner(concurrency=4, timeout=0.3, retries=0)
        cancel = asyncio.Event()
        pairs = iter_pairs(["192.0.2.1"], list(range(1, 400)))
        count = 0
        async for _ in scanner.run(pairs, total=399, cancel=cancel):
            count += 1
            if count >= 4:
                cancel.set()
        self.assertLess(count, 399)

    async def test_banner_capture(self):
        async def greet(reader, writer):
            writer.write(b"SSH-2.0-TestServer\r\n")
            await writer.drain()

        server = await asyncio.start_server(greet, "127.0.0.1", 0)
        self.addCleanup(server.close)
        port = server.sockets[0].getsockname()[1]
        result = await probe("127.0.0.1", port, 1.0, banner=True)
        self.assertEqual(result.state, OPEN)
        self.assertIn("SSH-2.0", result.banner or "")

    async def test_concurrency_one_still_works(self):
        port = self.start_listener()
        results, _ = await scan(["127.0.0.1"], [port], concurrency=1,
                                timeout=1.0, retries=0)
        self.assertEqual(results[0].state, OPEN)


class RateLimiterTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_limit_is_instant(self):
        limiter = RateLimiter(None)
        for _ in range(1000):
            await limiter.acquire()

    async def test_limit_throttles(self):
        limiter = RateLimiter(50, burst=1)
        start = asyncio.get_running_loop().time()
        for _ in range(6):
            await limiter.acquire()
        elapsed = asyncio.get_running_loop().time() - start
        self.assertGreater(elapsed, 0.05)


class LimitTests(unittest.TestCase):
    def test_safe_concurrency_clamps(self):
        from ipscan.limits import fd_budget, safe_concurrency
        value, note = safe_concurrency(10**9)
        self.assertLessEqual(value, fd_budget())
        self.assertIsNotNone(note)

    def test_default_is_reasonable(self):
        from ipscan.limits import safe_concurrency
        value, _ = safe_concurrency(None, 10_000)
        self.assertGreaterEqual(value, 16)
        self.assertLessEqual(value, 8192)

    def test_total_probes_caps_value(self):
        from ipscan.limits import safe_concurrency
        value, _ = safe_concurrency(1000, 5)
        self.assertEqual(value, 5)


if __name__ == "__main__":
    unittest.main()
