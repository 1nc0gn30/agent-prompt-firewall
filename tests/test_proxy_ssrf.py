"""The inline proxy must not be an open relay (x-target-url SSRF) and must bind locally."""
import json, os, socket, sys, tempfile, threading, unittest, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from agent_prompt_firewall.proxy import ProxyService
from agent_prompt_firewall.storage import FirewallStorage


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Upstream(BaseHTTPRequestHandler):
    hits = []
    def log_message(self, *a): pass
    def do_POST(self):
        Upstream.hits.append({"path": self.path, "headers": dict(self.headers)})
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = b'{"choices":[{"message":{"content":"ok"}}]}'
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)


class TestProxySSRF(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = HTTPServer(("127.0.0.1", free_port()), Upstream)
        threading.Thread(target=cls.up.serve_forever, daemon=True).start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.port = free_port()
        cls.svc = ProxyService(port=cls.port, storage=FirewallStorage(db_path=os.path.join(cls.tmp.name, "fw.db")))
        cls.svc.start()

    @classmethod
    def tearDownClass(cls):
        cls.svc.stop(); cls.up.shutdown(); cls.tmp.cleanup()

    def _post(self, headers):
        body = json.dumps({"messages": [{"role": "user", "content": "hello there"}]}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/chat/completions", data=body,
                                     headers={"Content-Type": "application/json", **headers}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_defaults_bind_localhost(self):
        self.assertEqual(ProxyService().host, "127.0.0.1")

    def test_override_rejected_by_default(self):
        os.environ.pop("FIREWALL_ALLOW_TARGET_OVERRIDE", None)
        Upstream.hits.clear()
        status = self._post({"x-target-url": f"http://127.0.0.1:{self.up.server_port}"})
        self.assertEqual(status, 403)
        self.assertEqual(Upstream.hits, [], "proxy contacted attacker-chosen URL")

    def test_override_opt_in_forwards_and_strips_header(self):
        os.environ["FIREWALL_ALLOW_TARGET_OVERRIDE"] = "1"
        try:
            Upstream.hits.clear()
            status = self._post({"x-target-url": f"http://127.0.0.1:{self.up.server_port}"})
            self.assertEqual(status, 200)
            self.assertEqual(len(Upstream.hits), 1)
            self.assertNotIn("x-target-url", {k.lower() for k in Upstream.hits[0]["headers"]})
            self.assertEqual(self._post({"x-target-url": "file:///etc/passwd"}), 403)
        finally:
            os.environ.pop("FIREWALL_ALLOW_TARGET_OVERRIDE", None)


if __name__ == "__main__":
    unittest.main()
