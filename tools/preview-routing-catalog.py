"""Isolated, loopback-only UI test fixture. Never opens production state."""
import os
import tempfile

_fixture = tempfile.TemporaryDirectory(prefix="quantum-routing-preview-")
os.environ.update(QV_DATA_DIR=_fixture.name, QV_DOWNLOAD_ROOT=_fixture.name,
                  QV_ADMIN_USER="fixture", QV_ADMIN_PASSWORD="fixture-only",
                  QV_SUBSCRIPTION_UPSTREAM="https://example.invalid/sub")
import quantumvpn_operator_panel as panel


class Fixture(panel.App):
    def admin(self, require_login_page=True):
        db = self.connection_db()
        return {"user": "fixture", "role": "owner", "db": db, "s": panel.settings(db),
                "ip": "127.0.0.1", "basic": True}


if __name__ == "__main__":
    panel.PUBLIC_BASE = "http://127.0.0.1:8767"
    # Synthetic measurements only in this disposable fixture; no probes leave PC.
    panel._routing_scan_addresses = lambda kind, target: ["1.1.1.1"]
    panel._routing_tcp_latency_ms = lambda address: 17
    server = panel.ThreadingHTTPServer(("127.0.0.1", 8767), Fixture)
    print("Isolated routing UI fixture at http://127.0.0.1:8767/operator?tab=routing", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        _fixture.cleanup()
