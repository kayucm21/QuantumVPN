import base64
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image
from tools import quantumvpn_resources as r


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))  # test fixture only
        r.schema(self.db)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def do(self, operation, **values):
        result = r.action(self.db, self.tmp.name, {k: [str(v)] for k, v in {"action": operation, **values}.items()}, {}, "test")
        self.db.commit()
        return result

    def manifest(self, device="test", version=r.MIN_VERSION):
        return r.client_manifest(self.db, device, version, lambda: self.key)

    def test_draft_is_not_published(self):
        self.do("save", brand_name="QuantumVPN")
        self.assertIsNone(self.manifest())

    def test_signed_domain_separated_manifest_and_compatibility(self):
        self.do("save", welcome="Привет!")
        self.do("production", revision=1)
        envelope = self.manifest()
        data = r.canonical(envelope["payload"]).encode()
        self.key.public_key().verify(base64.urlsafe_b64decode(envelope["signature"] + "=="), data)
        self.assertEqual(envelope["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(envelope["payload"]["kind"], r.KIND)
        self.assertIsNone(self.manifest(version=r.MIN_VERSION - 1))

    def test_rollback_has_new_sequence_and_preserves_history(self):
        self.do("save", brand_name="First")
        self.do("production", revision=1)
        self.do("save", brand_name="Second")
        self.do("production", revision=2)
        self.do("rollback", revision=1)
        value = self.manifest()["payload"]
        self.assertEqual((value["revision"], value["sequence"]), (1, 3))
        self.assertEqual(self.db.execute("select count(*) from resource_bundles").fetchone()[0], 2)

    def test_test_group_is_stable_and_stop_restores_production(self):
        self.do("save", brand_name="Production")
        self.do("production", revision=1)
        self.do("save", brand_name="Test")
        self.do("staging", revision=2, percent=10)
        revisions = [self.manifest(str(i))["payload"]["revision"] for i in range(100)]
        self.assertIn(1, revisions)
        self.assertIn(2, revisions)
        self.assertEqual(revisions, [self.manifest(str(i))["payload"]["revision"] for i in range(100)])
        self.do("stop_test")
        self.assertEqual(self.manifest()["payload"]["revision"], 1)

    def test_executable_and_url_fields_rejected(self):
        for document in ({"code": "alert(1)"}, {"texts": {"script": "abc"}, "theme": {}, "assets": {}},
                         {"texts": {}, "theme": {"url": "https://evil.test"}, "assets": {}},
                         {"texts": {}, "theme": {}, "assets": {"dex": {}}}):
            with self.assertRaises(ValueError):
                r.validate(document)

    def test_invalid_text_and_color_limits(self):
        for values in ({"brand_name": "x" * 33}, {"welcome": "bad\ntext"}, {"accent": "red"}):
            with self.assertRaises(ValueError):
                self.do("save", **values)

    def test_image_is_bounded_reencoded_and_content_addressed(self):
        source = io.BytesIO()
        Image.new("RGB", (1800, 1200), "blue").save(source, "JPEG", comment=b"private metadata")
        asset = r.store_image(self.tmp.name, source.getvalue(), "background")
        self.assertEqual((asset["width"], asset["height"]), (1440, 960))
        raw = (Path(self.tmp.name) / "resources/assets" / asset["sha256"]).read_bytes()
        self.assertNotIn(b"private metadata", raw)
        self.assertEqual(asset["size"], len(raw))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), asset["sha256"])

    def test_rejects_executable_and_animated_image(self):
        for raw in (b"MZ executable", b"<svg><script/></svg>", b"a" * (r.MAX_ASSET + 1)):
            with self.assertRaises(ValueError):
                r.store_image(self.tmp.name, raw, "logo")
        output = io.BytesIO()
        Image.new("RGB", (2, 2)).save(output, "PNG", save_all=True, append_images=[Image.new("RGB", (2, 2), "red")])
        with self.assertRaises(ValueError):
            r.store_image(self.tmp.name, output.getvalue(), "background")

    def test_bad_asset_cannot_be_published_or_traversed(self):
        self.do("save")
        for digest in ("../../operator.db", "f" * 64):
            with self.assertRaises(ValueError):
                r.asset_bytes(self.db, self.tmp.name, digest)
        with self.assertRaises(ValueError):
            self.do("production", revision=999)

    def test_preview_escapes_admin_input(self):
        self.do("save", brand_name="<script>test</script>")
        result = r.render(self.db)
        self.assertNotIn("<script>test</script>", result)
        self.assertIn("&lt;script&gt;", result)


if __name__ == "__main__":
    unittest.main()
