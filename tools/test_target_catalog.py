"""Offline data catalogue: real entries, bounded pages and no probe side effects."""
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

try:
    import quantumvpn_target_catalog as catalog
except ImportError:
    from tools import quantumvpn_target_catalog as catalog


class TargetCatalogTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        catalog.schema(self.db)
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_normalization_is_canonical_deduplicated_and_explicit_about_networks(self):
        entries = catalog.normalize_entries("EXAMPLE.COM.,example.com\nmedia.example.com;1.1.1.1,1.1.1.1/32\n2606:4700:4700:0:0:0:0:1111/128\n8.8.8.123/24")
        self.assertEqual([entry["target"] for entry in entries], ["example.com", "media.example.com", "1.1.1.1", "2606:4700:4700::1111", "8.8.8.0/24"])
        self.assertEqual([entry["kind"] for entry in entries], ["domain", "domain", "ip", "ip", "cidr"])
        self.assertFalse(entries[-1]["selectable"])
        self.assertEqual(catalog.normalize_entries("xn--e1afmkfd.xn--p1ai")[0]["kind"], "domain")

    def test_invalid_private_special_and_ambiguous_entries_fail_before_any_write(self):
        invalid = ["https://example.com/path", "example.com:443", "*.example.com", "regexp:.*", "geosite:youtube",
                   '<img src=x onerror="alert(1)">', "пример.рф", "foo.local", "service.internal", "service.home.arpa",
                   "x';delete from settings;--", "127.0.0.1", "10.0.0.0/8", "::1", "fc00::/7", "fe80::/64",
                   "192.0.2.0/24", "203.0.113.1", "224.0.0.0/4", "8.0.0.0/4", "2000::/3", "2001:db8::/32",
                   "[2606:4700:4700::1111]", "1.1.1.1%eth0", "example .com"]
        for target in invalid:
            with self.subTest(target=target), self.assertRaises(ValueError):
                catalog.import_entries(self.db, "valid.example.com\n" + target)
            self.assertEqual(catalog.page(self.db)["total"], 0)

    def test_import_limits_source_validation_and_caller_transaction(self):
        for raw in ("", "x" * (catalog.MAX_IMPORT_BYTES + 1), "\n".join("example.com" for _ in range(catalog.MAX_IMPORT_ENTRIES + 1))):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                catalog.normalize_entries(raw)
        for source in ("policy", "draft", "scan", "seed", "seed:youtube", "<script>", "bad source", "x" * 81):
            with self.subTest(source=source), self.assertRaises(ValueError):
                catalog.import_entries(self.db, "example.com", source=source)
        result = catalog.import_entries(self.db, "example.com\n1.1.1.1")
        self.assertEqual(result, {"accepted": 2, "added": 2, "existing": 0, "total": 2})
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(catalog.page(self.db)["total"], 0)

    def test_multiple_sources_do_not_duplicate_targets_and_import_is_additive(self):
        catalog.import_entries(self.db, "example.com\n1.1.1.1", source="import")
        result = catalog.import_entries(self.db, "EXAMPLE.COM\nmedia.example.com", source="operator-list")
        self.assertEqual(result["added"], 1)
        self.assertEqual(result["existing"], 1)
        items = catalog.page(self.db)["items"]
        self.assertEqual(len(items), 3)
        domain = next(item for item in items if item["target"] == "example.com")
        self.assertEqual(domain["sources"], ["import", "operator-list"])
        self.assertEqual(domain["status"], "unchecked")
        self.assertIsNone(domain["latency_ms"])

    def test_more_than_three_real_entries_page_search_type_and_stable_order(self):
        catalog.import_entries(self.db, "\n".join(f"site{index:03d}.example.com" for index in range(125)) + "\n1.1.1.1\n8.8.8.0/24")
        first, second = catalog.page(self.db), catalog.page(self.db, offset=50)
        self.assertEqual(first["total"], 127)
        self.assertEqual(len(first["items"]), 50)
        self.assertEqual(len(second["items"]), 50)
        self.assertFalse({item["target"] for item in first["items"]} & {item["target"] for item in second["items"]})
        search = catalog.page(self.db, query="SITE01")
        self.assertEqual(search["matched"], 10)
        self.assertEqual(len(search["items"]), 10)
        networks = catalog.page(self.db, kind="cidr")
        self.assertEqual(networks["matched"], 1)
        self.assertFalse(networks["items"][0]["selectable"])
        self.assertEqual(catalog.page(self.db, kind="ip")["matched"], 1)
        self.assertEqual(catalog.page(self.db, offset=999)["items"], [])

    def test_search_is_parameterized_wildcards_literal_and_read_only(self):
        catalog.import_entries(self.db, "example.com\nmedia.example.com")
        self.db.commit()
        statements = []
        self.db.set_trace_callback(statements.append)
        for query in ("%' OR 1=1--", "_", "%", "\\", '<script>alert(1)</script>'):
            with self.subTest(query=query):
                self.assertEqual(catalog.page(self.db, query=query)["matched"], 0)
        self.assertEqual(catalog.page(self.db, query="example.com")["matched"], 2)
        self.assertTrue(all(statement.lstrip().lower().startswith("select") for statement in statements))
        self.assertFalse(self.db.in_transaction)
        for arguments in ({"query": "x" * 161}, {"query": "x\n"}, {"kind": "regex"}, {"offset": -1}, {"offset": 100001}, {"limit": 51}, {"limit": 0}, {"offset": "NaN"}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                catalog.page(self.db, **arguments)

    def state(self):
        now = 1_790_000_000
        return {"routing_proxy_domains": "youtube.com,example.com", "routing_direct_cidrs": "10.0.0.0/8,1.1.1.1/32",
                "routing_scan_targets": "example.com,media.example.com,example.com",
                "routing_draft_payload": json.dumps({"rules": {"proxy_domains": ["draft.example.com", "example.com"]}}),
                "routing_last_scan": json.dumps([
                    {"target": "media.example.com", "kind": "domain", "status": "ok", "latency_ms": 28,
                     "checked_at": now, "addresses": [{"address": "1.1.1.1", "latency_ms": 28}, {"address": "127.0.0.1", "latency_ms": 1}]},
                    {"target": "unresolved.example.com", "kind": "domain", "status": "unresolved", "latency_ms": None, "checked_at": now, "addresses": []},
                    {"target": "10.0.0.1", "kind": "ip", "status": "ok", "latency_ms": 1, "checked_at": now, "addresses": []},
                ])}

    def test_policy_sync_known_sources_public_dns_and_noop_fingerprint(self):
        state = self.state()
        payload = {"rules": {"proxy_domains": ["draft.example.com", "example.com"]}}
        original = json.dumps(state, sort_keys=True)
        with mock.patch.object(catalog.time, "time", return_value=1_790_000_100):
            result = catalog.sync_policy(self.db, state, payload)
        self.assertTrue(result["changed"])
        self.assertEqual(json.dumps(state, sort_keys=True), original)
        values = {item["target"]: item for item in catalog.page(self.db)["items"]}
        self.assertNotIn("10.0.0.1", values)
        self.assertNotIn("10.0.0.0/8", values)
        self.assertNotIn("127.0.0.1", values)
        self.assertEqual(values["example.com"]["sources"], ["draft", "manual", "policy"])
        self.assertEqual(values["media.example.com"]["latency_ms"], 28)
        self.assertEqual(values["1.1.1.1"]["sources"], ["dns", "policy"])
        self.assertEqual(values["unresolved.example.com"]["status"], "unresolved")
        self.assertEqual(catalog.page(self.db, query="1.1.1.1")["matched"], 2)
        changes = self.db.total_changes
        self.assertFalse(catalog.sync_policy(self.db, state, payload)["changed"])
        self.assertEqual(self.db.total_changes, changes)

    def test_sync_removes_obsolete_rules_but_preserves_imports_and_discovered_targets(self):
        catalog.import_entries(self.db, "example.com\nimported.example.com")
        catalog.sync_policy(self.db, self.state(), {})
        catalog.sync_policy(self.db, {}, {})
        values = {item["target"]: item for item in catalog.page(self.db)["items"]}
        self.assertEqual(set(values), {"example.com", "imported.example.com", "media.example.com", "unresolved.example.com", "1.1.1.1"})
        self.assertEqual(values["example.com"]["sources"], ["import"])
        self.assertEqual(values["media.example.com"]["sources"], ["scan"])
        self.assertEqual(values["1.1.1.1"]["sources"], ["dns"])
        self.assertNotIn("youtube.com", values)
        self.assertNotIn("draft.example.com", values)

    def test_two_different_batches_preserve_previous_domains_public_ips_and_measurements(self):
        first = {"routing_last_scan": json.dumps([{"target": "first.example.com", "status": "ok", "latency_ms": 19,
                                                   "checked_at": 1_790_000_001, "addresses": [{"address": "1.1.1.1", "latency_ms": 19}]}])}
        second = {"routing_last_scan": json.dumps([{"target": "second.example.com", "status": "ok", "latency_ms": 31,
                                                    "checked_at": 1_790_000_002, "addresses": [{"address": "8.8.8.8", "latency_ms": 31}]}])}
        with mock.patch.object(catalog.time, "time", return_value=1_790_000_100):
            catalog.sync_policy(self.db, first, {})
            catalog.sync_policy(self.db, second, {})
        values = {item["target"]: item for item in catalog.page(self.db)["items"]}
        self.assertEqual(set(values), {"first.example.com", "second.example.com", "1.1.1.1", "8.8.8.8"})
        self.assertEqual(values["first.example.com"]["latency_ms"], 19)
        self.assertEqual(values["first.example.com"]["checked_at"], 1_790_000_001)
        self.assertEqual(values["second.example.com"]["latency_ms"], 31)

    def test_corrupt_evidence_never_becomes_fake_successful_measurement(self):
        state = {"routing_last_scan": json.dumps([{"target": "fake.example.com", "status": "ok", "latency_ms": 1,
                                                   "checked_at": 9_999_999_999, "addresses": [{"address": "10.0.0.1", "latency_ms": 1}]}])}
        catalog.sync_policy(self.db, state, {})
        item = catalog.page(self.db)["items"][0]
        self.assertEqual(item["status"], "unchecked")
        self.assertIsNone(item["latency_ms"])
        self.assertEqual(item["checked_at"], 0)
        self.assertEqual(item["addresses"], [])

    def test_cap_failure_is_atomic_and_preserves_caller_writes(self):
        catalog.import_entries(self.db, "example.com", source="first")
        with mock.patch.object(catalog, "MAX_CATALOG_ENTRIES", 1):
            with self.assertRaises(ValueError):
                catalog.import_entries(self.db, "example.com\nsecond.example.com", source="second")
            result = catalog.sync_policy(self.db, {"routing_proxy_domains": "third.example.com"}, {})
            self.assertFalse(result["changed"])
            self.assertEqual(result["skipped"], 1)
            self.assertEqual(result["warning"]["code"], "catalog_capacity")
        item = catalog.page(self.db)["items"][0]
        self.assertEqual(item["target"], "example.com")
        self.assertEqual(item["sources"], ["first"])
        self.assertTrue(self.db.in_transaction)

    def test_full_100k_catalog_keeps_search_and_successful_caller_scan_available(self):
        total = catalog.MAX_CATALOG_ENTRIES
        self.assertEqual(total, 100_000)
        self.db.executemany("insert into routing_target_catalog(target,kind,created_at) values (?,'domain',0)",
                            ((f"target{index:06d}.example.com",) for index in range(total)))
        self.db.execute("insert into routing_target_catalog_sources(target,source) select target,'import' from routing_target_catalog")
        self.db.execute("create table caller_scan_state(key text primary key,value text)")
        self.db.commit()
        manual = {"routing_scan_targets": "new.manual.example.com,new.manual.example.com"}
        self.db.execute("insert into caller_scan_state values ('manual','saved')")
        result = catalog.sync_policy(self.db, manual, {})
        self.assertEqual(result["total"], total)
        self.assertFalse(result["changed"])
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["warning"]["code"], "catalog_capacity")
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(catalog.page(self.db, query="target000001")["matched"], 1)
        self.assertEqual(self.db.execute("select value from caller_scan_state where key='manual'").fetchone()[0], "saved")
        now = int(catalog.time.time())
        scan = {"routing_scan_targets": "new.manual.example.com",
                "routing_last_scan": json.dumps([{"target": "new.scan.example.com", "status": "ok", "latency_ms": 17,
                                                   "checked_at": now, "addresses": [{"address": "1.1.1.1", "latency_ms": 17}]}])}
        self.db.execute("insert into caller_scan_state values ('findings',?)", (scan["routing_last_scan"],))
        result = catalog.sync_policy(self.db, scan, {})
        self.assertEqual(result["skipped"], 3)  # manual, scan domain and discovered public IP
        self.assertEqual(result["total"], total)
        self.assertEqual(catalog.page(self.db, query="new.scan.example.com")["matched"], 0)
        self.assertEqual(self.db.execute("select count(*) from routing_target_catalog_sources").fetchone()[0], total)
        self.assertIsNone(self.db.execute("select value from routing_target_catalog_state where key='policy_fingerprint'").fetchone())
        self.db.commit()
        self.assertEqual(self.db.execute("select value from caller_scan_state where key='findings'").fetchone()[0], scan["routing_last_scan"])
        # Optional sync did not acknowledge the failed fingerprint. Once room
        # exists, the same successful scan can be indexed without rerunning it.
        for index in range(3):
            target = f"target{index:06d}.example.com"
            self.db.execute("delete from routing_target_catalog_sources where target=?", (target,))
            self.db.execute("delete from routing_target_catalog where target=?", (target,))
        retry = catalog.sync_policy(self.db, scan, {})
        self.assertTrue(retry["changed"])
        self.assertNotIn("warning", retry)
        self.assertEqual(catalog.page(self.db, query="new.scan.example.com")["items"][0]["latency_ms"], 17)
        self.assertFalse(catalog.sync_policy(self.db, scan, {})["changed"])

    def test_source_capacity_sync_is_nonfatal_but_import_remains_fail_closed(self):
        catalog.import_entries(self.db, "example.com", source="import")
        with mock.patch.object(catalog, "MAX_CATALOG_SOURCES", 1):
            result = catalog.sync_policy(self.db, {"routing_scan_targets": "second.example.com"}, {})
            self.assertEqual(result["skipped"], 1)
            self.assertEqual(result["warning"]["code"], "catalog_capacity")
            with self.assertRaises(catalog.CatalogCapacityError):
                catalog.import_entries(self.db, "example.com", source="second-source")
        self.assertEqual(catalog.page(self.db)["items"][0]["sources"], ["import"])
        self.assertEqual(catalog.page(self.db)["total"], 1)
        self.assertTrue(self.db.in_transaction)

    def test_seed_capacity_remains_fail_closed_and_atomic(self):
        catalog.import_entries(self.db, "kept.example.com")
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "seed.json"
            file.write_text(json.dumps(self.seed([{"target": "new.seed.example.com", "kind": "domain", "category": "known"}])), encoding="utf-8")
            with mock.patch.object(catalog, "MAX_CATALOG_ENTRIES", 1), self.assertRaises(catalog.CatalogCapacityError):
                catalog.install_seed(self.db, file)
        self.assertEqual(catalog.page(self.db)["total"], 1)
        self.assertEqual(catalog.page(self.db)["items"][0]["target"], "kept.example.com")
        self.assertEqual(catalog.page(self.db)["items"][0]["sources"], ["import"])
        self.assertIsNone(self.db.execute("select value from routing_target_catalog_state where key='seed_fingerprint'").fetchone())
        self.assertTrue(self.db.in_transaction)

    def seed(self, entries=None):
        return {"schema": 1, "sources": [{"id": "roscomvpn-geosite", "revision": "a" * 40, "license": "MIT",
                                          "url": "https://github.com/hydraponique/roscomvpn-geosite/tree/" + "a" * 40}],
                "entries": entries or [{"target": "example.com", "kind": "domain", "category": "youtube"},
                                       {"target": "example.com", "kind": "domain", "category": "google"},
                                       {"target": "media.example.com", "kind": "domain", "category": "youtube"}]}

    def test_checked_in_seed_keeps_pinned_provenance_license_and_unique_targets(self):
        assets = Path(__file__).with_name("assets")
        file = assets / "routing-catalog-seed.json"
        seed = json.loads(file.read_bytes())
        source = seed["sources"][0]
        self.assertEqual(source["revision"], "6b4fe3a4013eae99fea11caaddba160a8b0c0577")
        self.assertEqual(hashlib.sha256((assets / source["license_file"]).read_bytes()).hexdigest(), source["license_sha256"])
        result = catalog.install_seed(self.db, file)
        self.assertEqual(result["total"], 2883)
        self.assertEqual(len({entry["target"] for entry in seed["entries"]}), 2883)
        self.assertEqual(catalog.page(self.db, query="youtube")["matched"], 169)
        self.assertGreater(catalog.page(self.db, query="telegram")["matched"], 0)
        self.assertTrue(all(item["latency_ms"] is None for item in catalog.page(self.db)["items"]))

    def test_local_seed_provenance_dedup_no_fake_latency_and_noop(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "seed.json"
            file.write_text(json.dumps(self.seed()), encoding="utf-8")
            result = catalog.install_seed(self.db, file)
            self.assertEqual(result, {"changed": True, "total": 2, "entries": 2})
            self.assertTrue(self.db.in_transaction)
            first = catalog.page(self.db)["items"][0]
            self.assertEqual(first["sources"], ["seed:google", "seed:youtube"])
            self.assertIsNone(first["latency_ms"])
            self.assertEqual(first["checked_at"], 0)
            changes = self.db.total_changes
            self.assertFalse(catalog.install_seed(self.db, file)["changed"])
            self.assertEqual(self.db.total_changes, changes)
            catalog.import_entries(self.db, "kept.example.com")
            file.write_text(json.dumps(self.seed([{"target": "new.example.com", "kind": "domain", "category": "telegram"}])), encoding="utf-8")
            catalog.install_seed(self.db, file)
            self.assertEqual([item["target"] for item in catalog.page(self.db)["items"]], ["kept.example.com", "new.example.com"])

    def test_bad_seed_and_oversize_asset_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "seed.json"
            cases = [{}, {**self.seed(), "schema": 2}, {**self.seed(), "sources": []},
                     {**self.seed(), "entries": [{"target": "127.0.0.1", "kind": "ip", "category": "private"}]},
                     {**self.seed(), "entries": [{"target": "example.com", "kind": "ip", "category": "wrong"}]},
                     {**self.seed(), "sources": [{"id": "bad", "revision": "latest", "license": "MIT", "url": "https://example.com"}]}]
            for value in cases:
                file.write_text(json.dumps(value), encoding="utf-8")
                with self.subTest(value=value), self.assertRaises(ValueError):
                    catalog.install_seed(self.db, file)
                self.assertEqual(catalog.page(self.db)["total"], 0)
            file.write_bytes(b"x" * (catalog.MAX_SEED_BYTES + 1))
            with self.assertRaises(ValueError):
                catalog.install_seed(self.db, file)

    def test_bounded_large_catalog_and_literal_ipv6_search(self):
        catalog.import_entries(self.db, "\n".join(f"target{index:05d}.example.com" for index in range(20_000)))
        catalog.import_entries(self.db, "2606:4700:4700::1111")
        self.assertEqual(catalog.page(self.db)["total"], 20_001)
        self.assertEqual(len(catalog.page(self.db, offset=10_000)["items"]), 50)
        self.assertEqual(catalog.page(self.db, query="2606:4700:4700:0:0:0:0:1111")["matched"], 1)

    def test_workload_changes_only_worker_budget_and_overload_is_explicit(self):
        self.assertEqual(catalog.workload_workers(.1, .8), 8)
        self.assertEqual(catalog.workload_workers(.7, .8), 4)
        self.assertEqual(catalog.workload_workers(1.1, .8), 2)
        self.assertEqual(catalog.workload_workers(1.6, .8), 1)
        self.assertEqual(catalog.workload_workers(.1, .2), 2)
        self.assertEqual(catalog.workload_workers(), 4)
        for values in ((2.5, .8), (.1, .07), (float("nan"), .8), (float("inf"), .8), (-1, .8), (.1, 1.1), (True, .8)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                catalog.workload_workers(*values)


if __name__ == "__main__":
    unittest.main()
