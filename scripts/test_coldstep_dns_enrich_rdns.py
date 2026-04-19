import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.coldstep_dns import enrich_rdns


def _v2_model() -> dict:
    return {
        "schema_version": 2,
        "generated_at": "2026-04-18T17:00:00Z",
        "run": {"run_id": "test"},
        "capability_matrix": [],
        "events_by_type": [],
        "timeline": [],
        "egress_sankey": [
            {"source": "8.8.8.8", "target": "allow", "value": 3, "indicators": ["8.8.8.8"]},
            {"source": "evil.example.com", "target": "allow", "value": 1,
             "indicators": ["evil.example.com"]},
            {"source": "127.0.0.1", "target": "allow", "value": 1, "indicators": ["127.0.0.1"]},
        ],
        "diff": {
            "status": "ok",
            "traffic_new": [{"count": 1, "fingerprint": "x", "indicators": ["1.2.3.4"]}],
            "traffic_gone": [],
            "traffic_changed": [],
        },
        "otx": None,
    }


class EnrichRdnsTests(unittest.TestCase):
    def _write_model(self, model: dict) -> str:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        tmp.write(json.dumps(model))
        tmp.close()
        return tmp.name

    def test_writes_dns_lookups_for_resolvable_ipv4(self):
        path = self._write_model(_v2_model())
        try:
            rc = enrich_rdns.run(
                model_path=path,
                resolver=lambda ip: {"8.8.8.8": "dns.google", "1.2.3.4": "host.example.com"}.get(ip),
                wall_budget_s=2.0,
                stderr=io.StringIO(),
            )
            self.assertEqual(rc, 0)
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertIn("dns_lookups", data)
            self.assertEqual(data["dns_lookups"]["8.8.8.8"], "dns.google")
            self.assertEqual(data["dns_lookups"]["1.2.3.4"], "host.example.com")
            # Hostname indicators don't get reverse-lookup entries.
            self.assertNotIn("evil.example.com", data["dns_lookups"])
            # Schema fields are unchanged.
            self.assertEqual(data["schema_version"], 2)
            self.assertEqual(data["egress_sankey"][0]["source"], "8.8.8.8")
        finally:
            os.unlink(path)

    def test_no_resolvable_ips_writes_empty_dict(self):
        path = self._write_model(_v2_model())
        try:
            enrich_rdns.run(model_path=path, resolver=lambda ip: None,
                            wall_budget_s=2.0, stderr=io.StringIO())
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(data["dns_lookups"], {})
        finally:
            os.unlink(path)

    def test_idempotent_when_dns_lookups_already_present(self):
        # If a previous run already populated the field, we should re-enrich
        # cleanly (overwrite) - not crash, not deep-merge stale data.
        model = _v2_model()
        model["dns_lookups"] = {"8.8.8.8": "stale.example.com"}
        path = self._write_model(model)
        try:
            enrich_rdns.run(model_path=path,
                            resolver=lambda ip: "dns.google" if ip == "8.8.8.8" else None,
                            wall_budget_s=2.0, stderr=io.StringIO())
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(data["dns_lookups"]["8.8.8.8"], "dns.google")
        finally:
            os.unlink(path)

    def test_main_returns_zero_on_corrupt_model(self):
        tmp = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
        tmp.write(b"{not valid")
        tmp.close()
        old_env = {k: os.environ.get(k) for k in
                   ("COLDSTEP_REPORT_MODEL_IN", "COLDSTEP_RDNS_WALL_BUDGET_MS")}
        try:
            os.environ["COLDSTEP_REPORT_MODEL_IN"] = tmp.name
            self.assertEqual(enrich_rdns.main(), 0)
        finally:
            for k, v in old_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            os.unlink(tmp.name)

    def test_main_returns_zero_when_model_path_missing_env(self):
        old = os.environ.get("COLDSTEP_REPORT_MODEL_IN")
        try:
            os.environ.pop("COLDSTEP_REPORT_MODEL_IN", None)
            self.assertEqual(enrich_rdns.main(), 0)
        finally:
            if old is not None:
                os.environ["COLDSTEP_REPORT_MODEL_IN"] = old


if __name__ == "__main__":
    unittest.main()
