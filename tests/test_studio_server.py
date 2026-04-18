import json
import tempfile
import unittest
from pathlib import Path

from studio import server


class StudioServerTests(unittest.TestCase):
    def test_mutate_dest_address_flips_last_byte(self):
        self.assertEqual(
            server.mutate_dest_address("00" * 20),
            ("00" * 19) + "01",
        )

    def test_slugify_normalizes_labels(self):
        self.assertEqual(server.slugify("  QSB Demo / Session  "), "qsb-demo-session")
        self.assertEqual(server.slugify(""), "session")

    def test_build_command_for_setup_and_benchmark(self):
        setup = server.build_command(
            "setup",
            {"config": "A", "seed": "7", "funding_mode": "bare"},
        )
        self.assertIn("setup", setup)
        self.assertIn("--config", setup)
        self.assertIn("--funding-mode", setup)

        bench = server.build_command(
            "benchmark",
            {"bench_only": "true"},
        )
        self.assertIn(str(server.BENCHMARK_SCRIPT), bench)
        self.assertIn("--bench-only", bench)

    def test_artifact_snapshot_summarizes_qsb_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "qsb_state.json"
            payload = {
                "config": "A",
                "funding_mode": "bare",
                "n": 150,
                "t1s": 8,
                "t1b": 1,
                "t2s": 7,
                "t2b": 2,
                "full_script_hex": "aa" * 10,
                "script_hash160": "11" * 20,
                "funding_script_pubkey": "bb" * 12,
            }
            path.write_text(json.dumps(payload))
            snapshot = server.artifact_snapshot(path)
            self.assertEqual(snapshot["kind"], "json")
            self.assertEqual(snapshot["summary"]["script_size"], 10)
            self.assertEqual(snapshot["summary"]["funding_script_pubkey_size"], 12)

    def test_session_lifecycle_uses_workspace_snapshots(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original = server.SESSIONS_DIR
            try:
                server.SESSIONS_DIR = Path(tmpdir)
                session = server.ensure_session("My Demo")
                session_dir = Path(session["workspace"])
                self.assertTrue(session_dir.exists())
                state_path = session_dir / "qsb_state.json"
                state_path.write_text(
                    json.dumps(
                        {
                            "config": "test",
                            "funding_mode": "bare",
                            "n": 10,
                            "t1s": 2,
                            "t1b": 0,
                            "t2s": 2,
                            "t2b": 0,
                            "full_script_hex": "aa" * 4,
                            "script_hash160": "11" * 20,
                            "funding_script_pubkey": "bb" * 6,
                        }
                    )
                )
                snapshot = server.workspace_snapshot(session["id"])
                self.assertEqual(snapshot["label"], "My Demo")
                names = {artifact["name"] for artifact in snapshot["artifacts"]}
                self.assertIn("qsb_state.json", names)
                self.assertIn("binding_report.json", names)
                self.assertIn("binding_report.html", names)
            finally:
                server.SESSIONS_DIR = original

    def test_decode_pinning_hit_reads_first_pair(self):
        payload = server.decode_pinning_hit("sequence=12\nlocktime=99\nsequence=13\nlocktime=100\n")
        self.assertEqual(payload["sequence"], 12)
        self.assertEqual(payload["locktime"], 99)
        self.assertEqual(len(payload["pairs"]), 2)

    def test_nth_combination_fixed_first_matches_small_reference(self):
        combos = [
            [0, 1, 2],
            [0, 1, 3],
            [0, 1, 4],
            [0, 2, 3],
            [0, 2, 4],
            [0, 3, 4],
        ]
        for ordinal, combo in enumerate(combos):
            self.assertEqual(server.nth_combination_fixed_first(5, 3, 0, ordinal), combo)

    def test_decode_digest_hit_recovers_indices(self):
        digest_params = {"n": 5, "t": 3}
        content = "first=0\nfirst_offset=3\nbatch_idx=1\n"
        payload = server.decode_digest_hit(content, digest_params, "1")
        self.assertEqual(payload["selected_indices"], [0, 2, 4])

    def test_build_qsb_package_writes_zip_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original = server.SESSIONS_DIR
            try:
                server.SESSIONS_DIR = Path(tmpdir)
                session = server.ensure_session("Pack Demo")
                session_dir = Path(session["workspace"])
                (session_dir / "pinning.bin").write_bytes(b"abcd")
                manifest = server.build_qsb_package(session_dir, "pinning.bin", "pinning")
                self.assertEqual(manifest["mode"], "pinning")
                self.assertTrue((session_dir / "qsb.zip").exists())
                self.assertTrue((session_dir / "qsb_vast_package.json").exists())
            finally:
                server.SESSIONS_DIR = original

    def test_workspace_snapshot_auto_imports_hit_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original = server.SESSIONS_DIR
            try:
                server.SESSIONS_DIR = Path(tmpdir)
                session = server.ensure_session("Auto Import")
                session_dir = Path(session["workspace"])
                (session_dir / "gpu_digest_r1_params.json").write_text(json.dumps({"n": 5, "t": 3}))
                (session_dir / "pinning_hit.txt").write_text("sequence=12\nlocktime=99\n")
                (session_dir / "digest_r1_hit.txt").write_text("first=0\nfirst_offset=3\nbatch_idx=1\n")
                snapshot = server.workspace_snapshot(session["id"])
                names = {artifact["name"] for artifact in snapshot["artifacts"]}
                self.assertIn("pinning_import.json", names)
                self.assertIn("digest_r1_import.json", names)
            finally:
                server.SESSIONS_DIR = original

    def test_clone_session_copies_workspace_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original = server.SESSIONS_DIR
            try:
                server.SESSIONS_DIR = Path(tmpdir)
                session = server.ensure_session("Source Demo")
                session_dir = Path(session["workspace"])
                (session_dir / "qsb_state.json").write_text(json.dumps({"config": "A"}))
                clone = server.clone_session(session["id"], "Cloned Demo")
                clone_dir = Path(clone["workspace"])
                self.assertTrue((clone_dir / "qsb_state.json").exists())
                self.assertEqual(server.read_json(clone_dir / "session.json")["cloned_from"], session["id"])
            finally:
                server.SESSIONS_DIR = original

    def test_artifact_snapshot_summarizes_fleet_status(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "qsb_fleet_status.json"
            payload = {
                "stage": "pinning",
                "phase": "monitoring",
                "active_instances": 3,
                "cost_so_far": 12.5,
                "fleet_hourly": 4.2,
                "fleet_rate_est_mhs": 999,
            }
            path.write_text(json.dumps(payload))
            snapshot = server.artifact_snapshot(path)
            self.assertEqual(snapshot["summary"]["stage"], "pinning")
            self.assertEqual(snapshot["summary"]["active_instances"], 3)

    def test_build_workspace_overview_includes_static_binding_report(self):
        artifacts = [
            {
                "name": "qsb_state.json",
                "data": {
                    "config": "A",
                    "funding_mode": "bare",
                    "n": 150,
                    "t1s": 8,
                    "t1b": 1,
                    "t2s": 7,
                    "t2b": 2,
                    "full_script_hex": "aa" * 8,
                    "script_hash160": "11" * 20,
                },
            }
        ]
        overview = server.build_workspace_overview(artifacts)
        self.assertEqual(overview["binding"]["mode"], "static")
        self.assertEqual(overview["binding"]["steps"][0]["label"], "Pinning")
        self.assertEqual(overview["constraints"][0]["label"], "Relay")

    def test_artifact_snapshot_summarizes_binding_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "binding_report.json"
            payload = {
                "mode": "dynamic",
                "headline": "Changing the destination forces a new puzzle solve.",
                "steps": [{}, {}, {}],
                "mutation": {"all_checks_changed": True},
            }
            path.write_text(json.dumps(payload))
            snapshot = server.artifact_snapshot(path)
            self.assertEqual(snapshot["summary"]["mode"], "dynamic")
            self.assertEqual(snapshot["summary"]["steps"], 3)
            self.assertTrue(snapshot["summary"]["checks_changed"])


if __name__ == "__main__":
    unittest.main()
