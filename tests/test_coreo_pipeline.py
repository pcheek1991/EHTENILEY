import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import coreo_pipeline


REPO_ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT_SCRIPT = REPO_ROOT / "llm_pipeline" / "blueprint_v3.py"


def make_dump(root, program="demo"):
    folders = {
        "assembly": root / (program + "_ASSEMBLY"),
        "c": root / (program + "_C_PSEUDOCODE"),
        "inventory": root / (program + "_INVENTORY"),
    }
    for folder in folders.values():
        folder.mkdir(parents=True)
    (folders["assembly"] / "14_Assembly_dump.txt").write_text("assembly", encoding="utf-8")
    (folders["c"] / "13_function_dump.txt").write_text("pseudocode", encoding="utf-8")
    return folders


def make_pipeline_dump(root, program="demo"):
    folders = make_dump(root, program)
    functions = [
        ("Java_com_game_Core_keep", "00401000", "int Java_com_game_Core_keep(void) { return 1; }"),
        ("Java_com_game_Core_wrap", "00402000",
         "int Java_com_game_Core_wrap(void) { CreateFileA(); return 1; }"),
    ]
    assembly = []
    pseudocode = []
    for name, entry, body in functions:
        address = int(entry, 16)
        assembly.extend([
            "# FUNCTION: %s | ENTRY: %s" % (name, entry),
            "%08x PUSH EBP" % address,
            "%08x MOV EBP,ESP" % (address + 1),
            "%08x MOV EAX,0x1" % (address + 3),
            "%08x POP EBP" % (address + 8),
            "%08x RET" % (address + 9),
        ])
        pseudocode.extend([
            "// ====================",
            "// FUNCTION: %s" % name,
            "// ENTRY: %s" % entry,
            "// ====================",
            body,
        ])
    (folders["assembly"] / "14_Assembly_dump.txt").write_text(
        "\n".join(assembly) + "\n", encoding="utf-8"
    )
    (folders["c"] / "13_function_dump.txt").write_text(
        "\n".join(pseudocode) + "\n", encoding="utf-8"
    )
    (folders["inventory"] / "02_imports.txt").write_text(
        "LIBRARY\tNAME\nKERNEL32.dll\tCreateFileA\n", encoding="utf-8"
    )
    return folders


def function_text(entry, name):
    address = int(entry, 16)
    return (
        "// FUNCTION: %s  ENTRY: %s  CLASS: Core\n" % (name, entry)
        + "// CALLS: (none)\n"
        + "// CALLED BY: (none)\n"
        + "// GLOBALS/DATA: (none)\n"
        + "[ASSEMBLY]\n"
        + "%08x PUSH EBP\n" % address
        + "%08x MOV EBP,ESP\n" % (address + 1)
        + "%08x MOV EAX,0x1\n" % (address + 3)
        + "%08x POP EBP\n" % (address + 8)
        + "%08x RET\n" % (address + 9)
        + "[C PSEUDOCODE]\n"
        + "int %s(void) { return 1; }\n" % name
    )


def write_queue(path, rows):
    lines = ["GROUP\tENTRY\tNAME\tREASON"]
    lines.extend("\t".join(row) for row in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class CoreoPipelineTests(unittest.TestCase):
    def test_manifest_redacts_url_credentials_path_and_query(self):
        url = "https://user:password@example.test:8443/api/v1?token=secret#fragment"

        self.assertEqual("https://example.test:8443", coreo_pipeline.endpoint_origin(url))
        command = coreo_pipeline.manifest_command(["python", "runner.py", "--url", url])
        self.assertEqual("https://example.test:8443", command[-1])
        self.assertNotIn("password", repr(command))
        self.assertNotIn("secret", repr(command))
        self.assertNotIn("/api/v1", repr(command))

    def test_dump_paths_include_optional_inventory_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folders = make_dump(root)
            (folders["inventory"] / "04_classes.txt").write_text("classes", encoding="utf-8")
            (folders["inventory"] / "02_imports.txt").write_text("imports", encoding="utf-8")

            resolved_root, files = coreo_pipeline.resolve_dump_files(root, "demo")

            self.assertEqual(root.resolve(), resolved_root)
            self.assertEqual("14_Assembly_dump.txt", files["assembly"].name)
            self.assertTrue(files["classes"].is_file())
            self.assertTrue(files["imports"].is_file())

    def test_queue_filter_uses_only_selected_tracks_and_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            triage = Path(temp)
            write_queue(triage / "QUEUE_KEEP.tsv", [
                ("Alpha", "00401000", "keep_one", "game logic"),
                ("Beta", "00402000", "keep_two", "game logic"),
            ])
            write_queue(triage / "QUEUE_WRAP.tsv", [
                ("Alpha", "00403000", "wrap_one", "OS glue"),
            ])
            write_queue(triage / "QUEUE_UNKNOWN.tsv", [
                ("Alpha", "00404000", "unknown_one", "unclear"),
            ])

            selected = coreo_pipeline.read_queue_entries(
                triage, ("KEEP", "WRAP"), groups=("Alpha",)
            )

            self.assertEqual(
                [("00401000", "KEEP"), ("00403000", "WRAP")],
                [(item["entry"], item["track"]) for item in selected],
            )
            self.assertTrue(all(item["group"] == "Alpha" for item in selected))

    def test_blueprint_allowlist_preserves_unfiltered_default(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lite = root / "LITE_AC"
            group = lite / "Core"
            group.mkdir(parents=True)
            (group / "00401000_first.txt").write_text(
                function_text("00401000", "first"), encoding="utf-8"
            )
            (group / "00402000_second.txt").write_text(
                function_text("00402000", "second"), encoding="utf-8"
            )
            allowlist = root / "selected.txt"
            allowlist.write_text("00402000\n", encoding="utf-8")

            all_output = root / "all"
            filtered_output = root / "filtered"
            common = [
                sys.executable, str(BLUEPRINT_SCRIPT), "--group", str(group),
                "--index-dir", str(lite),
            ]
            all_result = subprocess.run(
                common + ["--out", str(all_output)],
                cwd=str(REPO_ROOT), capture_output=True, text=True, check=False,
            )
            filtered_result = subprocess.run(
                common + ["--out", str(filtered_output), "--entries-file", str(allowlist)],
                cwd=str(REPO_ROOT), capture_output=True, text=True, check=False,
            )
            reused_result = subprocess.run(
                common + ["--out", str(filtered_output), "--entries-file", str(allowlist)],
                cwd=str(REPO_ROOT), capture_output=True, text=True, check=False,
            )

            self.assertEqual(0, all_result.returncode, all_result.stdout + all_result.stderr)
            self.assertEqual(0, filtered_result.returncode,
                             filtered_result.stdout + filtered_result.stderr)
            self.assertEqual(2, len(list(all_output.glob("*.blueprint.txt"))))
            self.assertEqual(["00402000_second.blueprint.txt"],
                             [path.name for path in filtered_output.glob("*.blueprint.txt")])
            self.assertNotEqual(0, reused_result.returncode)
            self.assertIn("requires an output folder without old blueprint/check files",
                          reused_result.stderr)

    def test_mocked_pipeline_runs_both_selected_queues_and_records_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_dump(dump_root)
            out = root / "runs" / "demo-run"
            args = coreo_pipeline.build_parser().parse_args([
                "--dump-root", str(dump_root), "--program", "demo", "--out", str(out),
                "--group", "Alpha",
            ])
            commands = []

            def fake_run(command, cwd, check):
                commands.append(command)
                script = Path(command[1]).name
                if script == "make_full_lite_v2.py":
                    lite = Path(command[command.index("--out") + 1]) / "LITE_AC" / "Alpha"
                    lite.mkdir(parents=True)
                    (lite / "00401000_keep.txt").write_text(
                        function_text("00401000", "keep_one"), encoding="utf-8"
                    )
                    (lite / "00403000_wrap.txt").write_text(
                        function_text("00403000", "wrap_one"), encoding="utf-8"
                    )
                elif script == "triage_evidence_v2.py":
                    report_dir = Path(command[command.index("--report-dir") + 1])
                    report_dir.mkdir(parents=True)
                elif script == "build_roles_v2.py":
                    triage = Path(command[command.index("--triage") + 1])
                    write_queue(triage / "QUEUE_KEEP.tsv", [
                        ("Alpha", "00401000", "keep_one", "game logic"),
                        ("Beta", "00402000", "keep_two", "game logic"),
                    ])
                    write_queue(triage / "QUEUE_WRAP.tsv", [
                        ("Alpha", "00403000", "wrap_one", "OS glue"),
                    ])
                    write_queue(triage / "QUEUE_UNKNOWN.tsv", [
                        ("Alpha", "00404000", "unknown_one", "unclear"),
                    ])
                elif script == "blueprint_v3.py":
                    bp_out = Path(command[command.index("--out") + 1])
                    entries_file = Path(command[command.index("--entries-file") + 1])
                    bp_out.mkdir(parents=True)
                    for entry in entries_file.read_text(encoding="utf-8").splitlines():
                        stem = entry + "_function"
                        (bp_out / (stem + ".blueprint.txt")).write_text("blueprint", encoding="utf-8")
                        (bp_out / (stem + ".check.json")).write_text(
                            json.dumps({"entry": entry}), encoding="utf-8"
                        )
                elif script == "run_blueprint_llm_v3.py":
                    bp_dir = Path(command[command.index("--bp") + 1])
                    run_out = Path(command[command.index("--out") + 1])
                    run_out.mkdir(parents=True)
                    count = len(list(bp_dir.glob("*.blueprint.txt")))
                    (run_out / "RESULTS.txt").write_text(
                        "".join("PASS\tfunction\ttries 1\n" for _ in range(count)),
                        encoding="utf-8",
                    )
                return SimpleNamespace(returncode=0)

            with patch.object(coreo_pipeline.subprocess, "run", side_effect=fake_run):
                manifest = coreo_pipeline.run_pipeline(args, repo_root=REPO_ROOT)

            script_order = [Path(command[1]).name for command in commands]
            self.assertEqual([
                "make_full_lite_v2.py",
                "triage_evidence_v2.py",
                "build_roles_v2.py",
                "blueprint_v3.py",
                "run_blueprint_llm_v3.py",
            ], script_order)
            self.assertEqual(["00401000", "00403000"],
                             [item["entry"] for item in manifest["selection"]])
            self.assertEqual(["KEEP", "WRAP"],
                             [item["track"] for item in manifest["selection"]])
            self.assertEqual("completed", manifest["status"])
            self.assertEqual(2, manifest["outputs"]["groups"]["Alpha"]["result_summary"]["pass_count"])
            self.assertTrue((out / "source" / "14_Assembly_dump.txt").is_file())
            self.assertEqual(
                coreo_pipeline.sha256_file(dump_root / "demo_ASSEMBLY" / "14_Assembly_dump.txt"),
                manifest["inputs"]["ghidra_dump_files"]["assembly"]["sha256"],
            )
            self.assertEqual("completed", json.loads(
                (out / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )["status"])

    def test_subprocess_failure_is_saved_in_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_dump(dump_root)
            out = root / "run"
            args = coreo_pipeline.build_parser().parse_args([
                "--dump-root", str(dump_root), "--program", "demo", "--out", str(out),
            ])

            def failing_run(command, cwd, check):
                script = Path(command[1]).name
                if script == "make_full_lite_v2.py":
                    lite = Path(command[command.index("--out") + 1]) / "LITE_AC"
                    lite.mkdir(parents=True)
                    return SimpleNamespace(returncode=0)
                if script == "triage_evidence_v2.py":
                    raise subprocess.CalledProcessError(7, command)
                return SimpleNamespace(returncode=0)

            with patch.object(coreo_pipeline.subprocess, "run", side_effect=failing_run):
                with self.assertRaises(subprocess.CalledProcessError):
                    coreo_pipeline.run_pipeline(args, repo_root=REPO_ROOT)

            manifest = json.loads((out / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual("failed", manifest["status"])
            triage_stage = next(stage for stage in manifest["stages"]
                                if stage["name"] == "triage-functions")
            self.assertEqual("failed", triage_stage["status"])
            self.assertEqual(7, triage_stage["returncode"])

    def test_real_ghidra_pipeline_feeds_queue_selected_blueprints(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_pipeline_dump(dump_root)
            out = root / "run"
            args = coreo_pipeline.build_parser().parse_args([
                "--dump-root", str(dump_root), "--program", "demo", "--out", str(out),
            ])
            real_run = subprocess.run
            calls = []

            def run_with_stubbed_model(command, cwd, check):
                calls.append(Path(command[1]).name)
                if Path(command[1]).name != "run_blueprint_llm_v3.py":
                    return real_run(command, cwd=cwd, check=check)
                bp_dir = Path(command[command.index("--bp") + 1])
                run_dir = Path(command[command.index("--out") + 1])
                run_dir.mkdir(parents=True)
                count = len(list(bp_dir.glob("*.blueprint.txt")))
                (run_dir / "RESULTS.txt").write_text(
                    "".join("PASS\tfunction\ttries 1\n" for _ in range(count)),
                    encoding="utf-8",
                )
                return SimpleNamespace(returncode=0)

            with patch.object(coreo_pipeline.subprocess, "run", side_effect=run_with_stubbed_model):
                manifest = coreo_pipeline.run_pipeline(args, repo_root=REPO_ROOT)

            self.assertEqual([
                "make_full_lite_v2.py",
                "triage_evidence_v2.py",
                "build_roles_v2.py",
                "blueprint_v3.py",
                "run_blueprint_llm_v3.py",
            ], calls)
            self.assertEqual(
                [("00401000", "KEEP"), ("00402000", "WRAP")],
                [(item["entry"], item["track"]) for item in manifest["selection"]],
            )
            group_outputs = manifest["outputs"]["groups"]["Core"]
            self.assertEqual(2, group_outputs["result_summary"]["result_count"])
            self.assertEqual(2, len(list(Path(group_outputs["blueprints"]).glob("*.blueprint.txt"))))


if __name__ == "__main__":
    unittest.main()
