import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import coreo_pipeline


REPO_ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT_SCRIPT = REPO_ROOT / "llm_pipeline" / "blueprint_v3.py"
COREO_SCRIPT = REPO_ROOT / "coreo_pipeline.py"


class FakeChatHandler(BaseHTTPRequestHandler):
    source_code = ""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = "".join(
            "data: %s\n\n" % json.dumps({"choices": [{"delta": {"content": chunk}}]})
            for chunk in self.source_code.splitlines(keepends=True)
        ) + "data: [DONE]\n\n"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


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
    (folders["inventory"] / "04_classes.txt").write_text("", encoding="utf-8")
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
    def test_production_integration_is_one_function_in_one_file(self):
        tree = ast.parse(COREO_SCRIPT.read_text(encoding="utf-8"))
        functions = [node for node in ast.walk(tree)
                     if isinstance(node, (ast.FunctionDef, ast.Lambda))]

        self.assertEqual(1, len(functions))
        self.assertIsInstance(functions[0], ast.FunctionDef)
        self.assertEqual("run_coreo", functions[0].name)
        self.assertFalse(any(isinstance(node, ast.ClassDef) for node in ast.walk(tree)))

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

    def test_language_modes_and_javascript_compile_without_live_model(self):
        jsc = shutil.which("jsc.exe") or shutil.which("jsc")
        if not jsc and os.name == "nt":
            windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
            for framework, version in (
                    ("Framework", "v4.0.30319"),
                    ("Framework64", "v4.0.30319"),
                    ("Framework", "v2.0.50727"),
                    ("Framework64", "v2.0.50727")):
                candidate = windows_root / "Microsoft.NET" / framework / version / "jsc.exe"
                if candidate.is_file():
                    jsc = str(candidate)
                    break

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            blueprint_dir = root / "BLUEPRINT"
            blueprint_dir.mkdir()
            stem = "00000001_hello"
            (blueprint_dir / (stem + ".blueprint.txt")).write_text(
                "BLUEPRINT hello\nFACTS\nFunction returns the constant 1.\n",
                encoding="utf-8",
            )
            (blueprint_dir / (stem + ".check.json")).write_text(json.dumps({
                "function": "hello",
                "entry": "00000001",
                "must_call": [],
                "must_use_globals": [],
                "must_use_strings": [],
                "reads_after_call": [],
                "machine": {"loops": 0, "steps": [], "return_from": None, "cond_consts": []},
            }), encoding="utf-8")
            source_by_language = {
                "C": (
                    "/*\n"
                    "Purpose: Inferred: returns one.\n"
                    "Args: none.\n"
                    "Returns: one.\n"
                    "Globals: none.\n"
                    "Calls: none.\n"
                    "*/\n"
                    "int32_t hello(void) { return 1; }\n"
                ),
                "C++": (
                    "/*\n"
                    "Purpose: Inferred: returns one.\n"
                    "Args: none.\n"
                    "Returns: one.\n"
                    "Globals: none.\n"
                    "Calls: none.\n"
                    "*/\n"
                    "int32_t hello(void) { return 1; }\n"
                ),
            }
            if jsc:
                source_by_language["JScript"] = (
                "function hello() {\n"
                "    // Purpose: Inferred: returns a constant.\n"
                "    // Args: none\n"
                "    // Returns: one\n"
                "    // Globals: none\n"
                "    // Calls: none\n"
                "    return 1;\n"
                "}\n"
                )
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for language, source_code in source_by_language.items():
                    FakeChatHandler.source_code = source_code
                    output_dir = root / ("RUN_" + language)
                    command = [
                        sys.executable, str(REPO_ROOT / "llm_pipeline" / "run_blueprint_llm_v3.py"),
                        "--bp", str(blueprint_dir), "--out", str(output_dir),
                        "--url", "http://127.0.0.1:%d" % server.server_address[1],
                        "--lang", language,
                    ]
                    if language == "JScript":
                        command += ["--jsc", str(jsc)]
                    result = subprocess.run(
                        command, cwd=str(REPO_ROOT), capture_output=True, text=True,
                        timeout=120, check=False,
                    )
                    self.assertEqual(0, result.returncode,
                                     result.stdout + result.stderr + " (lang=%s)" % language)
                    self.assertIn(
                        "PASS\thello\t",
                        (output_dir / "RESULTS.txt").read_text(encoding="utf-8"),
                    )
                    if language == "JScript":
                        self.assertTrue((output_dir / "JSCRIPT" / (stem + ".js")).is_file())
                        executable = output_dir / "NET" / (stem + ".exe")
                        self.assertTrue(executable.is_file())
                        self.assertEqual(b"MZ", executable.read_bytes()[:2])
                    else:
                        code_dir = "CPP" if language == "C++" else "C"
                        extension = ".cpp" if language == "C++" else ".c"
                        self.assertTrue((output_dir / code_dir / (stem + extension)).is_file())
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_single_function_uses_selected_keep_wrap_queues_and_redacts_manifest_url(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_dump(dump_root)
            out = root / "runs" / "demo-run"
            url = "https://user:password@example.test:8443/api/v1?token=secret#fragment"
            jsc_path = root / "jsc.exe"
            jsc_path.write_text("stub compiler path", encoding="utf-8")
            commands = []

            def fake_process(command, cwd, check):
                commands.append(command)
                script = Path(command[1]).name
                if script == "make_full_lite_v2.py":
                    group = Path(command[command.index("--out") + 1]) / "LITE_AC" / "Alpha"
                    group.mkdir(parents=True)
                    (group / "00401000_keep.txt").write_text(
                        function_text("00401000", "keep_one"), encoding="utf-8"
                    )
                    (group / "00403000_wrap.txt").write_text(
                        function_text("00403000", "wrap_one"), encoding="utf-8"
                    )
                elif script == "triage_evidence_v2.py":
                    report_dir = Path(command[command.index("--report-dir") + 1])
                    report_dir.mkdir(parents=True)
                    (report_dir / "FUNCTIONS.tsv").write_text(
                        "GROUP\tENTRY\tNAME\tLABEL\tREASON\n", encoding="utf-8"
                    )
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

            status = coreo_pipeline.run_coreo([
                "--dump-root", str(dump_root), "--program", "demo", "--out", str(out),
                "--group", "Alpha", "--url", url, "--lang", "JScript", "--jsc", str(jsc_path),
            ], process_runner=fake_process)
            manifest = json.loads((out / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
            stage_names = [stage["name"] for stage in manifest["stages"]]
            selected = manifest["selection"]

            self.assertEqual(0, status)
            self.assertEqual([
                "make_full_lite_v2.py",
                "triage_evidence_v2.py",
                "build_roles_v2.py",
                "blueprint_v3.py",
                "run_blueprint_llm_v3.py",
            ], [Path(command[1]).name for command in commands])
            self.assertEqual(
                [("00401000", "KEEP"), ("00403000", "WRAP")],
                [(item["entry"], item["track"]) for item in selected],
            )
            self.assertEqual(2, manifest["outputs"]["groups"]["Alpha"]["result_summary"]["pass_count"])
            self.assertEqual("https://example.test:8443", manifest["options"]["llm"]["url_origin"])
            self.assertNotIn("password", json.dumps(manifest))
            self.assertNotIn("secret", json.dumps(manifest))
            runner_stage = next(stage for stage in manifest["stages"] if stage["name"] == "run-llm:Alpha")
            self.assertEqual("https://example.test:8443",
                             runner_stage["command"][runner_stage["command"].index("--url") + 1])
            self.assertEqual("JScript", runner_stage["command"][
                runner_stage["command"].index("--lang") + 1
            ])
            self.assertEqual(str(jsc_path.resolve()), runner_stage["command"][
                runner_stage["command"].index("--jsc") + 1
            ])
            self.assertEqual(str(jsc_path.resolve()), manifest["options"]["llm"]["jsc_path"])
            self.assertEqual("completed", manifest["status"])
            self.assertIn("select-queue-entries", stage_names)

    def test_failure_is_recorded_by_single_function(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_dump(dump_root)
            out = root / "run"

            def failing_process(command, cwd, check):
                script = Path(command[1]).name
                if script == "make_full_lite_v2.py":
                    (Path(command[command.index("--out") + 1]) / "LITE_AC").mkdir(parents=True)
                    return SimpleNamespace(returncode=0)
                if script == "triage_evidence_v2.py":
                    raise subprocess.CalledProcessError(7, command)
                return SimpleNamespace(returncode=0)

            status = coreo_pipeline.run_coreo([
                "--dump-root", str(dump_root), "--program", "demo", "--out", str(out),
            ], process_runner=failing_process)
            manifest = json.loads((out / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
            triage_stage = next(stage for stage in manifest["stages"]
                                if stage["name"] == "triage-functions")

            self.assertEqual(7, status)
            self.assertEqual("failed", manifest["status"])
            self.assertEqual("failed", triage_stage["status"])
            self.assertEqual(7, triage_stage["returncode"])

    def test_real_ghidra_pipeline_feeds_both_queues_without_live_model_call(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_pipeline_dump(dump_root)
            out = root / "run"
            real_run = subprocess.run
            calls = []

            def stub_only_llm(command, cwd, check):
                script = Path(command[1]).name
                calls.append(script)
                if script != "run_blueprint_llm_v3.py":
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

            status = coreo_pipeline.run_coreo([
                "--dump-root", str(dump_root), "--program", "demo", "--out", str(out),
            ], process_runner=stub_only_llm)
            manifest = json.loads((out / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
            group_output = manifest["outputs"]["groups"]["Core"]

            self.assertEqual(0, status)
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
            self.assertTrue((out / "source" / "04_classes.txt").is_file())
            self.assertTrue((out / "source" / "02_imports.txt").is_file())
            self.assertEqual(2, group_output["result_summary"]["result_count"])
            self.assertEqual(2, len(list(Path(group_output["blueprints"]).glob("*.blueprint.txt"))))


if __name__ == "__main__":
    unittest.main()
