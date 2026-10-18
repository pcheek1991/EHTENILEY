import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LUA_SCRIPT = REPO_ROOT / "coreo_pipeline.lua"
FSHARP_SCRIPT = REPO_ROOT / "coreo_pipeline.fsx"
LUA_EXECUTABLE = shutil.which("lua") or "lua"


class FakeChatHandler(BaseHTTPRequestHandler):
    language = "C"
    marker = ""
    seen_models = []
    seen_functions = []
    lock = threading.Lock()

    def do_POST(self):
        request_length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(request_length).decode("utf-8"))
        prompt = request["messages"][-1]["content"]
        match = re.search(r"^BLUEPRINT[ \t]+([^\s]+)", prompt, re.M)
        function_name = match.group(1) if match else "hello"
        with self.lock:
            self.seen_models.append(request["model"])
            self.seen_functions.append(function_name)

        marker_line = ("    // UTF-16 marker: %s\n" % self.marker) if self.marker else ""
        if self.language == "JScript":
            source = (
                "function %s() {\n"
                "    // Purpose: Inferred: returns one.\n"
                "    // Args: none\n"
                "    // Returns: one\n"
                "    // Globals: none\n"
                "    // Calls: none\n"
                "%s"
                "    return 1;\n"
                "}\n"
            ) % (function_name, marker_line)
        else:
            source = (
                "/*\n"
                "Purpose: Inferred: returns one.\n"
                "Args: none.\n"
                "Returns: one.\n"
                "Globals: none.\n"
                "Calls: none.\n"
                "*/\n"
                "%s"
                "int32_t %s(void) { return 1; }\n"
            ) % (marker_line, function_name)
        body = "".join(
            "data: %s\n\n" % json.dumps({"choices": [{"delta": {"content": chunk}}]})
            for chunk in source.splitlines(keepends=True)
        ) + "data: [DONE]\n\n"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def make_pipeline_dump(root, program="demo", include_third=True):
    folders = {
        "assembly": root / (program + "_ASSEMBLY"),
        "c": root / (program + "_C_PSEUDOCODE"),
        "inventory": root / (program + "_INVENTORY"),
    }
    for folder in folders.values():
        folder.mkdir(parents=True)
    functions = [
        ("Java_com_game_Core_keep", "00401000", "int Java_com_game_Core_keep(void) { return 1; }"),
        (
            "Java_com_game_Core_wrap",
            "00402000",
            "int Java_com_game_Core_wrap(void) { CreateFileA(); return 1; }",
        ),
    ]
    if include_third:
        functions.append(
            ("Java_com_game_Core_keep2", "00403000", "int Java_com_game_Core_keep2(void) { return 1; }")
        )
    assembly = []
    pseudocode = []
    for name, entry, body in functions:
        address = int(entry, 16)
        assembly.extend(
            [
                "# FUNCTION: %s | ENTRY: %s" % (name, entry),
                "%08x PUSH EBP" % address,
                "%08x MOV EBP,ESP" % (address + 1),
                "%08x MOV EAX,0x1" % (address + 3),
                "%08x POP EBP" % (address + 8),
                "%08x RET" % (address + 9),
            ]
        )
        pseudocode.extend(
            [
                "// ====================",
                "// FUNCTION: %s" % name,
                "// ENTRY: %s" % entry,
                "// ====================",
                body,
            ]
        )
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


def utf16_units(text):
    encoded = text.encode("utf-16-le", "surrogatepass")
    return [
        encoded[index] | (encoded[index + 1] << 8)
        for index in range(0, len(encoded), 2)
    ]


def reference_coreoao_hex(current, previous, before_previous):
    current_units = utf16_units(current)
    previous_units = utf16_units(previous)
    before_previous_units = utf16_units(before_previous)
    output = []
    for index in range(min(len(current_units), len(previous_units), len(before_previous_units))):
        m0 = current_units[index]
        m1 = previous_units[index]
        m2 = before_previous_units[index]
        value = (abs(m0 - m1) ^ abs(m1 - m2) ^ (m0 & 0x3F)) | ((~0x3F) & 0xFF)
        rotated = (value << 3) | (value >> 5)
        output.append((value | rotated) & 0xFF)
    return " ".join("%02X" % value for value in output)


def find_jsc():
    candidate = shutil.which("jsc.exe") or shutil.which("jsc")
    if candidate:
        return candidate
    if os.name == "nt":
        windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
        for framework, version in (
            ("Framework", "v4.0.30319"),
            ("Framework64", "v4.0.30319"),
            ("Framework", "v2.0.50727"),
            ("Framework64", "v2.0.50727"),
        ):
            path = windows_root / "Microsoft.NET" / framework / version / "jsc.exe"
            if path.is_file():
                return str(path)
    return None


class CoreoLuaPipelineTests(unittest.TestCase):
    def setUp(self):
        self.artifact_parent = REPO_ROOT / "tests" / ".coreo-lua-artifacts"
        self.artifact_parent.mkdir(exist_ok=True)
        self.workspace = self.artifact_parent / uuid.uuid4().hex
        self.workspace.mkdir()
        self.python_temp = self.workspace / "python-temp"
        self.python_temp.mkdir()
        self.env = os.environ.copy()
        for name in ("TMPDIR", "TEMP", "TMP"):
            self.env[name] = str(self.python_temp)

    def tearDown(self):
        shutil.rmtree(self.workspace, ignore_errors=True)
        try:
            self.artifact_parent.rmdir()
        except OSError:
            pass

    def run_lua(self, arguments, timeout=240):
        return subprocess.run(
            [LUA_EXECUTABLE, str(LUA_SCRIPT)] + [str(argument) for argument in arguments],
            cwd=str(REPO_ROOT),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def run_fsharp(self, arguments, timeout=240):
        return subprocess.run(
            ["dotnet", "fsi", "--quiet", "--exec", str(FSHARP_SCRIPT), "--"]
            + [str(argument) for argument in arguments],
            cwd=str(REPO_ROOT),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def start_fake_model(self):
        with FakeChatHandler.lock:
            FakeChatHandler.seen_models = []
            FakeChatHandler.seen_functions = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def stop_fake_model(self, server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    def pipeline_arguments(self, dump_root, output_dir, url, model, language="C", mode="FORWARD"):
        return [
            "--mode", mode,
            "--dump-root", dump_root,
            "--program", "demo",
            "--out", output_dir,
            "--python", sys.executable,
            "--url", url,
            "--model", model,
            "--lang", language,
        ]

    def test_help_and_lua_cand_bidi_reverse_and_fsharp_parity(self):
        help_result = self.run_lua(["--help"])
        self.assertEqual(0, help_result.returncode, help_result.stdout + help_result.stderr)
        self.assertIn("--mode FORWARD|REVERSE|BIDI", help_result.stdout)

        root = self.workspace / "path with spaces & shell chars"
        dump_root = root / "dumps"
        source_folders = make_pipeline_dump(dump_root)
        lua_output = root / "Lua output"
        model = "fake model & arg"
        FakeChatHandler.language = "C"
        FakeChatHandler.marker = "\u0100 and \U0001F680"
        server, thread = self.start_fake_model()
        llm_url = "http://127.0.0.1:%d?token=do-not-record" % server.server_address[1]
        try:
            result = self.run_lua(
                self.pipeline_arguments(
                    dump_root,
                    lua_output,
                    llm_url,
                    model,
                    language="C",
                    mode="BIDI",
                )
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

            fsharp_output = root / "FSharp parity output"
            fsharp_result = self.run_fsharp(
                self.pipeline_arguments(
                    dump_root,
                    fsharp_output,
                    llm_url,
                    model,
                    language="C",
                    mode="FORWARD",
                )
            )
            self.assertEqual(0, fsharp_result.returncode, fsharp_result.stdout + fsharp_result.stderr)

            cpp_output = root / "C++ output"
            grouper_directory = root / "grouper inputs"
            nested_grouper = grouper_directory / "nested"
            nested_grouper.mkdir(parents=True)
            grouper_file = nested_grouper / "functions.tsv"
            grouper_file.write_text(
                "ENTRY\tNAME\tGROUP\tCALLS\tCALLED_BY\tGLOBALS\tDATA\tCLASS\n",
                encoding="utf-8",
            )
            FakeChatHandler.language = "C++"
            cpp_args = self.pipeline_arguments(
                dump_root,
                cpp_output,
                llm_url,
                model,
                language="C++",
                mode="FORWARD",
            )
            cpp_args.extend(["--grouper-dir", grouper_directory])
            cpp_result = self.run_lua(
                cpp_args
            )
            self.assertEqual(0, cpp_result.returncode, cpp_result.stdout + cpp_result.stderr)

            jsc = find_jsc()
            if jsc:
                FakeChatHandler.language = "JScript"
                FakeChatHandler.marker = "\u0100 and \U0001F680"
                js_output = root / "JScript output"
                js_args = self.pipeline_arguments(
                    dump_root,
                    js_output,
                    llm_url,
                    model,
                    language="JScript",
                    mode="FORWARD",
                )
                js_args.extend(["--jsc", jsc])
                js_result = self.run_lua(js_args)
                self.assertEqual(0, js_result.returncode, js_result.stdout + js_result.stderr)
        finally:
            self.stop_fake_model(server, thread)

        lua_manifest_path = lua_output / "COREO_MANIFEST.json"
        manifest_text = lua_manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
        self.assertEqual("completed", manifest["status"])
        self.assertEqual("BIDI", manifest["mode"])
        self.assertEqual(3, len(manifest["selection"]))
        self.assertTrue(all(item["track"] in ("KEEP", "WRAP") for item in manifest["selection"]))
        selection_stage = next(
            stage for stage in manifest["stages"] if stage["name"] == "select-queue-entries"
        )
        self.assertEqual(["KEEP", "WRAP"], selection_stage["tracks"])
        self.assertTrue(manifest["bidi"]["round_trip_verified"])
        self.assertEqual(4, manifest["bidi"]["restored_count"])
        self.assertGreaterEqual(len(FakeChatHandler.seen_models), 3)
        self.assertTrue(all(seen_model == model for seen_model in FakeChatHandler.seen_models))
        selected_names = {item["name"] for item in manifest["selection"]}
        self.assertEqual(selected_names, set(FakeChatHandler.seen_functions))
        self.assertNotIn("do-not-record", manifest_text)
        self.assertEqual(
            "http://127.0.0.1:%d" % server.server_address[1],
            manifest["options"]["llm"]["url_origin"],
        )
        for stage in manifest["stages"]:
            for value in stage.get("command", []):
                self.assertNotIn("do-not-record", value)

        for name, folder in (
            ("14_Assembly_dump.txt", "assembly"),
            ("13_function_dump.txt", "c"),
            ("04_classes.txt", "inventory"),
            ("02_imports.txt", "inventory"),
        ):
            self.assertEqual(
                (source_folders[folder] / name).read_bytes(),
                (lua_output / "BIDI_RESTORE" / "source" / name).read_bytes(),
            )

        optimizer = manifest["hex_optimizer"]
        self.assertEqual("COREOAO CAND", optimizer["algorithm"])
        self.assertEqual("coreoaoBytes-js-v1", optimizer["contract_version"])
        self.assertEqual(0x3F, optimizer["mask"])
        self.assertEqual(3, optimizer["shift"])
        self.assertEqual("UTF-16 code units", optimizer["input_encoding"])
        self.assertFalse(optimizer["reversible"])
        self.assertTrue(optimizer["original_sources_retained"])
        self.assertEqual("manifest selection order", optimizer["source_order"])
        self.assertEqual(1, optimizer["output_count"])
        self.assertEqual(2, optimizer["skipped_count"])
        self.assertEqual(
            [item["entry"] for item in manifest["selection"][:2]],
            [item["entry"] for item in optimizer["skipped_entries"]],
        )
        record = optimizer["outputs"][0]
        source_path = Path(record["source_path"])
        previous_path = Path(record["previous_source_path"])
        before_previous_path = Path(record["before_previous_source_path"])
        self.assertEqual("C", source_path.parent.name)
        source_text = source_path.read_text(encoding="utf-8")
        previous_text = previous_path.read_text(encoding="utf-8")
        before_previous_text = before_previous_path.read_text(encoding="utf-8")
        for text in (source_text, previous_text, before_previous_text):
            self.assertIn("\u0100", text)
            self.assertIn("\U0001F680", text)
        self.assertEqual(hashlib.sha256(source_path.read_bytes()).hexdigest(), record["source_sha256"])
        self.assertEqual(hashlib.sha256(previous_path.read_bytes()).hexdigest(), record["previous_source_sha256"])
        self.assertEqual(
            hashlib.sha256(before_previous_path.read_bytes()).hexdigest(),
            record["before_previous_source_sha256"],
        )
        expected_hex = reference_coreoao_hex(source_text, previous_text, before_previous_text)
        sidecar_path = Path(record["sidecar_path"])
        self.assertEqual("COREOAO", sidecar_path.parent.name)
        sidecar_text = sidecar_path.read_text(encoding="utf-8")
        self.assertEqual(expected_hex + "\n", sidecar_text)
        self.assertEqual(
            min(len(utf16_units(source_text)), len(utf16_units(previous_text)), len(utf16_units(before_previous_text))),
            record["byte_count"],
        )
        self.assertTrue(all(
            len(value) == 2 and int(value, 16) <= 0xFF
            for value in sidecar_text.strip().split(" ")
        ))

        fsharp_manifest = json.loads((fsharp_output / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
        fsharp_optimizer = fsharp_manifest["hex_optimizer"]
        self.assertEqual(optimizer["output_count"], fsharp_optimizer["output_count"])
        self.assertEqual(
            Path(fsharp_optimizer["outputs"][0]["sidecar_path"]).read_bytes(),
            sidecar_path.read_bytes(),
        )

        cpp_manifest = json.loads((cpp_output / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual("C++", cpp_manifest["hex_optimizer"]["language"])
        self.assertEqual(1, cpp_manifest["hex_optimizer"]["output_count"])
        grouper_input = cpp_manifest["inputs"]["config_inputs"]["grouper-dir"]
        self.assertEqual("directory", grouper_input["kind"])
        self.assertEqual(
            [{
                "path": "nested/functions.tsv",
                "sha256": hashlib.sha256(grouper_file.read_bytes()).hexdigest(),
            }],
            grouper_input["files"],
        )
        cpp_record = cpp_manifest["hex_optimizer"]["outputs"][0]
        self.assertEqual("CPP", Path(cpp_record["source_path"]).parent.name)
        self.assertEqual(
            reference_coreoao_hex(
                Path(cpp_record["source_path"]).read_text(encoding="utf-8"),
                Path(cpp_record["previous_source_path"]).read_text(encoding="utf-8"),
                Path(cpp_record["before_previous_source_path"]).read_text(encoding="utf-8"),
            ) + "\n",
            Path(cpp_record["sidecar_path"]).read_text(encoding="utf-8"),
        )

        restored_output = root / "standalone reverse output"
        reverse = self.run_lua([
            "--mode", "REVERSE",
            "--source-run", lua_output,
            "--out", restored_output,
        ])
        self.assertEqual(0, reverse.returncode, reverse.stdout + reverse.stderr)
        reverse_manifest = json.loads(
            (restored_output / "COREO_MANIFEST.json").read_text(encoding="utf-8")
        )
        self.assertEqual("REVERSE", reverse_manifest["mode"])
        self.assertEqual(4, len(reverse_manifest["outputs"]["restored_files"]))

        occupied = self.run_lua([
            "--mode", "REVERSE",
            "--source-run", lua_output,
            "--out", restored_output,
        ])
        self.assertNotEqual(0, occupied.returncode)
        self.assertIn("COREO output directory already exists", occupied.stderr)

        tampered_input = lua_output / "source" / "14_Assembly_dump.txt"
        tampered_input.write_bytes(tampered_input.read_bytes() + b"tampered\n")
        tampered_output = root / "tampered restore"
        tampered = self.run_lua([
            "--mode", "REVERSE",
            "--source-run", lua_output,
            "--out", tampered_output,
        ])
        self.assertNotEqual(0, tampered.returncode)
        self.assertIn("preserved source hash mismatch", tampered.stderr)
        self.assertFalse(tampered_output.exists())

    def test_lua_failure_manifest_records_failed_stage(self):
        root = self.workspace / "failure path with &"
        dump_root = root / "dumps"
        make_pipeline_dump(dump_root, include_third=False)
        output_dir = root / "failed run"
        result = self.run_lua([
            "--dump-root", dump_root,
            "--program", "demo",
            "--out", output_dir,
            "--python", root / "missing python.exe",
        ])
        self.assertNotEqual(0, result.returncode)
        manifest = json.loads((output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual("failed", manifest["status"])
        stage = next(stage for stage in manifest["stages"] if stage["name"] == "group-functions")
        self.assertEqual("failed", stage["status"])


if __name__ == "__main__":
    unittest.main()
