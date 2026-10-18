import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT_SCRIPT = REPO_ROOT / "llm_pipeline" / "blueprint_v3.py"
FSHARP_COREO_SCRIPT = REPO_ROOT / "coreo_pipeline.fsx"


class FakeChatHandler(BaseHTTPRequestHandler):
    language = "C"
    marker = ""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        prompt = request["messages"][-1]["content"]
        match = re.search(r"^BLUEPRINT[ \t]+([^\s]+)", prompt, re.M)
        function_name = match.group(1) if match else "hello"
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


def make_pipeline_dump(root, program="demo", include_third=False):
    folders = {
        "assembly": root / (program + "_ASSEMBLY"),
        "c": root / (program + "_C_PSEUDOCODE"),
        "inventory": root / (program + "_INVENTORY"),
    }
    for folder in folders.values():
        folder.mkdir(parents=True)
    functions = [
        ("Java_com_game_Core_keep", "00401000", "int Java_com_game_Core_keep(void) { return 1; }"),
        ("Java_com_game_Core_wrap", "00402000",
         "int Java_com_game_Core_wrap(void) { CreateFileA(); return 1; }"),
    ]
    if include_third:
        functions.append((
            "Java_com_game_Core_keep2",
            "00403000",
            "int Java_com_game_Core_keep2(void) { return 1; }",
        ))
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


def run_fsharp_coreo(args, timeout=180):
    return subprocess.run(
        ["dotnet", "fsi", "--quiet", "--exec", str(FSHARP_COREO_SCRIPT), "--"] + args,
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout, check=False,
    )


def js_utf16_units(text):
    encoded = text.encode("utf-16-le", "surrogatepass")
    return [
        encoded[index] | (encoded[index + 1] << 8)
        for index in range(0, len(encoded), 2)
    ]


def reference_coreoao_hex(current, previous, before_previous):
    current_units = js_utf16_units(current)
    previous_units = js_utf16_units(previous)
    before_previous_units = js_utf16_units(before_previous)
    output = []
    for index in range(min(len(current_units), len(previous_units), len(before_previous_units))):
        m0 = current_units[index]
        m1 = previous_units[index]
        m2 = before_previous_units[index]
        value = (
            abs(m0 - m1) ^ abs(m1 - m2) ^ (m0 & 0x3F)
        ) | ((~0x3F) & 0xFF)
        rotation = 3 % 8
        rotated = (value << rotation) | (value >> (8 - rotation))
        output.append((value | rotated) & 0xFF)
    return " ".join("%02X" % value for value in output)


class CoreoPipelineTests(unittest.TestCase):
    def test_fsharp_canonical_entry_is_one_function_in_one_file(self):
        source = FSHARP_COREO_SCRIPT.read_text(encoding="utf-8")
        top_level_bindings = [line for line in source.splitlines() if line.startswith("let ")]

        self.assertEqual(1, len(top_level_bindings))
        self.assertTrue(top_level_bindings[0].startswith("let runCoreo "))
        self.assertNotRegex(source, r"\b(?:eval|exec)\s*\(")
        self.assertNotRegex(source, r"\bfun\b")

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

    def test_fsharp_bidi_round_trip_and_reverse_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            folders = make_pipeline_dump(dump_root)
            output_dir = root / "bidi-run"
            FakeChatHandler.language = "C"
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                llm_url = "http://127.0.0.1:%d?coreo-secret=redact-me" % server.server_address[1]
                result = run_fsharp_coreo([
                    "--mode", "BIDI",
                    "--dump-root", str(dump_root),
                    "--program", "demo",
                    "--out", str(output_dir),
                    "--python", sys.executable,
                    "--url", llm_url,
                ], timeout=240)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            manifest = json.loads((output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual("BIDI", manifest["mode"])
            self.assertEqual("completed", manifest["status"])
            self.assertEqual(0, manifest["hex_optimizer"]["output_count"])
            self.assertEqual(2, manifest["hex_optimizer"]["skipped_count"])
            self.assertFalse(manifest["hex_optimizer"]["reversible"])
            manifest_text = (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            self.assertNotIn("redact-me", manifest_text)
            self.assertEqual(
                [("00401000", "KEEP"), ("00402000", "WRAP")],
                [(item["entry"], item["track"]) for item in manifest["selection"]],
            )
            llm_stages = [
                stage for stage in manifest["stages"]
                if stage["name"].startswith("run-llm:")
            ]
            self.assertEqual(1, len(llm_stages))
            self.assertEqual("completed", llm_stages[0]["status"])
            self.assertEqual(2, llm_stages[0]["result_count"])
            self.assertTrue(manifest["bidi"]["round_trip_verified"])
            self.assertEqual(4, manifest["bidi"]["restored_count"])
            for name, folder in (
                    ("14_Assembly_dump.txt", "assembly"),
                    ("13_function_dump.txt", "c"),
                    ("04_classes.txt", "inventory"),
                    ("02_imports.txt", "inventory")):
                self.assertEqual(
                    (folders[folder] / name).read_bytes(),
                    (output_dir / "BIDI_RESTORE" / "source" / name).read_bytes(),
                )

            restored_dir = root / "reverse-run"
            reverse_result = run_fsharp_coreo([
                "--mode", "REVERSE", "--source-run", str(output_dir), "--out", str(restored_dir),
            ])
            self.assertEqual(0, reverse_result.returncode,
                             reverse_result.stdout + reverse_result.stderr)
            reverse_manifest = json.loads(
                (restored_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )
            self.assertEqual("REVERSE", reverse_manifest["mode"])
            self.assertEqual(4, len(reverse_manifest["outputs"]["restored_files"]))
            for name in (
                    "14_Assembly_dump.txt", "13_function_dump.txt", "04_classes.txt", "02_imports.txt"):
                self.assertEqual(
                    (output_dir / "source" / name).read_bytes(),
                    (restored_dir / "source" / name).read_bytes(),
                )

            tampered_input = output_dir / "source" / "14_Assembly_dump.txt"
            tampered_input.write_bytes(tampered_input.read_bytes() + b"tampered\n")
            tampered_restore = root / "tampered-restore"
            tampered_result = run_fsharp_coreo([
                "--mode", "REVERSE", "--source-run", str(output_dir),
                "--out", str(tampered_restore),
            ])
            self.assertNotEqual(0, tampered_result.returncode)
            self.assertIn("preserved source hash mismatch", tampered_result.stderr)
            self.assertFalse(tampered_restore.exists())

    def test_fsharp_coreoao_hex_sidecars_across_languages(self):
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

        languages = ["C", "C++"]
        if jsc:
            languages.append("JScript")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_pipeline_dump(dump_root, include_third=True)
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for language in languages:
                    FakeChatHandler.language = language
                    FakeChatHandler.marker = "\u0100" if language == "C" else ""
                    output_dir = root / ("COREO_" + language.replace("+", "plus"))
                    args = [
                        "--mode", "BIDI" if language == "C" else "FORWARD",
                        "--dump-root", str(dump_root),
                        "--program", "demo",
                        "--out", str(output_dir),
                        "--python", sys.executable,
                        "--url", "http://127.0.0.1:%d" % server.server_address[1],
                        "--lang", language,
                    ]
                    if language == "JScript":
                        args.extend(["--jsc", str(jsc)])
                    result = run_fsharp_coreo(args, timeout=240)
                    self.assertEqual(0, result.returncode,
                                     result.stdout + result.stderr + " (lang=%s)" % language)

                    manifest = json.loads(
                        (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
                    )
                    optimizer = manifest["hex_optimizer"]
                    self.assertEqual(language, optimizer["language"])
                    self.assertEqual(0x3F, optimizer["mask"])
                    self.assertEqual(3, optimizer["shift"])
                    self.assertEqual("UTF-16 code units", optimizer["input_encoding"])
                    self.assertIn("min(M0.Length", optimizer["length_policy"])
                    self.assertFalse(optimizer["reversible"])
                    self.assertTrue(optimizer["original_sources_retained"])
                    self.assertEqual(
                        "manifest selection order",
                        optimizer["source_order"],
                    )
                    self.assertEqual(1, optimizer["output_count"])
                    self.assertEqual(2, optimizer["skipped_count"])
                    self.assertEqual(1, len(optimizer["outputs"]))
                    self.assertEqual(2, len(optimizer["skipped_entries"]))
                    self.assertEqual(
                        [item["entry"] for item in manifest["selection"][:2]],
                        [item["entry"] for item in optimizer["skipped_entries"]],
                    )
                    if language == "C":
                        self.assertTrue(manifest["bidi"]["round_trip_verified"])

                    record = optimizer["outputs"][0]
                    source_path = Path(record["source_path"])
                    previous_path = Path(record["previous_source_path"])
                    before_previous_path = Path(record["before_previous_source_path"])
                    expected_directory = {"C": "C", "C++": "CPP", "JScript": "JSCRIPT"}[language]
                    self.assertEqual(expected_directory, source_path.parent.name)
                    source_text = source_path.read_text(encoding="utf-8")
                    previous_text = previous_path.read_text(encoding="utf-8")
                    before_previous_text = before_previous_path.read_text(encoding="utf-8")
                    if language == "C":
                        self.assertIn("\u0100", source_text)
                        self.assertIn("\u0100", previous_text)
                        self.assertIn("\u0100", before_previous_text)
                    self.assertEqual(
                        hashlib.sha256(source_path.read_bytes()).hexdigest(),
                        record["source_sha256"],
                    )
                    self.assertEqual(
                        hashlib.sha256(previous_path.read_bytes()).hexdigest(),
                        record["previous_source_sha256"],
                    )
                    self.assertEqual(
                        hashlib.sha256(before_previous_path.read_bytes()).hexdigest(),
                        record["before_previous_source_sha256"],
                    )
                    expected_hex = reference_coreoao_hex(
                        source_text, previous_text, before_previous_text
                    )
                    sidecar_path = Path(record["sidecar_path"])
                    self.assertEqual("COREOAO", sidecar_path.parent.name)
                    self.assertNotEqual(source_path, sidecar_path)
                    sidecar_text = sidecar_path.read_text(encoding="utf-8")
                    self.assertEqual(expected_hex + "\n", sidecar_text)
                    self.assertEqual(
                        "F7" if language == "JScript" else "FF",
                        sidecar_text.split(" ", 1)[0],
                    )
                    self.assertEqual(
                        hashlib.sha256(sidecar_path.read_bytes()).hexdigest(),
                        record["sidecar_sha256"],
                    )
                    self.assertEqual(
                        min(
                            len(js_utf16_units(source_text)),
                            len(js_utf16_units(previous_text)),
                            len(js_utf16_units(before_previous_text)),
                        ),
                        record["byte_count"],
                    )
                    self.assertTrue(all(
                        len(value) == 2 and int(value, 16) <= 0xFF
                        for value in sidecar_text.strip().split(" ")
                    ))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_fsharp_failure_manifest_records_upstream_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_pipeline_dump(dump_root)
            output_dir = root / "failed-run"
            result = run_fsharp_coreo([
                "--dump-root", str(dump_root),
                "--program", "demo",
                "--out", str(output_dir),
                "--python", str(root / "missing-python.exe"),
            ])
            self.assertNotEqual(0, result.returncode)
            manifest = json.loads((output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8"))
            self.assertEqual("failed", manifest["status"])
            stage = next(item for item in manifest["stages"] if item["name"] == "group-functions")
            self.assertEqual("failed", stage["status"])

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
            languages = ["C", "C++"]
            if jsc:
                languages.append("JScript")
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for language in languages:
                    FakeChatHandler.language = language
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


if __name__ == "__main__":
    unittest.main()
