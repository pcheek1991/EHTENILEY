import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COREO_SCRIPT = REPO_ROOT / "coreo_pipeline.py"
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_coreo_pipeline import (  # noqa: E402
    FakeChatHandler,
    make_pipeline_dump,
    reference_coreoao_hex,
    run_fsharp_coreo,
)


def run_python_coreo(args, timeout=240):
    return subprocess.run(
        [sys.executable, str(COREO_SCRIPT)] + [str(argument) for argument in args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def find_jsc():
    jsc = shutil.which("jsc.exe") or shutil.which("jsc")
    if jsc or os.name != "nt":
        return jsc
    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    for framework, version in (
            ("Framework", "v4.0.30319"),
            ("Framework64", "v4.0.30319"),
            ("Framework", "v2.0.50727"),
            ("Framework64", "v2.0.50727")):
        candidate = windows_root / "Microsoft.NET" / framework / version / "jsc.exe"
        if candidate.is_file():
            return str(candidate)
    return None


class CoreoPythonPortTests(unittest.TestCase):
    def test_python3_entry_point_is_one_function(self):
        source = COREO_SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(COREO_SCRIPT))
        functions = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.Lambda))
        ]
        self.assertEqual(1, len(functions))
        self.assertIsInstance(functions[0], ast.FunctionDef)
        self.assertEqual("run_coreo", functions[0].name)
        self.assertNotRegex(source, r"\b(?:eval|exec)\s*\(")

    def test_python3_bidi_cand_matches_fsharp_and_reverse_integrity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "synthetic dumps"
            source_folders = make_pipeline_dump(dump_root, include_third=True)
            fsharp_output = root / "FSharp output"
            python_output = root / "Python output"
            FakeChatHandler.language = "C"
            FakeChatHandler.marker = "\u0100 and \U0001F680"
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                model_url = "http://127.0.0.1:%d?coreo-secret=redact-me" % server.server_address[1]
                common = [
                    "--mode", "BIDI",
                    "--dump-root", str(dump_root),
                    "--program", "demo",
                    "--python", sys.executable,
                    "--url", model_url,
                ]
                fsharp_result = run_fsharp_coreo(
                    common + ["--out", str(fsharp_output)], timeout=300
                )
                self.assertEqual(0, fsharp_result.returncode,
                                 fsharp_result.stdout + fsharp_result.stderr)
                python_result = run_python_coreo(
                    common + ["--out", str(python_output)], timeout=300
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            self.assertEqual(0, python_result.returncode,
                             python_result.stdout + python_result.stderr)
            fsharp_manifest = json.loads(
                (fsharp_output / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )
            python_manifest_path = python_output / "COREO_MANIFEST.json"
            python_manifest_text = python_manifest_path.read_text(encoding="utf-8")
            python_manifest = json.loads(python_manifest_text)
            self.assertEqual("BIDI", python_manifest["mode"])
            self.assertEqual("completed", python_manifest["status"])
            self.assertTrue(python_manifest["bidi"]["round_trip_verified"])
            self.assertEqual(4, python_manifest["bidi"]["restored_count"])
            self.assertNotIn("redact-me", python_manifest_text)
            self.assertEqual(
                [(item["entry"], item["track"]) for item in fsharp_manifest["selection"]],
                [(item["entry"], item["track"]) for item in python_manifest["selection"]],
            )
            for name, folder in (
                    ("14_Assembly_dump.txt", "assembly"),
                    ("13_function_dump.txt", "c"),
                    ("04_classes.txt", "inventory"),
                    ("02_imports.txt", "inventory")):
                self.assertEqual(
                    (source_folders[folder] / name).read_bytes(),
                    (python_output / "BIDI_RESTORE" / "source" / name).read_bytes(),
                )

            fsharp_optimizer = fsharp_manifest["hex_optimizer"]
            python_optimizer = python_manifest["hex_optimizer"]
            self.assertEqual(1, python_optimizer["output_count"])
            self.assertEqual(2, python_optimizer["skipped_count"])
            self.assertFalse(python_optimizer["reversible"])
            self.assertTrue(python_optimizer["original_sources_retained"])
            self.assertEqual(
                [item["entry"] for item in python_manifest["selection"][:2]],
                [item["entry"] for item in python_optimizer["skipped_entries"]],
            )
            python_record = python_optimizer["outputs"][0]
            source_texts = [
                Path(python_record[key]).read_text(encoding="utf-8")
                for key in (
                    "source_path", "previous_source_path", "before_previous_source_path",
                )
            ]
            expected_hex = reference_coreoao_hex(*source_texts) + "\n"
            python_sidecar = Path(python_record["sidecar_path"])
            fsharp_sidecar = Path(fsharp_optimizer["outputs"][0]["sidecar_path"])
            self.assertEqual(expected_hex, python_sidecar.read_text(encoding="utf-8"))
            self.assertEqual(fsharp_sidecar.read_bytes(), python_sidecar.read_bytes())
            self.assertEqual(
                hashlib.sha256(python_sidecar.read_bytes()).hexdigest(),
                python_record["sidecar_sha256"],
            )
            self.assertTrue(all(
                "\u0100" in source_text and "\U0001F680" in source_text
                for source_text in source_texts
            ))

            reverse_output = root / "standalone reverse"
            reverse_result = run_python_coreo([
                "--mode", "REVERSE", "--source-run", str(python_output),
                "--out", str(reverse_output),
            ])
            self.assertEqual(0, reverse_result.returncode,
                             reverse_result.stdout + reverse_result.stderr)
            reverse_manifest = json.loads(
                (reverse_output / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )
            self.assertEqual("REVERSE", reverse_manifest["mode"])
            self.assertEqual(4, len(reverse_manifest["outputs"]["restored_files"]))

            tampered = python_output / "source" / "14_Assembly_dump.txt"
            tampered.write_bytes(tampered.read_bytes() + b"tampered\n")
            tampered_output = root / "tampered reverse"
            tampered_result = run_python_coreo([
                "--mode", "REVERSE", "--source-run", str(python_output),
                "--out", str(tampered_output),
            ])
            self.assertNotEqual(0, tampered_result.returncode)
            self.assertIn("preserved source hash mismatch", tampered_result.stderr)
            self.assertFalse(tampered_output.exists())

    def test_python3_cpp_and_jscript_targets(self):
        jsc = find_jsc()
        languages = [("C++", "CPP", ".cpp")]
        if jsc:
            languages.append(("JScript", "JSCRIPT", ".js"))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_pipeline_dump(dump_root, include_third=True)
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for language, code_directory, extension in languages:
                    FakeChatHandler.language = language
                    FakeChatHandler.marker = ""
                    output_dir = root / ("Python_" + language.replace("+", "plus"))
                    args = [
                        "--mode", "FORWARD",
                        "--dump-root", str(dump_root),
                        "--program", "demo",
                        "--out", str(output_dir),
                        "--python", sys.executable,
                        "--url", "http://127.0.0.1:%d" % server.server_address[1],
                        "--lang", language,
                    ]
                    if language == "JScript":
                        args.extend(["--jsc", jsc])
                    result = run_python_coreo(args, timeout=300)
                    self.assertEqual(0, result.returncode,
                                     result.stdout + result.stderr + " (lang=%s)" % language)
                    manifest = json.loads(
                        (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
                    )
                    optimizer = manifest["hex_optimizer"]
                    self.assertEqual(language, optimizer["language"])
                    self.assertEqual(1, optimizer["output_count"])
                    record = optimizer["outputs"][0]
                    source_path = Path(record["source_path"])
                    self.assertEqual(code_directory, source_path.parent.name)
                    source_texts = [
                        Path(record[key]).read_text(encoding="utf-8")
                        for key in (
                            "source_path", "previous_source_path", "before_previous_source_path",
                        )
                    ]
                    expected = reference_coreoao_hex(*source_texts) + "\n"
                    self.assertEqual(
                        expected,
                        Path(record["sidecar_path"]).read_text(encoding="utf-8"),
                    )
                    if language == "JScript":
                        self.assertTrue(
                            (source_path.parents[1] / "NET" /
                             (source_path.stem + ".exe")).exists()
                            or not any(line.startswith("PASS\t") for line in
                                       (Path(record["sidecar_path"]).parents[1] /
                                        "RESULTS.txt").read_text(encoding="utf-8").splitlines())
                        )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_python3_failure_manifest_and_help(self):
        help_result = subprocess.run(
            [sys.executable, str(COREO_SCRIPT), "--help"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, help_result.returncode, help_result.stdout + help_result.stderr)
        self.assertIn("--mode", help_result.stdout)
        self.assertIn("REVERSE", help_result.stdout)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_pipeline_dump(dump_root)
            output_dir = root / "failed-run"
            result = run_python_coreo([
                "--dump-root", str(dump_root),
                "--program", "demo",
                "--out", str(output_dir),
                "--python", str(root / "missing-python.exe"),
            ])
            self.assertNotEqual(0, result.returncode)
            manifest = json.loads(
                (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )
            self.assertEqual("failed", manifest["status"])
            stage = next(item for item in manifest["stages"] if item["name"] == "group-functions")
            self.assertEqual("failed", stage["status"])


if __name__ == "__main__":
    unittest.main()
