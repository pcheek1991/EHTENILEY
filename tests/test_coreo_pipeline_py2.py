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
PY2_COREO_SCRIPT = REPO_ROOT / "coreo_pipeline_py2.py"
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_coreo_pipeline import (  # noqa: E402
    FakeChatHandler,
    make_pipeline_dump,
    reference_coreoao_hex,
    run_fsharp_coreo,
)


PYTHON2 = os.environ.get("PYTHON2") or shutil.which("python2") or shutil.which("python2.7")


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


def run_python2_coreo(args, timeout=300):
    return subprocess.run(
        [PYTHON2, str(PY2_COREO_SCRIPT)] + [str(argument) for argument in args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@unittest.skipUnless(PYTHON2, "Python 2 runtime/venv is unavailable")
class CoreoPython2PortTests(unittest.TestCase):
    def test_python2_bidi_matches_fsharp_and_reverse_integrity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "synthetic dumps"
            source_folders = make_pipeline_dump(dump_root, include_third=True)
            fsharp_output = root / "FSharp output"
            python2_output = root / "Python2 output"
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
                python2_result = run_python2_coreo(
                    common + ["--out", str(python2_output)], timeout=300
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            self.assertEqual(0, python2_result.returncode,
                             python2_result.stdout + python2_result.stderr)
            fsharp_manifest = json.loads(
                (fsharp_output / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )
            python2_manifest_path = python2_output / "COREO_MANIFEST.json"
            python2_manifest_text = python2_manifest_path.read_text(encoding="utf-8")
            python2_manifest = json.loads(python2_manifest_text)
            self.assertEqual("BIDI", python2_manifest["mode"])
            self.assertEqual("completed", python2_manifest["status"])
            self.assertTrue(python2_manifest["bidi"]["round_trip_verified"])
            self.assertEqual(4, python2_manifest["bidi"]["restored_count"])
            self.assertNotIn("redact-me", python2_manifest_text)
            self.assertEqual(
                [(item["entry"], item["track"]) for item in fsharp_manifest["selection"]],
                [(item["entry"], item["track"]) for item in python2_manifest["selection"]],
            )
            for name, folder in (
                    ("14_Assembly_dump.txt", "assembly"),
                    ("13_function_dump.txt", "c"),
                    ("04_classes.txt", "inventory"),
                    ("02_imports.txt", "inventory")):
                self.assertEqual(
                    (source_folders[folder] / name).read_bytes(),
                    (python2_output / "BIDI_RESTORE" / "source" / name).read_bytes(),
                )

            fsharp_optimizer = fsharp_manifest["hex_optimizer"]
            python2_optimizer = python2_manifest["hex_optimizer"]
            self.assertEqual(1, python2_optimizer["output_count"])
            self.assertEqual(2, python2_optimizer["skipped_count"])
            self.assertFalse(python2_optimizer["reversible"])
            self.assertTrue(python2_optimizer["original_sources_retained"])
            python2_record = python2_optimizer["outputs"][0]
            source_texts = [
                Path(python2_record[key]).read_text(encoding="utf-8")
                for key in (
                    "source_path", "previous_source_path", "before_previous_source_path",
                )
            ]
            for source_text in source_texts:
                self.assertIn("\u0100", source_text)
                self.assertIn("\U0001F680", source_text)
            self.assertEqual(
                reference_coreoao_hex(*source_texts) + "\n",
                Path(python2_record["sidecar_path"]).read_text(encoding="utf-8"),
            )
            fsharp_sidecar = Path(fsharp_optimizer["outputs"][0]["sidecar_path"])
            python2_sidecar = Path(python2_record["sidecar_path"])
            self.assertEqual(fsharp_sidecar.read_bytes(), python2_sidecar.read_bytes())
            self.assertEqual(
                hashlib.sha256(python2_sidecar.read_bytes()).hexdigest(),
                python2_record["sidecar_sha256"],
            )

            reverse_dir = root / "standalone reverse"
            reverse_result = run_python2_coreo([
                "--mode", "REVERSE", "--source-run", str(python2_output),
                "--out", str(reverse_dir), "--python", sys.executable,
            ])
            self.assertEqual(0, reverse_result.returncode,
                             reverse_result.stdout + reverse_result.stderr)
            reverse_manifest = json.loads(
                (reverse_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )
            self.assertEqual("REVERSE", reverse_manifest["mode"])
            self.assertEqual(4, len(reverse_manifest["outputs"]["restored_files"]))

            tampered = python2_output / "source" / "14_Assembly_dump.txt"
            tampered.write_bytes(tampered.read_bytes() + b"tampered\n")
            tampered_dir = root / "tampered reverse"
            tampered_result = run_python2_coreo([
                "--mode", "REVERSE", "--source-run", str(python2_output),
                "--out", str(tampered_dir), "--python", sys.executable,
            ])
            self.assertNotEqual(0, tampered_result.returncode)
            self.assertIn("preserved source hash mismatch", tampered_result.stderr)
            self.assertFalse(tampered_dir.exists())

    def test_python2_language_targets(self):
        jsc = find_jsc()
        languages = [("C++", "CPP")]
        if jsc:
            languages.append(("JScript", "JSCRIPT"))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dump_root = root / "dumps"
            make_pipeline_dump(dump_root, include_third=True)
            server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for language, code_directory in languages:
                    FakeChatHandler.language = language
                    FakeChatHandler.marker = ""
                    output_dir = root / ("Python2_" + language.replace("+", "plus"))
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
                    result = run_python2_coreo(args, timeout=300)
                    self.assertEqual(0, result.returncode,
                                     result.stdout + result.stderr + " (lang=%s)" % language)
                    manifest = json.loads(
                        (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
                    )
                    self.assertEqual(language, manifest["hex_optimizer"]["language"])
                    self.assertEqual(1, manifest["hex_optimizer"]["output_count"])
                    record = manifest["hex_optimizer"]["outputs"][0]
                    self.assertEqual(code_directory, Path(record["source_path"]).parent.name)
                    self.assertEqual(
                        reference_coreoao_hex(
                            Path(record["source_path"]).read_text(encoding="utf-8"),
                            Path(record["previous_source_path"]).read_text(encoding="utf-8"),
                            Path(record["before_previous_source_path"]).read_text(encoding="utf-8"),
                        ) + "\n",
                        Path(record["sidecar_path"]).read_text(encoding="utf-8"),
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_python2_cli_help(self):
        result = subprocess.run(
            [PYTHON2, str(PY2_COREO_SCRIPT), "--help"],
            cwd=str(REPO_ROOT), capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("REVERSE", result.stdout)


if __name__ == "__main__":
    unittest.main()
