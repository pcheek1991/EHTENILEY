import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COREO_WRAPPER = REPO_ROOT / "coreo_pipeline.ps1"
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_coreo_pipeline import (  # noqa: E402
    FakeChatHandler,
    make_pipeline_dump,
    reference_coreoao_hex,
    run_fsharp_coreo,
)


def find_pwsh():
    executable = shutil.which("pwsh")
    if executable:
        return executable
    for candidate in (
        Path(r"C:\Program Files\PowerShell\7\pwsh.exe"),
        Path(r"C:\Program Files\PowerShell\7-preview\pwsh.exe"),
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def find_jsc():
    executable = shutil.which("jsc.exe") or shutil.which("jsc")
    if executable or os.name != "nt":
        return executable

    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
    for framework, version in (
        ("Framework", "v4.0.30319"),
        ("Framework64", "v4.0.30319"),
        ("Framework", "v2.0.50727"),
        ("Framework64", "v2.0.50727"),
    ):
        candidate = windows_root / "Microsoft.NET" / framework / version / "jsc.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def run_csharp_coreo(args, timeout=300):
    pwsh = find_pwsh()
    if not pwsh:
        raise RuntimeError("PowerShell Core (pwsh) is required for the C# COREO wrapper")
    return subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-File", str(COREO_WRAPPER)]
        + [str(argument) for argument in args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


class CoreoCSharpPortTests(unittest.TestCase):
    def setUp(self):
        self.workspace = TESTS_DIR / "_coreo_csharp_test_workspace" / self._testMethodName
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
        self.workspace.mkdir(parents=True)

    def tearDown(self):
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
        parent = self.workspace.parent
        if parent.exists() and not any(parent.iterdir()):
            parent.rmdir()

    def test_csharp_bidi_sidecars_match_fsharp_and_reverse_integrity(self):
        dump_root = self.workspace / "synthetic dumps"
        source_folders = make_pipeline_dump(dump_root, include_third=True)
        fsharp_output = self.workspace / "FSharp output"
        csharp_output = self.workspace / "CSharp output"
        FakeChatHandler.language = "C"
        FakeChatHandler.marker = "\u0100 and \U0001F680"
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            model_url = "http://127.0.0.1:%d?coreo-secret=redact-me" % server.server_address[1]
            common = [
                "--mode", "BIDI",
                "--dump-root", dump_root,
                "--program", "demo",
                "--python", sys.executable,
                "--url", model_url,
            ]
            fsharp_result = run_fsharp_coreo(
                common + ["--out", fsharp_output], timeout=300
            )
            self.assertEqual(0, fsharp_result.returncode, fsharp_result.stdout + fsharp_result.stderr)
            csharp_result = run_csharp_coreo(
                common + ["--out", csharp_output], timeout=300
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertEqual(0, csharp_result.returncode, csharp_result.stdout + csharp_result.stderr)
        fsharp_manifest = json.loads(
            (fsharp_output / "COREO_MANIFEST.json").read_text(encoding="utf-8")
        )
        manifest_path = csharp_output / "COREO_MANIFEST.json"
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
        self.assertEqual("BIDI", manifest["mode"])
        self.assertEqual("completed", manifest["status"])
        self.assertTrue(manifest["bidi"]["round_trip_verified"])
        self.assertEqual(4, manifest["bidi"]["restored_count"])
        self.assertNotIn("redact-me", manifest_text)
        self.assertNotIn("coreo-secret", manifest_text)
        self.assertEqual(
            [(item["entry"], item["track"]) for item in fsharp_manifest["selection"]],
            [(item["entry"], item["track"]) for item in manifest["selection"]],
        )
        for name, folder in (
            ("14_Assembly_dump.txt", "assembly"),
            ("13_function_dump.txt", "c"),
            ("04_classes.txt", "inventory"),
            ("02_imports.txt", "inventory"),
        ):
            self.assertEqual(
                (source_folders[folder] / name).read_bytes(),
                (csharp_output / "BIDI_RESTORE" / "source" / name).read_bytes(),
            )

        optimizer = manifest["hex_optimizer"]
        self.assertEqual("COREOAO CAND", optimizer["algorithm"])
        self.assertEqual(1, optimizer["output_count"])
        self.assertEqual(2, optimizer["skipped_count"])
        self.assertFalse(optimizer["reversible"])
        self.assertTrue(optimizer["original_sources_retained"])
        self.assertEqual(
            [item["entry"] for item in manifest["selection"][:2]],
            [item["entry"] for item in optimizer["skipped_entries"]],
        )
        record = optimizer["outputs"][0]
        source_texts = [
            Path(record[key]).read_text(encoding="utf-8")
            for key in (
                "source_path",
                "previous_source_path",
                "before_previous_source_path",
            )
        ]
        expected_hex = reference_coreoao_hex(*source_texts) + "\n"
        sidecar_path = Path(record["sidecar_path"])
        fsharp_sidecar = Path(fsharp_manifest["hex_optimizer"]["outputs"][0]["sidecar_path"])
        self.assertEqual(expected_hex.encode("utf-8"), sidecar_path.read_bytes())
        self.assertEqual(fsharp_sidecar.read_bytes(), sidecar_path.read_bytes())
        self.assertEqual(
            hashlib.sha256(sidecar_path.read_bytes()).hexdigest(),
            record["sidecar_sha256"],
        )
        self.assertTrue(all("\u0100" in text and "\U0001F680" in text for text in source_texts))

        reverse_output = self.workspace / "standalone reverse"
        reverse_result = run_csharp_coreo([
            "--mode", "REVERSE",
            "--source-run", csharp_output,
            "--out", reverse_output,
        ])
        self.assertEqual(0, reverse_result.returncode, reverse_result.stdout + reverse_result.stderr)
        reverse_manifest = json.loads(
            (reverse_output / "COREO_MANIFEST.json").read_text(encoding="utf-8")
        )
        self.assertEqual("REVERSE", reverse_manifest["mode"])
        self.assertEqual(4, len(reverse_manifest["outputs"]["restored_files"]))

        tampered = csharp_output / "source" / "14_Assembly_dump.txt"
        tampered.write_bytes(tampered.read_bytes() + b"tampered\n")
        tampered_output = self.workspace / "tampered reverse"
        tampered_result = run_csharp_coreo([
            "--mode", "REVERSE",
            "--source-run", csharp_output,
            "--out", tampered_output,
        ])
        self.assertNotEqual(0, tampered_result.returncode)
        self.assertIn("preserved source hash mismatch", tampered_result.stderr)
        self.assertFalse(tampered_output.exists())

    def test_csharp_c_cpp_and_jscript_output_paths(self):
        jsc = find_jsc()
        if os.name == "nt":
            self.assertIsNotNone(jsc, "the supported .NET Framework jsc.exe should be installed")
        languages = [
            ("C", "C", ".c"),
            ("C++", "CPP", ".cpp"),
        ]
        if jsc:
            languages.append(("JScript", "JSCRIPT", ".js"))

        dump_root = self.workspace / "dumps"
        make_pipeline_dump(dump_root, include_third=True)
        FakeChatHandler.marker = ""
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for language, code_directory, extension in languages:
                with self.subTest(language=language):
                    FakeChatHandler.language = language
                    output_dir = self.workspace / ("CSharp_" + language.replace("+", "plus"))
                    args = [
                        "--mode", "FORWARD",
                        "--dump-root", dump_root,
                        "--program", "demo",
                        "--out", output_dir,
                        "--python", sys.executable,
                        "--url", "http://127.0.0.1:%d" % server.server_address[1],
                        "--lang", language,
                    ]
                    if language == "JScript":
                        args.extend(["--jsc", jsc])
                    result = run_csharp_coreo(args)
                    self.assertEqual(
                        0, result.returncode,
                        result.stdout + result.stderr + " (lang=%s)" % language,
                    )
                    manifest = json.loads(
                        (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
                    )
                    optimizer = manifest["hex_optimizer"]
                    self.assertEqual(language, optimizer["language"])
                    self.assertEqual(1, optimizer["output_count"])
                    record = optimizer["outputs"][0]
                    source_path = Path(record["source_path"])
                    self.assertEqual(code_directory, source_path.parent.name)
                    self.assertEqual(extension, source_path.suffix)
                    source_texts = [
                        Path(record[key]).read_text(encoding="utf-8")
                        for key in (
                            "source_path",
                            "previous_source_path",
                            "before_previous_source_path",
                        )
                    ]
                    expected = reference_coreoao_hex(*source_texts) + "\n"
                    sidecar_path = Path(record["sidecar_path"])
                    self.assertEqual(expected.encode("utf-8"), sidecar_path.read_bytes())
                    self.assertEqual(
                        hashlib.sha256(sidecar_path.read_bytes()).hexdigest(),
                        record["sidecar_sha256"],
                    )
                    if language == "JScript":
                        executable_path = source_path.parents[1] / "NET" / (source_path.stem + ".exe")
                        self.assertTrue(executable_path.is_file())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_csharp_help_and_failure_manifest(self):
        help_result = run_csharp_coreo(["--help"])
        self.assertEqual(0, help_result.returncode, help_result.stdout + help_result.stderr)
        self.assertIn("--mode", help_result.stdout)
        self.assertIn("REVERSE", help_result.stdout)

        dump_root = self.workspace / "dumps"
        make_pipeline_dump(dump_root)
        output_dir = self.workspace / "failed-run"
        result = run_csharp_coreo([
            "--dump-root", dump_root,
            "--program", "demo",
            "--out", output_dir,
            "--python", self.workspace / "missing-python.exe",
        ])
        self.assertNotEqual(0, result.returncode)
        manifest = json.loads(
            (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
        )
        self.assertEqual("failed", manifest["status"])
        grouping_stage = next(
            stage for stage in manifest["stages"] if stage["name"] == "group-functions"
        )
        self.assertEqual("failed", grouping_stage["status"])


if __name__ == "__main__":
    unittest.main()
