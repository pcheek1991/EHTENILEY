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
R_COREO_SCRIPT = REPO_ROOT / "coreo_pipeline.R"
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from test_coreo_pipeline import (  # noqa: E402
    FakeChatHandler,
    js_utf16_units,
    make_pipeline_dump,
    reference_coreoao_hex,
)


def find_rscript():
    rscript = shutil.which("Rscript") or shutil.which("Rscript.exe")
    if rscript or os.name != "nt":
        return rscript
    roots = []
    if os.environ.get("R_HOME"):
        roots.append(Path(os.environ["R_HOME"]))
    roots.extend([
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "R",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "R",
    ])
    candidates = []
    for root in roots:
        for executable in (
                root / "bin" / "Rscript.exe",
                root / "bin" / "x64" / "Rscript.exe"):
            if executable.is_file():
                candidates.append(executable)
        if root.is_dir():
            for version_directory in sorted(root.glob("R-*")):
                for executable in (
                        version_directory / "bin" / "Rscript.exe",
                        version_directory / "bin" / "x64" / "Rscript.exe"):
                    if executable.is_file():
                        candidates.append(executable)
    return str(candidates[-1]) if candidates else None


RSCRIPT = find_rscript()


def run_r_coreo(args, timeout=300):
    return subprocess.run(
        [RSCRIPT, "--vanilla", str(R_COREO_SCRIPT)] + args,
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
        ("Framework64", "v2.0.50727"),
    ):
        candidate = (
            windows_root
            / "Microsoft.NET"
            / framework
            / version
            / "jsc.exe"
        )
        if candidate.is_file():
            return str(candidate)
    return None


class RCoreoContractTests(unittest.TestCase):
    def test_documented_entry_point_preserves_canonical_modes_and_cand(self):
        source = R_COREO_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("#' Run the complete COREO orchestration pipeline.", source)
        self.assertIn("run_coreo <- function", source)
        self.assertIn('"FORWARD", "REVERSE", "BIDI"', source)
        self.assertIn('"coreoaoBytes-js-v1"', source)
        self.assertIn("mask <- 0x3fL", source)
        self.assertIn("shift <- 3L", source)
        self.assertIn(
            'formula = "v=(abs(M0[i]-M1[i]) ^ abs(M1[i]-M2[i]) ^ '
            '(M0[i] & mask)) | (~mask & 0xFF); out[i]=(v | '
            '((v << (shift % 8)) | (v >> (8-(shift % 8))))) & 0xFF"',
            source,
        )
        self.assertIn("input_encoding = \"UTF-16 code units\"", source)
        self.assertIn("manifest selection order", source)
        self.assertIn("bitwXor(", source)
        self.assertIn("bitwShiftL(value, rotation)", source)
        self.assertIn("0xd800L", source)
        self.assertIn("0xdc00L", source)
        self.assertIn("original_sources_retained = TRUE", source)
        self.assertIn("generated language source is retained and is not recovered from hex", source)
        self.assertIn('JScript = "JSCRIPT"', source)
        self.assertIn('`C++` = "CPP"', source)


@unittest.skipUnless(RSCRIPT, "Rscript is unavailable; R parity integration is blocked")
class RCoreoIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.work_root = TESTS_DIR / (".coreo-r-test-work-" + str(os.getpid()))
        self.root = self.work_root / self._testMethodName
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True)

    def tearDown(self):
        if self.root.exists():
            shutil.rmtree(self.root)
        if self.work_root.exists():
            try:
                self.work_root.rmdir()
            except OSError:
                pass

    def start_fake_model(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeChatHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = "http://127.0.0.1:%d" % server.server_address[1]
        return server, thread, url

    def run_pipeline(self, args):
        result = run_r_coreo(args)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        return result

    def test_bidi_cand_utf16_provenance_and_reverse_integrity(self):
        dump_root = self.root / "dumps"
        folders = make_pipeline_dump(dump_root, include_third=True)
        output_dir = self.root / "bidi-run"
        FakeChatHandler.language = "C"
        FakeChatHandler.marker = "\U0001f600"
        server, thread, base_url = self.start_fake_model()
        try:
            result = self.run_pipeline([
                "--mode", "BIDI",
                "--dump-root", str(dump_root),
                "--program", "demo",
                "--out", str(output_dir),
                "--python", sys.executable,
                "--url", base_url + "?coreo-secret=redact-me",
            ])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        manifest_path = output_dir / "COREO_MANIFEST.json"
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest = json.loads(manifest_text)
        optimizer = manifest["hex_optimizer"]
        self.assertEqual(0, result.returncode)
        self.assertEqual("completed", manifest["status"])
        self.assertTrue(manifest["bidi"]["round_trip_verified"])
        self.assertEqual(4, manifest["bidi"]["restored_count"])
        self.assertEqual(
            [("00401000", "KEEP"), ("00403000", "KEEP"), ("00402000", "WRAP")],
            [(item["entry"], item["track"]) for item in manifest["selection"]],
        )
        self.assertEqual(1, optimizer["output_count"])
        self.assertEqual(2, optimizer["skipped_count"])
        self.assertFalse(optimizer["reversible"])
        self.assertTrue(optimizer["original_sources_retained"])
        self.assertNotIn("redact-me", manifest_text)
        self.assertEqual(base_url, manifest["options"]["llm"]["url_origin"])

        record = optimizer["outputs"][0]
        source_path = Path(record["source_path"])
        previous_path = Path(record["previous_source_path"])
        before_previous_path = Path(record["before_previous_source_path"])
        source_texts = [
            path.read_text(encoding="utf-8")
            for path in (source_path, previous_path, before_previous_path)
        ]
        self.assertTrue(all("\U0001f600" in text for text in source_texts))
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
        expected_hex = reference_coreoao_hex(*source_texts)
        sidecar_path = Path(record["sidecar_path"])
        self.assertEqual("COREOAO", sidecar_path.parent.name)
        self.assertEqual(
            (expected_hex + "\n").encode("ascii"),
            sidecar_path.read_bytes(),
        )
        self.assertEqual(
            min(len(js_utf16_units(text)) for text in source_texts),
            record["byte_count"],
        )
        self.assertEqual(
            hashlib.sha256(sidecar_path.read_bytes()).hexdigest(),
            record["sidecar_sha256"],
        )

        for name, folder in (
            ("14_Assembly_dump.txt", "assembly"),
            ("13_function_dump.txt", "c"),
            ("04_classes.txt", "inventory"),
            ("02_imports.txt", "inventory"),
        ):
            self.assertEqual(
                (folders[folder] / name).read_bytes(),
                (output_dir / "BIDI_RESTORE" / "source" / name).read_bytes(),
            )

        staged_input = output_dir / "source" / "14_Assembly_dump.txt"
        staged_input.write_bytes(staged_input.read_bytes() + b"tampered\n")
        restore_dir = self.root / "tampered-restore"
        tampered = run_r_coreo([
            "--mode", "REVERSE",
            "--source-run", str(output_dir),
            "--out", str(restore_dir),
            "--python", sys.executable,
        ])
        self.assertNotEqual(0, tampered.returncode)
        self.assertIn("preserved source hash mismatch", tampered.stderr)
        self.assertFalse(restore_dir.exists())

    def run_target_language(self, language, code_folder, extension, jsc=None):
        dump_root = self.root / "dumps"
        if not dump_root.exists():
            make_pipeline_dump(dump_root, include_third=True)
        server, thread, base_url = self.start_fake_model()
        try:
            FakeChatHandler.language = language
            FakeChatHandler.marker = ""
            output_dir = self.root / ("run-" + language.replace("+", "plus"))
            args = [
                "--mode", "FORWARD",
                "--dump-root", str(dump_root),
                "--program", "demo",
                "--out", str(output_dir),
                "--python", sys.executable,
                "--url", base_url,
                "--lang", language,
            ]
            if jsc:
                args.extend(["--jsc", jsc])
            self.run_pipeline(args)
            manifest = json.loads(
                (output_dir / "COREO_MANIFEST.json").read_text(encoding="utf-8")
            )
            optimizer = manifest["hex_optimizer"]
            self.assertEqual(language, optimizer["language"])
            self.assertEqual(1, optimizer["output_count"])
            self.assertEqual(2, optimizer["skipped_count"])
            source = Path(optimizer["outputs"][0]["source_path"])
            self.assertEqual(code_folder, source.parent.name)
            self.assertEqual(extension, source.suffix)
            self.assertTrue(Path(optimizer["outputs"][0]["sidecar_path"]).is_file())
            return manifest, source
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_cpp_target(self):
        manifest, _ = self.run_target_language("C++", "CPP", ".cpp")
        self.assertEqual("completed", manifest["status"])

    def test_optional_jscript_target(self):
        jsc = find_jsc()
        if not jsc:
            self.skipTest("jsc.exe is unavailable; JScript compile integration skipped")
        manifest, source = self.run_target_language("JScript", "JSCRIPT", ".js", jsc)
        group_name = manifest["hex_optimizer"]["outputs"][0]["group"]
        executable = (
            Path(manifest["outputs"]["groups"][group_name]["llm_run"])
            / "NET"
            / (source.stem + ".exe")
        )
        self.assertTrue(executable.is_file())
        self.assertEqual(b"MZ", executable.read_bytes()[:2])


if __name__ == "__main__":
    unittest.main()
