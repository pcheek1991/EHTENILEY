#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""Run the existing Ghidra and LLM components through one COREO entry point."""
from __future__ import print_function

import argparse
import csv
import ctypes
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime
from distutils.spawn import find_executable
from pathlib2 import Path

try:
    from urlparse import urlsplit
except ImportError:
    from urllib.parse import urlsplit


COREO_VERSION = "1"
REPO_ROOT = Path(__file__).resolve().parent
PROGRAM_NAME = re.compile(ur"^[\w.-]+$", re.UNICODE)
GROUP_NAME = re.compile(ur"^[\w.~-]+$", re.UNICODE)
ENTRY = re.compile(ur"^[0-9a-fA-F]{8}$")


def utc_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_replace(source, destination):
    source_path = unicode(source)
    destination_path = unicode(destination)
    if os.name == "nt":
        move_file = ctypes.windll.kernel32.MoveFileExW
        move_file.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        move_file.restype = ctypes.c_int
        if not move_file(source_path, destination_path, 0x1 | 0x8):
            raise ctypes.WinError()
    else:
        os.rename(source_path, destination_path)


def json_text(value):
    return json.dumps(value, indent=2, ensure_ascii=True).decode("ascii")


def run_coreo(argv=None, process_runner=None):
    """Run COREO; process_runner is injectable so tests can stub model calls."""
    if sys.version_info[0] < 3:
        default_python = os.environ.get("PYTHON3") or "python3"
    else:
        default_python = os.environ.get("PYTHON") or sys.executable
    parser = argparse.ArgumentParser(
        description="Run the Ghidra Python and LLM pipelines together from a completed PyGhidra dump."
    )
    parser.add_argument("--mode", type=str.upper, choices=("FORWARD", "REVERSE", "BIDI"),
                        default="FORWARD", help="run forward, reverse, or both (default: forward)")
    parser.add_argument("--dump-root", type=Path,
                        help="root containing the three <program>_ASSEMBLY/C_PSEUDOCODE/INVENTORY folders")
    parser.add_argument("--program",
                        help="sanitized Ghidra program name used as the three dump-folder prefix")
    parser.add_argument("--out", type=Path,
                        help="new COREO run directory; existing directories are never reused")
    parser.add_argument("--source-run", type=Path,
                        help="existing COREO run used as the source for REVERSE mode")
    parser.add_argument("--python", default=default_python,
                        help="Python executable used for the existing Ghidra/LLM pipeline CLIs")
    parser.add_argument("--track", type=str.upper, choices=("BOTH", "KEEP", "WRAP"),
                        default="BOTH", help="queue tracks to process (default: both KEEP and WRAP)")
    parser.add_argument("--group", dest="groups", action="append",
                        help="process only this exact group; may be repeated (default: every queued group)")
    parser.add_argument("--manual-groups", type=Path,
                        help="optional groups.tsv passed through to make_full_lite_v2.py")
    parser.add_argument("--grouper-dir", type=Path,
                        help="optional folder tree with functions.tsv files passed to make_full_lite_v2.py")
    parser.add_argument("--sms", type=Path, help="optional SMS symbol dump passed to make_full_lite_v2.py")
    parser.add_argument("--max-group", type=int, default=150)
    parser.add_argument("--common", type=int, default=12)
    parser.add_argument("--min-prefix", type=int, default=4)
    parser.add_argument("--overrides", type=Path, help="optional per-program OVERRIDES.tsv")
    parser.add_argument("--runtime-prefixes", help="optional triage runtime prefixes")
    parser.add_argument("--crt-start", help="optional triage CRT start address in hexadecimal")
    parser.add_argument("--model", default="qwen2.5-coder-14b-instruct")
    parser.add_argument("--url", default="http://127.0.0.1:1234")
    parser.add_argument("--lang", choices=("C", "C++", "JScript"), default="C")
    parser.add_argument("--jsc", type=Path, help="optional path to the JScript.NET compiler")
    parser.add_argument("--temp", type=float, default=0.0)
    args = parser.parse_args(argv)
    execute = process_runner if process_runner is not None else subprocess.call
    manifest = None
    manifest_path = None
    manifest_temp = None
    active_stage = None
    input_records = {}

    try:
        if args.mode == "REVERSE":
            if args.source_run is None or args.out is None:
                raise ValueError("REVERSE mode requires --source-run and --out")
            source_run = args.source_run.expanduser().resolve()
            source_manifest_path = source_run / "COREO_MANIFEST.json"
            if not source_manifest_path.is_file():
                raise ValueError("COREO source manifest not found: " + str(source_manifest_path))
            source_manifest_bytes = source_manifest_path.read_bytes()
            source_manifest_hash = hashlib.sha256(source_manifest_bytes).hexdigest()
            source_document = json.loads(source_manifest_bytes.decode("utf-8"))
            source_inputs = source_document.get("inputs")
            source_records = (
                source_inputs.get("ghidra_dump_files")
                if isinstance(source_inputs, dict) else None
            )
            if not isinstance(source_records, dict):
                raise ValueError("source manifest is missing Ghidra dump file records")
            source_folder = source_run / "source"
            restore_items = []
            for role, basename, required in (
                ("assembly", "14_Assembly_dump.txt", True),
                ("c_pseudocode", "13_function_dump.txt", True),
                ("classes", "04_classes.txt", False),
                ("imports", "02_imports.txt", False),
            ):
                record = source_records.get(role)
                if record is None:
                    if required:
                        raise ValueError("source manifest is missing required input record: " + role)
                    continue
                if not isinstance(record, dict) or not isinstance(record.get("present"), bool):
                    raise ValueError("source manifest has an invalid input record: " + role)
                if not record["present"]:
                    if required:
                        raise ValueError("source manifest marks required input absent: " + role)
                    continue
                recorded_path = record.get("staged_path")
                if (not isinstance(recorded_path, basestring) or
                        os.path.basename(recorded_path.rstrip("/\\")) != basename):
                    raise ValueError("source manifest has an unexpected staged path for " + role)
                staged_path = source_folder / basename
                if not staged_path.is_file():
                    raise ValueError("preserved source artifact is missing: " + str(staged_path))
                expected_hash = record.get("sha256")
                if not isinstance(expected_hash, basestring):
                    raise ValueError("source manifest is missing the SHA-256 for " + role)
                actual_hash = hashlib.sha256(staged_path.read_bytes()).hexdigest()
                if actual_hash != expected_hash.lower():
                    raise ValueError("preserved source hash mismatch: " + str(staged_path))
                restore_items.append({
                    "role": role,
                    "original_path": record.get("source_path"),
                    "staged_path": staged_path,
                    "sha256": actual_hash,
                })
            if len(restore_items) < 2:
                raise ValueError("source manifest does not contain both required Ghidra dump files")

            out_dir = args.out.expanduser().resolve()
            if out_dir.exists():
                raise ValueError("COREO output directory already exists: " + str(out_dir))
            out_dir.parent.mkdir(parents=True, exist_ok=True)
            out_dir.mkdir()
            manifest_path = out_dir / "COREO_MANIFEST.json"
            manifest_temp = out_dir / "COREO_MANIFEST.json.tmp"
            manifest = {
                "schema_version": 1,
                "coreo_version": COREO_VERSION,
                "mode": "REVERSE",
                "status": "running",
                "started_at": utc_timestamp(),
                "finished_at": None,
                "source_run": str(source_run),
                "inputs": {
                    "source_manifest": {
                        "path": str(source_manifest_path),
                        "sha256": source_manifest_hash,
                    },
                },
                "stages": [],
                "selection": [],
                "outputs": {
                    "restored_source": str(out_dir / "source"),
                    "restored_files": [],
                },
            }
            active_stage = {
                "name": "restore-original-ghidra-inputs",
                "status": "running",
                "started_at": utc_timestamp(),
            }
            manifest["stages"].append(active_stage)
            manifest["current_stage"] = active_stage["name"]
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)
            restore_dir = out_dir / "source"
            restore_dir.mkdir()
            restored_records = []
            for item in restore_items:
                destination = restore_dir / item["staged_path"].name
                shutil.copy2(unicode(item["staged_path"]), unicode(destination))
                restored_hash = hashlib.sha256(destination.read_bytes()).hexdigest()
                if restored_hash != item["sha256"]:
                    raise ValueError("restored source hash mismatch: " + str(destination))
                restored_records.append({
                    "role": item["role"],
                    "original_path": item["original_path"],
                    "restored_path": str(destination),
                    "sha256": restored_hash,
                })
            manifest["outputs"]["restored_files"] = restored_records
            active_stage["restored_count"] = len(restored_records)
            active_stage["returncode"] = 0
            active_stage["status"] = "completed"
            active_stage["finished_at"] = utc_timestamp()
            active_stage = None
            manifest.pop("current_stage", None)
            manifest["status"] = "completed"
            manifest["finished_at"] = utc_timestamp()
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)
            print("COREO restored %d verified source artifact(s)." % len(restored_records))
            print("COREO reverse manifest: " + str(manifest_path))
            return 0

        if args.dump_root is None or args.program is None or args.out is None:
            raise ValueError("FORWARD and BIDI modes require --dump-root, --program, and --out")
        if args.program in (".", "..") or not PROGRAM_NAME.match(args.program):
            raise ValueError("program must be the sanitized Ghidra dump folder name")
        dump_root = args.dump_root.expanduser().resolve()
        if not dump_root.is_dir():
            raise ValueError("Ghidra dump root is not a directory: " + str(dump_root))
        source_files = {
            "assembly": dump_root / (args.program + "_ASSEMBLY") / "14_Assembly_dump.txt",
            "c_pseudocode": dump_root / (args.program + "_C_PSEUDOCODE") / "13_function_dump.txt",
            "classes": dump_root / (args.program + "_INVENTORY") / "04_classes.txt",
            "imports": dump_root / (args.program + "_INVENTORY") / "02_imports.txt",
        }
        missing = [str(source_files[name]) for name in ("assembly", "c_pseudocode")
                   if not source_files[name].is_file()]
        if missing:
            raise ValueError("missing required PyGhidra dump file(s): " + ", ".join(missing))
        if args.lang == "JScript":
            if args.jsc is not None:
                args.jsc = Path(args.jsc).expanduser().resolve()
            else:
                jsc_path = find_executable("jsc.exe") or find_executable("jsc")
                if not jsc_path and os.name == "nt":
                    windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
                    for framework, version in (
                        ("Framework", "v4.0.30319"),
                        ("Framework64", "v4.0.30319"),
                        ("Framework", "v2.0.50727"),
                        ("Framework64", "v2.0.50727"),
                    ):
                        candidate = windows_root / "Microsoft.NET" / framework / version / "jsc.exe"
                        if candidate.is_file():
                            jsc_path = str(candidate)
                            break
                args.jsc = Path(jsc_path).expanduser().resolve() if jsc_path else None
            if args.jsc is None or not args.jsc.is_file():
                raise ValueError("JScript mode requires jsc.exe; pass --jsc or install it in a standard .NET Framework path")
        elif args.jsc is not None:
            raise ValueError("--jsc can only be used with --lang JScript")

        config_inputs = {}
        config_paths = (
            ("manual_groups", False),
            ("grouper_dir", True),
            ("sms", False),
            ("overrides", False),
            ("jsc", False),
        )
        for name, is_directory in config_paths:
            config_path = getattr(args, name)
            if config_path is None:
                continue
            config_path = Path(config_path).expanduser().resolve()
            setattr(args, name, config_path)
            if is_directory and not config_path.is_dir():
                raise ValueError("%s is not a directory: %s" % (name, config_path))
            if not is_directory and not config_path.is_file():
                raise ValueError("%s is not a file: %s" % (name, config_path))
            if is_directory:
                config_files = []
                for config_file in sorted(config_path.rglob("*")):
                    if not config_file.is_file():
                        continue
                    digest = hashlib.sha256()
                    with open(unicode(config_file), "rb") as source:
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            digest.update(chunk)
                    config_files.append({
                        "path": config_file.relative_to(config_path).as_posix(),
                        "sha256": digest.hexdigest(),
                    })
                config_inputs[name] = {
                    "path": str(config_path), "kind": "directory", "files": config_files,
                }
            else:
                digest = hashlib.sha256()
                with open(unicode(config_path), "rb") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                config_inputs[name] = {
                    "path": str(config_path), "kind": "file", "sha256": digest.hexdigest(),
                }

        out_dir = args.out.expanduser().resolve()
        if out_dir.exists():
            raise ValueError("COREO output directory already exists: " + str(out_dir))
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        out_dir.mkdir()

        tracks = ("KEEP", "WRAP") if args.track == "BOTH" else (args.track,)
        ghidra_out = out_dir / "ghidra" / "OUT"
        lite_dir = ghidra_out / "LITE_AC"
        triage_dir = ghidra_out / "TRIAGE"
        llm_root = out_dir / "llm"
        source_dir = out_dir / "source"
        manifest_path = out_dir / "COREO_MANIFEST.json"
        manifest_temp = out_dir / "COREO_MANIFEST.json.tmp"

        endpoint_origin = "[redacted]"
        try:
            parsed_url = urlsplit(args.url)
            host = parsed_url.hostname
            if parsed_url.scheme and host:
                if ":" in host:
                    host = "[" + host + "]"
                port = parsed_url.port
                endpoint_origin = parsed_url.scheme + "://" + host
                if port:
                    endpoint_origin += ":" + str(port)
        except ValueError:
            pass

        manifest = {
            "schema_version": 1,
            "coreo_version": COREO_VERSION,
            "mode": args.mode,
            "status": "running",
            "started_at": utc_timestamp(),
            "finished_at": None,
            "program": args.program,
            "dump_root": str(dump_root),
            "output_dir": str(out_dir),
            "inputs": {"ghidra_dump_files": {}, "config_inputs": config_inputs},
            "options": {
                "track": args.track,
                "groups": args.groups or [],
                "grouping": {
                    "max_group": args.max_group,
                    "common": args.common,
                    "min_prefix": args.min_prefix,
                    "manual_groups": str(args.manual_groups) if args.manual_groups else None,
                    "grouper_dir": str(args.grouper_dir) if args.grouper_dir else None,
                    "sms": str(args.sms) if args.sms else None,
                },
                "triage": {
                    "overrides": str(args.overrides) if args.overrides else None,
                    "runtime_prefixes": args.runtime_prefixes,
                    "crt_start": args.crt_start,
                },
                "llm": {
                    "model": args.model,
                    "url_origin": endpoint_origin,
                    "lang": args.lang,
                    "jsc_path": str(args.jsc) if args.jsc else None,
                    "temperature": args.temp,
                },
            },
            "stages": [],
            "selection": [],
            "outputs": {
                "ghidra": str(ghidra_out),
                "triage": str(triage_dir),
                "llm": str(llm_root),
                "groups": {},
            },
        }
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        active_stage = {
            "name": "stage-ghidra-inputs",
            "status": "running",
            "started_at": utc_timestamp(),
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)
        staged_files = {}
        required_inputs = {"assembly", "c_pseudocode"}
        source_dir.mkdir(parents=True, exist_ok=True)
        for name, source_path in source_files.items():
            if not source_path.is_file():
                input_records[name] = {
                    "present": False, "source_path": str(source_path), "staged_path": None,
                }
                if name in required_inputs:
                    raise ValueError("required Ghidra input disappeared: " + str(source_path))
                continue
            staged_path = source_dir / source_path.name
            shutil.copy2(unicode(source_path), unicode(staged_path))
            source_digest = hashlib.sha256()
            with open(unicode(source_path), "rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    source_digest.update(chunk)
            staged_digest = hashlib.sha256()
            with open(unicode(staged_path), "rb") as staged:
                while True:
                    chunk = staged.read(1024 * 1024)
                    if not chunk:
                        break
                    staged_digest.update(chunk)
            if source_digest.digest() != staged_digest.digest():
                raise ValueError("staged input hash mismatch: " + str(source_path))
            staged_files[name] = staged_path
            input_records[name] = {
                "present": True,
                "source_path": str(source_path),
                "staged_path": str(staged_path),
                "sha256": source_digest.hexdigest(),
            }
        manifest["inputs"]["ghidra_dump_files"] = input_records
        active_stage["status"] = "completed"
        active_stage["finished_at"] = utc_timestamp()
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        grouping_script = REPO_ROOT / "ghidra_pipeline" / "python_scripts" / "make_full_lite_v2.py"
        grouping_command = [
            args.python, str(grouping_script), "--in", str(source_dir), "--out", str(ghidra_out),
            "--max-group", str(args.max_group), "--common", str(args.common),
            "--min-prefix", str(args.min_prefix),
        ]
        if args.manual_groups:
            grouping_command += ["--groups", str(args.manual_groups)]
        if args.grouper_dir:
            grouping_command += ["--grouper-dir", str(args.grouper_dir)]
        if args.sms:
            grouping_command += ["--sms", str(args.sms)]
        active_stage = {
            "name": "group-functions",
            "status": "running",
            "started_at": utc_timestamp(),
            "command": grouping_command,
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)
        command_status = execute(grouping_command, cwd=str(REPO_ROOT))
        if hasattr(command_status, "returncode"):
            command_status = command_status.returncode
        if command_status:
            raise subprocess.CalledProcessError(command_status, grouping_command)
        if not lite_dir.is_dir():
            raise ValueError("grouping did not create LITE_AC: " + str(lite_dir))
        active_stage["returncode"] = 0
        active_stage["status"] = "completed"
        active_stage["finished_at"] = utc_timestamp()
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        triage_script = REPO_ROOT / "ghidra_pipeline" / "python_scripts" / "triage_evidence_v2.py"
        triage_command = [
            args.python, str(triage_script), "--lite", str(lite_dir),
            "--report-dir", str(triage_dir),
        ]
        if staged_files.get("imports"):
            triage_command += ["--imports", str(staged_files["imports"])]
        else:
            triage_command += ["--no-imports"]
        if args.overrides:
            triage_command += ["--overrides", str(args.overrides)]
        else:
            triage_command += ["--no-overrides"]
        if args.runtime_prefixes is not None:
            triage_command += ["--runtime-prefixes", args.runtime_prefixes]
        if args.crt_start is not None:
            triage_command += ["--crt-start", args.crt_start]
        active_stage = {
            "name": "triage-functions",
            "status": "running",
            "started_at": utc_timestamp(),
            "command": triage_command,
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)
        command_status = execute(triage_command, cwd=str(REPO_ROOT))
        if hasattr(command_status, "returncode"):
            command_status = command_status.returncode
        if command_status:
            raise subprocess.CalledProcessError(command_status, triage_command)
        if not (triage_dir / "FUNCTIONS.tsv").is_file():
            raise ValueError("triage did not create FUNCTIONS.tsv: " + str(triage_dir))
        active_stage["returncode"] = 0
        active_stage["status"] = "completed"
        active_stage["finished_at"] = utc_timestamp()
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        roles_script = REPO_ROOT / "ghidra_pipeline" / "python_scripts" / "build_roles_v2.py"
        roles_command = [
            args.python, str(roles_script), "--triage", str(triage_dir), "--out-dir", str(triage_dir),
        ]
        active_stage = {
            "name": "build-roles-and-queues",
            "status": "running",
            "started_at": utc_timestamp(),
            "command": roles_command,
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)
        command_status = execute(roles_command, cwd=str(REPO_ROOT))
        if hasattr(command_status, "returncode"):
            command_status = command_status.returncode
        if command_status:
            raise subprocess.CalledProcessError(command_status, roles_command)
        queue_paths = [triage_dir / ("QUEUE_%s.tsv" % track) for track in tracks]
        missing_queues = [str(path) for path in queue_paths if not path.is_file()]
        if missing_queues:
            raise ValueError("roles stage did not create selected queue file(s): " + ", ".join(missing_queues))
        active_stage["returncode"] = 0
        active_stage["status"] = "completed"
        active_stage["finished_at"] = utc_timestamp()
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        active_stage = {
            "name": "select-queue-entries",
            "status": "running",
            "started_at": utc_timestamp(),
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)
        selected = []
        seen_entries = set()
        group_filter = set(args.groups or [])
        required_columns = {"GROUP", "ENTRY", "NAME", "REASON"}
        for track in tracks:
            queue_path = triage_dir / ("QUEUE_%s.tsv" % track)
            queue_text = io.open(
                unicode(queue_path), "r", encoding="utf-8", errors="replace"
            ).read()
            queue_lines = queue_text.splitlines()
            if not queue_lines:
                raise ValueError("empty queue file: " + str(queue_path))
            headers = queue_lines[0].lstrip(u"\ufeff").split(u"\t")
            indices = dict((name, headers.index(name)) for name in required_columns
                           if name in headers)
            if len(indices) != len(required_columns):
                raise ValueError("invalid queue header in " + str(queue_path))
            group_index = indices["GROUP"]
            entry_index = indices["ENTRY"]
            name_index = indices["NAME"]
            reason_index = indices["REASON"]
            highest_index = max(group_index, entry_index, name_index, reason_index)
            for line_number in range(2, len(queue_lines) + 1):
                line = queue_lines[line_number - 1]
                if not line.strip():
                    continue
                fields = line.split(u"\t")
                if len(fields) <= highest_index:
                    raise ValueError("invalid row %d in %s" % (line_number, queue_path))
                group = fields[group_index].strip()
                entry = fields[entry_index].strip()
                if not group or not GROUP_NAME.match(group) or group in (".", ".."):
                    raise ValueError("invalid group on line %d in %s" % (line_number, queue_path))
                if not ENTRY.match(entry):
                    raise ValueError("invalid ENTRY on line %d in %s" % (line_number, queue_path))
                if group_filter and group not in group_filter:
                    continue
                identity = (group, entry.lower())
                if identity in seen_entries:
                    raise ValueError("function appears more than once in selected queues: %s %s" % identity)
                seen_entries.add(identity)
                selected.append({
                    "group": group,
                    "entry": entry,
                    "name": fields[name_index].strip(),
                    "track": track,
                    "reason": fields[reason_index].strip(),
                    "queue_path": unicode(queue_path.resolve()),
                })
        for group in {item["group"] for item in selected}:
            if not (lite_dir / group).is_dir():
                raise ValueError("selected group is missing from LITE_AC: " + str(lite_dir / group))
        manifest["selection"] = selected
        active_stage["selected_count"] = len(selected)
        active_stage["tracks"] = list(tracks)
        active_stage["groups"] = args.groups or []
        active_stage["status"] = "completed"
        active_stage["finished_at"] = utc_timestamp()
        active_stage = None
        manifest.pop("current_stage", None)
        if not selected:
            manifest["status"] = "completed"
            manifest["finished_at"] = utc_timestamp()
            manifest["note"] = "No KEEP/WRAP queue entries matched; blueprint and LLM stages were skipped."
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)
            print(manifest["note"])
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        by_group = {}
        for item in selected:
            by_group.setdefault(item["group"], []).append(item)
        blueprint_script = REPO_ROOT / "llm_pipeline" / "blueprint_v3.py"
        runner_script = REPO_ROOT / "llm_pipeline" / "run_blueprint_llm_v3.py"
        model_slug = re.sub(r"[^\w.-]+", "_", args.model.strip()).strip("._") or "model"

        for group in sorted(by_group, key=lambda value: value.lower()):
            entries = by_group[group]
            group_dir = lite_dir / group
            group_output = llm_root / group
            entries_file = group_output / "SELECTED_ENTRIES.txt"
            bp_dir = group_output / "BLUEPRINT_v3"
            run_dir = group_output / ("RUN1_v3_" + model_slug)
            active_stage = {
                "name": "generate-blueprints:" + group,
                "status": "running",
                "started_at": utc_timestamp(),
            }
            manifest["stages"].append(active_stage)
            manifest["current_stage"] = active_stage["name"]
            group_output.mkdir(parents=True, exist_ok=True)
            with io.open(unicode(entries_file), "w", encoding="utf-8", newline=u"\n") as entries_stream:
                entries_stream.writelines(item["entry"] + "\n" for item in entries)
            manifest["outputs"]["groups"][group] = {
                "selected_entries_file": str(entries_file),
                "blueprints": str(bp_dir),
                "llm_run": str(run_dir),
                "selected_entries": [item["entry"] for item in entries],
            }
            blueprint_command = [
                args.python, str(blueprint_script), "--group", str(group_dir),
                "--index-dir", str(lite_dir), "--out", str(bp_dir),
                "--entries-file", str(entries_file),
            ]
            active_stage["command"] = blueprint_command
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)
            command_status = execute(blueprint_command, cwd=str(REPO_ROOT))
            if hasattr(command_status, "returncode"):
                command_status = command_status.returncode
            if command_status:
                raise subprocess.CalledProcessError(command_status, blueprint_command)
            checks = sorted(bp_dir.glob("*.check.json"))
            blueprints = sorted(bp_dir.glob("*.blueprint.txt"))
            check_stems = {path.name[:-len(".check.json")] for path in checks}
            blueprint_stems = {path.name[:-len(".blueprint.txt")] for path in blueprints}
            if check_stems != blueprint_stems:
                raise ValueError("blueprint and check files do not have matching names")
            observed_entries = set()
            for check_path in checks:
                with io.open(unicode(check_path), "r", encoding="utf-8") as check_stream:
                    check_data = json.load(check_stream)
                if not isinstance(check_data, dict):
                    raise ValueError("check file root is not an object: " + str(check_path))
                entry = str(check_data.get("entry", "")).lower()
                if not ENTRY.match(entry):
                    raise ValueError("check file has an invalid entry: " + str(check_path))
                if entry in observed_entries:
                    raise ValueError("duplicate blueprint generated for entry " + entry)
                observed_entries.add(entry)
            expected_entries = {item["entry"].lower() for item in entries}
            if observed_entries != expected_entries:
                missing_entries = sorted(expected_entries - observed_entries)
                extra_entries = sorted(observed_entries - expected_entries)
                raise ValueError(
                    "blueprint selection mismatch; missing=%s extra=%s" % (missing_entries, extra_entries)
                )
            if len(checks) != len(entries) or len(blueprints) != len(entries):
                raise ValueError("blueprint/check file count does not match selected queue entries")
            active_stage["returncode"] = 0
            active_stage["blueprint_count"] = len(blueprints)
            active_stage["status"] = "completed"
            active_stage["finished_at"] = utc_timestamp()
            active_stage = None
            manifest.pop("current_stage", None)
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)

            runner_command = [
                args.python, str(runner_script), "--bp", str(bp_dir), "--out", str(run_dir),
                "--model", args.model, "--url", args.url, "--lang", args.lang, "--temp", str(args.temp),
            ]
            if args.lang == "JScript":
                runner_command += ["--jsc", str(args.jsc)]
            recorded_runner_command = list(runner_command)
            recorded_url_index = recorded_runner_command.index("--url") + 1
            recorded_runner_command[recorded_url_index] = endpoint_origin
            active_stage = {
                "name": "run-llm:" + group,
                "status": "running",
                "started_at": utc_timestamp(),
                "command": recorded_runner_command,
            }
            manifest["stages"].append(active_stage)
            manifest["current_stage"] = active_stage["name"]
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)
            command_status = execute(runner_command, cwd=str(REPO_ROOT))
            if hasattr(command_status, "returncode"):
                command_status = command_status.returncode
            if command_status:
                raise subprocess.CalledProcessError(command_status, runner_command)
            results_path = run_dir / "RESULTS.txt"
            if not results_path.is_file():
                raise ValueError("LLM runner did not write RESULTS.txt: " + str(results_path))
            result_lines = [
                line for line in results_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
                if line
            ]
            if len(result_lines) != len(entries):
                raise ValueError(
                    "LLM result count %d does not match selected entry count %d"
                    % (len(result_lines), len(entries))
                )
            if any(not line.startswith(("PASS\t", "FAIL\t")) for line in result_lines):
                raise ValueError("LLM runner wrote an unrecognized result row")
            result_summary = {
                "result_count": len(result_lines),
                "pass_count": sum(line.startswith("PASS\t") for line in result_lines),
                "fail_count": sum(line.startswith("FAIL\t") for line in result_lines),
            }
            active_stage.update(result_summary)
            active_stage["returncode"] = 0
            active_stage["status"] = "completed"
            active_stage["finished_at"] = utc_timestamp()
            active_stage = None
            manifest.pop("current_stage", None)
            manifest["outputs"]["groups"][group]["result_summary"] = result_summary
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)

        active_stage = {
            "name": "coreoao-hex-optimizer",
            "status": "running",
            "started_at": utc_timestamp(),
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        mask = 0x3F
        shift = 3
        source_directory_name, source_extension = {
            "C": ("C", ".c"),
            "C++": ("CPP", ".cpp"),
            "JScript": ("JSCRIPT", ".js"),
        }[args.lang]
        selected_source_paths = []
        selected_source_texts = []
        selected_source_hashes = []
        selected_run_directories = []
        hex_output_records = []
        hex_output_paths = []
        skipped_hex_entries = []
        hex_optimizer = {
            "algorithm": "COREOAO CAND",
            "contract_version": "coreoaoBytes-js-v1",
            "language": args.lang,
            "mask": mask,
            "shift": shift,
            "input_encoding": "UTF-16 code units",
            "length_policy": "one output byte per shared UTF-16 index; length is min(M0.Length, M1.Length, M2.Length)",
            "source_order": "manifest selection order",
            "formula": "v=(abs(M0[i]-M1[i]) ^ abs(M1[i]-M2[i]) ^ (M0[i] & mask)) | (~mask & 0xFF); out[i]=(v | ((v << (shift % 8)) | (v >> (8-(shift % 8))))) & 0xFF",
            "output_format": "uppercase two-digit hex bytes separated by spaces, LF-terminated",
            "reversible": False,
            "original_sources_retained": True,
            "reverse_scope": "COREO REVERSE restores Ghidra dump inputs only; generated language source is retained and is not recovered from hex.",
            "outputs": hex_output_records,
            "skipped_entries": skipped_hex_entries,
            "output_count": 0,
            "skipped_count": 0,
        }
        manifest["hex_optimizer"] = hex_optimizer
        manifest["outputs"]["coreoao_hex"] = []
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        for item in selected:
            group_record = manifest["outputs"]["groups"][item["group"]]
            run_directory = Path(group_record["llm_run"])
            code_directory = run_directory / source_directory_name
            source_matches = sorted(code_directory.glob(
                item["entry"] + "_*" + source_extension
            ))
            if len(source_matches) != 1:
                raise ValueError(
                    "expected one %s source artifact for selected entry %s, found %d"
                    % (args.lang, item["entry"], len(source_matches))
                )
            source_path = source_matches[0]
            source_bytes = source_path.read_bytes()
            selected_source_paths.append(source_path)
            selected_source_texts.append(source_bytes.decode("utf-8"))
            selected_source_hashes.append(hashlib.sha256(source_bytes).hexdigest())
            selected_run_directories.append(run_directory)

        created_hex_directories = set()
        for source_index, item in enumerate(selected):
            if source_index < 2:
                skipped_hex_entries.append({
                    "entry": item["entry"],
                    "group": item["group"],
                    "track": item["track"],
                    "source_path": str(selected_source_paths[source_index]),
                    "source_sha256": selected_source_hashes[source_index],
                    "reason": "two prior selected source artifacts are required",
                })
                continue
            messages = (
                selected_source_texts[source_index],
                selected_source_texts[source_index - 1],
                selected_source_texts[source_index - 2],
            )
            code_units = []
            for text in messages:
                encoded = text.encode("utf-16-le", "surrogatepass")
                if encoded:
                    code_units.append(list(struct.unpack("<%dH" % (len(encoded) // 2), encoded)))
                else:
                    code_units.append([])
            output_length = min(len(units) for units in code_units)
            output_bytes = []
            for m0, m1, m2 in zip(
                code_units[0][:output_length],
                code_units[1][:output_length],
                code_units[2][:output_length],
            ):
                diff1 = abs(m0 - m1)
                diff2 = abs(m1 - m2)
                value = (diff1 ^ diff2 ^ (m0 & mask)) | ((~mask) & 0xFF)
                rotation = shift % 8
                rotated = (value << rotation) | (value >> (8 - rotation))
                output_bytes.append((value | rotated) & 0xFF)
            hex_text = " ".join("%02X" % value for value in output_bytes)

            run_directory = selected_run_directories[source_index]
            hex_directory = run_directory / "COREOAO"
            if hex_directory not in created_hex_directories:
                if hex_directory.exists():
                    raise ValueError("COREOAO output directory already exists: " + str(hex_directory))
                hex_directory.mkdir()
                created_hex_directories.add(hex_directory)
            source_path = selected_source_paths[source_index]
            sidecar_path = hex_directory / (source_path.stem + ".hex")
            if sidecar_path.exists():
                raise ValueError("COREOAO sidecar already exists: " + str(sidecar_path))
            sidecar_bytes = (hex_text + "\n").encode("utf-8")
            sidecar_path.write_bytes(sidecar_bytes)
            sidecar_hash = hashlib.sha256(sidecar_bytes).hexdigest()
            hex_output_records.append({
                "entry": item["entry"],
                "group": item["group"],
                "track": item["track"],
                "source_path": str(source_path),
                "source_sha256": selected_source_hashes[source_index],
                "previous_source_path": str(selected_source_paths[source_index - 1]),
                "previous_source_sha256": selected_source_hashes[source_index - 1],
                "before_previous_source_path": str(selected_source_paths[source_index - 2]),
                "before_previous_source_sha256": selected_source_hashes[source_index - 2],
                "sidecar_path": str(sidecar_path),
                "sidecar_sha256": sidecar_hash,
                "byte_count": len(output_bytes),
            })
            hex_output_paths.append(str(sidecar_path))
            manifest["outputs"]["groups"][item["group"]]["coreoao_hex"] = str(hex_directory)

        hex_optimizer["output_count"] = len(hex_output_records)
        hex_optimizer["skipped_count"] = len(skipped_hex_entries)
        active_stage["input_count"] = len(selected)
        active_stage["output_count"] = len(hex_output_records)
        active_stage["skipped_count"] = len(skipped_hex_entries)
        active_stage["returncode"] = 0
        active_stage["status"] = "completed"
        active_stage["finished_at"] = utc_timestamp()
        active_stage = None
        manifest.pop("current_stage", None)
        manifest["outputs"]["coreoao_hex"] = hex_output_paths
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)

        if args.mode == "BIDI":
            bidi_restore_dir = out_dir / "BIDI_RESTORE"
            script_path = REPO_ROOT / "coreo_pipeline.py"
            bidi_command = [
                args.python, str(script_path), "--mode", "REVERSE",
                "--source-run", str(out_dir), "--out", str(bidi_restore_dir),
                "--python", args.python,
            ]
            active_stage = {
                "name": "bidi-reverse-source",
                "status": "running",
                "started_at": utc_timestamp(),
                "command": bidi_command,
            }
            manifest["stages"].append(active_stage)
            manifest["current_stage"] = active_stage["name"]
            manifest_temp.write_text(
                json_text(manifest) + u"\n", encoding="utf-8"
            )
            atomic_replace(manifest_temp, manifest_path)
            reverse_status = run_coreo([
                "--mode", "REVERSE",
                "--source-run", str(out_dir),
                "--out", str(bidi_restore_dir),
                "--python", args.python,
            ], process_runner=process_runner)
            if reverse_status != 0:
                raise ValueError("COREO reverse pass exited with code %d" % reverse_status)
            reverse_manifest_path = bidi_restore_dir / "COREO_MANIFEST.json"
            if not reverse_manifest_path.is_file():
                raise ValueError("COREO reverse pass did not write its manifest")
            with io.open(unicode(reverse_manifest_path), "r", encoding="utf-8") as reverse_stream:
                reverse_manifest = json.load(reverse_stream)
            if reverse_manifest.get("status") != "completed" or reverse_manifest.get("mode") != "REVERSE":
                raise ValueError("COREO reverse pass did not complete")
            restored_directory = bidi_restore_dir / "source"
            verified_restores = 0
            for role, basename in (
                ("assembly", "14_Assembly_dump.txt"),
                ("c_pseudocode", "13_function_dump.txt"),
                ("classes", "04_classes.txt"),
                ("imports", "02_imports.txt"),
            ):
                input_record = input_records.get(role)
                if input_record is None or not input_record.get("present"):
                    continue
                expected_hash = input_record["sha256"]
                restored_path = restored_directory / basename
                if not restored_path.is_file():
                    raise ValueError("BiDi restore omitted " + role)
                actual_hash = hashlib.sha256(restored_path.read_bytes()).hexdigest()
                if actual_hash != expected_hash:
                    raise ValueError("BiDi round-trip hash mismatch for " + role)
                verified_restores += 1
            manifest["bidi"] = {
                "reverse_run": str(bidi_restore_dir),
                "restored_count": verified_restores,
                "round_trip_verified": True,
            }
            active_stage["restored_count"] = verified_restores
            active_stage["round_trip_verified"] = True
            active_stage["returncode"] = 0
            active_stage["status"] = "completed"
            active_stage["finished_at"] = utc_timestamp()
            active_stage = None
            manifest.pop("current_stage", None)

        manifest["status"] = "completed"
        manifest["finished_at"] = utc_timestamp()
        manifest_temp.write_text(
            json_text(manifest) + u"\n", encoding="utf-8"
        )
        atomic_replace(manifest_temp, manifest_path)
        print("COREO completed for %d selected function(s)." % len(selected))
        print("COREO manifest: " + str(manifest_path))
        return 0
    except (ValueError, OSError, UnicodeError, subprocess.CalledProcessError, csv.Error) as exc:
        if manifest is not None:
            if active_stage is not None and active_stage["status"] == "running":
                active_stage["status"] = "failed"
                active_stage["finished_at"] = utc_timestamp()
                if isinstance(exc, subprocess.CalledProcessError):
                    active_stage["error"] = "external command failed with exit code %d" % exc.returncode
                    active_stage["returncode"] = exc.returncode
                else:
                    active_stage["error"] = str(exc)
            if input_records:
                manifest["inputs"]["ghidra_dump_files"] = input_records
            manifest["status"] = "failed"
            manifest["error"] = (
                "external command failed with exit code %d" % exc.returncode
                if isinstance(exc, subprocess.CalledProcessError) else str(exc)
            )
            manifest["finished_at"] = utc_timestamp()
            manifest.pop("current_stage", None)
            if manifest_path is not None and manifest_temp is not None:
                manifest_temp.write_text(
                    json_text(manifest) + u"\n", encoding="utf-8"
                )
                atomic_replace(manifest_temp, manifest_path)
        if isinstance(exc, subprocess.CalledProcessError) and exc.returncode:
            print("COREO failed: external command returned exit code %d" % exc.returncode,
                  file=sys.stderr)
            return exc.returncode
        print("COREO failed: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_coreo())
