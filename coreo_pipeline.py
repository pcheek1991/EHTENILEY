#!/usr/bin/env python3
"""Run the existing Ghidra and LLM components through one COREO entry point."""

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


COREO_VERSION = "1"
REPO_ROOT = Path(__file__).resolve().parent
PROGRAM_NAME = re.compile(r"[\w.-]+", re.UNICODE)
GROUP_NAME = re.compile(r"[\w.~-]+", re.UNICODE)
ENTRY = re.compile(r"[0-9a-fA-F]{8}")


def run_coreo(argv=None, process_runner=None):
    """Run COREO; process_runner is injectable so tests can stub model calls."""
    parser = argparse.ArgumentParser(
        description="Run the Ghidra Python and LLM pipelines together from a completed PyGhidra dump."
    )
    parser.add_argument("--dump-root", type=Path, required=True,
                        help="root containing the three <program>_ASSEMBLY/C_PSEUDOCODE/INVENTORY folders")
    parser.add_argument("--program", required=True,
                        help="sanitized Ghidra program name used as the three dump-folder prefix")
    parser.add_argument("--out", type=Path, required=True,
                        help="new COREO run directory; existing directories are never reused")
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
    execute = process_runner if process_runner is not None else subprocess.run
    manifest = None
    manifest_path = None
    manifest_temp = None
    active_stage = None
    input_records = {}

    try:
        if args.program in (".", "..") or not PROGRAM_NAME.fullmatch(args.program):
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
                jsc_path = shutil.which("jsc.exe") or shutil.which("jsc")
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
                    with open(config_file, "rb") as source:
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
                with open(config_path, "rb") as source:
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
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
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
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)

        active_stage = {
            "name": "stage-ghidra-inputs",
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)
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
            shutil.copy2(source_path, staged_path)
            source_digest = hashlib.sha256()
            with open(source_path, "rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    source_digest.update(chunk)
            staged_digest = hashlib.sha256()
            with open(staged_path, "rb") as staged:
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
        active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)

        grouping_script = REPO_ROOT / "ghidra_pipeline" / "python_scripts" / "make_full_lite_v2.py"
        grouping_command = [
            sys.executable, str(grouping_script), "--in", str(source_dir), "--out", str(ghidra_out),
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
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "command": grouping_command,
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)
        command_result = execute(grouping_command, cwd=str(REPO_ROOT), check=True)
        if getattr(command_result, "returncode", 0) != 0:
            raise subprocess.CalledProcessError(command_result.returncode, grouping_command)
        if not lite_dir.is_dir():
            raise ValueError("grouping did not create LITE_AC: " + str(lite_dir))
        active_stage["returncode"] = 0
        active_stage["status"] = "completed"
        active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)

        triage_script = REPO_ROOT / "ghidra_pipeline" / "python_scripts" / "triage_evidence_v2.py"
        triage_command = [
            sys.executable, str(triage_script), "--lite", str(lite_dir),
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
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "command": triage_command,
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)
        command_result = execute(triage_command, cwd=str(REPO_ROOT), check=True)
        if getattr(command_result, "returncode", 0) != 0:
            raise subprocess.CalledProcessError(command_result.returncode, triage_command)
        if not (triage_dir / "FUNCTIONS.tsv").is_file():
            raise ValueError("triage did not create FUNCTIONS.tsv: " + str(triage_dir))
        active_stage["returncode"] = 0
        active_stage["status"] = "completed"
        active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)

        roles_script = REPO_ROOT / "ghidra_pipeline" / "python_scripts" / "build_roles_v2.py"
        roles_command = [
            sys.executable, str(roles_script), "--triage", str(triage_dir), "--out-dir", str(triage_dir),
        ]
        active_stage = {
            "name": "build-roles-and-queues",
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "command": roles_command,
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)
        command_result = execute(roles_command, cwd=str(REPO_ROOT), check=True)
        if getattr(command_result, "returncode", 0) != 0:
            raise subprocess.CalledProcessError(command_result.returncode, roles_command)
        queue_paths = [triage_dir / ("QUEUE_%s.tsv" % track) for track in tracks]
        missing_queues = [str(path) for path in queue_paths if not path.is_file()]
        if missing_queues:
            raise ValueError("roles stage did not create selected queue file(s): " + ", ".join(missing_queues))
        active_stage["returncode"] = 0
        active_stage["status"] = "completed"
        active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        active_stage = None
        manifest.pop("current_stage", None)
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)

        active_stage = {
            "name": "select-queue-entries",
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        manifest["stages"].append(active_stage)
        manifest["current_stage"] = active_stage["name"]
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)
        selected = []
        seen_entries = set()
        group_filter = set(args.groups or [])
        required_columns = {"GROUP", "ENTRY", "NAME", "REASON"}
        for track in tracks:
            queue_path = triage_dir / ("QUEUE_%s.tsv" % track)
            with open(queue_path, encoding="utf-8", errors="replace", newline="") as queue_file:
                reader = csv.DictReader(queue_file, delimiter="\t")
                if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
                    raise ValueError("invalid queue header in " + str(queue_path))
                for line_number, row in enumerate(reader, 2):
                    group = (row.get("GROUP") or "").strip()
                    entry = (row.get("ENTRY") or "").strip()
                    if not group or not GROUP_NAME.fullmatch(group) or group in (".", ".."):
                        raise ValueError("invalid group on line %d in %s" % (line_number, queue_path))
                    if not ENTRY.fullmatch(entry):
                        raise ValueError("invalid ENTRY on line %d in %s" % (line_number, queue_path))
                    if group_filter and group not in group_filter:
                        continue
                    identity = (group, entry.lower())
                    if identity in seen_entries:
                        raise ValueError("function appears more than once in selected queues: %s %s" % identity)
                    seen_entries.add(identity)
                    selected.append({
                        "group": group,
                        "entry": entry.lower(),
                        "name": (row.get("NAME") or "").strip(),
                        "track": track,
                        "reason": (row.get("REASON") or "").strip(),
                        "queue_path": str(queue_path.resolve()),
                    })
        for group in {item["group"] for item in selected}:
            if not (lite_dir / group).is_dir():
                raise ValueError("selected group is missing from LITE_AC: " + str(lite_dir / group))
        manifest["selection"] = selected
        active_stage["selected_count"] = len(selected)
        active_stage["tracks"] = list(tracks)
        active_stage["groups"] = args.groups or []
        active_stage["status"] = "completed"
        active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        active_stage = None
        manifest.pop("current_stage", None)
        if not selected:
            manifest["status"] = "completed"
            manifest["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            manifest["note"] = "No KEEP/WRAP queue entries matched; blueprint and LLM stages were skipped."
            manifest_temp.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            manifest_temp.replace(manifest_path)
            print(manifest["note"])
            print("COREO manifest: " + str(manifest_path))
            return 0
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)

        by_group = {}
        for item in selected:
            by_group.setdefault(item["group"], []).append(item)
        blueprint_script = REPO_ROOT / "llm_pipeline" / "blueprint_v3.py"
        runner_script = REPO_ROOT / "llm_pipeline" / "run_blueprint_llm_v3.py"
        model_slug = re.sub(r"[^\w.-]+", "_", args.model.strip()).strip("._") or "model"

        for group in sorted(by_group, key=str.casefold):
            entries = by_group[group]
            group_dir = lite_dir / group
            group_output = llm_root / group
            entries_file = group_output / "SELECTED_ENTRIES.txt"
            bp_dir = group_output / "BLUEPRINT_v3"
            run_dir = group_output / ("RUN1_v3_" + model_slug)
            active_stage = {
                "name": "generate-blueprints:" + group,
                "status": "running",
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            }
            manifest["stages"].append(active_stage)
            manifest["current_stage"] = active_stage["name"]
            group_output.mkdir(parents=True, exist_ok=True)
            with open(entries_file, "w", encoding="utf-8", newline="\n") as entries_stream:
                entries_stream.writelines(item["entry"] + "\n" for item in entries)
            manifest["outputs"]["groups"][group] = {
                "selected_entries_file": str(entries_file),
                "blueprints": str(bp_dir),
                "llm_run": str(run_dir),
                "selected_entries": [item["entry"] for item in entries],
            }
            blueprint_command = [
                sys.executable, str(blueprint_script), "--group", str(group_dir),
                "--index-dir", str(lite_dir), "--out", str(bp_dir),
                "--entries-file", str(entries_file),
            ]
            active_stage["command"] = blueprint_command
            manifest_temp.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            manifest_temp.replace(manifest_path)
            command_result = execute(blueprint_command, cwd=str(REPO_ROOT), check=True)
            if getattr(command_result, "returncode", 0) != 0:
                raise subprocess.CalledProcessError(command_result.returncode, blueprint_command)
            checks = sorted(bp_dir.glob("*.check.json"))
            blueprints = sorted(bp_dir.glob("*.blueprint.txt"))
            check_stems = {path.name[:-len(".check.json")] for path in checks}
            blueprint_stems = {path.name[:-len(".blueprint.txt")] for path in blueprints}
            if check_stems != blueprint_stems:
                raise ValueError("blueprint and check files do not have matching names")
            observed_entries = set()
            for check_path in checks:
                with open(check_path, encoding="utf-8") as check_stream:
                    check_data = json.load(check_stream)
                if not isinstance(check_data, dict):
                    raise ValueError("check file root is not an object: " + str(check_path))
                entry = str(check_data.get("entry", "")).lower()
                if not ENTRY.fullmatch(entry):
                    raise ValueError("check file has an invalid entry: " + str(check_path))
                if entry in observed_entries:
                    raise ValueError("duplicate blueprint generated for entry " + entry)
                observed_entries.add(entry)
            expected_entries = {item["entry"] for item in entries}
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
            active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            active_stage = None
            manifest.pop("current_stage", None)
            manifest_temp.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            manifest_temp.replace(manifest_path)

            runner_command = [
                sys.executable, str(runner_script), "--bp", str(bp_dir), "--out", str(run_dir),
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
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "command": recorded_runner_command,
            }
            manifest["stages"].append(active_stage)
            manifest["current_stage"] = active_stage["name"]
            manifest_temp.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            manifest_temp.replace(manifest_path)
            command_result = execute(runner_command, cwd=str(REPO_ROOT), check=True)
            if getattr(command_result, "returncode", 0) != 0:
                raise subprocess.CalledProcessError(command_result.returncode, runner_command)
            results_path = run_dir / "RESULTS.txt"
            if not results_path.is_file():
                raise ValueError("LLM runner did not write RESULTS.txt: " + str(results_path))
            result_lines = [
                line for line in results_path.read_text(encoding="utf-8", errors="replace").splitlines()
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
            active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            active_stage = None
            manifest.pop("current_stage", None)
            manifest["outputs"]["groups"][group]["result_summary"] = result_summary
            manifest_temp.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            manifest_temp.replace(manifest_path)

        manifest["status"] = "completed"
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        manifest_temp.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        manifest_temp.replace(manifest_path)
        print("COREO completed for %d selected function(s)." % len(selected))
        print("COREO manifest: " + str(manifest_path))
        return 0
    except (ValueError, OSError, UnicodeError, subprocess.CalledProcessError, csv.Error) as exc:
        if manifest is not None:
            if active_stage is not None and active_stage["status"] == "running":
                active_stage["status"] = "failed"
                active_stage["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
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
            manifest["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            manifest.pop("current_stage", None)
            if manifest_path is not None and manifest_temp is not None:
                manifest_temp.write_text(
                    json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
                manifest_temp.replace(manifest_path)
        if isinstance(exc, subprocess.CalledProcessError) and exc.returncode:
            print("COREO failed: external command returned exit code %d" % exc.returncode,
                  file=sys.stderr)
            return exc.returncode
        print("COREO failed: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(run_coreo())
