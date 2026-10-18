#!/usr/bin/env python3
"""Run the Ghidra Python pipeline and the LLM pipeline as one provenance-tracked flow."""

import argparse
import csv
import hashlib
import json
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


class PipelineError(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint_path(path):
    path = Path(path).expanduser().resolve()
    if path.is_file():
        return {"path": str(path), "kind": "file", "sha256": sha256_file(path)}
    if path.is_dir():
        files = []
        for item in sorted(p for p in path.rglob("*") if p.is_file()):
            files.append({
                "path": item.relative_to(path).as_posix(),
                "sha256": sha256_file(item),
            })
        return {"path": str(path), "kind": "directory", "files": files}
    raise PipelineError("input path does not exist: " + str(path))


def write_manifest(path, manifest):
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with open(temp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    temp_path.replace(path)


def endpoint_origin(url):
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if not parsed.scheme or not host:
            return "[redacted]"
        if ":" in host:
            host = "[" + host + "]"
        port = parsed.port
        return parsed.scheme + "://" + host + ((":" + str(port)) if port else "")
    except ValueError:
        return "[redacted]"


def manifest_command(command):
    safe_command = [str(part) for part in command]
    for index, part in enumerate(safe_command[:-1]):
        if part == "--url":
            safe_command[index + 1] = endpoint_origin(safe_command[index + 1])
    return safe_command


def valid_program_name(program):
    if program in (".", "..") or not PROGRAM_NAME.fullmatch(program):
        raise PipelineError("program must be the sanitized Ghidra dump folder name")


def resolve_dump_files(dump_root, program):
    valid_program_name(program)
    root = Path(dump_root).expanduser().resolve()
    if not root.is_dir():
        raise PipelineError("Ghidra dump root is not a directory: " + str(root))

    candidates = {
        "assembly": root / (program + "_ASSEMBLY") / "14_Assembly_dump.txt",
        "c_pseudocode": root / (program + "_C_PSEUDOCODE") / "13_function_dump.txt",
        "classes": root / (program + "_INVENTORY") / "04_classes.txt",
        "imports": root / (program + "_INVENTORY") / "02_imports.txt",
    }
    missing = [str(candidates[name]) for name in ("assembly", "c_pseudocode")
               if not candidates[name].is_file()]
    if missing:
        raise PipelineError("missing required PyGhidra dump file(s): " + ", ".join(missing))
    return root, candidates


def validate_config_inputs(args):
    config_paths = {
        "manual_groups": (args.manual_groups, False),
        "grouper_dir": (args.grouper_dir, True),
        "sms": (args.sms, False),
        "overrides": (args.overrides, False),
    }
    fingerprints = {}
    for name, (path, is_dir) in config_paths.items():
        if path is None:
            continue
        path = Path(path).expanduser().resolve()
        setattr(args, name, path)
        if is_dir and not path.is_dir():
            raise PipelineError("%s is not a directory: %s" % (name, path))
        if not is_dir and not path.is_file():
            raise PipelineError("%s is not a file: %s" % (name, path))
        fingerprints[name] = fingerprint_path(path)
    return fingerprints


def copy_dump_inputs(source_files, source_dir, manifest, manifest_path):
    stage = start_stage(manifest, manifest_path, "stage-ghidra-inputs")
    staged_files = {}
    records = {}
    required = {"assembly", "c_pseudocode"}
    try:
        source_dir.mkdir(parents=True, exist_ok=True)
        for name, source in source_files.items():
            source = Path(source)
            if not source.is_file():
                records[name] = {
                    "present": False,
                    "source_path": str(source),
                    "staged_path": None,
                }
                if name in required:
                    raise PipelineError("required Ghidra input disappeared: " + str(source))
                continue
            destination = source_dir / source.name
            shutil.copy2(source, destination)
            source_hash = sha256_file(source)
            staged_hash = sha256_file(destination)
            if source_hash != staged_hash:
                raise PipelineError("staged input hash mismatch: " + str(source))
            staged_files[name] = destination
            records[name] = {
                "present": True,
                "source_path": str(source),
                "staged_path": str(destination),
                "sha256": source_hash,
            }
        manifest["inputs"]["ghidra_dump_files"] = records
    except (OSError, PipelineError) as exc:
        manifest["inputs"]["ghidra_dump_files"] = records
        fail_stage(stage, manifest, manifest_path, str(exc))
        raise
    finish_stage(stage, manifest, manifest_path)
    return staged_files


def start_stage(manifest, manifest_path, name, command=None):
    stage = {"name": name, "status": "running", "started_at": now()}
    if command is not None:
        stage["command"] = manifest_command(command)
    manifest["stages"].append(stage)
    manifest["current_stage"] = name
    write_manifest(manifest_path, manifest)
    return stage


def finish_stage(stage, manifest, manifest_path, details=None):
    stage["status"] = "completed"
    stage["finished_at"] = now()
    if details:
        stage.update(details)
    manifest.pop("current_stage", None)
    write_manifest(manifest_path, manifest)


def fail_stage(stage, manifest, manifest_path, error, returncode=None):
    stage["status"] = "failed"
    stage["finished_at"] = now()
    stage["error"] = error
    if returncode is not None:
        stage["returncode"] = returncode
    manifest["status"] = "failed"
    manifest["error"] = error
    manifest["finished_at"] = now()
    manifest.pop("current_stage", None)
    write_manifest(manifest_path, manifest)


def run_command(name, command, repo_root, manifest, manifest_path):
    stage = start_stage(manifest, manifest_path, name, command)
    try:
        subprocess.run([str(part) for part in command], cwd=str(repo_root), check=True)
    except subprocess.CalledProcessError as exc:
        fail_stage(stage, manifest, manifest_path,
                   "external command failed with exit code %d" % exc.returncode, exc.returncode)
        raise
    except OSError as exc:
        fail_stage(stage, manifest, manifest_path, str(exc))
        raise
    stage["returncode"] = 0
    finish_stage(stage, manifest, manifest_path)
    return stage


def validate_stage(stage, manifest, manifest_path, callback):
    try:
        details = callback()
    except (OSError, UnicodeError, PipelineError, json.JSONDecodeError) as exc:
        fail_stage(stage, manifest, manifest_path, str(exc))
        raise
    if details:
        stage.update(details)
        write_manifest(manifest_path, manifest)


def require_directory(path, message):
    if not Path(path).is_dir():
        raise PipelineError(message)
    return {}


def require_files(paths, message):
    missing = [str(path) for path in paths if not Path(path).is_file()]
    if missing:
        raise PipelineError("%s: %s" % (message, ", ".join(missing)))
    return {}


def read_queue_entries(triage_dir, tracks, groups=None):
    selected = []
    seen = set()
    group_filter = set(groups or ())
    required_columns = {"GROUP", "ENTRY", "NAME", "REASON"}
    for track in tracks:
        path = Path(triage_dir) / ("QUEUE_%s.tsv" % track)
        if not path.is_file():
            raise PipelineError("queue file not found: " + str(path))
        try:
            with open(path, encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.DictReader(f, delimiter="\t")
                if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
                    raise PipelineError("invalid queue header in " + str(path))
                for line_number, row in enumerate(reader, 2):
                    group = (row.get("GROUP") or "").strip()
                    entry = (row.get("ENTRY") or "").strip()
                    if not group or not GROUP_NAME.fullmatch(group) or group in (".", ".."):
                        raise PipelineError("invalid group on line %d in %s" % (line_number, path))
                    if not ENTRY.fullmatch(entry):
                        raise PipelineError("invalid ENTRY on line %d in %s" % (line_number, path))
                    if group_filter and group not in group_filter:
                        continue
                    identity = (group, entry.lower())
                    if identity in seen:
                        raise PipelineError("function appears more than once in selected queues: %s %s" % identity)
                    seen.add(identity)
                    selected.append({
                        "group": group,
                        "entry": entry.lower(),
                        "name": (row.get("NAME") or "").strip(),
                        "track": track,
                        "reason": (row.get("REASON") or "").strip(),
                        "queue_path": str(path.resolve()),
                    })
        except csv.Error as exc:
            raise PipelineError("could not parse queue %s: %s" % (path, exc))
    return sorted(selected, key=lambda item: (item["group"].casefold(), item["entry"]))


def verify_blueprints(bp_dir, entries):
    checks = sorted(Path(bp_dir).glob("*.check.json"))
    blueprints = sorted(Path(bp_dir).glob("*.blueprint.txt"))
    check_stems = {path.name[:-len(".check.json")] for path in checks}
    blueprint_stems = {path.name[:-len(".blueprint.txt")] for path in blueprints}
    if check_stems != blueprint_stems:
        raise PipelineError("blueprint and check files do not have matching names")
    observed = set()
    for path in checks:
        with open(path, encoding="utf-8") as f:
            check = json.load(f)
        if not isinstance(check, dict):
            raise PipelineError("check file root is not an object: " + str(path))
        entry = str(check.get("entry", "")).lower()
        if not ENTRY.fullmatch(entry):
            raise PipelineError("check file has an invalid entry: " + str(path))
        if entry in observed:
            raise PipelineError("duplicate blueprint generated for entry " + entry)
        observed.add(entry)
    expected = {item["entry"] for item in entries}
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise PipelineError("blueprint selection mismatch; missing=%s extra=%s" % (missing, extra))
    if len(checks) != len(entries) or len(blueprints) != len(entries):
        raise PipelineError("blueprint/check file count does not match selected queue entries")
    return {"blueprint_count": len(blueprints)}


def verify_llm_results(run_dir, expected_count):
    path = Path(run_dir) / "RESULTS.txt"
    if not path.is_file():
        raise PipelineError("LLM runner did not write RESULTS.txt: " + str(path))
    lines = [line for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line]
    if len(lines) != expected_count:
        raise PipelineError("LLM result count %d does not match selected entry count %d" % (len(lines), expected_count))
    if any(not line.startswith(("PASS\t", "FAIL\t")) for line in lines):
        raise PipelineError("LLM runner wrote an unrecognized result row")
    passed = sum(line.startswith("PASS\t") for line in lines)
    failed = sum(line.startswith("FAIL\t") for line in lines)
    return {"result_count": len(lines), "pass_count": passed, "fail_count": failed}


def build_parser():
    parser = argparse.ArgumentParser(
        description="Run the Ghidra Python and LLM pipelines together from a completed PyGhidra dump."
    )
    parser.add_argument("--dump-root", type=Path, required=True,
                        help="root containing the three <program>_ASSEMBLY/C_PSEUDOCODE/INVENTORY folders")
    parser.add_argument("--program", required=True,
                        help="sanitized Ghidra program name used as the three dump-folder prefix")
    parser.add_argument("--out", type=Path, required=True,
                        help="new COREO run directory; existing directories are never reused")
    parser.add_argument("--track", type=lambda value: value.upper(), choices=("BOTH", "KEEP", "WRAP"),
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
    parser.add_argument("--lang", choices=("C", "C++"), default="C")
    parser.add_argument("--temp", type=float, default=0.0)
    return parser


def run_pipeline(args, repo_root=REPO_ROOT):
    dump_root, source_files = resolve_dump_files(args.dump_root, args.program)
    config_inputs = validate_config_inputs(args)
    out_dir = Path(args.out).expanduser().resolve()
    if out_dir.exists():
        raise PipelineError("COREO output directory already exists: " + str(out_dir))
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir()

    tracks = ("KEEP", "WRAP") if args.track == "BOTH" else (args.track,)
    ghidra_out = out_dir / "ghidra" / "OUT"
    lite_dir = ghidra_out / "LITE_AC"
    triage_dir = ghidra_out / "TRIAGE"
    llm_root = out_dir / "llm"
    source_dir = out_dir / "source"
    manifest_path = out_dir / "COREO_MANIFEST.json"
    manifest = {
        "schema_version": 1,
        "coreo_version": COREO_VERSION,
        "status": "running",
        "started_at": now(),
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
                "url_origin": endpoint_origin(args.url),
                "lang": args.lang,
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
    write_manifest(manifest_path, manifest)

    try:
        staged_files = copy_dump_inputs(source_files, source_dir, manifest, manifest_path)
        grouping_script = repo_root / "ghidra_pipeline" / "python_scripts" / "make_full_lite_v2.py"
        triage_script = repo_root / "ghidra_pipeline" / "python_scripts" / "triage_evidence_v2.py"
        roles_script = repo_root / "ghidra_pipeline" / "python_scripts" / "build_roles_v2.py"
        blueprint_script = repo_root / "llm_pipeline" / "blueprint_v3.py"
        runner_script = repo_root / "llm_pipeline" / "run_blueprint_llm_v3.py"

        grouping_command = [
            sys.executable, grouping_script, "--in", source_dir, "--out", ghidra_out,
            "--max-group", args.max_group, "--common", args.common, "--min-prefix", args.min_prefix,
        ]
        if args.manual_groups:
            grouping_command += ["--groups", args.manual_groups.resolve()]
        if args.grouper_dir:
            grouping_command += ["--grouper-dir", args.grouper_dir.resolve()]
        if args.sms:
            grouping_command += ["--sms", args.sms.resolve()]
        grouping_stage = run_command(
            "group-functions", grouping_command, repo_root, manifest, manifest_path
        )
        validate_stage(
            grouping_stage, manifest, manifest_path,
            lambda: require_directory(lite_dir, "grouping did not create LITE_AC: " + str(lite_dir)),
        )

        triage_command = [
            sys.executable, triage_script, "--lite", lite_dir, "--report-dir", triage_dir,
        ]
        if staged_files.get("imports"):
            triage_command += ["--imports", staged_files["imports"]]
        else:
            triage_command += ["--no-imports"]
        if args.overrides:
            triage_command += ["--overrides", args.overrides.resolve()]
        else:
            triage_command += ["--no-overrides"]
        if args.runtime_prefixes is not None:
            triage_command += ["--runtime-prefixes", args.runtime_prefixes]
        if args.crt_start is not None:
            triage_command += ["--crt-start", args.crt_start]
        run_command("triage-functions", triage_command, repo_root, manifest, manifest_path)

        roles_command = [
            sys.executable, roles_script, "--triage", triage_dir, "--out-dir", triage_dir,
        ]
        roles_stage = run_command("build-roles-and-queues", roles_command, repo_root, manifest, manifest_path)
        queue_paths = [triage_dir / ("QUEUE_%s.tsv" % track) for track in tracks]
        validate_stage(
            roles_stage, manifest, manifest_path,
            lambda: require_files(queue_paths, "roles stage did not create every selected queue"),
        )

        selection_stage = start_stage(manifest, manifest_path, "select-queue-entries")
        selected = read_queue_entries(triage_dir, tracks, args.groups)
        for group in {item["group"] for item in selected}:
            if not (lite_dir / group).is_dir():
                raise PipelineError("selected group is missing from LITE_AC: " + str(lite_dir / group))
        manifest["selection"] = selected
        finish_stage(
            selection_stage, manifest, manifest_path,
            {"selected_count": len(selected), "tracks": list(tracks), "groups": args.groups or []},
        )
        if not selected:
            manifest["status"] = "completed"
            manifest["finished_at"] = now()
            manifest["note"] = "No KEEP/WRAP queue entries matched; blueprint and LLM stages were skipped."
            write_manifest(manifest_path, manifest)
            print(manifest["note"])
            print("COREO manifest: " + str(manifest_path))
            return manifest

        by_group = {}
        for item in selected:
            by_group.setdefault(item["group"], []).append(item)

        for group in sorted(by_group, key=str.casefold):
            entries = by_group[group]
            group_dir = lite_dir / group
            group_output = llm_root / group
            selection_file_stage = start_stage(
                manifest, manifest_path, "write-selection-file:" + group
            )
            try:
                group_output.mkdir(parents=True, exist_ok=True)
                entries_file = group_output / "SELECTED_ENTRIES.txt"
                with open(entries_file, "w", encoding="utf-8", newline="\n") as f:
                    f.writelines(item["entry"] + "\n" for item in entries)
            except OSError as exc:
                fail_stage(selection_file_stage, manifest, manifest_path, str(exc))
                raise
            finish_stage(selection_file_stage, manifest, manifest_path)
            bp_dir = group_output / "BLUEPRINT_v3"
            blueprint_command = [
                sys.executable, blueprint_script, "--group", group_dir, "--index-dir", lite_dir,
                "--out", bp_dir, "--entries-file", entries_file,
            ]
            blueprint_stage = run_command(
                "generate-blueprints:" + group, blueprint_command, repo_root, manifest, manifest_path
            )
            validate_stage(
                blueprint_stage, manifest, manifest_path,
                lambda bp_dir=bp_dir, entries=entries: verify_blueprints(bp_dir, entries),
            )

            model_slug = re.sub(r"[^\w.-]+", "_", args.model.strip()).strip("._") or "model"
            run_dir = group_output / ("RUN1_v3_" + model_slug)
            manifest["outputs"]["groups"][group] = {
                "selected_entries_file": str(entries_file),
                "blueprints": str(bp_dir),
                "llm_run": str(run_dir),
                "selected_entries": [item["entry"] for item in entries],
            }
            write_manifest(manifest_path, manifest)
            run_command(
                "run-llm:" + group,
                [
                    sys.executable, runner_script, "--bp", bp_dir, "--out", run_dir,
                    "--model", args.model, "--url", args.url, "--lang", args.lang, "--temp", args.temp,
                ],
                repo_root, manifest, manifest_path,
            )
            results_stage = start_stage(manifest, manifest_path, "verify-llm-results:" + group)
            result_summary = verify_llm_results(run_dir, len(entries))
            finish_stage(results_stage, manifest, manifest_path, result_summary)
            manifest["outputs"]["groups"][group]["result_summary"] = result_summary
            write_manifest(manifest_path, manifest)

        manifest["status"] = "completed"
        manifest["finished_at"] = now()
        write_manifest(manifest_path, manifest)
        print("COREO completed for %d selected function(s)." % len(selected))
        print("COREO manifest: " + str(manifest_path))
        return manifest
    except (PipelineError, OSError, UnicodeError, subprocess.CalledProcessError,
            csv.Error, json.JSONDecodeError) as exc:
        active = next((stage for stage in reversed(manifest["stages"])
                       if stage["status"] == "running"), None)
        if active:
            fail_stage(active, manifest, manifest_path, str(exc),
                       exc.returncode if isinstance(exc, subprocess.CalledProcessError) else None)
        manifest["status"] = "failed"
        manifest["error"] = (
            "external command failed with exit code %d" % exc.returncode
            if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        )
        manifest["finished_at"] = now()
        write_manifest(manifest_path, manifest)
        raise


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        run_pipeline(args)
    except (PipelineError, OSError, UnicodeError, subprocess.CalledProcessError,
            csv.Error, json.JSONDecodeError) as exc:
        if isinstance(exc, subprocess.CalledProcessError) and exc.returncode:
            print("COREO failed: external command returned exit code %d" % exc.returncode,
                  file=sys.stderr)
            return exc.returncode
        print("COREO failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
