using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class CoreoPipeline
{
    private const string CoreoVersion = "1";
    private const int CoreoMask = 0x3F;
    private const int CoreoShift = 3;
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly Regex ProgramNamePattern = new Regex(@"\A[\w.-]+\z", RegexOptions.CultureInvariant);
    private static readonly Regex GroupNamePattern = new Regex(@"\A[\w.~-]+\z", RegexOptions.CultureInvariant);
    private static readonly Regex EntryPattern = new Regex(@"\A[0-9a-fA-F]{8}\z", RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private sealed class ParsedOptions
    {
        public Dictionary<string, string> Values { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
        public HashSet<string> Provided { get; } = new HashSet<string>(StringComparer.Ordinal);
        public List<string> Groups { get; } = new List<string>();
        public bool HelpRequested { get; set; }
    }

    private sealed class ExecutionState
    {
        public Dictionary<string, object> Manifest { get; set; }
        public Dictionary<string, object> ActiveStage { get; set; }
        public string ManifestPath { get; set; }
        public string ManifestTemp { get; set; }
        public int FailureCode { get; set; } = 1;
    }

    private sealed class RestoreItem
    {
        public string Role { get; set; }
        public string OriginalPath { get; set; }
        public string StagedPath { get; set; }
        public string Sha256 { get; set; }
    }

    public static int Run(string[] rawArgs, string repositoryRoot)
    {
        var state = new ExecutionState();
        try
        {
            var parsed = ParseOptions(rawArgs ?? Array.Empty<string>());
            if (parsed.HelpRequested)
            {
                Console.WriteLine(
                    "Usage: pwsh -File coreo_pipeline.ps1 --mode FORWARD|REVERSE|BIDI --dump-root ROOT --program NAME --out NEW_DIR [--source-run RUN_DIR] [--track BOTH|KEEP|WRAP] [--group NAME] [--lang C|C++|JScript] [--jsc PATH]");
                return 0;
            }

            var root = Path.GetFullPath(repositoryRoot ?? AppContext.BaseDirectory);
            var mode = parsed.Values["--mode"].ToUpperInvariant();
            if (mode != "FORWARD" && mode != "REVERSE" && mode != "BIDI")
            {
                throw new ArgumentException("--mode must be FORWARD, REVERSE, or BIDI");
            }

            if (mode == "REVERSE")
            {
                return RunReverse(parsed, state);
            }

            return RunForward(parsed, state, root, mode);
        }
        catch (Exception exception)
        {
            return HandleFailure(state, exception);
        }
    }

    private static ParsedOptions ParseOptions(string[] rawArgs)
    {
        var parsed = new ParsedOptions();
        parsed.Values["--mode"] = "FORWARD";
        parsed.Values["--track"] = "BOTH";
        parsed.Values["--max-group"] = "150";
        parsed.Values["--common"] = "12";
        parsed.Values["--min-prefix"] = "4";
        parsed.Values["--model"] = "qwen2.5-coder-14b-instruct";
        parsed.Values["--url"] = "http://127.0.0.1:1234";
        parsed.Values["--lang"] = "C";
        parsed.Values["--temp"] = "0.0";
        var configuredPython = Environment.GetEnvironmentVariable("PYTHON");
        parsed.Values["--python"] = String.IsNullOrWhiteSpace(configuredPython) ? "python" : configuredPython;

        var knownOptions = new HashSet<string>(new[]
        {
            "--dump-root", "--program", "--out", "--track", "--mode", "--source-run",
            "--manual-groups", "--grouper-dir", "--sms", "--max-group", "--common",
            "--min-prefix", "--overrides", "--runtime-prefixes", "--crt-start", "--model",
            "--url", "--lang", "--jsc", "--temp", "--python"
        }, StringComparer.Ordinal);

        var args = rawArgs.Length > 0 && rawArgs[0] == "--"
            ? rawArgs.Skip(1).ToArray()
            : rawArgs;
        for (var position = 0; position < args.Length;)
        {
            var option = args[position];
            if (option == "-h" || option == "--help")
            {
                parsed.HelpRequested = true;
                position++;
                continue;
            }

            if (option == "--group")
            {
                if (position + 1 >= args.Length)
                {
                    throw new ArgumentException("--group needs a value");
                }

                parsed.Groups.Add(args[position + 1]);
                position += 2;
                continue;
            }

            if (!knownOptions.Contains(option))
            {
                throw new ArgumentException("unknown option: " + option);
            }

            if (position + 1 >= args.Length)
            {
                throw new ArgumentException(option + " needs a value");
            }

            parsed.Values[option] = args[position + 1];
            parsed.Provided.Add(option);
            position += 2;
        }

        return parsed;
    }

    private static int RunReverse(ParsedOptions parsed, ExecutionState state)
    {
        foreach (var required in new[] { "--source-run", "--out" })
        {
            if (!parsed.Provided.Contains(required))
            {
                throw new ArgumentException("required option missing for REVERSE mode: " + required);
            }
        }

        var sourceRun = Path.GetFullPath(parsed.Values["--source-run"]);
        var sourceManifestPath = Path.Combine(sourceRun, "COREO_MANIFEST.json");
        if (!File.Exists(sourceManifestPath))
        {
            throw new FileNotFoundException("COREO source manifest not found: " + sourceManifestPath);
        }

        var sourceManifestBytes = File.ReadAllBytes(sourceManifestPath);
        var sourceManifestHash = Sha256(sourceManifestBytes);
        var restoreItems = ReadRestoreItems(sourceRun, sourceManifestPath);
        if (restoreItems.Count < 2)
        {
            throw new InvalidDataException("source manifest does not contain both required Ghidra dump files");
        }

        var outputDir = Path.GetFullPath(parsed.Values["--out"]);
        EnsureFreshOutputDirectory(outputDir);

        state.ManifestPath = Path.Combine(outputDir, "COREO_MANIFEST.json");
        state.ManifestTemp = state.ManifestPath + ".tmp";
        var inputs = NewObject();
        inputs["source_manifest"] = NewObject(
            "path", sourceManifestPath,
            "sha256", sourceManifestHash);
        var outputs = NewObject();
        var restoredFiles = new List<object>();
        outputs["restored_source"] = Path.Combine(outputDir, "source");
        outputs["restored_files"] = restoredFiles;
        state.Manifest = NewObject(
            "schema_version", 1,
            "coreo_version", CoreoVersion,
            "mode", "REVERSE",
            "status", "running",
            "started_at", Timestamp(),
            "finished_at", null,
            "source_run", sourceRun,
            "inputs", inputs,
            "stages", new List<object>(),
            "selection", new List<object>(),
            "outputs", outputs);
        SaveManifest(state);

        var stage = BeginStage(state, "restore-original-ghidra-inputs");
        var restoreDir = (string)outputs["restored_source"];
        Directory.CreateDirectory(restoreDir);
        foreach (var item in restoreItems)
        {
            var destination = Path.Combine(restoreDir, Path.GetFileName(item.StagedPath));
            File.Copy(item.StagedPath, destination, false);
            var restoredHash = Sha256File(destination);
            if (!String.Equals(restoredHash, item.Sha256, StringComparison.Ordinal))
            {
                throw new InvalidDataException("restored source hash mismatch: " + destination);
            }

            restoredFiles.Add(NewObject(
                "role", item.Role,
                "original_path", item.OriginalPath,
                "restored_path", destination,
                "sha256", restoredHash));
        }

        stage["restored_count"] = restoredFiles.Count;
        CompleteStage(state, stage, 0);
        state.Manifest["status"] = "completed";
        state.Manifest["finished_at"] = Timestamp();
        SaveManifest(state);
        Console.WriteLine("COREO restored " + restoredFiles.Count.ToString(CultureInfo.InvariantCulture) + " verified source artifact(s).");
        Console.WriteLine("COREO reverse manifest: " + state.ManifestPath);
        return 0;
    }

    private static List<RestoreItem> ReadRestoreItems(string sourceRun, string sourceManifestPath)
    {
        using (var document = JsonDocument.Parse(File.ReadAllBytes(sourceManifestPath)))
        {
            var root = document.RootElement;
            JsonElement inputs;
            JsonElement sourceFiles;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("inputs", out inputs) ||
                inputs.ValueKind != JsonValueKind.Object ||
                !inputs.TryGetProperty("ghidra_dump_files", out sourceFiles) ||
                sourceFiles.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException("source manifest is missing Ghidra dump file records");
            }

            var restoreItems = new List<RestoreItem>();
            var sourceFolder = Path.Combine(sourceRun, "source");
            var expectedArtifacts = new[]
            {
                new { Role = "assembly", Name = "14_Assembly_dump.txt", Required = true },
                new { Role = "c_pseudocode", Name = "13_function_dump.txt", Required = true },
                new { Role = "classes", Name = "04_classes.txt", Required = false },
                new { Role = "imports", Name = "02_imports.txt", Required = false }
            };

            foreach (var artifact in expectedArtifacts)
            {
                JsonElement record;
                if (!sourceFiles.TryGetProperty(artifact.Role, out record))
                {
                    if (artifact.Required)
                    {
                        throw new InvalidDataException("source manifest is missing required input record: " + artifact.Role);
                    }

                    continue;
                }

                if (record.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException("source manifest has an invalid input record: " + artifact.Role);
                }

                JsonElement presentElement;
                if (!record.TryGetProperty("present", out presentElement) ||
                    (presentElement.ValueKind != JsonValueKind.True && presentElement.ValueKind != JsonValueKind.False))
                {
                    throw new InvalidDataException("source manifest has an invalid input record: " + artifact.Role);
                }

                var present = presentElement.GetBoolean();
                if (!present)
                {
                    if (artifact.Required)
                    {
                        throw new InvalidDataException("source manifest marks required input absent: " + artifact.Role);
                    }

                    continue;
                }

                var recordedPath = GetRequiredString(record, "staged_path", artifact.Role);
                if (!String.Equals(Path.GetFileName(recordedPath), artifact.Name, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("source manifest has an unexpected staged path for " + artifact.Role);
                }

                var stagedPath = Path.Combine(sourceFolder, artifact.Name);
                if (!File.Exists(stagedPath))
                {
                    throw new FileNotFoundException("preserved source artifact is missing: " + stagedPath);
                }

                var expectedHash = GetRequiredString(record, "sha256", artifact.Role).ToLowerInvariant();
                var actualHash = Sha256File(stagedPath);
                if (!String.Equals(actualHash, expectedHash, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("preserved source hash mismatch: " + stagedPath);
                }

                string originalPath;
                JsonElement originalPathElement;
                if (!record.TryGetProperty("source_path", out originalPathElement) ||
                    (originalPathElement.ValueKind != JsonValueKind.String &&
                     originalPathElement.ValueKind != JsonValueKind.Null))
                {
                    throw new InvalidDataException("source manifest is missing the original path for " + artifact.Role);
                }

                originalPath = originalPathElement.ValueKind == JsonValueKind.Null
                    ? null
                    : originalPathElement.GetString();
                restoreItems.Add(new RestoreItem
                {
                    Role = artifact.Role,
                    OriginalPath = originalPath,
                    StagedPath = stagedPath,
                    Sha256 = actualHash
                });
            }

            return restoreItems;
        }
    }

    private static int RunForward(ParsedOptions parsed, ExecutionState state, string repositoryRoot, string mode)
    {
        foreach (var required in new[] { "--dump-root", "--program", "--out" })
        {
            if (!parsed.Provided.Contains(required))
            {
                throw new ArgumentException("required option missing: " + required);
            }
        }

        var values = parsed.Values;
        var programName = values["--program"];
        if (programName == "." || programName == ".." || !ProgramNamePattern.IsMatch(programName))
        {
            throw new ArgumentException("program must be the sanitized Ghidra dump folder name");
        }

        var dumpRoot = Path.GetFullPath(values["--dump-root"]);
        if (!Directory.Exists(dumpRoot))
        {
            throw new DirectoryNotFoundException("Ghidra dump root is not a directory: " + dumpRoot);
        }

        var sourceFiles = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["assembly"] = Path.Combine(dumpRoot, programName + "_ASSEMBLY", "14_Assembly_dump.txt"),
            ["c_pseudocode"] = Path.Combine(dumpRoot, programName + "_C_PSEUDOCODE", "13_function_dump.txt"),
            ["classes"] = Path.Combine(dumpRoot, programName + "_INVENTORY", "04_classes.txt"),
            ["imports"] = Path.Combine(dumpRoot, programName + "_INVENTORY", "02_imports.txt")
        };
        var missingInputs = new[] { "assembly", "c_pseudocode" }
            .Where(name => !File.Exists(sourceFiles[name]))
            .Select(name => sourceFiles[name])
            .ToArray();
        if (missingInputs.Length > 0)
        {
            throw new FileNotFoundException("missing required PyGhidra dump file(s): " + String.Join(", ", missingInputs));
        }

        var language = values["--lang"];
        if (language != "C" && language != "C++" && language != "JScript")
        {
            throw new ArgumentException("--lang must be C, C++, or JScript");
        }

        var jscPath = "";
        if (language == "JScript")
        {
            if (parsed.Provided.Contains("--jsc"))
            {
                jscPath = Path.GetFullPath(values["--jsc"]);
            }
            else
            {
                jscPath = FindJsc();
            }

            if (String.IsNullOrEmpty(jscPath) || !File.Exists(jscPath))
            {
                throw new FileNotFoundException("JScript mode requires jsc.exe; pass --jsc or install it in a standard .NET Framework path");
            }

            values["--jsc"] = jscPath;
        }
        else if (parsed.Provided.Contains("--jsc"))
        {
            throw new ArgumentException("--jsc can only be used with --lang JScript");
        }

        var configInputs = BuildConfigInputs(parsed);

        var track = values["--track"].ToUpperInvariant();
        var tracks = track == "BOTH" ? new[] { "KEEP", "WRAP" } : new[] { track };
        if (tracks.Any(value => value != "KEEP" && value != "WRAP"))
        {
            throw new ArgumentException("--track must be BOTH, KEEP, or WRAP");
        }
        values["--track"] = track;

        var maxGroup = ParseInteger(values["--max-group"], "--max-group");
        var common = ParseInteger(values["--common"], "--common");
        var minPrefix = ParseInteger(values["--min-prefix"], "--min-prefix");
        var temperature = ParseDouble(values["--temp"], "--temp");
        var outputDir = Path.GetFullPath(values["--out"]);
        EnsureFreshOutputDirectory(outputDir);

        var ghidraOut = Path.Combine(outputDir, "ghidra", "OUT");
        var liteDir = Path.Combine(ghidraOut, "LITE_AC");
        var triageDir = Path.Combine(ghidraOut, "TRIAGE");
        var llmRoot = Path.Combine(outputDir, "llm");
        var sourceDir = Path.Combine(outputDir, "source");
        state.ManifestPath = Path.Combine(outputDir, "COREO_MANIFEST.json");
        state.ManifestTemp = state.ManifestPath + ".tmp";

        var endpointOrigin = RedactedEndpointOrigin(values["--url"]);
        var groupingOptions = NewObject(
            "max_group", maxGroup,
            "common", common,
            "min_prefix", minPrefix,
            "manual_groups", ValueOrNull(values, "--manual-groups"),
            "grouper_dir", ValueOrNull(values, "--grouper-dir"),
            "sms", ValueOrNull(values, "--sms"));
        var triageOptions = NewObject(
            "overrides", ValueOrNull(values, "--overrides"),
            "runtime_prefixes", ValueOrNull(values, "--runtime-prefixes"),
            "crt_start", ValueOrNull(values, "--crt-start"));
        var llmOptions = NewObject(
            "model", values["--model"],
            "url_origin", endpointOrigin,
            "lang", language,
            "jsc_path", ValueOrNull(values, "--jsc"),
            "temperature", temperature);
        var options = NewObject(
            "track", track,
            "groups", parsed.Groups.ToArray(),
            "grouping", groupingOptions,
            "triage", triageOptions,
            "llm", llmOptions);
        var dumpFileRecords = NewObject();
        var manifestInputs = NewObject(
            "ghidra_dump_files", dumpFileRecords,
            "config_inputs", configInputs);
        var groupOutputs = NewObject();
        var outputs = NewObject(
            "ghidra", ghidraOut,
            "triage", triageDir,
            "llm", llmRoot,
            "groups", groupOutputs);
        state.Manifest = NewObject(
            "schema_version", 1,
            "coreo_version", CoreoVersion,
            "mode", mode,
            "status", "running",
            "started_at", Timestamp(),
            "finished_at", null,
            "program", programName,
            "dump_root", dumpRoot,
            "output_dir", outputDir,
            "inputs", manifestInputs,
            "options", options,
            "stages", new List<object>(),
            "selection", new List<object>(),
            "outputs", outputs);
        SaveManifest(state);

        var inputStage = BeginStage(state, "stage-ghidra-inputs");
        var stagedFiles = new Dictionary<string, string>(StringComparer.Ordinal);
        Directory.CreateDirectory(sourceDir);
        foreach (var inputName in new[] { "assembly", "c_pseudocode", "classes", "imports" })
        {
            var sourcePath = sourceFiles[inputName];
            if (!File.Exists(sourcePath))
            {
                dumpFileRecords[inputName] = NewObject(
                    "present", false,
                    "source_path", sourcePath,
                    "staged_path", null);
                if (inputName == "assembly" || inputName == "c_pseudocode")
                {
                    throw new FileNotFoundException("required Ghidra input disappeared: " + sourcePath);
                }

                continue;
            }

            var stagedPath = Path.Combine(sourceDir, Path.GetFileName(sourcePath));
            File.Copy(sourcePath, stagedPath, true);
            var sourceHash = Sha256File(sourcePath);
            var stagedHash = Sha256File(stagedPath);
            if (!String.Equals(sourceHash, stagedHash, StringComparison.Ordinal))
            {
                throw new InvalidDataException("staged input hash mismatch: " + sourcePath);
            }

            stagedFiles[inputName] = stagedPath;
            dumpFileRecords[inputName] = NewObject(
                "present", true,
                "source_path", sourcePath,
                "staged_path", stagedPath,
                "sha256", sourceHash);
        }
        CompleteStage(state, inputStage);

        var pythonExe = values["--python"];
        var groupingScript = Path.Combine(repositoryRoot, "ghidra_pipeline", "python_scripts", "make_full_lite_v2.py");
        var groupingArgs = new List<string>
        {
            groupingScript, "--in", sourceDir, "--out", ghidraOut,
            "--max-group", maxGroup.ToString(CultureInfo.InvariantCulture),
            "--common", common.ToString(CultureInfo.InvariantCulture),
            "--min-prefix", minPrefix.ToString(CultureInfo.InvariantCulture)
        };
        if (values.ContainsKey("--manual-groups"))
        {
            groupingArgs.Add("--groups");
            groupingArgs.Add(values["--manual-groups"]);
        }
        if (values.ContainsKey("--grouper-dir"))
        {
            groupingArgs.Add("--grouper-dir");
            groupingArgs.Add(values["--grouper-dir"]);
        }
        if (values.ContainsKey("--sms"))
        {
            groupingArgs.Add("--sms");
            groupingArgs.Add(values["--sms"]);
        }
        var groupingStage = RunCommandStage(
            state, "group-functions", pythonExe, groupingArgs, repositoryRoot, "grouping");
        if (!Directory.Exists(liteDir))
        {
            throw new InvalidDataException("grouping did not create LITE_AC: " + liteDir);
        }
        CompleteStage(state, groupingStage, 0);

        var triageScript = Path.Combine(repositoryRoot, "ghidra_pipeline", "python_scripts", "triage_evidence_v2.py");
        var triageArgs = new List<string>
        {
            triageScript, "--lite", liteDir, "--report-dir", triageDir
        };
        if (stagedFiles.ContainsKey("imports"))
        {
            triageArgs.Add("--imports");
            triageArgs.Add(stagedFiles["imports"]);
        }
        else
        {
            triageArgs.Add("--no-imports");
        }
        if (values.ContainsKey("--overrides"))
        {
            triageArgs.Add("--overrides");
            triageArgs.Add(values["--overrides"]);
        }
        else
        {
            triageArgs.Add("--no-overrides");
        }
        if (values.ContainsKey("--runtime-prefixes"))
        {
            triageArgs.Add("--runtime-prefixes");
            triageArgs.Add(values["--runtime-prefixes"]);
        }
        if (values.ContainsKey("--crt-start"))
        {
            triageArgs.Add("--crt-start");
            triageArgs.Add(values["--crt-start"]);
        }
        var triageStage = RunCommandStage(
            state, "triage-functions", pythonExe, triageArgs, repositoryRoot, "triage");
        if (!File.Exists(Path.Combine(triageDir, "FUNCTIONS.tsv")))
        {
            throw new InvalidDataException("triage did not create FUNCTIONS.tsv: " + triageDir);
        }
        CompleteStage(state, triageStage, 0);

        var rolesScript = Path.Combine(repositoryRoot, "ghidra_pipeline", "python_scripts", "build_roles_v2.py");
        var rolesArgs = new List<string>
        {
            rolesScript, "--triage", triageDir, "--out-dir", triageDir
        };
        var rolesStage = RunCommandStage(
            state, "build-roles-and-queues", pythonExe, rolesArgs, repositoryRoot, "roles");
        var missingQueues = tracks
            .Select(currentTrack => Path.Combine(triageDir, "QUEUE_" + currentTrack + ".tsv"))
            .Where(path => !File.Exists(path))
            .ToArray();
        if (missingQueues.Length > 0)
        {
            throw new InvalidDataException("roles stage did not create selected queue file(s): " + String.Join(", ", missingQueues));
        }
        CompleteStage(state, rolesStage, 0);

        var selectionStage = BeginStage(state, "select-queue-entries");
        var selected = SelectQueueEntries(triageDir, liteDir, tracks, parsed.Groups);
        var selection = (List<object>)state.Manifest["selection"];
        selection.AddRange(selected.Cast<object>());
        selectionStage["selected_count"] = selected.Count;
        selectionStage["tracks"] = tracks;
        selectionStage["groups"] = parsed.Groups.ToArray();
        CompleteStage(state, selectionStage);

        if (selected.Count == 0)
        {
            var note = "No KEEP/WRAP queue entries matched; blueprint and LLM stages were skipped.";
            state.Manifest["note"] = note;
            Console.WriteLine(note);
        }

        var byGroup = new Dictionary<string, List<Dictionary<string, object>>>(StringComparer.Ordinal);
        foreach (var item in selected)
        {
            var groupName = (string)item["group"];
            if (!byGroup.ContainsKey(groupName))
            {
                byGroup[groupName] = new List<Dictionary<string, object>>();
            }

            byGroup[groupName].Add(item);
        }

        var blueprintScript = Path.Combine(repositoryRoot, "llm_pipeline", "blueprint_v3.py");
        var runnerScript = Path.Combine(repositoryRoot, "llm_pipeline", "run_blueprint_llm_v3.py");
        var modelSlug = Regex.Replace(values["--model"].Trim(), @"[^\w.-]+", "_")
            .Trim('.', '_');
        if (modelSlug.Length == 0)
        {
            modelSlug = "model";
        }

        foreach (var groupName in byGroup.Keys.OrderBy(name => name, StringComparer.OrdinalIgnoreCase))
        {
            var entries = byGroup[groupName];
            var groupDir = Path.Combine(liteDir, groupName);
            var groupOutput = Path.Combine(llmRoot, groupName);
            var entriesFile = Path.Combine(groupOutput, "SELECTED_ENTRIES.txt");
            var blueprintDir = Path.Combine(groupOutput, "BLUEPRINT_v3");
            var runDir = Path.Combine(groupOutput, "RUN1_v3_" + modelSlug);
            var blueprintStage = BeginStage(state, "generate-blueprints:" + groupName);
            Directory.CreateDirectory(groupOutput);
            var entryText = String.Join("\n", entries.Select(item => (string)item["entry"])) + "\n";
            File.WriteAllText(entriesFile, entryText, Utf8);
            var groupOutputRecord = NewObject(
                "selected_entries_file", entriesFile,
                "blueprints", blueprintDir,
                "llm_run", runDir,
                "selected_entries", entries.Select(item => (string)item["entry"]).ToArray());
            groupOutputs[groupName] = groupOutputRecord;

            var blueprintArgs = new List<string>
            {
                blueprintScript, "--group", groupDir, "--index-dir", liteDir,
                "--out", blueprintDir, "--entries-file", entriesFile
            };
            SetStageCommand(blueprintStage, pythonExe, blueprintArgs);
            SaveManifest(state);
            var blueprintExitCode = RunProcess(pythonExe, blueprintArgs, repositoryRoot);
            EnsureProcessSucceeded(state, blueprintExitCode, "blueprint");
            var blueprintFiles = ValidateBlueprints(blueprintDir, entries);
            blueprintStage["blueprint_count"] = blueprintFiles;
            CompleteStage(state, blueprintStage, 0);

            var runnerArgs = new List<string>
            {
                runnerScript, "--bp", blueprintDir, "--out", runDir,
                "--model", values["--model"],
                "--url", values["--url"],
                "--lang", language,
                "--temp", values["--temp"]
            };
            if (language == "JScript")
            {
                runnerArgs.Add("--jsc");
                runnerArgs.Add(jscPath);
            }

            var recordedRunnerArgs = new List<string>(runnerArgs);
            var urlIndex = recordedRunnerArgs.IndexOf("--url");
            if (urlIndex >= 0 && urlIndex + 1 < recordedRunnerArgs.Count)
            {
                recordedRunnerArgs[urlIndex + 1] = endpointOrigin;
            }

            var runnerStage = BeginStage(state, "run-llm:" + groupName);
            SetStageCommand(runnerStage, pythonExe, recordedRunnerArgs);
            SaveManifest(state);
            var runnerExitCode = RunProcess(pythonExe, runnerArgs, repositoryRoot);
            EnsureProcessSucceeded(state, runnerExitCode, "LLM runner");
            var resultSummary = ValidateResults(runDir, entries.Count);
            runnerStage["result_count"] = resultSummary["result_count"];
            runnerStage["pass_count"] = resultSummary["pass_count"];
            runnerStage["fail_count"] = resultSummary["fail_count"];
            CompleteStage(state, runnerStage, 0);
            groupOutputRecord["result_summary"] = resultSummary;
            SaveManifest(state);
        }

        RunCoreoaoOptimizer(state, selected, groupOutputs, language);

        if (mode == "BIDI")
        {
            RunBidiReverse(state, outputDir, values["--python"], repositoryRoot, dumpFileRecords);
        }

        state.Manifest["status"] = "completed";
        state.Manifest["finished_at"] = Timestamp();
        SaveManifest(state);
        Console.WriteLine("COREO completed for " + selected.Count.ToString(CultureInfo.InvariantCulture) + " selected function(s).");
        Console.WriteLine("COREO manifest: " + state.ManifestPath);
        return 0;
    }

    private static Dictionary<string, object> BuildConfigInputs(ParsedOptions parsed)
    {
        var values = parsed.Values;
        var configInputs = NewObject();
        var configOptions = new[]
        {
            "--manual-groups", "--grouper-dir", "--sms", "--overrides", "--jsc"
        };

        foreach (var option in configOptions)
        {
            if (!values.ContainsKey(option))
            {
                continue;
            }

            var configPath = Path.GetFullPath(values[option]);
            var isDirectory = option == "--grouper-dir";
            if (isDirectory && !Directory.Exists(configPath))
            {
                throw new DirectoryNotFoundException(option + " is not a directory: " + configPath);
            }
            if (!isDirectory && !File.Exists(configPath))
            {
                throw new FileNotFoundException(option + " is not a file: " + configPath);
            }

            values[option] = configPath;
            if (isDirectory)
            {
                var files = Directory.GetFiles(configPath, "*", SearchOption.AllDirectories)
                    .OrderBy(path => Path.GetRelativePath(configPath, path), StringComparer.OrdinalIgnoreCase)
                    .Select(path => (object)NewObject(
                        "path", Path.GetRelativePath(configPath, path).Replace('\\', '/'),
                        "sha256", Sha256File(path)))
                    .ToList();
                configInputs[option.Substring(2)] = NewObject(
                    "path", configPath,
                    "kind", "directory",
                    "files", files);
            }
            else
            {
                configInputs[option.Substring(2)] = NewObject(
                    "path", configPath,
                    "kind", "file",
                    "sha256", Sha256File(configPath));
            }
        }

        return configInputs;
    }

    private static List<Dictionary<string, object>> SelectQueueEntries(
        string triageDir,
        string liteDir,
        string[] tracks,
        List<string> groups)
    {
        var selected = new List<Dictionary<string, object>>();
        var seenEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var groupFilter = new HashSet<string>(groups, StringComparer.Ordinal);

        foreach (var track in tracks)
        {
            var queuePath = Path.Combine(triageDir, "QUEUE_" + track + ".tsv");
            var lines = File.ReadAllLines(queuePath, Utf8);
            if (lines.Length == 0)
            {
                throw new InvalidDataException("empty queue file: " + queuePath);
            }

            var headers = lines[0].TrimStart('\uFEFF').Split('\t');
            var groupIndex = Array.IndexOf(headers, "GROUP");
            var entryIndex = Array.IndexOf(headers, "ENTRY");
            var nameIndex = Array.IndexOf(headers, "NAME");
            var reasonIndex = Array.IndexOf(headers, "REASON");
            if (groupIndex < 0 || entryIndex < 0 || nameIndex < 0 || reasonIndex < 0)
            {
                throw new InvalidDataException("invalid queue header in " + queuePath);
            }

            var highestIndex = Math.Max(Math.Max(groupIndex, entryIndex), Math.Max(nameIndex, reasonIndex));
            for (var lineIndex = 1; lineIndex < lines.Length; lineIndex++)
            {
                if (String.IsNullOrWhiteSpace(lines[lineIndex]))
                {
                    continue;
                }

                var fields = lines[lineIndex].Split('\t');
                if (fields.Length <= highestIndex)
                {
                    throw new InvalidDataException("invalid row " + (lineIndex + 1).ToString(CultureInfo.InvariantCulture) + " in " + queuePath);
                }

                var groupName = fields[groupIndex].Trim();
                var entry = fields[entryIndex].Trim();
                if (groupName.Length == 0 ||
                    groupName == "." ||
                    groupName == ".." ||
                    !GroupNamePattern.IsMatch(groupName))
                {
                    throw new InvalidDataException("invalid group on line " + (lineIndex + 1).ToString(CultureInfo.InvariantCulture) + " in " + queuePath);
                }
                if (!EntryPattern.IsMatch(entry))
                {
                    throw new InvalidDataException("invalid ENTRY on line " + (lineIndex + 1).ToString(CultureInfo.InvariantCulture) + " in " + queuePath);
                }

                if (groupFilter.Count > 0 && !groupFilter.Contains(groupName))
                {
                    continue;
                }

                var normalizedEntry = entry.ToLowerInvariant();
                var identity = groupName + "\0" + normalizedEntry;
                if (!seenEntries.Add(identity))
                {
                    throw new InvalidDataException("duplicate queued function " + groupName + " " + entry);
                }

                selected.Add(NewObject(
                    "group", groupName,
                    "entry", normalizedEntry,
                    "name", fields[nameIndex].Trim(),
                    "track", track,
                    "reason", fields[reasonIndex].Trim(),
                    "queue_path", queuePath));
            }
        }

        foreach (var groupName in selected.Select(item => (string)item["group"]).Distinct(StringComparer.Ordinal))
        {
            var groupPath = Path.Combine(liteDir, groupName);
            if (!Directory.Exists(groupPath))
            {
                throw new InvalidDataException("selected group is missing from LITE_AC: " + groupPath);
            }
        }

        return selected;
    }

    private static int ValidateBlueprints(string blueprintDir, List<Dictionary<string, object>> entries)
    {
        var checkFiles = Directory.GetFiles(blueprintDir, "*.check.json", SearchOption.TopDirectoryOnly);
        var blueprintFiles = Directory.GetFiles(blueprintDir, "*.blueprint.txt", SearchOption.TopDirectoryOnly);
        var checkStems = new HashSet<string>(
            checkFiles.Select(path => Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(path))),
            StringComparer.Ordinal);
        var blueprintStems = new HashSet<string>(
            blueprintFiles.Select(path => Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(path))),
            StringComparer.Ordinal);
        if (!checkStems.SetEquals(blueprintStems))
        {
            throw new InvalidDataException("blueprint and check files do not have matching names");
        }

        var observedEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var checkPath in checkFiles)
        {
            using (var document = JsonDocument.Parse(File.ReadAllBytes(checkPath)))
            {
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    throw new InvalidDataException("check file root is not an object: " + checkPath);
                }

                var entry = GetRequiredString(document.RootElement, "entry", checkPath);
                if (!EntryPattern.IsMatch(entry))
                {
                    throw new InvalidDataException("check file has an invalid entry: " + checkPath);
                }
                if (!observedEntries.Add(entry.ToLowerInvariant()))
                {
                    throw new InvalidDataException("duplicate blueprint generated for entry " + entry);
                }
            }
        }

        var expectedEntries = new HashSet<string>(
            entries.Select(item => ((string)item["entry"]).ToLowerInvariant()),
            StringComparer.OrdinalIgnoreCase);
        if (!observedEntries.SetEquals(expectedEntries))
        {
            throw new InvalidDataException("blueprint entry set does not match the selected queues");
        }
        if (checkFiles.Length != entries.Count || blueprintFiles.Length != entries.Count)
        {
            throw new InvalidDataException("blueprint/check file count does not match selected queue entries");
        }

        return blueprintFiles.Length;
    }

    private static Dictionary<string, object> ValidateResults(string runDir, int selectedCount)
    {
        var resultsPath = Path.Combine(runDir, "RESULTS.txt");
        if (!File.Exists(resultsPath))
        {
            throw new InvalidDataException("LLM runner did not write RESULTS.txt: " + resultsPath);
        }

        var resultLines = File.ReadAllLines(resultsPath, Utf8).Where(line => line.Length > 0).ToArray();
        if (resultLines.Length != selectedCount)
        {
            throw new InvalidDataException(
                "LLM result count " + resultLines.Length.ToString(CultureInfo.InvariantCulture) +
                " does not match selected entry count " + selectedCount.ToString(CultureInfo.InvariantCulture));
        }

        var passCount = 0;
        var failCount = 0;
        foreach (var line in resultLines)
        {
            if (line.StartsWith("PASS\t", StringComparison.Ordinal))
            {
                passCount++;
            }
            else if (line.StartsWith("FAIL\t", StringComparison.Ordinal))
            {
                failCount++;
            }
            else
            {
                throw new InvalidDataException("LLM runner wrote an unrecognized result row");
            }
        }

        return NewObject(
            "result_count", resultLines.Length,
            "pass_count", passCount,
            "fail_count", failCount);
    }

    private static void RunCoreoaoOptimizer(
        ExecutionState state,
        List<Dictionary<string, object>> selected,
        Dictionary<string, object> groupOutputs,
        string language)
    {
        var hexStage = BeginStage(state, "coreoao-hex-optimizer");
        var sourceDirectoryName = language == "C" ? "C" : language == "C++" ? "CPP" : "JSCRIPT";
        var sourceExtension = language == "C" ? ".c" : language == "C++" ? ".cpp" : ".js";
        var sourcePaths = new List<string>();
        var sourceTexts = new List<string>();
        var sourceHashes = new List<string>();
        var runDirectories = new List<string>();

        foreach (var item in selected)
        {
            var groupName = (string)item["group"];
            var groupRecord = (Dictionary<string, object>)groupOutputs[groupName];
            var runDirectory = (string)groupRecord["llm_run"];
            var codeDirectory = Path.Combine(runDirectory, sourceDirectoryName);
            var entry = (string)item["entry"];
            var sourceMatches = Directory.GetFiles(
                codeDirectory,
                entry + "_*" + sourceExtension,
                SearchOption.TopDirectoryOnly);
            if (sourceMatches.Length != 1)
            {
                throw new InvalidDataException(
                    "expected one " + language + " source artifact for selected entry " + entry +
                    ", found " + sourceMatches.Length.ToString(CultureInfo.InvariantCulture));
            }

            var sourcePath = sourceMatches[0];
            var sourceBytes = File.ReadAllBytes(sourcePath);
            sourcePaths.Add(sourcePath);
            sourceTexts.Add(ReadUtf8(sourceBytes, sourcePath));
            sourceHashes.Add(Sha256(sourceBytes));
            runDirectories.Add(runDirectory);
        }

        var outputRecords = new List<object>();
        var outputPaths = new List<string>();
        var skippedEntries = new List<object>();
        var hexOptimizer = NewObject(
            "algorithm", "COREOAO CAND",
            "contract_version", "coreoaoBytes-js-v1",
            "language", language,
            "mask", CoreoMask,
            "shift", CoreoShift,
            "input_encoding", "UTF-16 code units",
            "length_policy", "one output byte per shared UTF-16 index; length is min(M0.Length, M1.Length, M2.Length)",
            "source_order", "manifest selection order",
            "formula", "v=(abs(M0[i]-M1[i]) ^ abs(M1[i]-M2[i]) ^ (M0[i] & mask)) | (~mask & 0xFF); out[i]=(v | ((v << (shift % 8)) | (v >> (8-(shift % 8))))) & 0xFF",
            "output_format", "uppercase two-digit hex bytes separated by spaces, LF-terminated",
            "reversible", false,
            "original_sources_retained", true,
            "reverse_scope", "COREO REVERSE restores Ghidra dump inputs only; generated language source is retained and is not recovered from hex.",
            "outputs", outputRecords,
            "skipped_entries", skippedEntries,
            "output_count", 0,
            "skipped_count", 0);
        state.Manifest["hex_optimizer"] = hexOptimizer;
        var outputs = (Dictionary<string, object>)state.Manifest["outputs"];
        outputs["coreoao_hex"] = outputPaths;
        SaveManifest(state);

        var createdHexDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var sourceIndex = 0; sourceIndex < selected.Count; sourceIndex++)
        {
            var item = selected[sourceIndex];
            if (sourceIndex < 2)
            {
                skippedEntries.Add(NewObject(
                    "entry", item["entry"],
                    "group", item["group"],
                    "track", item["track"],
                    "source_path", sourcePaths[sourceIndex],
                    "source_sha256", sourceHashes[sourceIndex],
                    "reason", "two prior selected source artifacts are required"));
                continue;
            }

            var current = sourceTexts[sourceIndex];
            var previous = sourceTexts[sourceIndex - 1];
            var beforePrevious = sourceTexts[sourceIndex - 2];
            var outputLength = Math.Min(current.Length, Math.Min(previous.Length, beforePrevious.Length));
            var bytes = new byte[outputLength];
            var rotation = CoreoShift % 8;
            for (var characterIndex = 0; characterIndex < outputLength; characterIndex++)
            {
                var m0 = (int)current[characterIndex];
                var m1 = (int)previous[characterIndex];
                var m2 = (int)beforePrevious[characterIndex];
                var value = (Math.Abs(m0 - m1) ^
                             Math.Abs(m1 - m2) ^
                             (m0 & CoreoMask)) |
                            ((~CoreoMask) & 0xFF);
                var rotated = (value << rotation) | (value >> (8 - rotation));
                bytes[characterIndex] = (byte)((value | rotated) & 0xFF);
            }

            var hexDirectory = Path.Combine(runDirectories[sourceIndex], "COREOAO");
            if (createdHexDirectories.Add(hexDirectory))
            {
                if (Directory.Exists(hexDirectory) || File.Exists(hexDirectory))
                {
                    throw new IOException("COREOAO output directory already exists: " + hexDirectory);
                }

                Directory.CreateDirectory(hexDirectory);
            }

            var sourcePathForSidecar = sourcePaths[sourceIndex];
            var sidecarPath = Path.Combine(
                hexDirectory,
                Path.GetFileNameWithoutExtension(sourcePathForSidecar) + ".hex");
            if (File.Exists(sidecarPath))
            {
                throw new IOException("COREOAO sidecar already exists: " + sidecarPath);
            }

            var sidecarText = String.Join(" ", bytes.Select(value => value.ToString("X2", CultureInfo.InvariantCulture))) + "\n";
            var sidecarBytes = new UTF8Encoding(false).GetBytes(sidecarText);
            File.WriteAllBytes(sidecarPath, sidecarBytes);
            var sidecarHash = Sha256(sidecarBytes);
            outputRecords.Add(NewObject(
                "entry", item["entry"],
                "group", item["group"],
                "track", item["track"],
                "source_path", sourcePathForSidecar,
                "source_sha256", sourceHashes[sourceIndex],
                "previous_source_path", sourcePaths[sourceIndex - 1],
                "previous_source_sha256", sourceHashes[sourceIndex - 1],
                "before_previous_source_path", sourcePaths[sourceIndex - 2],
                "before_previous_source_sha256", sourceHashes[sourceIndex - 2],
                "sidecar_path", sidecarPath,
                "sidecar_sha256", sidecarHash,
                "byte_count", bytes.Length));
            outputPaths.Add(sidecarPath);
            var groupOutputRecord = (Dictionary<string, object>)groupOutputs[(string)item["group"]];
            groupOutputRecord["coreoao_hex"] = hexDirectory;
        }

        hexOptimizer["output_count"] = outputRecords.Count;
        hexOptimizer["skipped_count"] = skippedEntries.Count;
        hexStage["input_count"] = selected.Count;
        hexStage["output_count"] = outputRecords.Count;
        hexStage["skipped_count"] = skippedEntries.Count;
        CompleteStage(state, hexStage, 0);
        outputs["coreoao_hex"] = outputPaths;
        SaveManifest(state);
    }

    private static void RunBidiReverse(
        ExecutionState state,
        string outputDir,
        string pythonExe,
        string repositoryRoot,
        Dictionary<string, object> dumpFileRecords)
    {
        var bidiRestoreDir = Path.Combine(outputDir, "BIDI_RESTORE");
        var wrapperPath = Path.Combine(repositoryRoot, "coreo_pipeline.ps1");
        var executable = Environment.ProcessPath;
        if (String.IsNullOrEmpty(executable))
        {
            executable = "pwsh";
        }

        var args = new List<string>
        {
            "-NoLogo", "-NoProfile", "-File", wrapperPath,
            "--mode", "REVERSE",
            "--source-run", outputDir,
            "--out", bidiRestoreDir,
            "--python", pythonExe
        };
        var bidiStage = RunCommandStage(
            state, "bidi-reverse-source", executable, args, repositoryRoot, "COREO reverse pass");
        var reverseManifestPath = Path.Combine(bidiRestoreDir, "COREO_MANIFEST.json");
        if (!File.Exists(reverseManifestPath))
        {
            throw new InvalidDataException("COREO reverse pass did not write its manifest");
        }

        using (var document = JsonDocument.Parse(File.ReadAllBytes(reverseManifestPath)))
        {
            var status = GetRequiredString(document.RootElement, "status", reverseManifestPath);
            var reverseMode = GetRequiredString(document.RootElement, "mode", reverseManifestPath);
            if (status != "completed" || reverseMode != "REVERSE")
            {
                throw new InvalidDataException("COREO reverse pass did not complete");
            }
        }

        var restoredDirectory = Path.Combine(bidiRestoreDir, "source");
        var verifiedRestores = 0;
        foreach (var artifact in new[]
        {
            new { Role = "assembly", Name = "14_Assembly_dump.txt" },
            new { Role = "c_pseudocode", Name = "13_function_dump.txt" },
            new { Role = "classes", Name = "04_classes.txt" },
            new { Role = "imports", Name = "02_imports.txt" }
        })
        {
            object recordObject;
            if (!dumpFileRecords.TryGetValue(artifact.Role, out recordObject))
            {
                continue;
            }

            var record = (Dictionary<string, object>)recordObject;
            if (!(bool)record["present"])
            {
                continue;
            }

            var expectedHash = (string)record["sha256"];
            var restoredPath = Path.Combine(restoredDirectory, artifact.Name);
            if (!File.Exists(restoredPath))
            {
                throw new FileNotFoundException("BiDi restore omitted " + artifact.Role);
            }
            var actualHash = Sha256File(restoredPath);
            if (!String.Equals(actualHash, expectedHash, StringComparison.Ordinal))
            {
                throw new InvalidDataException("BiDi round-trip hash mismatch for " + artifact.Role);
            }

            verifiedRestores++;
        }

        state.Manifest["bidi"] = NewObject(
            "reverse_run", bidiRestoreDir,
            "restored_count", verifiedRestores,
            "round_trip_verified", true);
        bidiStage["restored_count"] = verifiedRestores;
        bidiStage["round_trip_verified"] = true;
        CompleteStage(state, bidiStage, 0);
    }

    private static Dictionary<string, object> RunCommandStage(
        ExecutionState state,
        string stageName,
        string executable,
        List<string> args,
        string workingDirectory,
        string description)
    {
        var stage = BeginStage(state, stageName);
        SetStageCommand(stage, executable, args);
        SaveManifest(state);
        var exitCode = RunProcess(executable, args, workingDirectory);
        EnsureProcessSucceeded(state, exitCode, description);
        return stage;
    }

    private static void EnsureProcessSucceeded(ExecutionState state, int exitCode, string description)
    {
        if (exitCode != 0)
        {
            state.FailureCode = exitCode;
            throw new InvalidOperationException(
                description + " command exited with code " + exitCode.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static int RunProcess(string executable, IList<string> args, string workingDirectory)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false
        };
        foreach (var argument in args)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using (var process = new Process { StartInfo = startInfo })
        {
            if (!process.Start())
            {
                throw new InvalidOperationException("could not start " + executable);
            }

            process.WaitForExit();
            return process.ExitCode;
        }
    }

    private static Dictionary<string, object> BeginStage(ExecutionState state, string name)
    {
        var stage = NewObject(
            "name", name,
            "status", "running",
            "started_at", Timestamp());
        ((List<object>)state.Manifest["stages"]).Add(stage);
        state.ActiveStage = stage;
        state.Manifest["current_stage"] = name;
        SaveManifest(state);
        return stage;
    }

    private static void SetStageCommand(
        Dictionary<string, object> stage,
        string executable,
        IEnumerable<string> args)
    {
        var command = new List<string> { executable };
        command.AddRange(args);
        stage["command"] = command;
    }

    private static void CompleteStage(ExecutionState state, Dictionary<string, object> stage, int? returnCode = null)
    {
        if (returnCode.HasValue)
        {
            stage["returncode"] = returnCode.Value;
        }

        stage["status"] = "completed";
        stage["finished_at"] = Timestamp();
        state.ActiveStage = null;
        state.Manifest.Remove("current_stage");
        SaveManifest(state);
    }

    private static int HandleFailure(ExecutionState state, Exception exception)
    {
        if (state.ActiveStage != null &&
            state.ActiveStage.TryGetValue("status", out var status) &&
            String.Equals(status as string, "running", StringComparison.Ordinal))
        {
            state.ActiveStage["status"] = "failed";
            state.ActiveStage["finished_at"] = Timestamp();
            state.ActiveStage["error"] = exception.Message;
            if (state.FailureCode != 1)
            {
                state.ActiveStage["returncode"] = state.FailureCode;
            }
        }

        if (state.Manifest != null)
        {
            state.Manifest["status"] = "failed";
            state.Manifest["error"] = exception.Message;
            state.Manifest["finished_at"] = Timestamp();
            state.Manifest.Remove("current_stage");
            try
            {
                SaveManifest(state);
            }
            catch
            {
                // Keep the original failure as the reported error.
            }
        }

        Console.Error.WriteLine("COREO failed: " + exception.Message);
        return state.FailureCode;
    }

    private static void SaveManifest(ExecutionState state)
    {
        if (state.Manifest == null || String.IsNullOrEmpty(state.ManifestPath) || String.IsNullOrEmpty(state.ManifestTemp))
        {
            return;
        }

        var text = JsonSerializer.Serialize(state.Manifest, JsonOptions) + "\n";
        File.WriteAllText(state.ManifestTemp, text, Utf8);
        File.Move(state.ManifestTemp, state.ManifestPath, true);
    }

    private static void EnsureFreshOutputDirectory(string outputDir)
    {
        if (Directory.Exists(outputDir) || File.Exists(outputDir))
        {
            throw new IOException("COREO output directory already exists: " + outputDir);
        }

        var parent = Path.GetDirectoryName(outputDir);
        if (!String.IsNullOrEmpty(parent))
        {
            Directory.CreateDirectory(parent);
        }

        Directory.CreateDirectory(outputDir);
    }

    private static string FindJsc()
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (!String.IsNullOrWhiteSpace(path))
        {
            foreach (var directory in path.Split(Path.PathSeparator))
            {
                if (String.IsNullOrWhiteSpace(directory))
                {
                    continue;
                }

                var candidate = Path.Combine(directory, "jsc.exe");
                if (File.Exists(candidate))
                {
                    return Path.GetFullPath(candidate);
                }
            }
        }

        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
        {
            var windowsRoot = Environment.GetEnvironmentVariable("WINDIR");
            if (String.IsNullOrWhiteSpace(windowsRoot))
            {
                windowsRoot = @"C:\Windows";
            }

            foreach (var framework in new[]
            {
                new[] { "Framework", "v4.0.30319" },
                new[] { "Framework64", "v4.0.30319" },
                new[] { "Framework", "v2.0.50727" },
                new[] { "Framework64", "v2.0.50727" }
            })
            {
                var candidate = Path.Combine(
                    windowsRoot, "Microsoft.NET", framework[0], framework[1], "jsc.exe");
                if (File.Exists(candidate))
                {
                    return Path.GetFullPath(candidate);
                }
            }
        }

        return "";
    }

    private static string RedactedEndpointOrigin(string endpoint)
    {
        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) &&
            !String.IsNullOrEmpty(uri.Scheme) &&
            !String.IsNullOrEmpty(uri.Host))
        {
            var host = uri.IdnHost;
            if (host.IndexOf(':') >= 0 && !host.StartsWith("[", StringComparison.Ordinal))
            {
                host = "[" + host + "]";
            }

            var origin = uri.Scheme + "://" + host;
            if (!uri.IsDefaultPort)
            {
                origin += ":" + uri.Port.ToString(CultureInfo.InvariantCulture);
            }

            return origin;
        }

        return "[redacted]";
    }

    private static int ParseInteger(string value, string option)
    {
        if (!Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
        {
            throw new ArgumentException(option + " must be an integer");
        }

        return result;
    }

    private static double ParseDouble(string value, string option)
    {
        if (!Double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var result))
        {
            throw new ArgumentException(option + " must be a number");
        }

        return result;
    }

    private static string ValueOrNull(Dictionary<string, string> values, string option)
    {
        return values.ContainsKey(option) ? values[option] : null;
    }

    private static string Timestamp()
    {
        return DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    }

    private static string ReadUtf8(byte[] bytes, string path)
    {
        try
        {
            using (var reader = new StreamReader(new MemoryStream(bytes), Utf8, true))
            {
                return reader.ReadToEnd();
            }
        }
        catch (DecoderFallbackException exception)
        {
            throw new InvalidDataException("source is not valid UTF-8: " + path, exception);
        }
    }

    private static string Sha256File(string path)
    {
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(path))
        {
            return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }
    }

    private static string Sha256(byte[] bytes)
    {
        using (var sha = SHA256.Create())
        {
            return Convert.ToHexString(sha.ComputeHash(bytes)).ToLowerInvariant();
        }
    }

    private static string GetRequiredString(JsonElement element, string property, string context)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty(property, out var value) ||
            value.ValueKind != JsonValueKind.String)
        {
            throw new InvalidDataException("missing or invalid " + property + " in " + context);
        }

        return value.GetString();
    }

    private static Dictionary<string, object> NewObject(params object[] keyValues)
    {
        if (keyValues.Length % 2 != 0)
        {
            throw new ArgumentException("key/value arguments must be paired");
        }

        var result = new Dictionary<string, object>(StringComparer.Ordinal);
        for (var index = 0; index < keyValues.Length; index += 2)
        {
            result[(string)keyValues[index]] = keyValues[index + 1];
        }

        return result;
    }
}
