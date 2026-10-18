open System
open System.Collections.Generic
open System.Diagnostics
open System.Globalization
open System.IO
open System.Security.Cryptography
open System.Text
open System.Text.Json
open System.Text.RegularExpressions

let runCoreo (rawArgs: string array) =
    let values = Dictionary<string, string>(StringComparer.Ordinal)
    values.["--track"] <- "BOTH"
    values.["--max-group"] <- "150"
    values.["--common"] <- "12"
    values.["--min-prefix"] <- "4"
    values.["--model"] <- "qwen2.5-coder-14b-instruct"
    values.["--url"] <- "http://127.0.0.1:1234"
    values.["--lang"] <- "C"
    values.["--mode"] <- "FORWARD"
    values.["--temp"] <- "0.0"
    values.["--python"] <- (if String.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("PYTHON")) then "python" else Environment.GetEnvironmentVariable("PYTHON"))
    let knownOptions =
        HashSet<string>(
            [|
                "--dump-root"; "--program"; "--out"; "--track"; "--mode"; "--source-run"; "--manual-groups"; "--grouper-dir"
                "--sms"; "--max-group"; "--common"; "--min-prefix"; "--overrides"; "--runtime-prefixes"
                "--crt-start"; "--model"; "--url"; "--lang"; "--jsc"; "--temp"; "--python"
            |],
            StringComparer.Ordinal
        )
    let groups = ResizeArray<string>()
    let mutable position = 0
    let mutable helpRequested = false
    let mutable manifestRef: Dictionary<string, obj> option = None
    let mutable activeStageRef: Dictionary<string, obj> option = None
    let mutable manifestPath = ""
    let mutable manifestTemp = ""
    let mutable failureCode = 1

    try
        let args =
            if rawArgs.Length > 0 && rawArgs.[0] = "--" then rawArgs.[1..]
            else rawArgs
        while position < args.Length do
            let optionName = args.[position]
            if optionName = "-h" || optionName = "--help" then
                helpRequested <- true
                position <- position + 1
            elif optionName = "--group" then
                if position + 1 >= args.Length then
                    raise (ArgumentException("--group needs a value"))
                groups.Add(args.[position + 1])
                position <- position + 2
            elif knownOptions.Contains(optionName) then
                if position + 1 >= args.Length then
                    raise (ArgumentException(optionName + " needs a value"))
                values.[optionName] <- args.[position + 1]
                position <- position + 2
            else
                raise (ArgumentException("unknown option: " + optionName))

        let mode = values.["--mode"].ToUpperInvariant()
        if mode <> "FORWARD" && mode <> "REVERSE" && mode <> "BIDI" then
            raise (ArgumentException("--mode must be FORWARD, REVERSE, or BIDI"))

        if helpRequested then
            Console.WriteLine(
                "Usage: dotnet fsi --exec coreo_pipeline.fsx -- --mode FORWARD|REVERSE|BIDI --dump-root ROOT --program NAME --out NEW_DIR [--source-run RUN_DIR] [--track BOTH|KEEP|WRAP] [--group NAME] [--lang C|C++|JScript] [--jsc PATH]"
            )
            0
        elif mode = "REVERSE" then
            for requiredOption in [| "--source-run"; "--out" |] do
                if not (values.ContainsKey(requiredOption)) then
                    raise (ArgumentException("required option missing for REVERSE mode: " + requiredOption))
            let sourceRun = Path.GetFullPath(values.["--source-run"])
            let sourceManifestPath = Path.Combine(sourceRun, "COREO_MANIFEST.json")
            if not (File.Exists(sourceManifestPath)) then
                raise (FileNotFoundException("COREO source manifest not found: " + sourceManifestPath))
            let outputDir = Path.GetFullPath(values.["--out"])
            if Directory.Exists(outputDir) || File.Exists(outputDir) then
                raise (IOException("COREO output directory already exists: " + outputDir))
            use sourceManifestStream = File.OpenRead(sourceManifestPath)
            use sourceManifestHash = SHA256.Create()
            let sourceManifestSha = Convert.ToHexString(sourceManifestHash.ComputeHash(sourceManifestStream)).ToLowerInvariant()
            let restoreItems = ResizeArray<string * string * string * string>()
            use sourceDocument = JsonDocument.Parse(File.ReadAllText(sourceManifestPath, UTF8Encoding(false)))
            let sourceFilesElement =
                sourceDocument.RootElement.GetProperty("inputs").GetProperty("ghidra_dump_files")
            let sourceFolder = Path.Combine(sourceRun, "source")
            let expectedArtifacts = [|
                "assembly", "14_Assembly_dump.txt", true
                "c_pseudocode", "13_function_dump.txt", true
                "classes", "04_classes.txt", false
                "imports", "02_imports.txt", false
            |]
            for role, basename, required in expectedArtifacts do
                let mutable recordElement = Unchecked.defaultof<JsonElement>
                if not (sourceFilesElement.TryGetProperty(role, &recordElement)) then
                    if required then
                        raise (InvalidDataException("source manifest is missing required input record: " + role))
                else
                    let present = recordElement.GetProperty("present").GetBoolean()
                    if not present && required then
                        raise (InvalidDataException("source manifest marks required input absent: " + role))
                    elif present then
                        let recordedPath = recordElement.GetProperty("staged_path").GetString()
                        if isNull recordedPath || Path.GetFileName(recordedPath) <> basename then
                            raise (InvalidDataException("source manifest has an unexpected staged path for " + role))
                        let stagedPath = Path.Combine(sourceFolder, basename)
                        if not (File.Exists(stagedPath)) then
                            raise (FileNotFoundException("preserved source artifact is missing: " + stagedPath))
                        let expectedHash = recordElement.GetProperty("sha256").GetString()
                        use inputStream = File.OpenRead(stagedPath)
                        use inputHash = SHA256.Create()
                        let actualHash = Convert.ToHexString(inputHash.ComputeHash(inputStream)).ToLowerInvariant()
                        if isNull expectedHash || actualHash <> expectedHash.ToLowerInvariant() then
                            raise (InvalidDataException("preserved source hash mismatch: " + stagedPath))
                        let originalPath = recordElement.GetProperty("source_path").GetString()
                        restoreItems.Add((role, originalPath, stagedPath, actualHash))
            if restoreItems.Count < 2 then
                raise (InvalidDataException("source manifest does not contain both required Ghidra dump files"))

            let parentDirectory = Path.GetDirectoryName(outputDir)
            if not (String.IsNullOrEmpty(parentDirectory)) then
                Directory.CreateDirectory(parentDirectory) |> ignore
            Directory.CreateDirectory(outputDir) |> ignore
            manifestPath <- Path.Combine(outputDir, "COREO_MANIFEST.json")
            manifestTemp <- Path.Combine(outputDir, "COREO_MANIFEST.json.tmp")
            let jsonOptions = JsonSerializerOptions()
            jsonOptions.WriteIndented <- true
            let utf8 = UTF8Encoding(false)
            let manifest = Dictionary<string, obj>(StringComparer.Ordinal)
            manifest.["schema_version"] <- box 1
            manifest.["coreo_version"] <- box "1"
            manifest.["mode"] <- box "REVERSE"
            manifest.["status"] <- box "running"
            manifest.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            manifest.["finished_at"] <- box null
            manifest.["source_run"] <- box sourceRun
            let inputs = Dictionary<string, obj>(StringComparer.Ordinal)
            let sourceManifestRecord = Dictionary<string, obj>(StringComparer.Ordinal)
            sourceManifestRecord.["path"] <- box sourceManifestPath
            sourceManifestRecord.["sha256"] <- box sourceManifestSha
            inputs.["source_manifest"] <- box sourceManifestRecord
            manifest.["inputs"] <- box inputs
            let stages = ResizeArray<obj>()
            manifest.["stages"] <- box stages
            manifest.["selection"] <- box (Array.empty<obj>)
            let outputs = Dictionary<string, obj>(StringComparer.Ordinal)
            let restoreFolder = Path.Combine(outputDir, "source")
            outputs.["restored_source"] <- box restoreFolder
            let restoredRecords = ResizeArray<obj>()
            outputs.["restored_files"] <- box restoredRecords
            manifest.["outputs"] <- box outputs
            manifestRef <- Some manifest
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)

            let restoreStage = Dictionary<string, obj>(StringComparer.Ordinal)
            restoreStage.["name"] <- box "restore-original-ghidra-inputs"
            restoreStage.["status"] <- box "running"
            restoreStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            stages.Add(box restoreStage)
            activeStageRef <- Some restoreStage
            manifest.["current_stage"] <- box "restore-original-ghidra-inputs"
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            Directory.CreateDirectory(restoreFolder) |> ignore
            for role, originalPath, stagedPath, expectedHash in restoreItems do
                let destination = Path.Combine(restoreFolder, Path.GetFileName(stagedPath))
                File.Copy(stagedPath, destination, false)
                use restoredStream = File.OpenRead(destination)
                use restoredHash = SHA256.Create()
                let restoredDigest = Convert.ToHexString(restoredHash.ComputeHash(restoredStream)).ToLowerInvariant()
                if restoredDigest <> expectedHash then
                    raise (InvalidDataException("restored source hash mismatch: " + destination))
                let record = Dictionary<string, obj>(StringComparer.Ordinal)
                record.["role"] <- box role
                record.["original_path"] <- box originalPath
                record.["restored_path"] <- box destination
                record.["sha256"] <- box restoredDigest
                restoredRecords.Add(box record)
            restoreStage.["restored_count"] <- box restoredRecords.Count
            restoreStage.["returncode"] <- box 0
            restoreStage.["status"] <- box "completed"
            restoreStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            activeStageRef <- None
            manifest.Remove("current_stage") |> ignore
            manifest.["status"] <- box "completed"
            manifest.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            Console.WriteLine(sprintf "COREO restored %d verified source artifact(s)." restoredRecords.Count)
            Console.WriteLine("COREO reverse manifest: " + manifestPath)
            0
        else
            for requiredOption in [| "--dump-root"; "--program"; "--out" |] do
                if not (values.ContainsKey(requiredOption)) then
                    raise (ArgumentException("required option missing: " + requiredOption))

            let programName = values.["--program"]
            if programName = "." || programName = ".." || not (Regex.IsMatch(programName, @"^[\w.-]+$")) then
                raise (ArgumentException("program must be the sanitized Ghidra dump folder name"))
            let repositoryRoot = Path.GetFullPath(__SOURCE_DIRECTORY__)
            let dumpRoot = Path.GetFullPath(values.["--dump-root"])
            if not (Directory.Exists(dumpRoot)) then
                raise (DirectoryNotFoundException("Ghidra dump root is not a directory: " + dumpRoot))

            let sourceFiles = Dictionary<string, string>(StringComparer.Ordinal)
            sourceFiles.["assembly"] <- Path.Combine(dumpRoot, programName + "_ASSEMBLY", "14_Assembly_dump.txt")
            sourceFiles.["c_pseudocode"] <- Path.Combine(dumpRoot, programName + "_C_PSEUDOCODE", "13_function_dump.txt")
            sourceFiles.["classes"] <- Path.Combine(dumpRoot, programName + "_INVENTORY", "04_classes.txt")
            sourceFiles.["imports"] <- Path.Combine(dumpRoot, programName + "_INVENTORY", "02_imports.txt")
            let requiredDumpFiles = [| "assembly"; "c_pseudocode" |]
            let missingDumpFiles = ResizeArray<string>()
            for inputName in requiredDumpFiles do
                if not (File.Exists(sourceFiles.[inputName])) then
                    missingDumpFiles.Add(sourceFiles.[inputName])
            if missingDumpFiles.Count > 0 then
                raise (FileNotFoundException("missing required PyGhidra dump file(s): " + String.Join(", ", missingDumpFiles)))

            let language = values.["--lang"]
            if language <> "C" && language <> "C++" && language <> "JScript" then
                raise (ArgumentException("--lang must be C, C++, or JScript"))
            let mutable jscPath = ""
            if language = "JScript" then
                if values.ContainsKey("--jsc") then
                    jscPath <- Path.GetFullPath(values.["--jsc"])
                else
                    let pathValue = Environment.GetEnvironmentVariable("PATH")
                    if not (String.IsNullOrWhiteSpace(pathValue)) then
                        for directory in pathValue.Split(Path.PathSeparator) do
                            if jscPath = "" && not (String.IsNullOrWhiteSpace(directory)) then
                                let candidate = Path.Combine(directory, "jsc.exe")
                                if File.Exists(candidate) then
                                    jscPath <- Path.GetFullPath(candidate)
                    if jscPath = "" && Environment.OSVersion.Platform = PlatformID.Win32NT then
                        let windowsRoot =
                            let value = Environment.GetEnvironmentVariable("WINDIR")
                            if String.IsNullOrWhiteSpace(value) then @"C:\Windows" else value
                        for framework, version in
                            [|
                                "Framework", "v4.0.30319"
                                "Framework64", "v4.0.30319"
                                "Framework", "v2.0.50727"
                                "Framework64", "v2.0.50727"
                            |] do
                            if jscPath = "" then
                                let candidate = Path.Combine(windowsRoot, "Microsoft.NET", framework, version, "jsc.exe")
                                if File.Exists(candidate) then
                                    jscPath <- candidate
                if jscPath = "" || not (File.Exists(jscPath)) then
                    raise (FileNotFoundException("JScript mode requires jsc.exe; pass --jsc or install it in a standard .NET Framework path"))
                values.["--jsc"] <- jscPath
            elif values.ContainsKey("--jsc") then
                raise (ArgumentException("--jsc can only be used with --lang JScript"))

            let configInputs = Dictionary<string, obj>(StringComparer.Ordinal)
            for optionName in [| "--manual-groups"; "--grouper-dir"; "--sms"; "--overrides"; "--jsc" |] do
                if values.ContainsKey(optionName) then
                    let configPath = Path.GetFullPath(values.[optionName])
                    let directoryInput = optionName = "--grouper-dir"
                    if directoryInput && not (Directory.Exists(configPath)) then
                        raise (DirectoryNotFoundException(optionName + " is not a directory: " + configPath))
                    if not directoryInput && not (File.Exists(configPath)) then
                        raise (FileNotFoundException(optionName + " is not a file: " + configPath))
                    values.[optionName] <- configPath
                    if directoryInput then
                        let configFiles = ResizeArray<obj>()
                        let configPaths = Directory.GetFiles(configPath, "*", SearchOption.AllDirectories)
                        Array.Sort(configPaths, StringComparer.OrdinalIgnoreCase)
                        for configFile in configPaths do
                            use configStream = File.OpenRead(configFile)
                            use sha = SHA256.Create()
                            let hash = Convert.ToHexString(sha.ComputeHash(configStream)).ToLowerInvariant()
                            let fileRecord = Dictionary<string, obj>()
                            fileRecord.["path"] <- box (Path.GetRelativePath(configPath, configFile).Replace('\\', '/'))
                            fileRecord.["sha256"] <- box hash
                            configFiles.Add(box fileRecord)
                        let record = Dictionary<string, obj>()
                        record.["path"] <- box configPath
                        record.["kind"] <- box "directory"
                        record.["files"] <- box configFiles
                        configInputs.[optionName.TrimStart([| '-' |])] <- box record
                    else
                        use configStream = File.OpenRead(configPath)
                        use sha = SHA256.Create()
                        let hash = Convert.ToHexString(sha.ComputeHash(configStream)).ToLowerInvariant()
                        let record = Dictionary<string, obj>()
                        record.["path"] <- box configPath
                        record.["kind"] <- box "file"
                        record.["sha256"] <- box hash
                        configInputs.[optionName.TrimStart([| '-' |])] <- box record

            let outputDir = Path.GetFullPath(values.["--out"])
            if Directory.Exists(outputDir) || File.Exists(outputDir) then
                raise (IOException("COREO output directory already exists: " + outputDir))
            let parentDirectory = Path.GetDirectoryName(outputDir)
            if not (String.IsNullOrEmpty(parentDirectory)) then
                Directory.CreateDirectory(parentDirectory) |> ignore
            Directory.CreateDirectory(outputDir) |> ignore

            let tracks = if values.["--track"] = "BOTH" then [| "KEEP"; "WRAP" |] else [| values.["--track"].ToUpperInvariant() |]
            let mutable invalidTrack = false
            for track in tracks do
                if track <> "KEEP" && track <> "WRAP" then
                    invalidTrack <- true
            if invalidTrack then
                raise (ArgumentException("--track must be BOTH, KEEP, or WRAP"))
            let ghidraOut = Path.Combine(outputDir, "ghidra", "OUT")
            let liteDir = Path.Combine(ghidraOut, "LITE_AC")
            let triageDir = Path.Combine(ghidraOut, "TRIAGE")
            let llmRoot = Path.Combine(outputDir, "llm")
            let sourceDir = Path.Combine(outputDir, "source")
            manifestPath <- Path.Combine(outputDir, "COREO_MANIFEST.json")
            manifestTemp <- Path.Combine(outputDir, "COREO_MANIFEST.json.tmp")

            let url = values.["--url"]
            let mutable parsedUri = Unchecked.defaultof<Uri>
            let endpointOrigin =
                if Uri.TryCreate(url, UriKind.Absolute, &parsedUri) then
                    let safeUri = UriBuilder(parsedUri)
                    safeUri.UserName <- ""
                    safeUri.Password <- ""
                    safeUri.Path <- ""
                    safeUri.Query <- ""
                    safeUri.Fragment <- ""
                    safeUri.Uri.GetLeftPart(UriPartial.Authority)
                else
                    "[redacted]"

            let jsonOptions = JsonSerializerOptions()
            jsonOptions.WriteIndented <- true
            let utf8 = UTF8Encoding(false)
            let manifest = Dictionary<string, obj>(StringComparer.Ordinal)
            manifest.["schema_version"] <- box 1
            manifest.["coreo_version"] <- box "1"
            manifest.["mode"] <- box mode
            manifest.["status"] <- box "running"
            manifest.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            manifest.["finished_at"] <- box null
            manifest.["program"] <- box programName
            manifest.["dump_root"] <- box dumpRoot
            manifest.["output_dir"] <- box outputDir
            let manifestInputs = Dictionary<string, obj>(StringComparer.Ordinal)
            let dumpFileRecords = Dictionary<string, obj>(StringComparer.Ordinal)
            manifestInputs.["ghidra_dump_files"] <- box dumpFileRecords
            manifestInputs.["config_inputs"] <- box configInputs
            manifest.["inputs"] <- box manifestInputs
            let options = Dictionary<string, obj>(StringComparer.Ordinal)
            options.["track"] <- box values.["--track"]
            options.["groups"] <- box (groups.ToArray())
            let groupingOptions = Dictionary<string, obj>(StringComparer.Ordinal)
            groupingOptions.["max_group"] <- box (Int32.Parse(values.["--max-group"], CultureInfo.InvariantCulture))
            groupingOptions.["common"] <- box (Int32.Parse(values.["--common"], CultureInfo.InvariantCulture))
            groupingOptions.["min_prefix"] <- box (Int32.Parse(values.["--min-prefix"], CultureInfo.InvariantCulture))
            groupingOptions.["manual_groups"] <- box (if values.ContainsKey("--manual-groups") then values.["--manual-groups"] else null)
            groupingOptions.["grouper_dir"] <- box (if values.ContainsKey("--grouper-dir") then values.["--grouper-dir"] else null)
            groupingOptions.["sms"] <- box (if values.ContainsKey("--sms") then values.["--sms"] else null)
            options.["grouping"] <- box groupingOptions
            let triageOptions = Dictionary<string, obj>(StringComparer.Ordinal)
            triageOptions.["overrides"] <- box (if values.ContainsKey("--overrides") then values.["--overrides"] else null)
            triageOptions.["runtime_prefixes"] <- box (if values.ContainsKey("--runtime-prefixes") then values.["--runtime-prefixes"] else null)
            triageOptions.["crt_start"] <- box (if values.ContainsKey("--crt-start") then values.["--crt-start"] else null)
            options.["triage"] <- box triageOptions
            let llmOptions = Dictionary<string, obj>(StringComparer.Ordinal)
            llmOptions.["model"] <- box values.["--model"]
            llmOptions.["url_origin"] <- box endpointOrigin
            llmOptions.["lang"] <- box language
            llmOptions.["jsc_path"] <- box (if values.ContainsKey("--jsc") then values.["--jsc"] else null)
            llmOptions.["temperature"] <- box (Double.Parse(values.["--temp"], CultureInfo.InvariantCulture))
            options.["llm"] <- box llmOptions
            manifest.["options"] <- box options
            let stages = ResizeArray<obj>()
            manifest.["stages"] <- box stages
            let selection = ResizeArray<obj>()
            manifest.["selection"] <- box selection
            let outputs = Dictionary<string, obj>(StringComparer.Ordinal)
            outputs.["ghidra"] <- box ghidraOut
            outputs.["triage"] <- box triageDir
            outputs.["llm"] <- box llmRoot
            let groupOutputs = Dictionary<string, obj>(StringComparer.Ordinal)
            outputs.["groups"] <- box groupOutputs
            manifest.["outputs"] <- box outputs
            manifestRef <- Some manifest
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)

            let inputStage = Dictionary<string, obj>(StringComparer.Ordinal)
            inputStage.["name"] <- box "stage-ghidra-inputs"
            inputStage.["status"] <- box "running"
            inputStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            stages.Add(box inputStage)
            activeStageRef <- Some inputStage
            manifest.["current_stage"] <- box "stage-ghidra-inputs"
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            Directory.CreateDirectory(sourceDir) |> ignore
            let stagedFiles = Dictionary<string, string>(StringComparer.Ordinal)
            for inputName, sourcePath in
                [|
                    "assembly", sourceFiles.["assembly"]
                    "c_pseudocode", sourceFiles.["c_pseudocode"]
                    "classes", sourceFiles.["classes"]
                    "imports", sourceFiles.["imports"]
                |] do
                if not (File.Exists(sourcePath)) then
                    let record = Dictionary<string, obj>(StringComparer.Ordinal)
                    record.["present"] <- box false
                    record.["source_path"] <- box sourcePath
                    record.["staged_path"] <- box null
                    dumpFileRecords.[inputName] <- box record
                    if inputName = "assembly" || inputName = "c_pseudocode" then
                        raise (FileNotFoundException("required Ghidra input disappeared: " + sourcePath))
                else
                    let stagedPath = Path.Combine(sourceDir, Path.GetFileName(sourcePath))
                    File.Copy(sourcePath, stagedPath, true)
                    use sourceStream = File.OpenRead(sourcePath)
                    use sourceSha = SHA256.Create()
                    let sourceHash = Convert.ToHexString(sourceSha.ComputeHash(sourceStream)).ToLowerInvariant()
                    use stagedStream = File.OpenRead(stagedPath)
                    use stagedSha = SHA256.Create()
                    let stagedHash = Convert.ToHexString(stagedSha.ComputeHash(stagedStream)).ToLowerInvariant()
                    if sourceHash <> stagedHash then
                        raise (InvalidDataException("staged input hash mismatch: " + sourcePath))
                    stagedFiles.[inputName] <- stagedPath
                    let record = Dictionary<string, obj>(StringComparer.Ordinal)
                    record.["present"] <- box true
                    record.["source_path"] <- box sourcePath
                    record.["staged_path"] <- box stagedPath
                    record.["sha256"] <- box sourceHash
                    dumpFileRecords.[inputName] <- box record
            inputStage.["status"] <- box "completed"
            inputStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            activeStageRef <- None
            manifest.Remove("current_stage") |> ignore
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)

            let pythonExe = if values.ContainsKey("--python") then values.["--python"] else "python"
            let groupingScript = Path.Combine(repositoryRoot, "ghidra_pipeline", "python_scripts", "make_full_lite_v2.py")
            let groupingCommand = ResizeArray<string>()
            groupingCommand.Add(pythonExe)
            groupingCommand.Add(groupingScript)
            groupingCommand.Add("--in")
            groupingCommand.Add(sourceDir)
            groupingCommand.Add("--out")
            groupingCommand.Add(ghidraOut)
            groupingCommand.Add("--max-group")
            groupingCommand.Add(values.["--max-group"])
            groupingCommand.Add("--common")
            groupingCommand.Add(values.["--common"])
            groupingCommand.Add("--min-prefix")
            groupingCommand.Add(values.["--min-prefix"])
            if values.ContainsKey("--manual-groups") then
                groupingCommand.Add("--groups")
                groupingCommand.Add(values.["--manual-groups"])
            if values.ContainsKey("--grouper-dir") then
                groupingCommand.Add("--grouper-dir")
                groupingCommand.Add(values.["--grouper-dir"])
            if values.ContainsKey("--sms") then
                groupingCommand.Add("--sms")
                groupingCommand.Add(values.["--sms"])
            let groupingStage = Dictionary<string, obj>(StringComparer.Ordinal)
            groupingStage.["name"] <- box "group-functions"
            groupingStage.["status"] <- box "running"
            groupingStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            groupingStage.["command"] <- box (groupingCommand.ToArray())
            stages.Add(box groupingStage)
            activeStageRef <- Some groupingStage
            manifest.["current_stage"] <- box "group-functions"
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            let groupingInfo = ProcessStartInfo()
            groupingInfo.FileName <- pythonExe
            groupingInfo.WorkingDirectory <- repositoryRoot
            groupingInfo.UseShellExecute <- false
            for argumentIndex in 1 .. groupingCommand.Count - 1 do
                groupingInfo.ArgumentList.Add(groupingCommand.[argumentIndex])
            let groupingExitCode =
                use groupingProcess = new Process()
                groupingProcess.StartInfo <- groupingInfo
                if not (groupingProcess.Start()) then
                    raise (InvalidOperationException("could not start make_full_lite_v2.py"))
                groupingProcess.WaitForExit()
                groupingProcess.ExitCode
            if groupingExitCode <> 0 then
                failureCode <- groupingExitCode
                raise (InvalidOperationException(sprintf "grouping command exited with code %d" groupingExitCode))
            if not (Directory.Exists(liteDir)) then
                raise (InvalidDataException("grouping did not create LITE_AC: " + liteDir))
            groupingStage.["returncode"] <- box 0
            groupingStage.["status"] <- box "completed"
            groupingStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            activeStageRef <- None
            manifest.Remove("current_stage") |> ignore
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)

            let triageScript = Path.Combine(repositoryRoot, "ghidra_pipeline", "python_scripts", "triage_evidence_v2.py")
            let triageCommand = ResizeArray<string>()
            triageCommand.Add(pythonExe)
            triageCommand.Add(triageScript)
            triageCommand.Add("--lite")
            triageCommand.Add(liteDir)
            triageCommand.Add("--report-dir")
            triageCommand.Add(triageDir)
            if stagedFiles.ContainsKey("imports") then
                triageCommand.Add("--imports")
                triageCommand.Add(stagedFiles.["imports"])
            else
                triageCommand.Add("--no-imports")
            if values.ContainsKey("--overrides") then
                triageCommand.Add("--overrides")
                triageCommand.Add(values.["--overrides"])
            else
                triageCommand.Add("--no-overrides")
            if values.ContainsKey("--runtime-prefixes") then
                triageCommand.Add("--runtime-prefixes")
                triageCommand.Add(values.["--runtime-prefixes"])
            if values.ContainsKey("--crt-start") then
                triageCommand.Add("--crt-start")
                triageCommand.Add(values.["--crt-start"])
            let triageStage = Dictionary<string, obj>(StringComparer.Ordinal)
            triageStage.["name"] <- box "triage-functions"
            triageStage.["status"] <- box "running"
            triageStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            triageStage.["command"] <- box (triageCommand.ToArray())
            stages.Add(box triageStage)
            activeStageRef <- Some triageStage
            manifest.["current_stage"] <- box "triage-functions"
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            let triageInfo = ProcessStartInfo()
            triageInfo.FileName <- pythonExe
            triageInfo.WorkingDirectory <- repositoryRoot
            triageInfo.UseShellExecute <- false
            for argumentIndex in 1 .. triageCommand.Count - 1 do
                triageInfo.ArgumentList.Add(triageCommand.[argumentIndex])
            let triageExitCode =
                use triageProcess = new Process()
                triageProcess.StartInfo <- triageInfo
                if not (triageProcess.Start()) then
                    raise (InvalidOperationException("could not start triage_evidence_v2.py"))
                triageProcess.WaitForExit()
                triageProcess.ExitCode
            if triageExitCode <> 0 then
                failureCode <- triageExitCode
                raise (InvalidOperationException(sprintf "triage command exited with code %d" triageExitCode))
            if not (File.Exists(Path.Combine(triageDir, "FUNCTIONS.tsv"))) then
                raise (InvalidDataException("triage did not create FUNCTIONS.tsv: " + triageDir))
            triageStage.["returncode"] <- box 0
            triageStage.["status"] <- box "completed"
            triageStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            activeStageRef <- None
            manifest.Remove("current_stage") |> ignore
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)

            let rolesScript = Path.Combine(repositoryRoot, "ghidra_pipeline", "python_scripts", "build_roles_v2.py")
            let rolesCommand =
                [|
                    pythonExe; rolesScript; "--triage"; triageDir; "--out-dir"; triageDir
                |]
            let rolesStage = Dictionary<string, obj>(StringComparer.Ordinal)
            rolesStage.["name"] <- box "build-roles-and-queues"
            rolesStage.["status"] <- box "running"
            rolesStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            rolesStage.["command"] <- box rolesCommand
            stages.Add(box rolesStage)
            activeStageRef <- Some rolesStage
            manifest.["current_stage"] <- box "build-roles-and-queues"
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            let rolesInfo = ProcessStartInfo()
            rolesInfo.FileName <- pythonExe
            rolesInfo.WorkingDirectory <- repositoryRoot
            rolesInfo.UseShellExecute <- false
            for argumentIndex in 1 .. rolesCommand.Length - 1 do
                rolesInfo.ArgumentList.Add(rolesCommand.[argumentIndex])
            let rolesExitCode =
                use rolesProcess = new Process()
                rolesProcess.StartInfo <- rolesInfo
                if not (rolesProcess.Start()) then
                    raise (InvalidOperationException("could not start build_roles_v2.py"))
                rolesProcess.WaitForExit()
                rolesProcess.ExitCode
            if rolesExitCode <> 0 then
                failureCode <- rolesExitCode
                raise (InvalidOperationException(sprintf "roles command exited with code %d" rolesExitCode))
            let queuePaths = ResizeArray<string>()
            for track in tracks do
                queuePaths.Add(Path.Combine(triageDir, "QUEUE_" + track + ".tsv"))
            let missingQueues = ResizeArray<string>()
            for queuePath in queuePaths do
                if not (File.Exists(queuePath)) then
                    missingQueues.Add(queuePath)
            if missingQueues.Count > 0 then
                raise (InvalidDataException("roles stage did not create selected queue file(s): " + String.Join(", ", missingQueues)))
            rolesStage.["returncode"] <- box 0
            rolesStage.["status"] <- box "completed"
            rolesStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            activeStageRef <- None
            manifest.Remove("current_stage") |> ignore
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)

            let selectionStage = Dictionary<string, obj>(StringComparer.Ordinal)
            selectionStage.["name"] <- box "select-queue-entries"
            selectionStage.["status"] <- box "running"
            selectionStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            stages.Add(box selectionStage)
            activeStageRef <- Some selectionStage
            manifest.["current_stage"] <- box "select-queue-entries"
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            let selected = ResizeArray<Dictionary<string, obj>>()
            let seenEntries = HashSet<string>(StringComparer.OrdinalIgnoreCase)
            let groupFilter = HashSet<string>(StringComparer.Ordinal)
            for group in groups do
                groupFilter.Add(group) |> ignore
            let requiredColumns = [| "GROUP"; "ENTRY"; "NAME"; "REASON" |]
            let groupNamePattern = Regex("^[\w.~-]+$", RegexOptions.CultureInvariant)
            let entryPattern = Regex("^[0-9a-fA-F]{8}$", RegexOptions.CultureInvariant)
            for track in tracks do
                let queuePath = Path.Combine(triageDir, "QUEUE_" + track + ".tsv")
                let queueLines = File.ReadAllLines(queuePath, utf8)
                if queueLines.Length = 0 then
                    raise (InvalidDataException("empty queue file: " + queuePath))
                let headers = queueLines.[0].TrimStart('\uFEFF').Split([| '\t' |], StringSplitOptions.None)
                let groupIndex = Array.IndexOf(headers, "GROUP")
                let entryIndex = Array.IndexOf(headers, "ENTRY")
                let nameIndex = Array.IndexOf(headers, "NAME")
                let reasonIndex = Array.IndexOf(headers, "REASON")
                if groupIndex < 0 || entryIndex < 0 || nameIndex < 0 || reasonIndex < 0 then
                    raise (InvalidDataException("invalid queue header in " + queuePath))
                for lineIndex in 1 .. queueLines.Length - 1 do
                    if not (String.IsNullOrWhiteSpace(queueLines.[lineIndex])) then
                        let fields = queueLines.[lineIndex].Split([| '\t' |], StringSplitOptions.None)
                        let highestIndex = max groupIndex (max entryIndex (max nameIndex reasonIndex))
                        if fields.Length <= highestIndex then
                            raise (InvalidDataException(sprintf "invalid row %d in %s" (lineIndex + 1) queuePath))
                        let groupName = fields.[groupIndex].Trim()
                        let entry = fields.[entryIndex].Trim()
                        if groupName = "" || groupName = "." || groupName = ".." || not (groupNamePattern.IsMatch(groupName)) then
                            raise (InvalidDataException(sprintf "invalid group on line %d in %s" (lineIndex + 1) queuePath))
                        if not (entryPattern.IsMatch(entry)) then
                            raise (InvalidDataException(sprintf "invalid ENTRY on line %d in %s" (lineIndex + 1) queuePath))
                        if groupFilter.Count = 0 || groupFilter.Contains(groupName) then
                            let identity = groupName + "\u0000" + entry.ToLowerInvariant()
                            if not (seenEntries.Add(identity)) then
                                raise (InvalidDataException(sprintf "duplicate queued function %s %s" groupName entry))
                            let row = Dictionary<string, obj>(StringComparer.Ordinal)
                            row.["group"] <- box groupName
                            row.["entry"] <- box (entry.ToLowerInvariant())
                            row.["name"] <- box (fields.[nameIndex].Trim())
                            row.["track"] <- box track
                            row.["reason"] <- box (fields.[reasonIndex].Trim())
                            row.["queue_path"] <- box queuePath
                            selected.Add(row)
            let selectedGroups = HashSet<string>(StringComparer.Ordinal)
            for item in selected do
                let groupName = item.["group"] :?> string
                selectedGroups.Add(groupName) |> ignore
                if not (Directory.Exists(Path.Combine(liteDir, groupName))) then
                    raise (InvalidDataException("selected group is missing from LITE_AC: " + Path.Combine(liteDir, groupName)))
            for item in selected do
                selection.Add(box item)
            selectionStage.["selected_count"] <- box selected.Count
            selectionStage.["tracks"] <- box tracks
            selectionStage.["groups"] <- box (groups.ToArray())
            selectionStage.["status"] <- box "completed"
            selectionStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            activeStageRef <- None
            manifest.Remove("current_stage") |> ignore
            if selected.Count = 0 then
                manifest.["note"] <- box "No KEEP/WRAP queue entries matched; blueprint and LLM stages were skipped."
                File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
                File.Move(manifestTemp, manifestPath, true)
                Console.WriteLine(manifest.["note"] :?> string)
            else
                File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
                File.Move(manifestTemp, manifestPath, true)
                let byGroup = Dictionary<string, ResizeArray<Dictionary<string, obj>>>(StringComparer.Ordinal)
                for item in selected do
                    let groupName = item.["group"] :?> string
                    if not (byGroup.ContainsKey(groupName)) then
                        byGroup.[groupName] <- ResizeArray<Dictionary<string, obj>>()
                    byGroup.[groupName].Add(item)
                let groupNames = byGroup.Keys |> Seq.toArray
                Array.Sort(groupNames, StringComparer.OrdinalIgnoreCase)
                let blueprintScript = Path.Combine(repositoryRoot, "llm_pipeline", "blueprint_v3.py")
                let runnerScript = Path.Combine(repositoryRoot, "llm_pipeline", "run_blueprint_llm_v3.py")
                let modelSlug = Regex.Replace(values.["--model"].Trim(), "[^\w.-]+", "_").Trim([| '.'; '_' |])
                let safeModelSlug = if modelSlug = "" then "model" else modelSlug
                for groupName in groupNames do
                    let entries = byGroup.[groupName]
                    let groupDir = Path.Combine(liteDir, groupName)
                    let groupOutput = Path.Combine(llmRoot, groupName)
                    let entriesFile = Path.Combine(groupOutput, "SELECTED_ENTRIES.txt")
                    let blueprintDir = Path.Combine(groupOutput, "BLUEPRINT_v3")
                    let runDir = Path.Combine(groupOutput, "RUN1_v3_" + safeModelSlug)
                    let blueprintStage = Dictionary<string, obj>(StringComparer.Ordinal)
                    blueprintStage.["name"] <- box ("generate-blueprints:" + groupName)
                    blueprintStage.["status"] <- box "running"
                    blueprintStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
                    stages.Add(box blueprintStage)
                    activeStageRef <- Some blueprintStage
                    manifest.["current_stage"] <- box blueprintStage.["name"]
                    Directory.CreateDirectory(groupOutput) |> ignore
                    let entryLines = Array.zeroCreate<string> entries.Count
                    for entryIndex in 0 .. entries.Count - 1 do
                        entryLines.[entryIndex] <- entries.[entryIndex].["entry"] :?> string
                    File.WriteAllLines(entriesFile, entryLines, utf8)
                    let groupOutputRecord = Dictionary<string, obj>(StringComparer.Ordinal)
                    groupOutputRecord.["selected_entries_file"] <- box entriesFile
                    groupOutputRecord.["blueprints"] <- box blueprintDir
                    groupOutputRecord.["llm_run"] <- box runDir
                    let selectedEntryNames = Array.zeroCreate<string> entries.Count
                    for entryIndex in 0 .. entries.Count - 1 do
                        selectedEntryNames.[entryIndex] <- entries.[entryIndex].["entry"] :?> string
                    groupOutputRecord.["selected_entries"] <- box selectedEntryNames
                    groupOutputs.[groupName] <- box groupOutputRecord
                    let blueprintCommand = [|
                        pythonExe; blueprintScript; "--group"; groupDir; "--index-dir"; liteDir
                        "--out"; blueprintDir; "--entries-file"; entriesFile
                    |]
                    blueprintStage.["command"] <- box blueprintCommand
                    File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
                    File.Move(manifestTemp, manifestPath, true)
                    let blueprintInfo = ProcessStartInfo()
                    blueprintInfo.FileName <- pythonExe
                    blueprintInfo.WorkingDirectory <- repositoryRoot
                    blueprintInfo.UseShellExecute <- false
                    for argumentIndex in 1 .. blueprintCommand.Length - 1 do
                        blueprintInfo.ArgumentList.Add(blueprintCommand.[argumentIndex])
                    let blueprintExitCode =
                        use blueprintProcess = new Process()
                        blueprintProcess.StartInfo <- blueprintInfo
                        if not (blueprintProcess.Start()) then
                            raise (InvalidOperationException("could not start blueprint_v3.py"))
                        blueprintProcess.WaitForExit()
                        blueprintProcess.ExitCode
                    if blueprintExitCode <> 0 then
                        failureCode <- blueprintExitCode
                        raise (InvalidOperationException(sprintf "blueprint command exited with code %d" blueprintExitCode))
                    let checkFiles = Directory.GetFiles(blueprintDir, "*.check.json")
                    let blueprintFiles = Directory.GetFiles(blueprintDir, "*.blueprint.txt")
                    let checkStems = HashSet<string>(StringComparer.Ordinal)
                    let blueprintStems = HashSet<string>(StringComparer.Ordinal)
                    for file in checkFiles do
                        let stem = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(file))
                        checkStems.Add(stem) |> ignore
                    for file in blueprintFiles do
                        let stem = Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(file))
                        blueprintStems.Add(stem) |> ignore
                    if not (checkStems.SetEquals(blueprintStems)) then
                        raise (InvalidDataException("blueprint and check files do not have matching names"))
                    let observedEntries = HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    for checkPath in checkFiles do
                        use document = JsonDocument.Parse(File.ReadAllText(checkPath, utf8))
                        if document.RootElement.ValueKind <> JsonValueKind.Object then
                            raise (InvalidDataException("check file root is not an object: " + checkPath))
                        let entry = document.RootElement.GetProperty("entry").GetString()
                        if isNull entry || not (entryPattern.IsMatch(entry)) then
                            raise (InvalidDataException("check file has an invalid entry: " + checkPath))
                        if not (observedEntries.Add(entry.ToLowerInvariant())) then
                            raise (InvalidDataException("duplicate blueprint generated for entry " + entry))
                    let expectedEntries = HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    for item in entries do
                        expectedEntries.Add(item.["entry"] :?> string) |> ignore
                    if not (observedEntries.SetEquals(expectedEntries)) then
                        raise (InvalidDataException("blueprint entry set does not match the selected queues"))
                    if checkFiles.Length <> entries.Count || blueprintFiles.Length <> entries.Count then
                        raise (InvalidDataException("blueprint/check file count does not match selected queue entries"))
                    blueprintStage.["returncode"] <- box 0
                    blueprintStage.["blueprint_count"] <- box blueprintFiles.Length
                    blueprintStage.["status"] <- box "completed"
                    blueprintStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
                    activeStageRef <- None
                    manifest.Remove("current_stage") |> ignore
                    File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
                    File.Move(manifestTemp, manifestPath, true)

                    let runnerCommandBuffer = ResizeArray<string>()
                    runnerCommandBuffer.Add(pythonExe)
                    runnerCommandBuffer.Add(runnerScript)
                    runnerCommandBuffer.Add("--bp")
                    runnerCommandBuffer.Add(blueprintDir)
                    runnerCommandBuffer.Add("--out")
                    runnerCommandBuffer.Add(runDir)
                    runnerCommandBuffer.Add("--model")
                    runnerCommandBuffer.Add(values.["--model"])
                    runnerCommandBuffer.Add("--url")
                    runnerCommandBuffer.Add(values.["--url"])
                    runnerCommandBuffer.Add("--lang")
                    runnerCommandBuffer.Add(language)
                    runnerCommandBuffer.Add("--temp")
                    runnerCommandBuffer.Add(values.["--temp"])
                    if language = "JScript" then
                        runnerCommandBuffer.Add("--jsc")
                        runnerCommandBuffer.Add(jscPath)
                    let runnerCommand = runnerCommandBuffer.ToArray()
                    let recordedRunnerCommand = Array.copy runnerCommand
                    let urlIndex = Array.IndexOf(recordedRunnerCommand, "--url")
                    if urlIndex >= 0 && urlIndex + 1 < recordedRunnerCommand.Length then
                        recordedRunnerCommand.[urlIndex + 1] <- endpointOrigin
                    let runnerStage = Dictionary<string, obj>(StringComparer.Ordinal)
                    runnerStage.["name"] <- box ("run-llm:" + groupName)
                    runnerStage.["status"] <- box "running"
                    runnerStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
                    runnerStage.["command"] <- box recordedRunnerCommand
                    stages.Add(box runnerStage)
                    activeStageRef <- Some runnerStage
                    manifest.["current_stage"] <- box runnerStage.["name"]
                    File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
                    File.Move(manifestTemp, manifestPath, true)
                    let runnerInfo = ProcessStartInfo()
                    runnerInfo.FileName <- pythonExe
                    runnerInfo.WorkingDirectory <- repositoryRoot
                    runnerInfo.UseShellExecute <- false
                    for argumentIndex in 1 .. runnerCommand.Length - 1 do
                        runnerInfo.ArgumentList.Add(runnerCommand.[argumentIndex])
                    let runnerExitCode =
                        use runnerProcess = new Process()
                        runnerProcess.StartInfo <- runnerInfo
                        if not (runnerProcess.Start()) then
                            raise (InvalidOperationException("could not start run_blueprint_llm_v3.py"))
                        runnerProcess.WaitForExit()
                        runnerProcess.ExitCode
                    if runnerExitCode <> 0 then
                        failureCode <- runnerExitCode
                        raise (InvalidOperationException(sprintf "LLM runner exited with code %d" runnerExitCode))
                    let resultsPath = Path.Combine(runDir, "RESULTS.txt")
                    if not (File.Exists(resultsPath)) then
                        raise (InvalidDataException("LLM runner did not write RESULTS.txt: " + resultsPath))
                    let resultLines = ResizeArray<string>()
                    for line in File.ReadAllLines(resultsPath, utf8) do
                        if not (String.IsNullOrEmpty(line)) then
                            resultLines.Add(line)
                    if resultLines.Count <> entries.Count then
                        raise (InvalidDataException(sprintf "LLM result count %d does not match selected entry count %d" resultLines.Count entries.Count))
                    let mutable passCount = 0
                    let mutable failCount = 0
                    for line in resultLines do
                        if line.StartsWith("PASS\t", StringComparison.Ordinal) then
                            passCount <- passCount + 1
                        elif line.StartsWith("FAIL\t", StringComparison.Ordinal) then
                            failCount <- failCount + 1
                        else
                            raise (InvalidDataException("LLM runner wrote an unrecognized result row"))
                    let resultSummary = Dictionary<string, obj>(StringComparer.Ordinal)
                    resultSummary.["result_count"] <- box resultLines.Count
                    resultSummary.["pass_count"] <- box passCount
                    resultSummary.["fail_count"] <- box failCount
                    runnerStage.["result_count"] <- box resultLines.Count
                    runnerStage.["pass_count"] <- box passCount
                    runnerStage.["fail_count"] <- box failCount
                    runnerStage.["returncode"] <- box 0
                    runnerStage.["status"] <- box "completed"
                    runnerStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
                    activeStageRef <- None
                    manifest.Remove("current_stage") |> ignore
                    groupOutputRecord.["result_summary"] <- box resultSummary
                    File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
                    File.Move(manifestTemp, manifestPath, true)
            if mode = "BIDI" then
                let bidiRestoreDir = Path.Combine(outputDir, "BIDI_RESTORE")
                let scriptPath = Path.Combine(repositoryRoot, "coreo_pipeline.fsx")
                let bidiCommand = [|
                    "dotnet"; "fsi"; "--quiet"; "--exec"; scriptPath; "--"
                    "--mode"; "REVERSE"; "--source-run"; outputDir; "--out"; bidiRestoreDir
                    "--python"; pythonExe
                |]
                let bidiStage = Dictionary<string, obj>(StringComparer.Ordinal)
                bidiStage.["name"] <- box "bidi-reverse-source"
                bidiStage.["status"] <- box "running"
                bidiStage.["started_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
                bidiStage.["command"] <- box bidiCommand
                stages.Add(box bidiStage)
                activeStageRef <- Some bidiStage
                manifest.["current_stage"] <- box "bidi-reverse-source"
                File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
                File.Move(manifestTemp, manifestPath, true)
                let bidiInfo = ProcessStartInfo()
                bidiInfo.FileName <- "dotnet"
                bidiInfo.WorkingDirectory <- repositoryRoot
                bidiInfo.UseShellExecute <- false
                for argumentIndex in 1 .. bidiCommand.Length - 1 do
                    bidiInfo.ArgumentList.Add(bidiCommand.[argumentIndex])
                let bidiExitCode =
                    use bidiProcess = new Process()
                    bidiProcess.StartInfo <- bidiInfo
                    if not (bidiProcess.Start()) then
                        raise (InvalidOperationException("could not start the COREO reverse pass"))
                    bidiProcess.WaitForExit()
                    bidiProcess.ExitCode
                if bidiExitCode <> 0 then
                    failureCode <- bidiExitCode
                    raise (InvalidOperationException(sprintf "COREO reverse pass exited with code %d" bidiExitCode))
                let reverseManifestPath = Path.Combine(bidiRestoreDir, "COREO_MANIFEST.json")
                if not (File.Exists(reverseManifestPath)) then
                    raise (InvalidDataException("COREO reverse pass did not write its manifest"))
                use reverseDocument = JsonDocument.Parse(File.ReadAllText(reverseManifestPath, utf8))
                if reverseDocument.RootElement.GetProperty("status").GetString() <> "completed"
                   || reverseDocument.RootElement.GetProperty("mode").GetString() <> "REVERSE" then
                    raise (InvalidDataException("COREO reverse pass did not complete"))
                let restoredDirectory = Path.Combine(bidiRestoreDir, "source")
                let mutable verifiedRestores = 0
                for role, basename in
                    [|
                        "assembly", "14_Assembly_dump.txt"
                        "c_pseudocode", "13_function_dump.txt"
                        "classes", "04_classes.txt"
                        "imports", "02_imports.txt"
                    |] do
                    if dumpFileRecords.ContainsKey(role) then
                        let inputRecord = dumpFileRecords.[role] :?> Dictionary<string, obj>
                        if inputRecord.["present"] :?> bool then
                            let expectedHash = inputRecord.["sha256"] :?> string
                            let restoredPath = Path.Combine(restoredDirectory, basename)
                            if not (File.Exists(restoredPath)) then
                                raise (FileNotFoundException("BiDi restore omitted " + role))
                            use restoredStream = File.OpenRead(restoredPath)
                            use restoredHash = SHA256.Create()
                            let actualHash = Convert.ToHexString(restoredHash.ComputeHash(restoredStream)).ToLowerInvariant()
                            if actualHash <> expectedHash then
                                raise (InvalidDataException("BiDi round-trip hash mismatch for " + role))
                            verifiedRestores <- verifiedRestores + 1
                let bidiSummary = Dictionary<string, obj>(StringComparer.Ordinal)
                bidiSummary.["reverse_run"] <- box bidiRestoreDir
                bidiSummary.["restored_count"] <- box verifiedRestores
                bidiSummary.["round_trip_verified"] <- box true
                manifest.["bidi"] <- box bidiSummary
                bidiStage.["restored_count"] <- box verifiedRestores
                bidiStage.["round_trip_verified"] <- box true
                bidiStage.["returncode"] <- box 0
                bidiStage.["status"] <- box "completed"
                bidiStage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
                activeStageRef <- None
                manifest.Remove("current_stage") |> ignore
            manifest.["status"] <- box "completed"
            manifest.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            File.WriteAllText(manifestTemp, JsonSerializer.Serialize(manifest, jsonOptions) + Environment.NewLine, utf8)
            File.Move(manifestTemp, manifestPath, true)
            Console.WriteLine(sprintf "COREO completed for %d selected function(s)." selected.Count)
            Console.WriteLine("COREO manifest: " + manifestPath)
            0
    with ex ->
        match activeStageRef with
        | Some stage when stage.["status"] :?> string = "running" ->
            stage.["status"] <- box "failed"
            stage.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            stage.["error"] <- box ex.Message
            if failureCode <> 1 then
                stage.["returncode"] <- box failureCode
        | _ -> ()
        match manifestRef with
        | Some failedManifest ->
            failedManifest.["status"] <- box "failed"
            failedManifest.["error"] <- box ex.Message
            failedManifest.["finished_at"] <- box (DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture))
            if failedManifest.ContainsKey("current_stage") then
                failedManifest.Remove("current_stage") |> ignore
            if manifestPath <> "" && manifestTemp <> "" then
                File.WriteAllText(manifestTemp, JsonSerializer.Serialize(failedManifest, JsonSerializerOptions(WriteIndented = true)) + Environment.NewLine, UTF8Encoding(false))
                File.Move(manifestTemp, manifestPath, true)
        | None -> ()
        Console.Error.WriteLine("COREO failed: " + ex.Message)
        failureCode

Environment.Exit(runCoreo (fsi.CommandLineArgs |> Array.skip 1))
