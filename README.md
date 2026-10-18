# ghidra-llm-pipeline

Thank you for downloading my Ghidra + LLM pipeline.

This is my first README. ASL (American Sign Language) is my first language, so my English is not perfect. I did my best.

-------------------------
----- Why I made it -----
-------------------------

I love an old PC simulation I have played since childhood, and I want to improve it under the hood.

Looking at open-source games like OpenRA and OpenTTD taught me this: a hobbyist reimplementation is not about getting the original source code. It is about building a new open-source version of the game that can load the assets of the original. Then anyone can expand it or contribute.

To do the work I use two kinds of AI together:
- Cloud AI for knowledge and advice (and for Python scripting help).
- Local LLMs for the heavy work (writing the code).

------------------------
----- The pipeline -----
------------------------

1. PyGhidra dumps the program as assembly and as C pseudocode.
2. Headers are the most important part. Each function gets a header with the functions and globals it uses.
3. Grouping: Python groups the functions that call each other into "classes".
4. Triage: Python reads the strings used by each group to guess what it is for.
5. Roles: a script lists the likely role of each class, and makes the work queues.

-------------------------------
----- The labels (triage) -----
-------------------------------

Every function gets one label. This saves a lot of time, because I do not waste effort on the big pool of OS and runtime junk.

|-----------|------------------------------------------------------------------------------------------------------------------
| Label 	| Meaning 
|-----------|------------------------------------------------------------------------------------------------------------------
| KEEP		| The game's own logic (for example the flight model, the damage model, TrackIR)
| WRAP		| Java-facing glue that calls OS or input APIs: keep the signature, write a new body. 
|			| (IL-2 1946 is an interesting engine: C++ and Java together.)
| REPLACE	| Old C runtime, allocator, thunks: the compiler or OS provides them, so a new 64-bit version does not need them 
| UNKNOWN	| Not clear: look at it by hand
|-----------|------------------------------------------------------------------------------------------------------------------

In my test program, about 44% of the functions were REPLACE, so they never needed to be converted.

--------------------------------------
----- Assembly, not C pseudocode -----
--------------------------------------

At the start I trusted the C pseudocode to have all the answers. That was naive. It is Ghidra's interpretation of the assembly,
and it guesses (variable types, lost arguments).

The assembly is the raw truth. It has no variable types, but it holds the exact behavior of each function.
So the scripts read the assembly, and turn it into a blueprint in C-like form. Ghidra's C is kept only as a hint.

-----------------------------------------------
----- LLM as a compiler, not an assembler -----
-----------------------------------------------

My early tests used the local LLMs (Qwen 2.5 Coder, DeepSeek Coder V2 Lite, Mellum 2) to read the assembly directly.
It never worked reliably. They hallucinated, because they are made to write code, not to read raw machine code.

After many failed experiments I split the work:

- Python is the assembler. It reads the assembly and writes the blueprint: exact facts, a register-level C draft and a checklist.
- The LLM is the compiler. It writes the real C freely from the blueprint.
- Python checks the answer (text checks and a real compiler) and fixes small slips.

NOTE: How Python checks the answer

- Text checks: the function name, every call, global and string from the blueprint,
  the loops, the step sizes, the compared constants, the return value, and that no
  register names or invented names are left.

- gcc compile check: the code is compiled with gcc (syntax only, nothing is run).
  This helped a lot. In an early run the text checks passed Mellum 2's answers, but
  none of them compiled, because of a header comment written outside a comment.
  gcc catches what text checks cannot see: undeclared or redeclared variables,
  wrong types, and broken braces or semicolons. A function counts as PASS only
  when the text checks and the compile are both OK. gcc does not prove the logic
  is right, so I still read the code against the blueprint.

- If a check fails, the LLM gets the list of what failed and tries once more.

- Python fixes small slips by itself, without the LLM: it declares each variable once,
  wraps loose header lines in a comment, makes the last return return the right
  result, and adds the includes and declarations.

The checklist came after I saw the LLMs fail on very long functions. It works like the checklist a pilot uses
before take-off and landing. Python writes it from the function, and checks the answer against it. In my tests the
long functions started to pass, and the runs got faster.

--------------------------------------
----- What is in this repository -----
--------------------------------------

|-------------------|---------------------------------------|---------------------------------------------
| Folder 			| What it does 							| Read 
|-------------------|---------------------------------------|---------------------------------------------
| `ghidra_pipeline`	| Dump, grouping, triage, roles 		| `ghidra_pipeline/INSTRUCTION.txt`
| `llm_pipeline` 	| Blueprints and the LLM runner (v3) 	| `llm_pipeline/INSTRUCTION_BLUEPRINT_LLM.txt`
|-------------------|---------------------------------------|---------------------------------------------

Start with `ghidra_pipeline`, then go to `llm_pipeline` when you are ready to use your local LLMs.

-----------------------
----- Quick start -----
-----------------------

First, analyze your program in PyGhidra and run `PyGhidra Scripts/decompile_full_dump.py`.
The two INSTRUCTION files explain the folder setup. Then:

First, analyze your program in PyGhidra and run `PyGhidra Scripts/decompile_full_dump.py`.
The two INSTRUCTION files explain the folder setup. Then:

```
python .\make_full_lite_v2.py --in . --out .\OUT
python .\triage_evidence_v2.py --lite .\OUT\LITE_AC
python .\build_roles_v2.py --triage .\OUT\TRIAGE

python .\blueprint_v3.py --group ".\SOURCE\LITE_AC\<GroupName>" --out ".\G_<GroupName>\BLUEPRINT_v3"
python .\run_blueprint_llm_v3.py --bp ".\G_<GroupName>\BLUEPRINT_v3" --out ".\G_<GroupName>\RUN1_v3_<model>" --model <model name>
```

You need Ghidra with PyGhidra, Python 3, LM Studio (one model loaded), gcc (recommended, used as a compile check), and the .NET SDK (`dotnet fsi`) for COREO. JScript mode additionally needs Microsoft `jsc.exe`.

------------------------------
----- COREO: both pipelines -----
------------------------------

All COREO orchestration lives in the single `runCoreo` function in `coreo_pipeline.fsx`; the F# Interactive script calls that same function. The function stays multiline to keep stage control flow and error/provenance handling readable. It composes, rather than replaces, the existing pipeline commands. First analyze the program in PyGhidra and run `ghidra_pipeline/PyGhidra Scripts/decompile_full_dump.py` as usual. That exporter runs inside Ghidra; COREO starts from its completed three-folder dump.

From the repository root, run:

```
dotnet fsi --quiet --exec .\coreo_pipeline.fsx -- --mode FORWARD --dump-root "$env:USERPROFILE\Downloads\Ghidra_Dumps" --program "<dump-folder-prefix>" --out ".\COREO_RUNS\<run-name>" --model "<loaded model name>"
```

COREO stages the source dump files without changing them, then runs grouping, triage, roles/queues, queue-filtered blueprints, and the local LLM runner in order. Both `QUEUE_KEEP.tsv` and `QUEUE_WRAP.tsv` are selected by default; use `--track KEEP` or `--track WRAP` and repeat `--group "<GroupName>"` to narrow the run. `UNKNOWN` and `REPLACE` are not automatically converted. LM Studio must be running with the requested model loaded.

The default output language remains C. Use `--lang C++` for C++, or `--lang JScript --jsc "<path to jsc.exe>"` for JScript.NET. JScript mode writes `.js` source under `JSCRIPT` and compiles a `.NET` `.exe` under `NET`; it never runs the generated executable. This JScript.NET target is not Java or JVM 1.3.1.

Each run uses a new output directory. `COREO_MANIFEST.json` records input hashes, options, selected queue rows, stage status, model settings, and output paths; server URL credentials, path, and query are redacted. Ghidra artifacts remain under `ghidra\OUT`; per-group blueprints and LLM results remain under `llm\<GroupName>`. You can still run every existing script directly as described in the two instruction files.

After LLM output is written, COREO adds language-independent `.hex` sidecars under `llm\<GroupName>\RUN1_v3_<model>\COREOAO`. In manifest selection order, each eligible current source is `M0`, with the preceding selected sources as `M1` and `M2`; the first two selections are skipped until a full history exists. The transform uses JavaScript-compatible UTF-16 code units, the fixed mask `0x3F`, and shift `3`, producing uppercase byte pairs separated by spaces:

```
v = (abs(M0[i] - M1[i]) XOR abs(M1[i] - M2[i]) XOR (M0[i] AND 0x3F)) OR 0xC0
out[i] = (v OR ((v << 3) OR (v >> 5))) AND 0xFF
```

Each sidecar has `min(M0.Length, M1.Length, M2.Length)` output bytes, using UTF-16 code-unit indices.
These sidecars are a deterministic, lossy mapping—not encryption or a reversible encoding. The original C/C++/JScript source files remain untouched, with their hashes and the three source paths recorded in the manifest. `REVERSE` and `BIDI` restore/verify the staged Ghidra dump inputs only; they do not decode or reconstruct source from `.hex`.

COREO can restore the staged Ghidra dump files from an earlier run into a new directory, checking their recorded SHA-256 hashes:

```
dotnet fsi --quiet --exec .\coreo_pipeline.fsx -- --mode REVERSE --source-run ".\COREO_RUNS\<prior-run>" --out ".\COREO_RESTORES\<restore-name>"
```

Use `--mode BIDI` with the normal `--dump-root`, `--program`, and `--out` arguments to run forward and then verify an exact restoration under `BIDI_RESTORE\source`. This inverse restores only the preserved dump artifacts; it does not reconstruct the original executable or reverse lossy LLM-generated C, C++, JScript, or .NET output.

--------------------------
----- Results so far -----
--------------------------

- One group of 6 functions from one 32-bit Windows program, three local models.
- All three models gave logically correct code (I read it against the blueprints).
  The automatic checker passed 6/6, 6/6 and 5/6.
- I keep working on it. This is the first release.

------------------
----- Limits -----
------------------

- Tested on one program only. Please try others.
- PASS means the checks and the compile are OK. It does not prove the logic is right.
- 32-bit programs only (addresses are read as 8 hex digits).
- Pointers are typed as 32-bit integers. A 64-bit build needs pointer-sized types.
- Triage labels are guesses, not proof.
- Some settings in the scripts are examples for my test program. Set them for yours.
- Please do not trust PASS alone. If you have a cloud AI such as Claude, give it the
  LLM output together with the original assembly and C pseudocode from the SOURCE
  folder, and ask it to compare them function by function. That tells you whether
  the code really passes. This is how I checked my own results. Only upload files
  you are allowed to share.

-------------------------
----- No game files -----
-------------------------

This repository has scripts and documentation only. No game files, code or data. Use it only on programs you own,
and follow the rules that apply to them.

----------------------
----- Contribute -----
----------------------

Try it on another game and tell me what worked and what did not. Ideas and
improvements are welcome.

You are free to take the scripts and improve them further. The Apache 2.0 license
lets you use, change and share them, so fork it, make your own version, and share
what you learn.

My favorite word is decentralization. For me it means community-based sharing and
support, where we improve together what we already have. I hope this brings new ideas to
hobbyist reimplementation (reverse engineering) and to LLM development.

-------------------
----- License -----
-------------------

Apache License 2.0. See `LICENSE` and `NOTICE`.

Copyright 2026 Ryu116 (also known as HappyTotoro116)
