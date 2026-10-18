# Copyright 2026 Ryu116 (also known as HappyTotoro116)
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0

r"""run_blueprint_llm_v3.py (v2 + return-value check) - sends each BLUEPRINT to a local LLM (LM Studio), checks C/C++ or JScript.NET output, retries once.

Usage:  python .\run_blueprint_llm_v3.py --bp ".\G_<GroupName>\BLUEPRINT_v3" --out ".\G_<GroupName>\RUN1_v3_<model>" [--model NAME] [--url http://127.0.0.1:1234] [--lang C|C++|JScript] [--jsc PATH]
Needs : *.blueprint.txt and *.check.json from blueprint_v3.py; LM Studio server running with the model loaded.
Writes: <out>\ALL_OUTPUT.txt   results + all code in ONE file (upload this one)
        <out>\RESULTS.txt      one line per function: PASS/FAIL, tries, seconds, tokens, reasons
        <out>\C\ (or CPP\)    the code files, one per function
        <out>\CHECKS\         PASS/FAIL + reasons, one per function
JScript mode writes `.js` source and compiles a `.NET` `.exe` with jsc.exe; it never runs the executable.
Checks (text checks plus the applicable compiler gate): function name present; every must_call / must_use_global / must_use_string
appears exactly as named; names FUN_xxxxxxxx / DAT_xxxxxxxx that are NOT in the blueprint are flagged as invented.
The LLM is free in style and structure; only these facts are enforced."""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--bp", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--model", default="qwen2.5-coder-14b-instruct")
ap.add_argument("--url", default="http://127.0.0.1:1234")
ap.add_argument("--lang", default="C", choices=["C", "C++", "JScript"])
ap.add_argument("--jsc", default=None, help="path to jsc.exe when --lang JScript")
ap.add_argument("--temp", type=float, default=0.0)
a = ap.parse_args()
JSC = None
if a.lang == "JScript":
    if a.jsc:
        JSC = os.path.abspath(a.jsc)
    else:
        JSC = shutil.which("jsc.exe") or shutil.which("jsc")
        if not JSC and os.name == "nt":
            windows_root = os.environ.get("WINDIR", r"C:\Windows")
            for framework, version in (
                    ("Framework", "v4.0.30319"),
                    ("Framework64", "v4.0.30319"),
                    ("Framework", "v2.0.50727"),
                    ("Framework64", "v2.0.50727")):
                candidate = os.path.join(windows_root, "Microsoft.NET", framework, version, "jsc.exe")
                if os.path.isfile(candidate):
                    JSC = candidate
                    break
    if not JSC or not os.path.isfile(JSC):
        ap.error("JScript mode requires jsc.exe; pass --jsc or install it in a standard .NET Framework path")
elif a.jsc:
    ap.error("--jsc can only be used with --lang JScript")

CODE_DIR = os.path.join(a.out, {"C": "C", "C++": "CPP", "JScript": "JSCRIPT"}[a.lang])
CHK_DIR = os.path.join(a.out, "CHECKS")
NET_DIR = os.path.join(a.out, "NET") if a.lang == "JScript" else None
for _d in (a.out, CODE_DIR, CHK_DIR, NET_DIR):
    if _d is None:
        continue
    os.makedirs(_d, exist_ok=True)

if a.lang == "JScript":
    SYSTEM_PROMPT = (
        "You are a careful JScript.NET programmer translating one function from a 32-bit Windows native-code BLUEPRINT. "
        "This target is Microsoft JScript.NET compiled by jsc.exe to a .NET executable; it is not Java or JVM bytecode. "
        "Write one complete JScript.NET function that preserves the BLUEPRINT FACTS. "
        "Use syntax accepted by the legacy jsc.exe compiler: use var, function declarations, ordinary loops and conditionals; "
        "do not use let, const, arrow functions, template strings, modules, #include, C declarations or prototypes. "
        "Do not invent FUN_/DAT_ names or leave raw x86 register names or assembly labels in the function. "
        "The original function name may be included in a comment if it is not a legal JScript identifier. "
        "Use every required callee, global and string by name when possible. "
        "Write a leading comment with Purpose: Inferred:, Args:, Returns:, Globals: and Calls:. "
        "Answer with one code block only, no explanation."
    )
else:
    SYSTEM = ("You are a careful C/C++ programmer reconstructing source code of a 32-bit Windows program. "
              "You get a BLUEPRINT made by a tool that read the machine code. The FACTS in it are exact. "
              "Write the complete function in %s. You are free to choose variable names, structure and comments. "
              "Rules you must follow: use every callee, global and string named in the FACTS with exactly that name; "
              "do NOT write #include lines, extern lines or function prototypes: the DECLARATIONS section is added to your code automatically; "
              "do not invent other FUN_/DAT_ names; do not use raw register names (eax, esp, ...) or goto labels: write normal structured C "
              "(if/else/while/for) with meaningful variable names, and use a local array for the stack frame; "
              "if the Ghidra C hint disagrees with the FACTS, trust the FACTS. "
              "When the PSEUDO section says it is complete, your code must do exactly that, in that order (same operations, same operands). "
              "If the BLUEPRINT has a CHECKLIST, it lists what the finished function must contain. "
              "Write only the function itself (with its header comment). "
              "Start the function with a header comment block for a human reader, with these lines: "
              "Purpose: (one or two plain sentences; this line is your interpretation, so begin it with 'Inferred:'), "
              "Args: (each argument and its meaning), Returns: (what the value is), "
              "Globals: (each global, whether it is read or written), Calls: (each function it calls, and why, if clear). "
              "Answer with one code block only, no explanation.")
    SYSTEM_PROMPT = SYSTEM % a.lang


PROG = {"i": 0, "n": 0, "name": "", "try": 1, "t0": 0.0, "last": 0.0, "done_secs": 0.0}
TOK = [0]


def show(ntok, t_ask, force=False):
    now = time.perf_counter()
    if not force and now - PROG["last"] < 0.4:
        return
    PROG["last"] = now
    el = now - PROG["t0"]
    finished = PROG["i"] - 1
    pct = 100.0 * finished / max(1, PROG["n"])
    rate = ntok / max(0.001, now - t_ask)
    eta = ""
    if finished > 0:
        avg = PROG["done_secs"] / finished
        left = max(0.0, avg * (PROG["n"] - finished) - el)
        eta = "  ETA %d:%02d" % (left // 60, left % 60)
    line = "[%d/%d %3.0f%%] %-30s try %d  %4.0f s  %5d tok  %4.1f tok/s%s" % (
        PROG["i"], PROG["n"], pct, PROG["name"][:30], PROG["try"], el, ntok, rate, eta)
    sys.stdout.write("\r" + line + " " * 4)
    sys.stdout.flush()


def ask(user):
    msgs = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]
    url = a.url.rstrip("/") + "/v1/chat/completions"
    parts, nt, t_ask = [], 0, time.perf_counter()
    try:
        body = json.dumps({"model": a.model, "temperature": a.temp, "max_tokens": 2500, "stream": True,
                           "messages": msgs}).encode()
        resp = urllib.request.urlopen(urllib.request.Request(url, body, {"Content-Type": "application/json"}), timeout=600)
        for raw in resp:
            ln = raw.decode("utf-8", "replace").strip()
            if not ln.startswith("data:"):
                continue
            d = ln[5:].strip()
            if d == "[DONE]":
                break
            try:
                piece = (json.loads(d)["choices"][0].get("delta") or {}).get("content") or ""
            except Exception:
                continue
            if piece:
                parts.append(piece)
                nt += 1
                show(nt, t_ask)
    except (urllib.error.URLError, ConnectionError, OSError):
        if not parts:
            raise
    if parts:
        txt = "".join(parts)
        TOK[0] += nt
    else:       # server did not stream: ordinary request
        body = json.dumps({"model": a.model, "temperature": a.temp, "max_tokens": 2500, "messages": msgs}).encode()
        r = json.load(urllib.request.urlopen(urllib.request.Request(url, body, {"Content-Type": "application/json"}), timeout=600))
        txt = r["choices"][0]["message"]["content"]
        TOK[0] += int((r.get("usage") or {}).get("completion_tokens") or 0)
    show(nt, t_ask, force=True)
    m = re.search(r"```(?:[a-zA-Z+]*)\n(.*?)```", txt, re.S)
    out = (m.group(1) if m else txt)
    out = "\n".join(l for l in out.split("\n") if not l.strip().startswith("```"))
    return out.strip() + "\n"


def mask_comments(code):
    return re.sub(r"/\*.*?\*/|//[^\n]*", lambda m: re.sub(r"[^\n]", " ", m.group(0)), code, flags=re.S)


HDR = re.compile(r"^\s*(?:Purpose|Inferred|Args|Returns|Globals|Calls)\s*:", re.I)


def repair_header(code):
    """Python repair: header lines (Purpose:/Args:/...) written outside a comment are wrapped in /* */."""
    lines = code.split("\n")
    incomment, loose = False, []
    for ln in lines:
        loose.append((not incomment) and bool(HDR.match(ln)))
        for m in re.finditer(r"/\*|\*/", ln):
            incomment = (m.group(0) == "/*")
    if not any(loose):
        return code
    out, i = [], 0
    while i < len(lines):
        if loose[i]:
            j = i
            while j + 1 < len(lines) and (loose[j + 1] or (not lines[j + 1].strip() and j + 2 < len(lines) and loose[j + 2])):
                j += 1
            out.append("/*")
            out += [x.replace("*/", "* /") for x in lines[i:j + 1]]
            out.append("*/")
            i = j + 1
        else:
            out.append(lines[i])
            i += 1
    return "\n".join(out)


def fix_return(code, rf):
    """Python repair: when the assembly returns the result of callee RF, the last return must return it."""
    if not rf:
        return code
    m = mask_comments(code)
    rets = list(re.finditer(r"\breturn\b([^;]*);", m))
    if not rets:
        return code
    last = rets[-1]
    call = r"(?:\(\*env\)->)?" + re.escape(rf) + r"\s*\("
    var = None
    for am in re.finditer(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?" + call, m[:last.start()]):
        var = am.group(1)
    if var is None:
        sm = list(re.finditer(r"^([ \t]*)(" + call + r"[^;]*;)", m[:last.start()], re.M))
        if not sm:
            return code
        s0 = sm[-1]
        code = code[:s0.start()] + s0.group(1) + "int32_t ret_" + rf + " = " + code[s0.start(2):]
        var = "ret_" + rf
        m = mask_comments(code)
        rets = list(re.finditer(r"\breturn\b([^;]*);", m))
        last = rets[-1]
    if re.search(r"\b" + re.escape(var) + r"\b", last.group(1)):
        return code
    return code[:last.start()] + "return " + var + ";" + code[last.end():]


def tidy(code, chk):
    code = repair_header(code)
    if a.lang == "JScript":
        return code
    fn = chk["function"].split("::")[-1]
    code = fix_regs(code, fn)
    return fix_return(code, (chk.get("machine") or {}).get("return_from"))


def check(code, chk, bp_text):
    bad = []
    if chk["function"] not in code:
        bad.append("function name %s is missing" % chk["function"])
    jni_names = {n for n in chk["must_call"] if ("(*env)->" + n) in bp_text}
    for n in chk["must_call"]:
        if n in jni_names:
            jni_call = (r"\b" + re.escape(n) + r"\s*\(") if a.lang == "JScript" else \
                (r"->\s*" + re.escape(n) + r"\s*\(")
            if not re.search(jni_call, code):
                bad.append("missing JNI call: (*env)->" + n)
        elif not re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", code):
            bad.append("missing call/name: " + n)
    for n in chk["must_use_globals"]:
        if not re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", code):
            bad.append("missing global: " + n)
    for s in chk["must_use_strings"]:
        if s not in code:
            bad.append("missing string: " + s)
    # order: a global read after a call in the assembly must appear after that call in the code
    for callee, g in chk.get("reads_after_call", []):
        calls = [m.start() for m in re.finditer(r"(?<![\w])" + re.escape(callee) + r"\s*\(", code)]
        if calls:
            tail = code[calls[-1]:]
            if not re.search(r"(?<![\w])" + re.escape(g) + r"(?![\w])", tail):
                bad.append("%s must be used AFTER the call to %s (assembly adds/reads it after the call)" % (g, callee))
    if not re.search(r"(?:Purpose|Inferred)\s*:", code, re.S):
        bad.append("missing header comment with a Purpose/Inferred line")
    if a.lang == "JScript":
        code_without_comments = mask_comments(code)
        for register in sorted(set(re.findall(
                r"\b(?:eax|ebx|ecx|edx|esi|edi|esp|ebp|al|bl|cl|dl|ah|ax)\b",
                code_without_comments, re.I))):
            bad.append("raw register used as a JScript variable: " + register)
    else:
        for m in sorted(set(re.findall(r"\b(?:esp|ebp)\b", code))):
            if re.search(r"\b(?:int|uint\d+_t|intptr_t|uintptr_t|char|unsigned)[\w\s\*]*\b" + m + r"\b\s*(?:=|;|,)", code):
                continue        # declared as an ordinary variable: allowed
            bad.append("raw stack register used as a variable: " + m + " (use a real local array/variable)")
    # labels copied from the blueprint's LIFTED section are valid C (the structuring left them as goto); invented ones are not
    inv = sorted(set(re.findall(r"\bL_[0-9a-fA-F]{8}\b", code)) - set(re.findall(r"\bL_[0-9a-fA-F]{8}\b", bp_text)))
    if inv:
        bad.append("invented assembly labels: " + ", ".join(inv))
    if a.lang != "JScript":
        for m in sorted(set(re.findall(r"\b(?:al|cl|dl|bl|ah|ax)\b", code))):
            if not re.search(r"\b(?:int|uint\d+_t|char|unsigned)[\w\s\*]*\b" + m + r"\b", code):
                bad.append("undeclared register-name variable: " + m)

    mc = chk.get("machine")
    if mc:
        nl = len(re.findall(r"\bdo\s*\{", code)) + len(re.findall(r"\bfor\s*\(", code)) + \
            len(re.findall(r"(?<!\})\s\bwhile\s*\(", code))
        for g in re.finditer(r"goto (L_[0-9a-f]{8});", code):
            if (g.group(1) + ":") in code[:g.start()]:
                nl += 1
        if nl < mc["loops"]:
            bad.append("checklist: the blueprint has %d loops, your code has only %d (do not drop a loop)" % (mc["loops"], nl))
        for n in mc["steps"]:
            if not re.search(r"(?:\+=|\+)\s*(?:%d|0x%x)\b" % (n, n), code, re.I):
                bad.append("checklist: a pointer/index advances by %d in the blueprint; missing in your code" % n)
        rf = mc.get("return_from")
        if rf:
            mcode = mask_comments(code)
            rets = re.findall(r"\breturn\s+([^;]+);", mcode)
            if rets:
                last = re.sub(r"^\((?:[\w\s\*]+)\)\s*", "", rets[-1].strip())
                assigned = set(re.findall(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?[^;=]*?\b" + re.escape(rf) + r"\s*\(", mcode))
                if not (re.search(r"\b" + re.escape(rf) + r"\s*\(", last) or last in assigned):
                    bad.append("checklist: the function must return the result of %s (your code returns %s)" % (rf, rets[-1].strip()))
        for v in mc["cond_consts"]:
            forms = [r"0x%x\b" % v, r"\b%d\b" % v]
            if 32 <= v < 127:
                ch = chr(v)
                forms.append(re.escape("'" + ("\\" + ch if ch in "\\'" else ch) + "'"))
            if not any(re.search(f, code, re.I) for f in forms):
                bad.append("checklist: constant 0x%x is compared in the blueprint; missing in your code" % v)
    allowed = set(re.findall(r"\b(?:FUN|DAT)_[0-9a-fA-F]{8}\b", bp_text))
    for n in sorted(set(re.findall(r"\b(?:FUN|DAT)_[0-9a-fA-F]{8}\b", code)) - allowed):
        bad.append("invented name: " + n)
    return bad


REGNAMES = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "al", "bl", "cl", "dl"]
PLAINTYPE = r"(?:int32_t|uint32_t|int|unsigned int|unsigned|uint8_t|char|unsigned char)"


def fix_regs(code, fname):
    """Python repair (no LLM): register-named variables are declared exactly once, at the top of the function.
    Removes duplicate/inner declarations of eax..ebp/al..dl and adds missing ones."""
    m = re.search(r"\b" + re.escape(fname) + r"\s*\([^)]*\)\s*\{", code)
    if not m:
        return code
    head, body = code[:m.end()], code[m.end():]
    used = []
    new = []
    for ln in body.split("\n"):
        done = False
        for r in REGNAMES:
            d = re.match(r"^(\s*)" + PLAINTYPE + r"\s+" + r + r"\s*(;.*|=[^=].*)$", ln)
            if d:
                if r not in used:
                    used.append(r)
                new.append(d.group(1) + r + " " + d.group(2) if d.group(2).startswith("=") else None)
                done = True
                break
        if not done:
            new.append(ln)
    body2 = "\n".join(x for x in new if x is not None)
    for r in REGNAMES:
        if r not in used and re.search(r"(?<![\w.>])" + r + r"(?![\w(])", re.sub(r"/\*.*?\*/|//[^\n]*", "", body2, flags=re.S)):
            used.append(r)
    if not used:
        return code
    decl = ["    uint32_t %s = 0;" % r if r.startswith("e") else "    uint8_t %s = 0;" % r for r in used]
    return head + "\n    /* registers (declared once by the tool) */\n" + "\n".join(decl) + body2


def strip_decls(code, chk):
    names = list(chk["must_call"]) + list(chk["must_use_globals"])
    keep = []
    for ln in code.split("\n"):
        t = ln.strip()
        if t.startswith("#include"):
            continue
        drop = False
        for n in names:
            e = re.escape(n)
            if re.match(r"^\s*(?:extern\s+)?(?!return\b|else\b)[A-Za-z_][\w \t\*]*?[\s\*](?:__\w+\s+)?" + e + r"\s*\([^;{}=]*\)\s*;\s*$", ln) or \
               re.match(r"^\s*(?:extern\s+|static\s+)?(?!return\b|else\b)[A-Za-z_][\w \t\*]*[\s\*]" + e + r"\s*(?:\[[^\]]*\])?\s*(?:=[^;]*)?;\s*$", ln):
                drop = True
                break
        if not drop:
            keep.append(ln)
    return "\n".join(keep).strip("\n") + "\n"


def finalize(code, chk):
    if a.lang == "JScript":
        return code.strip() + "\n"
    decl = list(chk.get("declarations", ["#include <stdint.h>"]))
    for _inc in ("#include <stddef.h>", "#include <stdbool.h>"):
        if _inc not in decl:
            decl.insert(1, _inc)
    return "\n".join(decl) + "\n\n" + strip_decls(code, chk)


def compile_gate(full_code, artifact_path=None):
    """Compile-check output without executing it; JScript mode may retain the generated .NET EXE.
    Returns None for C/C++ when no gcc/cc/clang is found."""
    if a.lang == "JScript":
        d = tempfile.mkdtemp()
        try:
            source_path = os.path.join(d, "t.js")
            with open(source_path, "w", encoding="utf-8") as source:
                source.write(full_code)
            result = subprocess.run([JSC, source_path], cwd=d, capture_output=True, text=True, timeout=60)
            diagnostics = (result.stdout or "") + "\n" + (result.stderr or "")
            if result.returncode:
                errors = [line.strip() for line in diagnostics.splitlines()
                          if re.search(r"\berror\b", line, re.I)]
                return errors or ["jsc.exe exited with code %d" % result.returncode]
            if artifact_path:
                compiled_path = os.path.join(d, "t.exe")
                if not os.path.isfile(compiled_path):
                    return ["jsc.exe did not produce the expected .NET executable"]
                os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
                shutil.copy2(compiled_path, artifact_path)
            return []
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ["jsc.exe compile failed: %s" % exc]
        finally:
            shutil.rmtree(d, ignore_errors=True)
    gcc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    if not gcc:
        return None
    env_calls = sorted(set(re.findall(r"->\s*([A-Z]\w+)\s*\(", full_code)))
    stub = ("#ifndef STUB_JNI_H\n#define STUB_JNI_H\n#include <stdint.h>\n"
            "typedef void *jobject; typedef void *jstring; typedef void *jclass; typedef void *jarray;\n"
            "typedef int32_t jint; typedef int32_t jboolean; typedef int64_t jlong;\n"
            "struct JNINativeInterface_ {\n" +
            "".join("  int32_t (*%s)();\n" % n for n in env_calls) +
            "  int32_t (*_dummy)();\n};\n"
            "typedef const struct JNINativeInterface_ *JNIEnv;\n#endif\n")
    d = tempfile.mkdtemp()
    try:
        open(os.path.join(d, "jni.h"), "w").write(stub)
        open(os.path.join(d, "t.c"), "w", encoding="utf-8").write(full_code)
        cmd = [gcc, "-std=gnu11", "-fsyntax-only", "-w", "-I", d, "-D__stdcall=", "-D__cdecl=",
               "-Wno-error=int-conversion", "-Wno-error=incompatible-pointer-types", "-fmax-errors=5",
               os.path.join(d, "t.c")]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        errs = [re.sub(r"^.*t\.c:", "line ", ln).strip() for ln in r.stderr.split("\n") if " error:" in ln]
        return errs
    except Exception as e:
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


stems = sorted(f[:-len(".blueprint.txt")] for f in os.listdir(a.bp) if f.endswith(".blueprint.txt"))
if not stems:
    sys.exit("no *.blueprint.txt in " + a.bp)
results = []
combined = []
T_START = time.perf_counter()
PROG["n"] = len(stems)
for idx, st in enumerate(stems, 1):
    bp = open(os.path.join(a.bp, st + ".blueprint.txt"), encoding="utf-8").read()
    chk = json.load(open(os.path.join(a.bp, st + ".check.json"), encoding="utf-8"))
    PROG.update(i=idx, name=chk["function"], t0=time.perf_counter(), last=0.0)
    PROG["try"] = 1
    tok0 = TOK[0]
    try:
        code = tidy(ask("BLUEPRINT\n\n" + bp), chk)
        bad = check(code, chk, bp)
        cerr = compile_gate(finalize(code, chk))
        bad += ["does not compile: " + e for e in (cerr or [])]
        tries = 1
        if bad:
            PROG["try"] = 2
            code = tidy(ask("BLUEPRINT\n\n" + bp + "\nYour previous answer failed these checks:\n- " + "\n- ".join(bad) +
                       "\nFix them and answer with the complete function again. Put the header comment inside /* */. "
                       "Declare every variable you use.\n\nPrevious answer:\n" + code), chk)
            bad = check(code, chk, bp)
            cerr = compile_gate(finalize(code, chk))
            bad += ["does not compile: " + e for e in (cerr or [])]
            tries = 2
    except Exception as e:
        print("FAILED to reach the model (%s). Is LM Studio's server running?" % type(e).__name__)
        sys.exit(1)
    secs, toks = time.perf_counter() - PROG["t0"], TOK[0] - tok0
    PROG["done_secs"] += secs
    code = finalize(code, chk)
    if a.lang == "JScript":
        if not bad:
            cerr = compile_gate(code, os.path.join(NET_DIR, st + ".exe"))
            if cerr is None:
                bad.append("jsc.exe compile check was skipped")
            else:
                bad += ["does not compile to a .NET executable: " + error for error in cerr]
        compiled = "jsc.exe checked .NET output" if cerr is not None else "JSC NOT FOUND"
    else:
        compiled = "compiler-checked" if cerr is not None else "COMPILER NOT FOUND (text checks only)"
    ext = {"C": ".c", "C++": ".cpp", "JScript": ".js"}[a.lang]
    open(os.path.join(CODE_DIR, st + ext), "w", encoding="utf-8", newline="\n").write(code)
    status = "PASS" if not bad else "FAIL"
    open(os.path.join(CHK_DIR, st + ".check.txt"), "w", encoding="utf-8", newline="\n").write(
        "%s (tries %d)\n%s\n" % (status, tries, "\n".join(bad)))
    combined.append("=" * 70 + "\n%s  %s  (tries %d, %s, %.0f s, %d tokens)\n%s\n%s" % (status, chk["function"], tries, compiled, secs, toks, "\n".join("  " + b for b in bad), code))
    results.append("%s\t%s\ttries %d\t%.0f s\t%d tokens\t%s" % (status, chk["function"], tries, secs, toks, "; ".join(bad)))
    sys.stdout.write("\r" + " " * 110 + "\r")
    print(results[-1])
T_ALL = time.perf_counter() - T_START
open(os.path.join(a.out, "RESULTS.txt"), "w", encoding="utf-8", newline="\n").write("\n".join(results) + "\n")
open(os.path.join(a.out, "ALL_OUTPUT.txt"), "w", encoding="utf-8", newline="\n").write(
    "MODEL %s  LANG %s  (runner v3)  TOTAL %.0f s (%.1f min), %d tokens\n" % (a.model, a.lang, T_ALL, T_ALL / 60.0, TOK[0]) + "\n".join(combined))
p = sum(1 for r in results if r.startswith("PASS"))
print("TOTAL TIME %.0f s (%.1f min), %d generated tokens" % (T_ALL, T_ALL / 60.0, TOK[0]))
print("PASS %d / %d  = %.0f%%   FAIL %d = %.0f%%" % (p, len(results), 100.0 * p / len(results), len(results) - p, 100.0 * (len(results) - p) / len(results)))
