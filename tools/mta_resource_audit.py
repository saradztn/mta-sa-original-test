#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
#  Security & Vulnerability Research Team — White Hat Hackers
# ----------------------------------------------------------------------------
#  MTA:SA security research test bed — mta-sa-original-test
#  Internal security research material. All rights reserved by the team above.
# ============================================================================
"""
mta_resource_audit.py - static security audit for an MTA:SA *server* resource tree.

Purpose: find the mistakes that actually get MTA private servers owned, before
someone else does. The rule set follows Multi Theft Auto's own guidance
(wiki: Script security): never trust client data, validate every parameter of a
client-triggerable event, check ACL rights before privileged actions, and do not
reuse native event names for remotely triggerable events.

Scope: this only reads files. It never connects to a server, never sends a
packet, never touches a running process. Point it at a path you own:

    python3 tools/mta_resource_audit.py /path/to/mta-server/mods/deathmatch/resources

Exit codes: 0 = nothing High, 1 = at least one High finding, 2 = usage error.
Output: human report on stdout, optional JSON/Markdown with --format/--out.

Limits, stated plainly: this is pattern analysis, not a proof. A finding means
"a human must read this function"; the absence of a finding means nothing at all
about false negatives. It cannot see ACL state (read your acl.xml), runtime
values, or anything inside compiled C++.

Rules (--rules to print):
  MTA001 client-event-unvalidated     client-triggerable event reaching a
                                      sensitive call with no validation token
  MTA002 sql-string-concat            query text built by concatenation
  MTA003 dynamic-code-exec            loadstring/load/runString on data
  MTA004 path-traversal               file* with concatenated or absolute path
  MTA005 dangerous-call               os.execute/io.popen/fetchRemote on data
  MTA006 backdoor-heuristics          escaped blobs + exec, debug.*, obfuscation
  MTA007 export-without-acl           exported privileged function, no ACL check
  MTA008 native-event-shadow          remotely triggerable native event name
  MTA009 planted-binary               .dll/.exe/.so inside a resource
  MTA010 cheat-family-signature       NRTH/NVX/DARKANARCHY/Overwack markers
  MTA011 client-writable-authority    client sets element data the server trusts
  MTA012 resource-structure           missing meta.xml or missing referenced file
"""

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}

RULES = {
    "MTA001": ("High", "event قابل للتحريك من العميل يصل إلى عملية حساسة بدون تحقق",
               "client-triggerable event reaching a sensitive call without validation"),
    "MTA002": ("High", "نص استعلام SQL مبني بالدمج (حقن SQL)",
               "SQL query text built by concatenation (injection)"),
    "MTA003": ("High", "تنفيذ كود من بيانات (loadstring/load/runString)",
               "dynamic code execution on data"),
    "MTA004": ("Medium", "تعامل مع ملفات بمسار مدمج أو مطلق (تجاوز مسار)",
               "file operation with concatenated or absolute path"),
    "MTA005": ("High", "استدعاء خطير على بيانات (os.execute/io.popen/fetchRemote)",
               "dangerous call on data"),
    "MTA006": ("High", "مؤشرات باب خلفي: كتلة مُشفَّرة + تنفيذ، debug.*, تشويش",
               "backdoor heuristics: escaped blob + exec, debug.*, obfuscation"),
    "MTA007": ("High", "دالة مُصدَّرة بصلاحيات بدون فحص ACL",
               "exported privileged function without an ACL check"),
    "MTA008": ("Medium", "اسم حدث أصلي (native) صار قابلاً للتحريك من العميل",
               "native event name made remotely triggerable"),
    "MTA009": ("High", "ملف تنفيذي مزروع داخل مورد (.dll/.exe/.so)",
               "planted binary inside a resource"),
    "MTA010": ("High", "بصمات عائلة أداة الغش NRTH/NVX/DARKANARCHY",
               "cheat-family signature NRTH/NVX/DARKANARCHY"),
    "MTA011": ("Medium", "بيانات عنصر يكتبها العميل ويعتمد عليها السيرفر",
               "client-writable element data the server trusts"),
    "MTA012": ("Low", "بنية مورد ناقصة (meta.xml أو ملف مُشار إليه)",
               "resource structure: missing meta.xml or referenced file"),
}

SENSITIVE_CALLS = [
    "dbExec", "dbQuery", "dbPoll", "executeSQLQuery", "dbConnect",
    "givePlayerMoney", "takePlayerMoney", "setPlayerMoney", "setAccountData",
    "setAccountPassword", "addAccount", "removeAccount", "setPlayerMuted",
    "banPlayer", "kickPlayer", "setPlayerTeam", "setElementHealth",
    "setPedArmor", "setElementPosition", "setElementFrozen", "spawnPlayer",
    "setVehicleLocked", "setVehicleEngineState", "warpPedIntoVehicle",
    "setElementData", "setElementModel", "setPlayerWantedLevel", "giveWeapon",
    "setTimer", "createElement", "destroyElement", "setPedSkin", "setCameraTarget",
    "outputChatBox", "triggerClientEvent", "call", "fileWrite", "fileDelete",
    "setPlayerNametagText", "setPlayerName", "aclSetRight", "aclSave",
]

# Tokens that actually *check* something. Lookups (getPlayerAccount,
# getPlayerSerial, getPlayerIP) are deliberately NOT here: fetching a value or
# an account is not a validation step.
STRONG_VALIDATION = [
    "tonumber(", "type(", "assert(", "isElement(", "getElementType(",
    "isGuestAccount", "string.match(", "string.find(", "string.gsub(",
    "validate", "sanitize", "math.floor(", "math.abs(", "math.min(", "math.max(",
]
ACL_VALIDATION = ["isObjectInACLGroup", "hasObjectPermissionTo", "isPlayerInACL",
                  "aclGetGroup", "getAccountName("]
VALIDATION_TOKENS = STRONG_VALIDATION + ["client"]  # for client-triggerable events
EXPORT_VALIDATION = STRONG_VALIDATION + ACL_VALIDATION

# Calls that decide money, accounts, privileges or bans.
PRIVILEGED_CALLS = [
    "givePlayerMoney", "takePlayerMoney", "setPlayerMoney", "setAccountData",
    "setAccountPassword", "addAccount", "removeAccount", "setPlayerMuted",
    "banPlayer", "kickPlayer", "aclSetRight", "aclSave", "aclCreateGroup",
    "setPlayerTeam", "setElementHealth",
]

NATIVE_EVENTS = [
    "onPlayerChat", "onPlayerLogin", "onPlayerQuit", "onPlayerJoin",
    "onPlayerCommand", "onPlayerDamage", "onPlayerWasted", "onPlayerSpawn",
    "onPlayerClick", "onPlayerLogout", "onResourceStart", "onResourceStop",
    "onResourceStartMap", "onClientResourceStart", "onPlayerModInfo",
]

DATE_RULES = r"(?i)date\s*\(|datetime\s*\("
FILE_FUNCS = ["fileOpen", "fileRead", "fileWrite", "fileDelete", "fileCreate",
              "fileExists", "fileCopy", "fileRename", "fileGetSize", "fileFlush"]
BINARY_EXT = {".dll", ".exe", ".so", ".bat", ".cmd", ".ps1", ".vbs", ".scr",
              ".com", ".sys", ".jar", ".sh"}
LUA_EXT = {".lua"}

CHEAT_MARKERS = [
    "NVXHookProc", "DARKANARCHY", "Overwack", "MH_CreateHook", "MH_Initialize",
    "nvx_content", "XRAOUF",
    "947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861",
]

# --------------------------------------------------------------------------
# Lua-aware masking: comments become spaces, everything keeps its offsets.
# --------------------------------------------------------------------------
def long_bracket_len(text, j):
    """Length of a Lua long-bracket opener at j ('[[', '[=[', ...), else 0."""
    n = len(text)
    if j >= n or text[j] != "[":
        return 0
    k = j + 1
    eq = 0
    while k < n and text[k] == "=":
        eq += 1
        k += 1
    if k < n and text[k] == "[":
        return (k + 1) - j
    return 0


def _blank(out, a, b):
    for k in range(a, min(b, len(out))):
        if out[k] != "\n":
            out[k] = " "


def mask_lua(text):
    """Blank out Lua comments (-- and --[[ ]]) while preserving offsets/lines.

    String literal *content* is kept: rules that read event names, data keys or
    file names need it. Use code_mask() when looking for calls.
    """
    n = len(text)
    out = list(text)
    i = 0
    while i < n:
        c = text[i]
        opener = long_bracket_len(text, i)
        if opener:
            eq = opener - 2
            close = "]" + "=" * eq + "]"
            j = text.find(close, i + opener)
            i = n if j == -1 else j + len(close)
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    j += 1
                    break
                if text[j] == "\n":
                    break
                j += 1
            i = j
            continue
        if c == "-" and i + 1 < n and text[i + 1] == "-":
            opener2 = long_bracket_len(text, i + 2)
            if opener2:
                eq = opener2 - 2
                close = "]" + "=" * eq + "]"
                j = text.find(close, i + 2 + opener2)
                j = n if j == -1 else j + len(close)
            else:
                j = text.find("\n", i)
                j = n if j == -1 else j
            _blank(out, i, j)
            i = j
            continue
        i += 1
    return "".join(out)


def code_mask(text):
    """Blank comments AND every string/char literal.

    Matching a call pattern against this mask cannot be fooled by a mention of
    that call inside a string or a comment - which is exactly the difference
    between "this resource calls loadstring" and "this resource documents it".
    """
    masked = mask_lua(text)
    out = list(masked)
    n = len(masked)
    i = 0
    while i < n:
        c = masked[i]
        opener = long_bracket_len(masked, i)
        if opener:
            eq = opener - 2
            close = "]" + "=" * eq + "]"
            j = masked.find(close, i + opener)
            j = n if j == -1 else j + len(close)
            _blank(out, i, j)
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                if masked[j] == "\\":
                    j += 2
                    continue
                if masked[j] == c:
                    j += 1
                    break
                if masked[j] == "\n":
                    break
                j += 1
            _blank(out, i, j)
            i = j
            continue
        i += 1
    return "".join(out)


def first_arg_is_literal(text, paren_pos):
    """True when the first argument at the original call site is a constant."""
    i = paren_pos + 1
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n:
        return False
    return text[i] in "\"'" or text.startswith("[[", i)


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


class Finding:
    def __init__(self, rule, resource, path, line, snippet, detail):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.resource = resource
        self.path = path
        self.line = line
        self.snippet = snippet.strip()[:160]
        self.detail = detail

    def as_dict(self):
        return {
            "rule": self.rule, "severity": self.severity, "resource": self.resource,
            "file": self.path, "line": self.line, "snippet": self.snippet,
            "detail": self.detail,
            "title": RULES[self.rule][1], "title_en": RULES[self.rule][2],
        }


def iter_files(root, exts=None):
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in (".git", "cache", "__pycache__")]
        for f in files:
            if exts is None or os.path.splitext(f)[1].lower() in exts:
                yield os.path.join(base, f)


def read_text(path):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def within(text, pos, limit):
    return text[max(0, pos - limit):pos + limit]


def split_args(masked, start):
    """Split a call's argument list, starting just after its '('. Returns
    (list_of_(start,end), offset_of_closing_paren)."""
    args = []
    cur = start
    depth = 0
    i = start
    n = len(masked)
    while i < n:
        c = masked[i]
        if c in "\"'":
            quote = c
            i += 1
            while i < n:
                if masked[i] == "\\":
                    i += 2
                    continue
                if masked[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                args.append((cur, i))
                return args, i
            depth -= 1
        elif c == "," and depth == 0:
            args.append((cur, i))
            cur = i + 1
        i += 1
    args.append((cur, n))
    return args, n


def find_function_start(masked, name):
    """Offset of `function name(` or `name = function(` if present."""
    m = re.search(r"\bfunction\s+%s\s*\(" % re.escape(name), masked)
    if not m:
        m = re.search(r"\b%s\s*=\s*function\s*\(" % re.escape(name), masked)
    return m.start() if m else None


def body_after(masked, start, max_lines=80):
    """Rough body span: from `start` to the first line that begins with `end`
    at or below the indentation of the line containing `start`.

    This is deliberately not a Lua parser. It is correct for the formatting
    convention used by every MTA resource seen so far (bodies indented one
    level deeper than their opener), and it fails safe: when in doubt it
    returns a fixed window rather than pretending to know the exact end.
    """
    line_start = masked.rfind("\n", 0, start) + 1
    prefix = masked[line_start:start]
    indent = len(prefix) - len(prefix.lstrip(" \t"))
    pos = masked.find("\n", start)
    if pos == -1:
        return (start, len(masked))
    pos += 1
    line_end = pos
    for _ in range(max_lines):
        nxt = masked.find("\n", pos)
        line_end = nxt if nxt != -1 else len(masked)
        line = masked[pos:line_end]
        stripped = line.lstrip(" \t")
        this_indent = len(line) - len(stripped)
        if stripped.startswith("end") and this_indent <= indent:
            return (start, line_end)
        if nxt == -1:
            break
        pos = nxt + 1
    return (start, line_end)


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def rule_client_events(res, path, text, masked, out):
    triggered = set(m.group(1) for m in re.finditer(
        r"addEvent\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*true", masked))
    for m in re.finditer(r"addEventHandler\s*\(", masked):
        args, _end = split_args(masked, m.end())
        if len(args) < 3:
            continue
        event = masked[args[0][0]:args[0][1]].strip().strip("\"'")
        if event not in triggered:
            continue
        handler = masked[args[2][0]:args[2][1]].strip()
        hstart = args[2][0]
        if not handler.startswith("function"):
            name = handler.split(":")[-1].split(".")[-1].strip()
            hstart = find_function_start(masked, name)
            if hstart is None:
                continue
            label = name
        else:
            label = "(anonymous)"
        a, b = body_after(masked, hstart, max_lines=80)
        chunk = masked[a:b]
        if any(tok in chunk for tok in VALIDATION_TOKENS):
            continue
        for call in SENSITIVE_CALLS:
            cm = re.search(r"\b%s\s*\(" % re.escape(call), chunk)
            if cm:
                off = a + cm.start()
                ln = line_of(text, off)
                out.append(Finding("MTA001", res, path, ln,
                                   text.split("\n")[ln - 1],
                                   "event '%s' -> handler %s -> %s() with no validation "
                                   "token in the body. First statement should type-check "
                                   "every parameter and verify 'client' and the player's "
                                   "rights." % (event, label, call)))
                break
    return out


def rule_native_event_shadow(res, path, text, masked, out):
    for m in re.finditer(r"addEvent\s*\(\s*[\"']([^\"']+)[\"']\s*,\s*true", masked):
        name = m.group(1)
        if name in NATIVE_EVENTS:
            ln = line_of(text, m.start())
            out.append(Finding("MTA008", res, path, ln,
                               text.split("\n")[ln - 1],
                               "native event name '%s' registered as remotely "
                               "triggerable: a client can now spoof it. Rename your "
                               "event (e.g. myResource:%s)." % (name, name)))
    return out


def rule_sql(res, path, text, masked, code, out):
    for m in re.finditer(r"\b(dbExec|dbQuery|executeSQLQuery)\s*\(([^\n]*)", code):
        call, args = m.group(1), m.group(2)
        raw = text[m.start():m.end()]
        if ".." in args or re.search(r"string\.format\s*\(", args):
            ln = line_of(text, m.start())
            out.append(Finding("MTA002", res, path, ln, raw,
                               "%s() receives a query built at runtime. Use the '?' "
                               "placeholders that MTA supports for dbExec/dbQuery, "
                               "e.g. dbExec(handle, \"UPDATE t SET x=? WHERE id=?\", v, id)."
                               % call))
    return out


def rule_dynamic_exec(res, path, text, masked, code, out):
    for m in re.finditer(r"\b(loadstring|load|runString)\s*\(", code):
        fn = m.group(1)
        if first_arg_is_literal(text, m.end() - 1):
            continue
        ln = line_of(text, m.start())
        out.append(Finding("MTA003", res, path, ln, text.split("\n")[ln - 1],
                           "%s() runs data, not a constant. If that data crossed the "
                           "network, it is remote code execution by design." % fn))
    for m in re.finditer(r"setTimer\s*\(\s*(loadstring|[A-Za-z_][\w.]*\s*\.\.)", code):
        ln = line_of(text, m.start())
        out.append(Finding("MTA003", res, path, ln, text.split("\n")[ln - 1],
                           "setTimer() with a string/code argument instead of a function."))
    return out


SANITIZER_TOKENS = ("string.match(", "string.gsub(", "string.find(", "gsub(",
                    "assert(", "[%", "%w", "%a", "reject", "whitelist", "allowed")


def rule_files(res, path, text, masked, out):
    for fn in FILE_FUNCS:
        for m in re.finditer(r"\b%s\s*\(([^\n]{0,120})" % re.escape(fn), masked):
            args = m.group(1)
            bad = ".." in args or re.search(r"[\"'][/\\]|\.\./|[:][/\\]", args)
            if not bad:
                continue
            window = masked[max(0, m.start() - 400):m.start()]
            if any(tok in window for tok in SANITIZER_TOKENS):
                continue
            ln = line_of(text, m.start())
            out.append(Finding("MTA004", res, path, ln, text.split("\n")[ln - 1],
                               "%s() path is built at runtime or absolute. Whitelist "
                               "allowed names and reject separators, '..' and drive/"
                               "root prefixes." % fn))
    return out


def rule_dangerous(res, path, text, masked, code, out):
    patterns = [
        (r"\bos\.execute\s*\(", "os.execute() - the MTA server should never need it"),
        (r"\bio\.popen\s*\(", "io.popen() - the MTA server should never need it"),
        (r"\bio\.open\s*\(", "io.open() bypasses the MTA file API and its sandboxing"),
        (r"fetchRemote\s*\(([^\n]{0,90})", "fetchRemote() - SSRF/data-exfil vector if the URL or body is partly client-controlled"),
        (r"\bsetAccountPassword\s*\(", "setAccountPassword() reached without an ACL check"),
        (r"\baddAccount\s*\(", "addAccount() reached without an ACL check"),
    ]
    for pat, why in patterns:
        for m in re.finditer(pat, code):
            ln = line_of(text, m.start())
            out.append(Finding("MTA005", res, path, ln, text.split("\n")[ln - 1], why))
    return out


def rule_backdoor(res, path, text, masked, code, out):
    escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}", masked)) + len(re.findall(r"\\\d{1,3}", masked))
    exec_fn = bool(re.search(r"\b(loadstring|load|runString)\s*\(", code))
    long_strings = [m for m in re.finditer(r"[\"'][^\"'\n]{300,}[\"']", masked)]
    if escapes >= 12 and exec_fn:
        out.append(Finding("MTA006", res, path, 1, "%d escape sequences in this file" % escapes,
                           "escaped-byte blob together with a dynamic exec call: this is "
                           "how leaked scripts hide payloads. Decode it manually before "
                           "trusting this resource."))
    if long_strings:
        ln = line_of(text, long_strings[0].start())
        out.append(Finding("MTA006", res, path, ln, text.split("\n")[ln - 1][:120],
                           "%d string literal(s) longer than 300 chars - check for "
                           "embedded/obfuscated payload." % len(long_strings)))
    for m in re.finditer(r"\bdebug\.[a-zA-Z_]+", code):
        ln = line_of(text, m.start())
        out.append(Finding("MTA006", res, path, ln, text.split("\n")[ln - 1],
                           "debug.* in a server resource: rarely legitimate, commonly "
                           "used to hide state from server-side checks."))
    for m in re.finditer(r"_G\s*\[\s*[^\]\"']|getfenv\s*\(|_ENV\s*\[\s*[^\]\"']", code):
        ln = line_of(text, m.start())
        out.append(Finding("MTA006", res, path, ln, text.split("\n")[ln - 1],
                           "environment table indexed with a runtime key - usual "
                           "pattern for hiding a function call from greps."))
    return out


def rule_exports(res, path, text, masked, code, out, export_names):
    for name in sorted(export_names):
        start = find_function_start(masked, name)
        if start is None:
            continue
        a, b = body_after(code, start, max_lines=90)
        chunk = code[a:b]
        if any(tok in chunk for tok in ACL_VALIDATION):
            continue
        hit, sev_note = None, ""
        for call in PRIVILEGED_CALLS:
            if re.search(r"\b%s\s*\(" % re.escape(call), chunk):
                hit, sev_note = call, "privileged"
                break
        if hit is None:
            for call in SENSITIVE_CALLS:
                if re.search(r"\b%s\s*\(" % re.escape(call), chunk):
                    hit, sev_note = call, "unvalidated"
                    break
        if hit is None:
            continue
        if sev_note == "unvalidated" and any(t in chunk for t in STRONG_VALIDATION):
            continue
        ln = line_of(text, a)
        out.append(Finding("MTA007", res, path, ln, "exported function %s" % name,
                           "export '%s' performs %s() with %s. Per MTA's own guidance, an "
                           "export or admin-styled event must verify the caller's rights "
                           "(isObjectInACLGroup / hasObjectPermissionTo) and type-check "
                           "every argument; otherwise anything able to call it inherits "
                           "the privilege."
                           % (name, hit,
                              "no ACL check at all" if sev_note == "privileged"
                              else "no type validation")))
    return out


def rule_client_data(res, path, text, masked, code, out, is_client):
    for m in re.finditer(r"setElementData\s*\(([^\n]{0,160})", code):
        args = m.group(1)
        if re.search(r",\s*true\s*\)", args) and is_client:
            ln = line_of(text, m.start())
            out.append(Finding("MTA011", res, path, ln, text.split("\n")[ln - 1],
                               "client script marks this element data as client-settable "
                               "and it is stored on the element: any player can write "
                               "any value here, so the server must never use it as a "
                               "decision input."))
    if not is_client:
        for m in re.finditer(r"if[^\n]{0,120}getElementData\s*\(([^\n]{0,80})", code):
            ln = line_of(text, m.start())
            out.append(Finding("MTA011", res, path, ln, text.split("\n")[ln - 1],
                               "server decision taken from element data. If this data is "
                               "set with the 'client-settable' flag or from a client "
                               "script, it is attacker-controlled."))
    return out


def rule_cheat_markers(root, out, res_hint=None):
    for path in iter_files(root, LUA_EXT | {".xml", ".def", ".txt", ".cfg", ".md", ".json"}):
        text = read_text(path)
        for marker in CHEAT_MARKERS:
            if marker in text:
                res = res_hint or (path[len(root):].strip(os.sep).split(os.sep)[0]
                                   if path.startswith(root) else "?")
                out.append(Finding("MTA010", res, path, 1, marker,
                                   "marker '%s' found inside a server resource. This "
                                   "family is a client-side loader/hook tool; it has no "
                                   "legitimate place in server content. Treat this "
                                   "resource as compromised or leaked-and-backdoored."
                                   % marker))
    return out


def rule_binaries(root, out, res_hint=None):
    for path in iter_files(root):
        ext = os.path.splitext(path)[1].lower()
        if ext in BINARY_EXT:
            res = res_hint or (path[len(root):].strip(os.sep).split(os.sep)[0]
                               if path.startswith(root) else "?")
            out.append(Finding("MTA009", res, path, 1, os.path.basename(path),
                               "executable '%s' inside the resource tree (%d bytes). The "
                               "MTA server cannot run it; it will be shipped to players "
                               "at download time. Remove it or explain it in writing."
                               % (ext, os.path.getsize(path))))
    return out


def rule_structure(root, out):
    for name in sorted(os.listdir(root)):
        rdir = os.path.join(root, name)
        if not os.path.isdir(rdir):
            continue
        meta = os.path.join(rdir, "meta.xml")
        if not os.path.isfile(meta):
            # A plain data folder (no Lua at all, no nested resource) is not a
            # broken resource, it is just a folder. Only complain when the
            # directory actually tries to be a resource.
            has_lua = any(os.path.splitext(f)[1].lower() == ".lua"
                          for _b, _d, _fs in os.walk(rdir) for f in _fs)
            has_nested = any(os.path.isfile(os.path.join(rdir, d, "meta.xml"))
                             for d in os.listdir(rdir)
                             if os.path.isdir(os.path.join(rdir, d)))
            if not has_lua and not has_nested:
                continue
            out.append(Finding("MTA012", name, meta, 1, "(no meta.xml)",
                               "directory has no meta.xml, so it is not a valid resource "
                               "(or it is hidden content)."))
            continue
        try:
            tree = ET.parse(meta)
        except ET.ParseError as exc:
            out.append(Finding("MTA012", name, meta, 1, str(exc),
                               "meta.xml does not parse; the resource will not start."))
            continue
        for el in tree.getroot():
            src = el.get("src") or el.get("file")
            if src and not os.path.exists(os.path.join(rdir, src)):
                out.append(Finding("MTA012", name, meta, 1, src,
                                   "<%s src=\"%s\"> points at a missing file."
                                   % (el.tag, src)))
    return out


# --------------------------------------------------------------------------
# Analysis driver
# --------------------------------------------------------------------------
def analyse_resource(root, res_name):
    findings = []
    rdir = os.path.join(root, res_name)
    meta = os.path.join(rdir, "meta.xml")
    script_types = {}
    export_names = set()
    if os.path.isfile(meta):
        try:
            tree = ET.parse(meta)
            for el in tree.getroot():
                if el.tag == "script":
                    src = el.get("src")
                    if src:
                        script_types[os.path.normpath(os.path.join(rdir, src))] = el.get("type", "shared")
                elif el.tag == "export":
                    fn = el.get("function")
                    if fn:
                        export_names.add(fn)
        except ET.ParseError:
            pass

    for path in iter_files(rdir, LUA_EXT):
        text = read_text(path)
        masked = mask_lua(text)      # comments hidden, literals kept
        code = code_mask(text)       # comments and literals hidden
        is_client = script_types.get(os.path.normpath(path)) == "client"
        rule_client_events(res_name, path, text, masked, findings)
        rule_native_event_shadow(res_name, path, text, masked, findings)
        rule_sql(res_name, path, text, masked, code, findings)
        rule_dynamic_exec(res_name, path, text, masked, code, findings)
        rule_files(res_name, path, text, masked, findings)
        rule_dangerous(res_name, path, text, masked, code, findings)
        rule_backdoor(res_name, path, text, masked, code, findings)
        rule_exports(res_name, path, text, masked, code, findings, export_names)
        rule_client_data(res_name, path, text, masked, code, findings, is_client)
    return findings


def analyse(root):
    findings = []
    if not os.path.isdir(root):
        raise SystemExit("not a directory: %s" % root)
    if os.path.isfile(os.path.join(root, "meta.xml")):
        # pointed straight at one resource
        res_name = os.path.basename(root.rstrip(os.sep))
        findings += analyse_resource(os.path.dirname(root), res_name)
        rule_binaries(root, findings, res_hint=res_name)
        rule_cheat_markers(root, findings, res_hint=res_name)
        findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.resource, f.path, f.line))
        return findings
    rule_structure(root, findings)
    for name in sorted(os.listdir(root)):
        if os.path.isdir(os.path.join(root, name)):
            findings += analyse_resource(root, name)
    rule_binaries(root, findings)
    rule_cheat_markers(root, findings)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.resource, f.path, f.line))
    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def render_text(findings, root):
    lines = []
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append("MTA resource audit — %s" % root)
    lines.append("findings: %d  (%s)" % (
        len(findings),
        ", ".join("%s=%d" % (s, counts.get(s, 0)) for s in ("High", "Medium", "Low"))))
    lines.append("")
    current = None
    for f in findings:
        if f.rule != current:
            current = f.rule
            sev, ar, en = RULES[f.rule]
            lines.append("[%s] %s — %s" % (sev, f.rule, en))
        rel = os.path.relpath(f.path, root) if f.path.startswith(root) else f.path
        lines.append("  %s:%d" % (rel, f.line))
        lines.append("    %s" % f.detail)
        if f.snippet:
            lines.append("    > %s" % f.snippet)
    if not findings:
        lines.append("nothing matched the rule set. That is not a clean bill of health:")
        lines.append("read the sensitive functions yourself and check your acl.xml.")
    return "\n".join(lines)


def render_markdown(findings, root):
    lines = ["# تقرير تدقيق موارد سيرفر MTA / MTA server resource audit", "",
             "root: `%s`" % root, "", "| rule | severity | resource | file:line | note |",
             "|---|---|---|---|---|"]
    for f in findings:
        rel = os.path.relpath(f.path, root) if f.path.startswith(root) else f.path
        lines.append("| %s | %s | %s | `%s:%d` | %s |" % (
            f.rule, f.severity, f.resource, rel, f.line,
            f.detail.replace("|", "\\|")))
    if not findings:
        lines.append("| — | — | — | — | no match |")
    lines.append("")
    lines.append("هذا التحليل نمطيّ ولا يُغني عن مراجعة بشرية؛ غياب النتيجة لا يعني سلامة الكود.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Demo tree: one vulnerable resource and one fixed twin, for training runs.
# --------------------------------------------------------------------------
DEMO_BAD_META = """<meta>
    <info author="demo" name="demo_bad" version="1.0" type="gamemode"/>
    <script src="server.lua" type="server"/>
    <script src="client.lua" type="client"/>
    <export function="giveCash" type="server"/>
    <file src="payload.dll"/>
</meta>
"""

DEMO_BAD_SERVER = """local db = dbConnect("sqlite", "demo.db")

addEvent("buyItem", true)
addEventHandler("buyItem", root, function(itemId, amount)
    dbExec(db, "UPDATE players SET cash = cash - " .. amount .. " WHERE id = " .. itemId)
end)

addEvent("onPlayerChat", true)
addEventHandler("onPlayerChat", root, function(msg)
    local f = loadstring(msg)
    if f then f() end
end)

addEvent("saveNote", true)
addEventHandler("saveNote", root, function(name, body)
    local h = fileOpen("notes/" .. name, true)
    fileWrite(h, body)
    fileClose(h)
end)

addEvent("adminStuff", true)
addEventHandler("adminStuff", root, function(who, cash)
    givePlayerMoney(getPlayerFromName(who), cash)
    os.execute("echo " .. who)
end)

function giveCash(player, amount, reason)
    setAccountData(getPlayerAccount(player), "cash", amount)
    setElementData(player, "mr:reason", reason)
end

outputDebugString("\\x6c\\x6f\\x61\\x64\\x73\\x74\\x72\\x69\\x6e\\x67\\x28\\x22\\x68\\x69\\x22\\x29\\x6c\\x6f\\x61\\x64\\x73\\x74\\x72\\x69\\x6e\\x67")
"""

DEMO_BAD_CLIENT = """addEvent("clientSync", true)
local function push()
    setElementData(localPlayer, "mr:vip", true, true)
    triggerServerEvent("buyItem", localPlayer, 1, 999999)
end
"""

DEMO_GOOD_META = """<meta>
    <info author="demo" name="demo_good" version="1.0" type="gamemode"/>
    <script src="server.lua" type="server"/>
    <script src="client.lua" type="client"/>
    <export function="giveCash" type="server"/>
</meta>
"""

DEMO_GOOD_SERVER = """local db = dbConnect("sqlite", "demo.db")

addEvent("buyItem", true)
addEventHandler("buyItem", root, function(itemId, amount)
    if not client or not isElement(client) then return false end
    itemId = tonumber(itemId)
    amount = tonumber(amount)
    if not itemId or not amount or amount < 1 or amount > 10 then return false end
    dbExec(db, "UPDATE players SET cash = cash - ? WHERE id = ?", amount, itemId)
end)

addEvent("saveNote", true)
addEventHandler("saveNote", root, function(name, body)
    if not client then return false end
    if type(name) ~= "string" or type(body) ~= "string" then return false end
    name = string.match(name, "^[%w_%-]+$")
    if not name or #name > 32 then return false end
    local h = fileOpen("notes/" .. name, true)
    if h then fileWrite(h, body) fileClose(h) end
end)

addEvent("adminStuff", true)
addEventHandler("adminStuff", root, function(who, cash)
    if not client or not isObjectInACLGroup("user." .. getAccountName(getPlayerAccount(client)),
                                            aclGetGroup("Admin")) then
        return false
    end
    cash = tonumber(cash) or 0
    if cash < 0 or cash > 1000 then return false end
    givePlayerMoney(getPlayerFromName(tostring(who)), cash)
end)

function giveCash(player, amount, reason)
    if type(player) ~= "player" or not isElement(player) then return false end
    local acc = getPlayerAccount(player)
    if not acc or isGuestAccount(acc) then return false end
    if not isObjectInACLGroup("user." .. getAccountName(acc), aclGetGroup("Admin")) then
        return false
    end
    amount = tonumber(amount) or 0
    if amount < 0 then return false end
    setAccountData(acc, "cash", amount)
    setElementData(player, "mr:reason", tostring(reason))
end
"""

DEMO_GOOD_CLIENT = """local function push()
    triggerServerEvent("buyItem", localPlayer, 1, 1)
end
"""


def make_demo(target):
    """Write a two-resource demo tree (vulnerable + fixed) under `target`."""
    bad = os.path.join(target, "demo_bad")
    good = os.path.join(target, "demo_good")
    os.makedirs(os.path.join(bad, "notes"), exist_ok=True)
    os.makedirs(os.path.join(good, "notes"), exist_ok=True)
    files = [
        (os.path.join(bad, "meta.xml"), DEMO_BAD_META),
        (os.path.join(bad, "server.lua"), DEMO_BAD_SERVER),
        (os.path.join(bad, "client.lua"), DEMO_BAD_CLIENT),
        (os.path.join(good, "meta.xml"), DEMO_GOOD_META),
        (os.path.join(good, "server.lua"), DEMO_GOOD_SERVER),
        (os.path.join(good, "client.lua"), DEMO_GOOD_CLIENT),
    ]
    for path, body in files:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    # a planted binary to trip MTA009 (content is irrelevant)
    with open(os.path.join(bad, "payload.dll"), "wb") as fh:
        fh.write(b"MZ" + b"\x00" * 62)
    return target


def main():
    ap = argparse.ArgumentParser(description="Static audit of an MTA:SA resource tree.")
    ap.add_argument("root", nargs="?", help="path to mods/deathmatch/resources")
    ap.add_argument("--format", choices=("text", "json", "markdown", "md"), default="text")
    ap.add_argument("--out", help="write the report to this file as well")
    ap.add_argument("--min-severity", choices=("High", "Medium", "Low", "Info"),
                    default="Low", help="only report at or above this severity")
    ap.add_argument("--rules", action="store_true", help="print the rule set and exit")
    ap.add_argument("--make-demo", metavar="DIR",
                    help="write a demo resource tree (vulnerable + fixed) and exit")
    args = ap.parse_args()

    if args.rules:
        for rid in sorted(RULES):
            sev, ar, en = RULES[rid]
            print("%s  %-6s %s\n          %s" % (rid, sev, en, ar))
        return 0

    if args.make_demo:
        make_demo(args.make_demo)
        print("demo tree written to %s (demo_bad = vulnerable, demo_good = fixed)"
              % args.make_demo)
        return 0

    if not args.root:
        ap.error("give a resource tree, or use --rules / --make-demo")

    findings = analyse(os.path.abspath(args.root))
    floor = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= floor]

    if args.format in ("markdown", "md"):
        report = render_markdown(findings, os.path.abspath(args.root))
    elif args.format == "json":
        report = json.dumps({"root": os.path.abspath(args.root),
                             "findings": [f.as_dict() for f in findings]},
                            ensure_ascii=False, indent=2)
    else:
        report = render_text(findings, os.path.abspath(args.root))

    print(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print("\nwritten: %s" % args.out)

    return 1 if any(f.severity == "High" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
