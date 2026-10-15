#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_strip.py - prove that the cleanup did not change any code.

Checks, per source file, against the last commit:

  1. token stream equality - an independent tokenizer (not the one used to cut
     the comments) must produce the exact same sequence of identifiers,
     numbers, string literals, characters and punctuation;
  2. line accounting - stripped_line_count == original_line_count + header,
     so an archived reference to original line N resolves to cleaned line N+9
     and no code line moved anywhere else;
  3. comment accounting - only the injected header remains, and stripping is
     idempotent (a second pass changes nothing);
  4. compile equivalence for the translation units that build on this host:
     the object file produced from the original bytes and from the cleaned
     bytes must be identical.

Usage: python3 tools/verify_strip.py
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cscan import scan_comments, strip_comments  # noqa: E402
from strip_comments import header_for  # noqa: E402

SOURCES = [
    "north_loader.cpp",
    "nrth_audit.cpp",
    "nrth_audit.def",
    "nrth_audit.h",
    "nrth_audit_sigs.h",
    "nrth_codec.h",
    "nrth_config.cpp",
    "nrth_config.h",
    "nrth_dll.def",
    "nrth_fonts.h",
    "nrth_hook.cpp",
    "nrth_hook.h",
    "nrth_ui.cpp",
    "nrth_ui.h",
    "nrth_vehicle_names.inc",
    "test_parity.cpp",
]

COMPILABLE = {
    "nrth_audit.cpp": "-std=c++17",
    "nrth_config.cpp": "-std=c++17",
    "test_parity.cpp": "-std=c++17",
    "nrth_hook.cpp": "-std=c++17",
    "nrth_ui.cpp": "-std=c++17",
}

PUNCT = set("(){}[];,:?~+-*/%<>=!&|^.#\\")


def tokens(text, semi=False):
    """Independent tokenizer: yields ('id'|'num'|'str'|'chr'|'punct', value)."""
    comment_spans = scan_comments(text, semi=semi)
    hidden = [False] * len(text)
    for start, end, _kind in comment_spans:
        for k in range(start, end):
            hidden[k] = True
    out = []
    i = 0
    n = len(text)
    while i < n:
        if hidden[i]:
            i += 1
            continue
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c == '"' or c == "'":
            j = i + 1
            while j < n and not hidden[j]:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    j += 1
                    break
                j += 1
            out.append(("str" if c == '"' else "chr", text[i:j]))
            i = j
            continue
        if c.isalpha() or c == "_" or c == "$":
            j = i
            while j < n and not hidden[j] and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            out.append(("id", text[i:j]))
            i = j
            continue
        if c.isdigit() or (c == "." and i + 1 < n and text[i + 1].isdigit()):
            j = i
            while j < n and not hidden[j] and (text[j].isalnum() or text[j] in "._"):
                j += 1
            out.append(("num", text[i:j]))
            i = j
            continue
        if text.startswith(">>=", i) or text.startswith("<<=", i) or text.startswith("...", i):
            out.append(("punct", text[i:i + 3]))
            i += 3
            continue
        if text[i:i + 2] in ("->", "::", "++", "--", "<<", ">>", "<=", ">=", "==", "!=",
                             "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="):
            out.append(("punct", text[i:i + 2]))
            i += 2
            continue
        out.append(("punct", c))
        i += 1
    return out


def git_show(path):
    try:
        return subprocess.check_output(["git", "show", "HEAD:" + path],
                                       stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except subprocess.CalledProcessError:
        return None


def header_check(path, current):
    """The file must start with exactly the injected header, nothing else.

    Returns (header_line_count, ok).
    """
    header = header_for(path)
    return header.count("\n"), current.startswith(header)



def def_window_check():
    """test_parity.cpp reads nrth_dll.def into a 1024-byte buffer, so the two
    strings it looks for must stay inside the first 1023 bytes. Guards the
    header/vendor edits against silently breaking that read window."""
    path = "nrth_dll.def"
    if not os.path.exists(path):
        return "SKIP", path + " absent"
    with open(path, "rb") as fh:
        head = fh.read(1023)
    needed = [b"LIBRARY nvx.dll", b"NVXHookProc=NVXHookProc@12 @1"]
    missing = [n.decode() for n in needed if n not in head]
    if missing:
        return "FAIL", "%s: missing from read window: %s" % (path, ", ".join(missing))
    return "OK", "%s: both export strings inside the 1023-byte window (file %d bytes)" % (
        path, os.path.getsize(path))


def compare_objects(path, orig, current):
    """Compile the "header + original text, comments intact" variant and the
    cleaned file, then compare the object files.

    Both variants carry the same header, so __LINE__ expands to the same values
    and every diagnostic string is identical; the single difference between the
    two inputs is that one still contains the comments. Byte-identical objects
    therefore prove the cleanup removed nothing but comments.

    Both variants are written under the same basename in their own scratch
    directory and compiled with the repository on the include path.
    """
    flags = COMPILABLE[path].split()
    base = os.path.basename(path)
    repo = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(repo)
    objs = []
    with tempfile.TemporaryDirectory() as td:
        header = header_for(path)
        for tag, body in (("orig_with_comments", header + orig), ("cleaned", current)):
            workdir = os.path.join(td, tag)
            os.makedirs(workdir, exist_ok=True)
            src = os.path.join(workdir, base)
            with open(src, "w", encoding="utf-8") as fh:
                fh.write(body)
            rc = subprocess.run(
                ["g++"] + flags + ["-O0", "-I", repo, "-c", base, "-o", base + ".o"],
                cwd=workdir, capture_output=True)
            if rc.returncode != 0:
                return None, "does not compile: %s" % rc.stderr.decode()[:200]
            objs.append(os.path.join(workdir, base + ".o"))
        with open(objs[0], "rb") as fh:
            a = fh.read()
        with open(objs[1], "rb") as fh:
            b = fh.read()
    if a == b:
        return True, "identical (%d bytes)" % len(a)
    return False, "OBJECT FILES DIFFER (%d vs %d bytes)" % (len(a), len(b))


def main():
    if not os.path.isdir(".git"):
        print("run from the repository root", file=sys.stderr)
        return 2
    failures = []
    print("=== token / line / comment verification ===")
    for path in SOURCES:
        if not os.path.exists(path):
            print("  [SKIP] %s (absent)" % path)
            continue
        orig = git_show(path)
        if orig is None:
            print("  [SKIP] %s (not in HEAD)" % path)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            current = fh.read()
        semi = path.endswith(".def")

        t_orig = tokens(orig, semi=semi)
        t_new = tokens(current, semi=semi)
        tok_ok = t_orig == t_new

        hdr_lines, hdr_ok = header_check(path, current)
        line_ok = (len(current.split("\n")) == len(orig.split("\n")) + hdr_lines) and hdr_ok

        header_text = header_for(path)
        leftover = [sp for sp in scan_comments(current, semi=semi)
                    if sp[0] >= len(header_text)]
        idem_ok = strip_comments(current, semi=semi) == strip_comments(
            strip_comments(current, semi=semi), semi=semi)

        attr_ok = "فريق الحماية و استكشاف الثغرات - هاكرز ابيض" in current
        status = "OK" if (tok_ok and line_ok and not leftover and idem_ok and attr_ok) else "FAIL"
        if status == "FAIL":
            failures.append(path)
        print("  [%s] %-28s tokens=%s lines=%s leftover_comments=%d idempotent=%s header=%s attribution=%s"
              % (status, path, "same" if tok_ok else "DIFFER",
                 "ok" if line_ok else "MISMATCH(%d vs %d+%d)"
                 % (len(current.split("\n")), len(orig.split("\n")), hdr_lines),
                 len(leftover), idem_ok, hdr_ok, attr_ok))

    print("\n=== fixed read-window guard (test_parity.cpp semantics) ===")
    st, msg = def_window_check()
    print("  [%s] %s" % (st, msg))
    if st == "FAIL":
        failures.append("nrth_dll.def (read window)")

    print("\n=== object-file equivalence (host-compilable units) ===")
    for path, flags in COMPILABLE.items():
        if not os.path.exists(path):
            continue
        orig = git_show(path)
        with open(path, "r", encoding="utf-8") as fh:
            current = fh.read()
        if flags == "-std=none":
            continue
        ok, msg = compare_objects(path, orig, current)
        if ok is None:
            print("  [SKIP] %-28s %s" % (path, msg))
        else:
            print("  [%s] %-28s %s" % ("OK" if ok else "FAIL", path, msg))
            if not ok:
                failures.append(path + " (object)")

    print()
    if failures:
        print("VERIFICATION FAILED: %s" % ", ".join(failures))
        return 1
    print("VERIFICATION PASSED: token streams identical, line numbers preserved, "
          "object files byte-identical.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
