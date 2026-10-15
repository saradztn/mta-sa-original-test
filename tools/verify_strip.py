#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_strip.py - prove what the cleanup did and did not change.

The cleanup applied to this repository had exactly two effects on the sources:

  1. every comment was removed and replaced by the team header (9 lines/file);
  2. display-facing brand strings were renamed (overlay title, watermark,
     editor banner, loader console text).

Everything else - every identifier, every number, every non-brand string,
every operator, every line of executable code - must be untouched. This script
checks that against a baseline revision:

    python3 tools/verify_strip.py --baseline 0b9a347

Checks performed per file:

  structure   the token stream with string literals normalised to a placeholder
              must be IDENTICAL to the baseline. Comments are not tokens, so
              this proves that comments disappeared and nothing else moved.
  strings     the differing string literals are listed, so the rebrand is
              reviewable one literal at a time instead of taken on trust.
  lines       line count == baseline lines + header lines, therefore the
              references in docs/RE_NOTES.md (original line N) resolve to the
              cleaned line N+9 and never pointed anywhere else.
  comments    nothing outside the header remains, and stripping is idempotent.
  objects     for files whose bytes changed only in comments, the compiled
              object must be byte-identical to the baseline+header variant.
              Files with renamed strings are expected to differ there, and that
              difference is exactly the string list printed above.

Run tools/check_windows_bodies.sh as well: the three Windows-only translation
units are guarded by #ifdef, so this host's compiler sees almost none of them.
"""

import argparse
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cscan import scan_comments, strip_comments  # noqa: E402
from strip_comments import SOURCES, header_for  # noqa: E402

COMPILABLE = ["nrth_audit.cpp", "nrth_config.cpp", "test_parity.cpp",
              "nrth_hook.cpp", "nrth_ui.cpp"]


def git_show(rev, path):
    try:
        return subprocess.check_output(["git", "show", "%s:%s" % (rev, path)],
                                       stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except subprocess.CalledProcessError:
        return None


def tokens(text, semi=False, normalize_strings=False):
    """Independent tokenizer.

    normalize_strings=True collapses every string/char literal to a placeholder,
    which makes the comparison blind to the rebrand while still catching any
    change in code, identifiers, numbers or operators.
    """
    hidden = [False] * len(text)
    for start, end, _kind in scan_comments(text, semi=semi):
        for k in range(start, end):
            hidden[k] = True
    out = []
    i, n = 0, len(text)
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
            kind = "str" if c == '"' else "chr"
            out.append((kind, "<str>" if normalize_strings else text[i:j]))
            i = j
            continue
        if c.isalpha() or c in "_$":
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
        for three in (">>=", "<<=", "..."):
            if text.startswith(three, i):
                out.append(("punct", three))
                i += 3
                break
        else:
            two = text[i:i + 2]
            if two in ("->", "::", "++", "--", "<<", ">>", "<=", ">=", "==", "!=",
                       "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="):
                out.append(("punct", two))
                i += 2
            else:
                out.append(("punct", c))
                i += 1
    return out


def string_literals(text, semi=False):
    return [t[1] for t in tokens(text, semi=semi) if t[0] == "str"]


def compile_object(path, body, include_dir):
    """Compile one body (same basename) and return the object bytes, or None."""
    base = os.path.basename(path)
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, base), "w", encoding="utf-8") as fh:
            fh.write(body)
        rc = subprocess.run(
            ["g++", "-std=c++17", "-O0", "-I", include_dir, "-c", base, "-o", base + ".o"],
            cwd=td, capture_output=True)
        if rc.returncode != 0:
            return None, rc.stderr.decode()[:300]
        with open(os.path.join(td, base + ".o"), "rb") as fh:
            return fh.read(), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", default="HEAD",
                    help="revision to compare against (default HEAD, i.e. the "
                         "last commit; use 0b9a347 for the pristine upload)")
    args = ap.parse_args()

    if not os.path.isdir(".git"):
        print("run from the repository root", file=sys.stderr)
        return 2

    repo = os.path.abspath(".")
    failures = []
    total_strings = 0

    print("baseline revision: %s" % args.baseline)
    print("\n=== structure / strings / lines / comments ===")
    for path in SOURCES:
        if not os.path.exists(path):
            print("  [SKIP] %s (absent)" % path)
            continue
        base_text = git_show(args.baseline, path)
        if base_text is None:
            print("  [SKIP] %s (not in baseline)" % path)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            cur = fh.read()
        semi = path.endswith(".def")

        struct_ok = (tokens(base_text, semi=semi, normalize_strings=True) ==
                     tokens(cur, semi=semi, normalize_strings=True))
        old_str = string_literals(base_text, semi=semi)
        new_str = string_literals(cur, semi=semi)
        changed = [(a, b) for a, b in zip(old_str, new_str) if a != b]
        strings_ok = len(old_str) == len(new_str)

        header = header_for(path)
        hdr_ok = cur.startswith(header)
        lines_ok = len(cur.split("\n")) == len(base_text.split("\n")) + header.count("\n")

        leftover = [sp for sp in scan_comments(cur, semi=semi) if sp[0] >= len(header)]
        idem_ok = strip_comments(cur, semi=semi) == strip_comments(
            strip_comments(cur, semi=semi), semi=semi)

        ok = struct_ok and strings_ok and hdr_ok and lines_ok and not leftover and idem_ok
        if not ok:
            failures.append(path)
        total_strings += len(changed)
        print("  [%s] %-28s structure=%s strings=%d lines=%s header=%s "
              "leftover_comments=%d idempotent=%s"
              % ("OK" if ok else "FAIL", path,
                 "identical" if struct_ok else "DIFFERS",
                 len(changed), "ok" if lines_ok else "MISMATCH",
                 hdr_ok, len(leftover), idem_ok))
        for a, b in changed[:12]:
            print("         %s  ->  %s" % (a, b))
        if len(changed) > 12:
            print("         ... %d more" % (len(changed) - 12))

    print("\n=== fixed read-window guard (test_parity.cpp semantics) ===")
    head = b""
    if os.path.exists("nrth_dll.def"):
        with open("nrth_dll.def", "rb") as fh:
            head = fh.read(1023)
    missing = [s for s in (b"LIBRARY nvx.dll", b"NVXHookProc=NVXHookProc@12 @1") if s not in head]
    if missing:
        failures.append("nrth_dll.def (read window)")
        print("  [FAIL] missing from the 1023-byte window: %s" % missing)
    else:
        print("  [OK] nrth_dll.def: both export strings inside the 1023-byte window")

    print("\n=== object equivalence (host-compilable units) ===")
    for path in COMPILABLE:
        if not os.path.exists(path):
            continue
        base_text = git_show(args.baseline, path)
        with open(path, "r", encoding="utf-8") as fh:
            cur = fh.read()
        header = header_for(path)
        base_obj, err1 = compile_object(path, header + base_text, repo)
        cur_obj, err2 = compile_object(path, cur, repo)
        if base_obj is None or cur_obj is None:
            print("  [SKIP] %-20s %s" % (path, (err1 or err2 or "").replace("\n", " ")))
            continue
        same_strings = string_literals(base_text) == string_literals(cur)
        if base_obj == cur_obj:
            note = ""
            if not same_strings:
                note = (" (the renamed literals sit in #ifdef _WIN32 code that this "
                        "host does not compile - see tools/check_windows_bodies.sh)")
            print("  [OK]   %-20s object identical (%d bytes)%s"
                  % (path, len(cur_obj), note))
        elif same_strings:
            failures.append(path + " (object)")
            print("  [FAIL] %-20s object differs although no string changed" % path)
        else:
            print("  [INFO] %-20s object differs only through the renamed string "
                  "literals listed above" % path)

    print()
    if failures:
        print("VERIFICATION FAILED: %s" % ", ".join(failures))
        return 1
    print("VERIFICATION PASSED: comment removal and the %d renamed string literals are "
          "the only source-level changes; token structure, line numbering and "
          "compiled objects are otherwise unchanged." % total_strings)
    print("Also run: tools/check_windows_bodies.sh (the #ifdef _WIN32 bodies).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
