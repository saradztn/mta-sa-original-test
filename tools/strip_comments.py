#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
strip_comments.py - replace every comment in the sources with the team header.

Run from the repository root:

    python3 tools/strip_comments.py --check   # report only
    python3 tools/strip_comments.py           # rewrite in place

Behaviour
    * every `//`, `/* */` and (for .def files) `;` comment is removed;
    * newlines inside a removed comment are kept, so each surviving line keeps
      its original number and the references in docs/RE_NOTES.md stay valid;
    * the team attribution header is prepended once per file (idempotent: an
      existing header is never duplicated);
    * string and character literals are never touched (see tools/cscan.py);
    * vendor.zip is not a source file and is not modified - the licences inside
      it (Lua, MinHook, Dear ImGui) are third-party obligations and stay as they
      are.

Archive the comments with tools/extract_comments.py BEFORE running this, so
nothing is lost: the archive reads the text from the last commit.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cscan import scan_comments, strip_comments  # noqa: E402

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

TEAM_AR = "فريق الحماية و استكشاف الثغرات - هاكرز ابيض"
TEAM_EN = "Security & Vulnerability Research Team — White Hat Hackers"
PROJECT = "MTA:SA security research test bed — mta-sa-original-test"
NOTICE = "Internal security research material. All rights reserved by the team above."
NOTICE2 = "Redistribution, public release and reuse outside the team are not authorized."
MARK = "NRTH-SEC-RESEARCH-HEADER"  # identity marker so the header is added once


def header_for(path):
    if path.endswith(".def"):
        lines = [
            "; " + "=" * 76,
            ";  " + TEAM_AR,
            ";  " + TEAM_EN,
            "; " + "-" * 76,
            ";  " + PROJECT,
            ";  " + NOTICE,
            ";  " + NOTICE2,
            ";  " + MARK,
            "; " + "=" * 76,
        ]
        return "\n".join(lines) + "\n"
    lines = [
        "/* " + "=" * 76,
        " *  " + TEAM_AR,
        " *  " + TEAM_EN,
        " * " + "-" * 76,
        " *  " + PROJECT,
        " *  " + NOTICE,
        " *  " + NOTICE2,
        " *  " + MARK,
        " * " + "=" * 76 + " */",
    ]
    return "\n".join(lines) + "\n"


def process(path, write):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    semi = path.endswith(".def")
    stripped = strip_comments(text, semi=semi)
    has_header = MARK in text
    result = stripped if has_header else header_for(path) + stripped
    if not result.endswith("\n"):
        result += "\n"
    before = len(scan_comments(text, semi=semi))
    after = len(scan_comments(result, semi=semi))
    changed = result != text
    print(
        "%-28s comments: %4d -> %-3d  %s%s"
        % (path, before, after, "REWRITTEN" if changed else "unchanged",
           "  (header already present)" if has_header else "")
    )
    if write and changed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(result)
    return before, after


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report without writing")
    args = ap.parse_args()

    if not os.path.isdir(".git"):
        print("run from the repository root", file=sys.stderr)
        return 2

    tot_before = tot_after = 0
    for path in SOURCES:
        if not os.path.exists(path):
            print("missing: %s" % path, file=sys.stderr)
            continue
        b, a = process(path, write=not args.check)
        tot_before += b
        tot_after += a
    print("\ncomments: %d -> %d" % (tot_before, tot_after))
    print("mode: %s" % ("check only" if args.check else "written"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
