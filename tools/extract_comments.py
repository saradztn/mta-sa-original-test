#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_comments.py - archive every comment of the source tree into one file.

Run it from the repository root, BEFORE stripping, so the archive holds the
real comment text (the notes keep line references that stay valid because the
stripper preserves line numbers).

    python3 tools/extract_comments.py

Writes docs/RE_NOTES.md: the reverse-engineering evidence that used to live in
inline comments (sample hashes, VA/RVA anchors, module-relative offsets, scope
decisions) plus a SHA-256 manifest of the pre-cleanup sources.
"""

import hashlib
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cscan import scan_comments  # noqa: E402

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

OUT = os.path.join("docs", "RE_NOTES.md")
EVIDENCE_TOKENS = ("0x", "SHA-256", "VA ", "RVA", "ordinal", "§")


def git_show(path):
    try:
        return subprocess.check_output(
            ["git", "show", "HEAD:" + path], stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        return None


def fence_for(body):
    fence = "```"
    while fence in body:
        fence += "`"
    return fence


def main():
    if not os.path.isdir(".git"):
        print("run from the repository root", file=sys.stderr)
        return 2

    entries = []          # (path, [(line, text, is_evidence)])
    manifest = []         # (path, sha256, size, n_comments)
    total_comments = 0

    for path in SOURCES:
        raw = git_show(path)
        if raw is None:
            print("skip (not in HEAD): %s" % path, file=sys.stderr)
            continue
        manifest.append((path, hashlib.sha256(raw).hexdigest(), len(raw), None))
        text = raw.decode("utf-8", "replace")
        semi = path.endswith(".def")
        spans = scan_comments(text, semi=semi)
        found = []
        for start, end, _kind in spans:
            span_text = text[start:end]
            line = text.count("\n", 0, start) + 1
            body = span_text.rstrip()
            is_evidence = any(tok in span_text for tok in EVIDENCE_TOKENS)
            found.append((line, body, is_evidence))
        manifest[-1] = (path, manifest[-1][1], manifest[-1][2], len(found))
        entries.append((path, found))
        total_comments += len(found)
        print("%-28s %4d comments" % (path, len(found)))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        w = fh.write
        w("# ملاحظات الهندسة العكسية — أرشيف التعليقات\n\n")
        w("**RE_NOTES — archive of the inline comments of this repository.**\n\n")
        w(
            "> هذا الملف يحفظ حرفياً كل تعليق كان مكتوباً داخل ملفات المصدر، قبل تنظيفها،\n"
            "> حتى تبقى الأدلة المرجعية (هاش العينة، عناوين VA/RVA، خريطة الأدلة، قرارات النطاق)\n"
            "> قابلة للمراجعة والتحقق. أرقام الأسطر تطابق الأسطر في النسخة الأصلية.\n"
            "> **ملاحظة إزاحة:** بعد التنظيف أُضيفت في أعلى كل ملف ترويسة فريق من 9 أسطر، لذا\n"
            "> يقابل سطر الكود الأصلي N السطر N+9 في الملف النظيف.\n"
            "> تم توليد الملف آلياً بواسطة `tools/extract_comments.py`.\n\n"
        )
        w(
            "The comment text is quoted verbatim below. Nothing was summarised, reworded or\n"
            "dropped: the source files now carry only the team attribution header, and every\n"
            "technical note that used to sit next to the code lives here instead.\n\n"
        )
        w("## فهرس / Index\n\n")
        w("| file | comments archived | bytes (before cleanup) |\n|---|---|---|\n")
        for path, sha, size, n in manifest:
            w("| `%s` | %d | %d |\n" % (path, n, size))
        w("| **total** | **%d** | |\n\n" % total_comments)

        w("## بصمة الملفات الأصلية (SHA-256)\n\n")
        w(
            "قيم `git show HEAD:<file>` قبل التنظيف — تُستخدم لإثبات أن الأرشيف أدناه يطابق\n"
            "النسخة التي كانت في المستودع.\n\n"
        )
        w("```text\n")
        for path, sha, size, _n in manifest:
            w("%s  %s\n" % (sha, path))
        w("```\n\n")

        w("---\n\n")
        for path, found in entries:
            w("## `%s`\n\n" % path)
            if not found:
                w("_لا توجد تعليقات في هذا الملف._\n\n")
                continue
            for line, body, is_evidence in found:
                marker = " ★" if is_evidence else ""
                w("### L%d%s\n\n" % (line, marker))
                fence = fence_for(body)
                w(fence + "text\n")
                w(body + "\n")
                w(fence + "\n\n")
        w("---\n\n")
        w(
            "★ = التعليق يحمل دليلاً مرجعياً (عنوان VA/RVA، هاش، رقم إصدار، مرجع قسم في تقرير).\n"
        )

    print("\nwrote %s (%d comments, %d files)" % (OUT, total_comments, len(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
