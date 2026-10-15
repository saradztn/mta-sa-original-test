#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cscan.py - comment scanner for the C/C++/def sources of this repository.

Scans text and returns the byte spans occupied by comments, skipping string
and character literals (including escaped quotes) and honouring the fact that
a `//` comment continues onto the next physical line when it ends with an odd
number of backslashes.

It is intentionally free of any knowledge about what the comments say: the
extract and strip tools share it so that the archive they write and the
comments they remove are always the same spans.
"""

LINE_COMMENT_MARKERS = ("//",)
BLOCK_COMMENT_MARKERS = (("/*", "*/"),)
SEMI_LINE_MARKERS = (";",)  # .def / module-definition files


def scan_comments(text, semi=False):
    """Yield (start, end, kind) spans of comments in ``text``.

    kind is 'line' or 'block'. ``semi=True`` treats ';' as a line comment
    marker as well, which is what .def files use.
    """
    line_markers = list(LINE_COMMENT_MARKERS) + (list(SEMI_LINE_MARKERS) if semi else [])
    spans = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]

        # -- string / character literal ------------------------------------
        if c == '"' or c == "'":
            quote = c
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                if text[i] == "\n" and quote == "'":
                    break  # unterminated char literal; be forgiving
                i += 1
            continue

        # -- block comment --------------------------------------------------
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            spans.append((i, end, "block"))
            i = end
            continue

        # -- line comment ---------------------------------------------------
        hit = None
        for m in line_markers:
            if text.startswith(m, i):
                hit = m
                break
        if hit is not None:
            start = i
            j = i + len(hit)
            while True:
                nl = text.find("\n", j)
                if nl == -1:
                    j = n
                    break
                line = text[j:nl]
                backslashes = len(line) - len(line.rstrip("\\"))
                if backslashes % 2 == 1:  # macro-style continuation
                    j = nl + 1
                    continue
                j = nl
                break
            spans.append((start, j, "line"))
            i = j
            continue

        i += 1
    return spans


def comment_text(text, span):
    """Return the raw source text of a comment span."""
    return text[span[0]:span[1]]


def strip_comments(text, semi=False, keep_newlines=True):
    """Return ``text`` with every comment removed.

    When ``keep_newlines`` is true the newlines that lived inside a removed
    comment are kept, so every surviving line keeps its original number and
    diagnostics or archived references stay valid.
    """
    spans = scan_comments(text, semi=semi)
    out = []
    cursor = 0
    for start, end, _kind in spans:
        out.append(text[cursor:start])
        if keep_newlines:
            out.append("\n" * text.count("\n", start, end))
        cursor = end
    out.append(text[cursor:])
    result = "".join(out)

    # Trailing whitespace left behind by an inline comment carries no meaning
    # and would make the diff noisy. Backslashes are never whitespace, so
    # macro continuations and continued string literals are untouched.
    result = "\n".join(line.rstrip() for line in result.split("\n"))
    return result
