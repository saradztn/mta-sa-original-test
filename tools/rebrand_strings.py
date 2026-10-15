#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rebrand the display-facing strings of the overlay and the loader.

Runs once (kept for the record of exactly what was replaced). Each pair is
asserted to exist before the file is written, and no replacement changes the
number of lines.

History note: the first run of this table wrote a *Python* concatenation
("-- " + BRAND + " lua editor\\n") into the C++ initializer of s_editorBuf.
Nothing on this host caught it, because that line lives inside
`#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)` and the Linux build never
compiles it. It was fixed in the same commit, and tools/check_windows_bodies.sh
was added so that the Windows-only bodies get parsed from then on. Artifact names (NVXHookProc export, NRTH.dll file name, the
C:\\NVX / C:\\Overwack directories) are deliberately NOT touched here - they are
functional contracts asserted by test_parity.cpp and are handled separately.
"""

import io

BRAND = "MTA:SA SECURITY"
CREDIT_EN = "Security & Vulnerability Research Team — White Hat Hackers"
CREDIT_AR = "فريق الحماية و استكشاف الثغرات - هاكرز ابيض"

EDITS = {
    "nrth_ui.cpp": [
        ('"-- DARKANARCHY lua editor\\n"', '"-- ' + BRAND + ' lua editor\\n"'),
        ('"DARKANARCHY | FPS: %.0f | %s: %s"', '"' + BRAND + ' | FPS: %.0f | %s: %s"'),
        ('"DARKANARCHY | FPS: %.0f | Server: %s"', '"' + BRAND + ' | FPS: %.0f | Server: %s"'),
        ('ImGui::TextColored(kBloodHi, "DARKANARCHY");',
         'ImGui::TextColored(kBloodHi, "' + BRAND + '");'),
        ('ImGui::Begin("DARKANARCHY", &s_menuOpen', 'ImGui::Begin("' + BRAND + '", &s_menuOpen'),
        ('ImGui::Text("D A R K A N A R C H Y");', 'ImGui::Text("M T A : S A   S E C U R I T Y");'),
        ('ImGui::TextDisabled("by XRAOUF");',
         'ImGui::TextDisabled("' + CREDIT_EN + '");'),
        ('\\"@nrth_inject\\"', '\\"@mta_inject\\"'),
        ('print(\\"NRTH: inject load error: \\"', 'print(\\"MTA:SA: inject load error: \\"'),
        ('print(\\"NRTH: inject error: \\"', 'print(\\"MTA:SA: inject error: \\"'),
        ('"nvx_top_%d"', '"mta_top_%d"'),
        ('"nvx_ssub_%d"', '"mta_ssub_%d"'),
        ('"nvx_csub_%d"', '"mta_csub_%d"'),
        ('"##nvx_content"', '"##mta_content"'),
    ],
    "north_loader.cpp": [
        ('SetConsoleTitleA("NORTH Loader");', 'SetConsoleTitleA("%s Loader");' % BRAND),
        ('printf("=== NORTH Loader ===\\n");', 'printf("=== %s Loader ===\\n");' % BRAND),
    ],
}


def main():
    for path, pairs in EDITS.items():
        src = io.open(path, encoding="utf-8").read()
        before_lines = src.count("\n")
        for old, new in pairs:
            n = src.count(old)
            assert n >= 1, "NOT FOUND in %s: %r" % (path, old)
            src = src.replace(old, new)
            print("%-16s x%d  %s" % (path, n, old[:72]))
        assert src.count("\n") == before_lines, "line count changed in " + path
        io.open(path, "w", encoding="utf-8").write(src)
    print("done")


if __name__ == "__main__":
    main()
