# ملاحظات الهندسة العكسية — أرشيف التعليقات

**RE_NOTES — archive of the inline comments of this repository.**

> هذا الملف يحفظ حرفياً كل تعليق كان مكتوباً داخل ملفات المصدر، قبل تنظيفها،
> حتى تبقى الأدلة المرجعية (هاش العينة، عناوين VA/RVA، خريطة الأدلة، قرارات النطاق)
> قابلة للمراجعة والتحقق. أرقام الأسطر تطابق الأسطر في النسخة الأصلية.
> **ملاحظة إزاحة:** بعد التنظيف أُضيفت في أعلى كل ملف ترويسة فريق من 9 أسطر، لذا
> يقابل سطر الكود الأصلي N السطر N+9 في الملف النظيف.
> تم توليد الملف آلياً بواسطة `tools/extract_comments.py`.

The comment text is quoted verbatim below. Nothing was summarised, reworded or
dropped: the source files now carry only the team attribution header, and every
technical note that used to sit next to the code lives here instead.

## فهرس / Index

| file | comments archived | bytes (before cleanup) |
|---|---|---|
| `north_loader.cpp` | 15 | 18716 |
| `nrth_audit.cpp` | 81 | 43721 |
| `nrth_audit.def` | 11 | 1624 |
| `nrth_audit.h` | 69 | 17705 |
| `nrth_audit_sigs.h` | 22 | 6521 |
| `nrth_codec.h` | 36 | 15838 |
| `nrth_config.cpp` | 9 | 6705 |
| `nrth_config.h` | 13 | 2488 |
| `nrth_dll.def` | 6 | 478 |
| `nrth_fonts.h` | 1 | 1684095 |
| `nrth_hook.cpp` | 161 | 96581 |
| `nrth_hook.h` | 64 | 9369 |
| `nrth_ui.cpp` | 99 | 101728 |
| `nrth_ui.h` | 4 | 2252 |
| `nrth_vehicle_names.inc` | 2 | 3628 |
| `test_parity.cpp` | 52 | 27397 |
| **total** | **645** | |

## بصمة الملفات الأصلية (SHA-256)

قيم `git show HEAD:<file>` قبل التنظيف — تُستخدم لإثبات أن الأرشيف أدناه يطابق
النسخة التي كانت في المستودع.

```text
086422c8846027d75e1c3a8e288b65421238dfe0f5589bb11f5fe1c9a443bbd5  north_loader.cpp
a165e5e6edecc2ffa764e003e41a46b2885c05d5a6cede3f8b79d655993c59d2  nrth_audit.cpp
8b22baf871beec804dbfd1a9e826ac13587080e17e999708e5cff0b1bed62dbd  nrth_audit.def
478ba9942d164a3b2adf1e0260d4ee5ab5c9430c12cbc2e43722c4b898474b33  nrth_audit.h
d524e500baebf9feaca3e20f1f55198ee6d80f66265467447f3437e35ae7e13f  nrth_audit_sigs.h
a496b146232eacd57fe6c47f60a3fa7ccfa437c15c2812b00830130439c2a595  nrth_codec.h
dd41d54f3737c2020e4f531222cd899cc5980b05301ce37f1512caf4cac06734  nrth_config.cpp
2a3649ae3d5cb7b3cb1f14cbc5187badcaff3a8dc257ad0d3320594f20d98f2e  nrth_config.h
a5ff1c165e84c818cc5957f71b178f724194b4aae93f4a614a4c1c9ec05fc04d  nrth_dll.def
4902a00b6da5d40f345872bd718c9c172b25f31e9f5a54c27e97fce471e89776  nrth_fonts.h
fc7cc4ca493f97c01028bdd09f1f16fd44e071ad48776e54523ab2e23d907705  nrth_hook.cpp
768f7f9b7b890fd10f3627e51244bc82598620e8e5c26c2b4634da6396262c1e  nrth_hook.h
3079bf5256e380f625561023ced2ad650b60bf04b7c97ed06f4247e01b123be4  nrth_ui.cpp
01250d47276fc5fe28d75c28637fb3da64de3c9089b5caae4c3f253afb88c048  nrth_ui.h
1cb9f7d5024cb27316b96b3c4716dbfe42b1dd8f5018a583c60ae475a60709d3  nrth_vehicle_names.inc
80784916cb8bbed578b7bd6a6738ed7f2ae3fe25a314dfbc3d6629b03115879b  test_parity.cpp
```

---

## `north_loader.cpp`

### L1

```text
/**
 * ============================================================================
 * NORTH LOADER — Behavioral Reimplementation (Result Class R2)
 * Reconstructed from reverse engineering of native x86 binary "NORTH LOADER.exe"
 * ============================================================================
 * Target Architecture : x86 32-bit (PE32)
 * Original Compiler   : Microsoft Visual C++ 2015-2022 (v140/v141/v142/v143) Debug
 * Original PDB Path   : C:\Users\user\Desktop\src CHEATS\over\Loader\Debug\NVX Loader.pdb
 * ============================================================================
 */
```

### L24

```text
// Active hook handles kept alive until loader exit so delayed game window startup
```

### L25

```text
// (e.g. MTA splash -> gta_sa.exe main window) still triggers WH_GETMESSAGE injection.
```

### L56

```text
// Enables SeDebugPrivilege in the current process token
```

### L78

```text
// Checks if a file exists and is not a directory
```

### L87

```text
// Finds the first process ID with the matching executable name (case-insensitive)
```

### L111

```text
// Finds all thread IDs belonging to a given PID (up to maxThreads)
```

### L158 ★

```text
// Helper struct and functions to map RVAs to file offsets in an unmapped PE image
```

### L180 ★

```text
// Parses on-disk PE headers and export table to locate an exported function's RVA
```

### L262

```text
// Verifies if the target DLL has been loaded into the process using K32EnumProcessModules
```

### L293

```text
// Classic injection method via CreateRemoteThread & LoadLibraryA
```

### L294

```text
// Returns 0 on success, 1 on generic failure, 2 on access denied (protected process)
```

### L374

```text
// Hook injection method via SetWindowsHookEx (WH_GETMESSAGE) & NVXHookProc
```

### L442

```text
// Wait for the game window to appear and pump messages so WH_GETMESSAGE maps NRTH.dll
```

### L560

```text
// Access denied
```

## `nrth_audit.cpp`

### L1 ★

```text
/**
 * ============================================================================
 * nrth_audit.cpp — NORTH/NVX **defensive audit** module (result class R2)
 * ============================================================================
 * Implements detection logic derived from the real mechanism of NRTH.dll
 * (mta_blue_team_case/mechanism_overview_ar.md §3.1, §3.2, §4):
 *   * the sample's positional-XOR string codec, so a defender can decode the
 *     obfuscated records of a new variant without re-doing the disassembly;
 *   * a byte-pattern matcher with '?' wildcards, matching the semantics of the
 *     sample's own resolver (VA 0x10002960), used here to locate the *targets*;
 *   * a prologue-state classifier that recognises the footprint the sample leaves
 *     when it detours a function (E9 / FF 25) or kills a check (C3 / C2 imm16).
 *
 * It contains NO injection, NO hook installation, NO memory writes, NO module
 * pinning, NO string obfuscation of payload, NO game-VM execution and NO feature
 * logic. It reads bytes and reports. See nrth_audit.h for the scope rationale.
 *
 * All buffer handling is bounds-checked against untrusted input: a truncated,
 * malformed or hostile PE must return an error, never read out of bounds.
 * ============================================================================
 */
```

### L29

```text
/* max pattern tokens (sample's longest: 120)      */
```

### L30

```text
/* hits kept per pattern per section               */
```

### L31

```text
/* bytes a near-detour may overwrite (5..8)        */
```

### L33

```text
/* -------------------------------------------------------------------------- */
```

### L34

```text
/* little-endian helpers                                                       */
```

### L35

```text
/* -------------------------------------------------------------------------- */
```

### L85

```text
/* -------------------------------------------------------------------------- */
```

### L86 ★

```text
/* codec:  out[p] = in[p] ^ ((p - key) & 0xFF)                                 */
```

### L87 ★

```text
/* Verified against the sample's decryptors 0x100078d0 (scalar, key 0x2D) and  */
```

### L88 ★

```text
/* 0x1000bc00 (SSE, key 0x20); the transform is symmetric so it also encodes.  */
```

### L89

```text
/* -------------------------------------------------------------------------- */
```

### L164

```text
/* -------------------------------------------------------------------------- */
```

### L165

```text
/* pattern engine — same surface syntax the sample uses ("55 8B ? A3 ...")     */
```

### L166

```text
/* -------------------------------------------------------------------------- */
```

### L193

```text
/* wildcard token: "?", "??" */
```

### L220

```text
/* trailing junk ignored */
```

### L228

```text
/* Scan for a compiled pattern; hits[] receives byte offsets. */
```

### L229

```text
/* Wildcard scan. Fills hits[] with at most maxHits byte offsets and returns how many it
 * wrote; *total (optional) receives the full number of matches, which can be larger —
 * callers must never index hits[] beyond the returned count. */
```

### L239

```text
/* anchor on the first concrete byte */
```

### L244

```text
/* all wildcards: refuse (would match everywhere) */
```

### L268

```text
/* non-overlapping matches */
```

### L288

```text
/* Shared token rewriter behind NrthPatWidenHead / NrthPatPatchHead. With `replace == NULL`
 * the first `head` tokens become '?'; otherwise they are dropped and `replace` (a concrete
 * footprint such as "E9 ? ? ? ?") is written in front. Returns the output token count. */
```

### L299

```text
/* skip the tokens the footprint replaces */
```

### L373

```text
/* -------------------------------------------------------------------------- */
```

### L374

```text
/* prologue classification: recognises the shapes produced by the sample's      */
```

### L375

```text
/* detour installation (MinHook) and by its one-byte "check kill" writes.       */
```

### L376

```text
/* -------------------------------------------------------------------------- */
```

### L397

```text
/* rel32, add to (rva+5) to resolve */
```

### L432

```text
/* ordinary prologue: nothing patched */
```

### L435

```text
/* -------------------------------------------------------------------------- */
```

### L436

```text
/* PE view                                                                      */
```

### L437

```text
/* -------------------------------------------------------------------------- */
```

### L447

```text
/* 'MZ' */
```

### L451

```text
/* 'PE\0\0' */
```

### L458

```text
/* Offsets relative to the 'PE\0\0' signature: Machine@4 NumberOfSections@6
       TimeDateStamp@8 PointerToSymbolTable@12 NumberOfSymbols@16
       SizeOfOptionalHeader@20 Characteristics@22, optional header@24. */
```

### L463

```text
/* after 'PE\0\0' + 20-byte file header */
```

### L490 ★

```text
/* File image vs. already-mapped dump. A file image has every section that carries
     * data on disk (`rsize > 0`) stored inside the buffer at a sane raw offset. A dump
     * keeps the virtual layout instead, so we index by RVA. Sections with rsize == 0
     * (uninitialised .data, .pdata, resource overlays, ...) say nothing either way. */
```

### L582

```text
/* -------------------------------------------------------------------------- */
```

### L583

```text
/* whole-module audit                                                           */
```

### L584

```text
/* -------------------------------------------------------------------------- */
```

### L585

```text
/* True when the compiled pattern matches at exactly this offset — used to decide whether a
 * widened ("patched") hit is really the pristine pattern, without relying on the capped
 * hit array. */
```

### L638

```text
/* The four shapes this audit looks for when the complete pattern does not match. Each one
 * is what the sample itself writes (or what MinHook writes on its behalf): the leading
 * tokens of the target function are replaced by the footprint, the rest of the function is
 * untouched. Requiring the concrete footprint bytes instead of a wildcarded head is what
 * keeps the on-disk check free of coincidences. */
```

### L645

```text
/* tokens written over the function entry            */
```

### L646

```text
/* how many pattern tokens they replace              */
```

### L647

```text
/* NrthPrologueState to report                       */
```

### L649

```text
/* the sample's 1-byte check kill */
```

### L650

```text
/* MinHook near jump            */
```

### L651

```text
/* absolute jump through memory  */
```

### L652

```text
/* push addr / ret trampoline      */
```

### L713

```text
/* hits beyond the buffer */
```

### L729

```text
/* the function entry is intact */
```

### L732

```text
/* keep where the detour points so an analyst can follow it */
```

### L733

```text
/* E9 rel32 */
```

### L738

```text
/* FF 25 abs32 / 68 abs32 */
```

### L752

```text
/* footprint hits beyond the buffer */
```

### L771

```text
/* ---- file I/O (read-only) ------------------------------------------------- */
```

### L818

```text
/* -------------------------------------------------------------------------- */
```

### L819

```text
/* hidden-signature discovery (variant triage)                                  */
```

### L820

```text
/* Anchored sweep: only positions whose positional-XOR decode *starts* with a     */
```

### L821

```text
/* compiler function prologue are considered, which pins the key in one step and    */
```

### L822

```text
/* keeps random-byte noise out. Mirrors tools/nrth_sig_export.py (data-sweep pass).  */
```

### L823

```text
/* -------------------------------------------------------------------------- */
```

### L839

```text
/* require at least one space-separated token pair */
```

### L863

```text
/* .data / .rdata / .text only */
```

### L910

```text
/* one prefix per position */
```

### L934

```text
/* one memset per call: rows is caller memory, so zero it before filling */
```

### L950 ★

```text
/* Alignment: within one build a signature locates one function, so the RVA is the key
         * that says "this row in the suspect image is the same function as this row in the
         * baseline". Without that requirement, any jump thunk that happens to match a pattern in
         * a different build is reported as a new detour - measured on NRTH.dll vs the
         * reconstruction, where signature #18 matched a thunk at 0x0d9f91. */
```

### L982

```text
/* -------------------------------------------------------------------------- */
```

### L983

```text
/* self test — evidence vectors taken from the original sample                  */
```

### L984

```text
/* -------------------------------------------------------------------------- */
```

### L1006 ★

```text
/* 1. codec: ciphertext recovered from NRTH.dll VA 0x10005c56 (inline dwords) */
```

### L1014 ★

```text
/* 2. codec: 8-byte SSE variant, ciphertext at NRTH.dll VA 0x1002069c */
```

### L1020 ★

```text
/* 3. codec: 12-byte record at NRTH.dll VA 0x100044df */
```

### L1027 ★

```text
/* 4. codec: first 16 bytes of the .rdata block behind hook signature #1
     *    (NRTH.dll VA 0x100f2060) -> "55 8B EC 8B 45 ?" */
```

### L1036

```text
/* 4b. tamper predicate: only real footprints count */
```

### L1045

```text
/* 5. transform is symmetric (encode == decode) */
```

### L1052

```text
/* 6. pattern engine: wildcards + compile errors */
```

### L1076

```text
/* 7. prologue classifier — the shapes the sample leaves behind */
```

### L1093

```text
/* 8. catalogue integrity: every generated row compiles and is anchored on a prologue */
```

### L1114

```text
/* 9. robustness: garbage must never crash or read out of bounds */
```

## `nrth_audit.def`

### L1

```text
; NRTH_audit.dll export definition (MinGW / MSVC compatible)
```

### L2

```text
;
```

### L3

```text
; Blue-team audit module for the NORTH/NVX MTA:SA case. Unlike NRTH.dll this module has no
```

### L4

```text
; injected-entry-point contract: every export is an ordinary C function that a scanner, an
```

### L5

```text
; EDR sensor or a triage script calls in its own process. Names are undecorated (extern "C",
```

### L6

```text
; default cdecl) so GetProcAddress("NrthAuditImageFile") works from C, Pascal, Python
```

### L7

```text
; (ctypes) and PowerShell alike. Ordinals are pinned so an internal rule set can keep working
```

### L8

```text
; if a name is ever renamed; new exports are appended, never renumbered.
```

### L9

```text
;
```

### L10

```text
; Nothing here touches another process: the whole API operates on a byte buffer the caller
```

### L11

```text
; already owns (a file copy or a dump it is allowed to read).
```

## `nrth_audit.h`

### L1 ★

```text
/**
 * ============================================================================
 * nrth_audit.h — PUBLIC CONTRACT of the NORTH/NVX **defensive audit** module
 * ============================================================================
 * Result class: R2 (newly authored defensive code) built on D2 evidence
 * (disassembly-derived findings) from the original sample. See
 * ../../mta_blue_team_case/report.md §2.1 for the scope decision behind this file.
 *
 * The module turns the sample's *own* mechanism primitives into detection logic:
 *
 *   mechanism in NRTH.dll                                this module
 *   --------------------------------------------------   --------------------------------
 *   §3.1 positional-XOR string codec (per-record key)    NrthXorTransform/NrthXorCrack
 *   §3.2 finds client.dll/netc.dll functions by code     NrthPatCompile/NrthPatScan —
 *        pattern with '?' wildcards (resolver 0x10002960)   same matcher semantics, used
 *                                                          to locate the *targets*
 *   §3.2 installs MinHook detours on them; §4 writes a   NrthClassifyPrologue — reports
 *        single 0xC3 (RET) byte over a netc.dll check    E9/FF25 detour + C3/C2 kill
 *   §2/§3 module pinning, injection, Lua-VM execution    NOT implemented (see below)
 *
 * WHAT THIS MODULE DELIBERATELY DOES **NOT** DO (blue-team scope decision):
 *   - it never opens another process, never injects, never hooks, never changes memory
 *     protection, never writes a byte outside its own caller-provided output buffers;
 *   - it cannot execute Lua in a game VM and contains no script payload, no feature
 *     logic, no overlay, no loader, no self-protection and no evasion;
 *   - it reads one *file* (a module copy, or a memory-dump the team already owns) and
 *     reports where the tool's hook targets are and whether a prologue looks patched.
 * Everything an attacker would need to weaponise this is deliberately absent, while
 * everything a defender needs (module-relative offsets + patch state) is present.
 *
 * Inputs are UNTRUSTED data: malformed/truncated PE input must fail safely.
 *
 * Version 1.2.0 (2026-10-11): NrthAuditDiff only alerts on a footprint that sits on the SAME located
 * function as the baseline (RVA agreement is the alignment key). Measured reason: diffing the
 * original NRTH.dll against our own reconstruction produced one DETOUR_JMP32 "added footprint",
 * which was a jump thunk of a different build, not a patch - see detection/audit_tool.md.
 * NrthAuditDiffRow gained susUnlocated, which counts exactly that case informationally.
 *
 * Version 1.1.0 (2026-10-10): added NrthPrologueIsTamper, NrthPatPatchHead and the A/B
 * comparison entry points (NrthAuditDiff / NrthAuditDiffFiles, ordinals 22-23). The patched-hit
 * rule was also tightened: a widened hit now counts only when the entry carries a concrete
 * footprint, which removed 5 false positives per 20 rows measured against NRTH.dll itself.
 * Builds as a Windows PE32 DLL (matching the sample's architecture) and also compiles
 * natively on Linux for unit testing — the logic is plain C++17 with no OS coupling.
 * ============================================================================
 */
```

### L52

```text
/* Linkage. Define NRTH_AUDIT_BUILD when compiling this module *into* NRTH_audit.dll, and
 * NRTH_AUDIT_STATIC when the sources are compiled straight into a consumer (the CLI does
 * that, so nrth_audit.exe has no import table dependency on the DLL). With neither define
 * the header declares the API as imported, which is what a third-party scanner tool should
 * do: LoadLibrary("NRTH_audit.dll") + GetProcAddress, or link against the import library. */
```

### L73

```text
/* ---- status codes -------------------------------------------------------- */
```

### L75

```text
/* bad argument / output buffer too small        */
```

### L76

```text
/* not a PE image / no sections                  */
```

### L77

```text
/* image shorter than its headers promise        */
```

### L78

```text
/* file could not be read                        */
```

### L80

```text
/* ---- prologue states: the runtime footprint of the tool's patching -------- */
```

### L83

```text
/* matches the tool's own search pattern          */
```

### L84

```text
/* E9 rel32        — MinHook-style near detour    */
```

### L85

```text
/* FF 25 [addr]    — absolute/far detour          */
```

### L86

```text
/* 68 xx push+ret  — trampoline push form         */
```

### L87

```text
/* C3              — "return immediately" patch   */
```

### L88

```text
/* C2 imm16        — cleaned-stack no-op patch     */
```

### L89

```text
/* C7 05 [g],imm   — global forced to a constant   */
```

### L90

```text
/* long 90/CC run  — body moved elsewhere          */
```

### L91

```text
/* FF 25/FF E0 style jump through register/memory   */
```

### L94

```text
/* ---- verified signature catalogue (generated: see nrth_audit_sigs.h) ----- */
```

### L97

```text
/* "55 8B EC 8B 45 ? A3 ? ? ? ? ..." ('?' = wildcard) */
```

### L98

```text
/* module the sample scans                       */
```

### L99

```text
/* what the sample does with the match           */
```

### L100 ★

```text
/* VA of the sample's string-decryptor call       */
```

### L101

```text
/* length of the recovered pattern text, in bytes */
```

### L102 ★

```text
/* effective key: plain[p]^(p-key)&0xFF           */
```

### L103

```text
/* 2 High / 1 Medium / 0 Low                     */
```

### L104

```text
/* VA(s) of the record construction site(s)      */
```

### L107

```text
/* ---- one result row per catalogue signature ------------------------------ */
```

### L110

```text
/* occurrences of the complete pattern            */
```

### L111

```text
/* occurrences where only the *tail* matches      */
```

### L112

```text
/*   (prologue differs) — the hook/kill footprint  */
```

### L114

```text
/* NrthPrologueState at firstPatchedRva            */
```

### L115 ★

```text
/* state-specific: detour target RVA / stub value  */
```

### L116

```text
/* 1 when the finding lies in a section ".text"    */
```

### L119

```text
/* ---- minimal PE view ----------------------------------------------------- */
```

### L135 ★

```text
/* 1 = image already loaded (VA offsets), 0 = file */
```

### L143

```text
/* --- version / catalogue -------------------------------------------------- */
```

### L148 ★

```text
/* 1 when the state is an active tamper footprint (detour jump, 0xC3/0xC2 kill, forced
 * constant, jump-through-memory), 0 for UNKNOWN/PRISTINE/PAD. NrthAuditImage counts a
 * widened hit as "patched" only when this predicate is true, so a coincidental tail match
 * on a perfectly normal function prologue never raises an alert. */
```

### L154 ★

```text
/* --- codec (§3.1: positional XOR, symmetric) ------------------------------ */
```

### L155 ★

```text
/* out[p] = in[p] ^ ((p - key) & 0xFF). Returns bytes written, or NVXA_E_*.      */
```

### L159 ★

```text
/* Best printable decode over all 256 keys (family keys 0x2D/0x20 win ties).
 * NUL-terminates `text`. Returns the printable length, or 0 when nothing decodes. */
```

### L164

```text
/* Locate + decrypt one obfuscated record of a sample of this family at `va`.      */
```

### L170

```text
/* --- pattern engine (same matching semantics as the sample's resolver) --------- */
```

### L171

```text
/* "55 8B ? A3" -> bytes/mask. Returns pattern length, or NVXA_E_*. */
```

### L175

```text
/* Wildcard scan; returns the number of offsets written into hits[] (byte offsets in buf),
   capped at maxHits. Only ever index hits[] with the returned count. */
```

### L180

```text
/* Widen a pattern: replace the first `head` tokens with wildcards, so a patched
 * prologue still anchors on the (unmodified) tail. Returns the new token count. */
```

### L184

```text
/* Same, but instead of '?'-wildcarding the first `head` tokens it *substitutes* the
 * concrete footprint tokens (e.g. "C3", "E9 ? ? ? ?", "FF 25 ? ? ? ?", "68 ? ? ? ? C3").
 * That is how NrthAuditImage recognises a hooked/killed function without the false
 * positives a wildcarded head produces on unrelated code. */
```

### L192

```text
/* --- patch footprint -------------------------------------------------------- */
```

### L193 ★

```text
/* func = bytes at a located target (file copy or owned dump).
 * outDetail = jump target RVA / stub value when derivable. */
```

### L198

```text
/* --- PE view --------------------------------------------------------------- */
```

### L201

```text
/* Section data for scanning, honouring file vs mapped layout. */
```

### L206 ★

```text
/* VA -> offset inside a mapped image (returns NULL when outside). */
```

### L210

```text
/* --- whole-module audit ----------------------------------------------------- */
```

### L211

```text
/* Audit every catalogue signature against an image buffer (file image or an owned,
 * already-read dump). Returns the number of signatures with any hit, or NVXA_E_*.
 * findings[] must hold NrthSigCount() entries (NULL is allowed = count only). */
```

### L220 ★

```text
/* RVA (not VA) of the module's .text start, or 0 — helper for callers. */
```

### L223

```text
/* --- A/B comparison: known-good copy vs the copy actually loaded ------------ */
```

### L224

```text
/* The strongest form of this check, because it removes every judgement call about
 * "is this prologue normal for this compiler": you give a clean `client.dll` (your
 * baseline, from the same MTA build) and the module as loaded in the suspect process,
 * and the diff says which located functions changed. Rows are per signature, in
 * catalogue order; `addedFootprint` is the number you alert on. */
```

### L231

```text
/* complete-pattern hits in the baseline image      */
```

### L233

```text
/* ... in the loaded/suspect image                  */
```

### L235 ★

```text
/* footprint at the suspect's first patched RVA     */
```

### L237 ★

```text
/* detour target RVA, when the state carries one    */
```

### L238 ★

```text
/* 1 when the suspect patched the SAME function the baseline
                                * located at this RVA and the baseline had no footprint there.
                                * This is the only field to alert on. */
```

### L241

```text
/* 1 when baseline found the pattern and suspect did not */
```

### L242 ★

```text
/* 1 when the suspect has a footprint at an RVA the baseline never
                                * located: a different build (or a pattern that matched unrelated
                                * code), reported so it can be seen but deliberately NOT an alert. */
```

### L247 ★

```text
/* Returns the number of rows with an added footprint (>=0) or NVXA_E_*. Both inputs
 * may be file images or dumps; they are only compared through the located-pattern
 * offsets, so differing ImageBases are fine. The located RVA is also what aligns the two
 * images: a footprint at an RVA the baseline never located is counted as `susUnlocated`,
 * not as tampering, so diffing two different builds yields no alert instead of a flood.
 * For a meaningful check the two files must still be the same build of the same module.
 * Multi-hit signatures are aligned on their FIRST located function only. */
```

### L260

```text
/* --- hidden-signature discovery (variant triage) ---------------------------- */
```

### L261

```text
/* Prologue-anchored sweep for obfuscated pattern strings held in a sample of this
 * family: for each aligned position, the key that makes the bytes read
 * "55 8B EC " / "53 8B DC " is tried, and a printable hex-pattern run >= minLen is
 * reported. textOut gets NUL-terminated strings, each <= 255 chars, separated by \n.
 * Returns the number of distinct candidates (0 is a valid answer, not an error). */
```

### L273

```text
/* --- self test ------------------------------------------------------------- */
```

### L274

```text
/* Runs the built-in evidence vectors (codec, pattern engine, classifier, catalogue
 * consistency). Writes a human-readable report; returns 0 when all checks pass,
 * otherwise the number of failed checks. */
```

### L283

```text
/* NRTH_AUDIT_H */
```

## `nrth_audit_sigs.h`

### L1 ★

```text
/**
 * ============================================================================
 * nrth_audit_sigs.h — GENERATED FILE, do not edit by hand
 * ============================================================================
 * Generated by tools/gen_nrth_audit_sigs_h.py from the catalogue produced by
 * tools/nrth_sig_export.py against the ORIGINAL sample
 *   NRTH.dll  SHA-256 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861
 *   ImageBase 0x10000000
 *
 * Every entry is a plaintext byte-signature that the sample keeps obfuscated and uses to
 * find a function in an MTA:SA module *by code pattern* (those functions are not exported
 * by name). Fields: signature length, pattern text, target module, role, VA of the
 * decryptor call that materialises the record, the pattern-text length, the
 * positional-XOR key (plain[p] = cipher[p] ^ ((p - key) & 0xFF)), and confidence
 * (2 = High: reassembled from the code path; 1 = Medium).
 *
 * This is detection data for integrity checking only. Nothing here is used to hook,
 * patch, inject or execute anything.
 * ============================================================================
 */
```

### L32

```text
/* High */
```

### L36

```text
/* High */
```

### L40

```text
/* High */
```

### L44

```text
/* High */
```

### L48

```text
/* High */
```

### L52

```text
/* High */
```

### L56

```text
/* High */
```

### L60

```text
/* High */
```

### L64

```text
/* High */
```

### L68

```text
/* High */
```

### L72

```text
/* High */
```

### L76

```text
/* High */
```

### L80

```text
/* High */
```

### L84

```text
/* High */
```

### L88

```text
/* High */
```

### L92

```text
/* High */
```

### L96

```text
/* High */
```

### L100

```text
/* High */
```

### L104

```text
/* High */
```

### L108

```text
/* High */
```

### L111

```text
/* NRTH_AUDIT_SIGS_H */
```

## `nrth_codec.h`

### L2 ★

```text
/**
 * ============================================================================
 * nrth_codec.h — Positional-XOR string codec & encrypted record catalogue
 * ============================================================================
 * Matches original NRTH.dll string obfuscation (§3.1):
 *   - 82 decryptor routines in the original binary (e.g. scalar 0x100078d0 with
 *     K=0x2D, SSE 0x1000bc00 with K=0x20, resolver 0x1000e0a0..0x10006c00 with K=0x40/0x2D)
 *   - Formula: plain[p] = cipher[p] ^ ((p - K) & 0xFF)
 *   - Single-use gate per record: usable length L = F - 1 (where F is field size
 *     including the encrypted trailing NUL byte).
 *   - Symmetric transform: encode == decode.
 * ============================================================================
 */
```

### L36

```text
/**
 * Single-use gate decryptor (matches original NRTH.dll decryptor pattern):
 *   Given a ciphertext buffer of field size F (`fieldSize`), key K (`key`),
 *   mutable plaintext buffer `plainBuf` (>= F bytes), and boolean `*gate`:
 *   On first invocation (`!*gate`), decodes L = F - 1 bytes, writes NUL at
 *   `plainBuf[L]`, and flips `*gate = true`. Subsequent calls return `plainBuf`
 *   immediately without re-running the loop.
 */
```

### L63

```text
/* ---- Core encrypted string records (evidence VAs from NRTH.dll) ---------- */
```

### L65 ★

```text
/* VA 0x10005c56 (decryptor 0x100078d0, K=0x2D, F=11, L=10) */
```

### L67 ★

```text
/* VA 0x1002069c (decryptor 0x1000bc00, K=0x20, F=9, L=8) */
```

### L69 ★

```text
/* VA 0x100044df (decryptor 0x100078d0, K=0x2D, F=13, L=12) */
```

### L71 ★

```text
/* VA 0x100e9890 (decryptor 0x100078d0, K=0x2D, F=8, L=7) */
```

### L73 ★

```text
/* VA 0x1000a850 (decryptor 0x100078d0, K=0x2D, F=10, L=9) */
```

### L75 ★

```text
/* VA 0x1000a870 (decryptor 0x100078d0, K=0x2D, F=11, L=10) */
```

### L77 ★

```text
/* VA 0x10012980 (decryptor 0x100078d0, K=0x2D, F=9, L=8) */
```

### L79 ★

```text
/* VA 0x1001fcff (decryptor 0x1000bc00, K=0x20, F=30, L=29) */
```

### L81 ★

```text
/* VA 0x1001fd7b (decryptor 0x1000bc00, K=0x20, F=13, L=12) */
```

### L83 ★

```text
/* VA 0x1001fdc5 (decryptor 0x1000bc00, K=0x20, F=15, L=14) */
```

### L85 ★

```text
/* VA 0x1001e530 (decryptor 0x1000bc00, K=0x20, F=19, L=18) */
```

### L88

```text
/* ---- 20 verified pattern-signature records (4-byte aligned in .rdata) ---- */
```

### L89 ★

```text
/* Sig #1: client.dll site 0x1000ca47 decryptor 0x1000e0a0 K=0x40 F=121 L=120 */
```

### L91 ★

```text
/* Sig #2: client.dll site 0x1000cfbe decryptor 0x1000db00 K=0x40 F=113 L=112 */
```

### L93 ★

```text
/* Sig #3: client.dll site 0x10005e54 decryptor 0x100074f0 K=0x2D F=96 L=95 */
```

### L95 ★

```text
/* Sig #4: client.dll site 0x1000c52b decryptor 0x1000e5f0 K=0x40 F=85 L=84 */
```

### L97 ★

```text
/* Sig #5: client.dll site 0x10005d28 decryptor 0x10007640 K=0x2D F=81 L=80 */
```

### L99 ★

```text
/* Sig #6: client.dll site 0x1000633b decryptor 0x10006f90 K=0x2D F=63 L=62 */
```

### L101 ★

```text
/* Sig #7: client.dll site 0x1000d30f decryptor 0x1000d700 K=0x40 F=59 L=58 */
```

### L103 ★

```text
/* Sig #8: client.dll site 0x1000cc11 decryptor 0x1000df50 K=0x40 F=58 L=57 */
```

### L105 ★

```text
/* Sig #9: client.dll site 0x1000cb35 decryptor 0x1000df50 K=0x40 F=58 L=57 */
```

### L107 ★

```text
/* Sig #10: client.dll site 0x10005c07 decryptor 0x10007780 K=0x2D F=53 L=52 */
```

### L109 ★

```text
/* Sig #11: client.dll site 0x1000c5fc decryptor 0x1000e4a0 K=0x40 F=48 L=47 */
```

### L111 ★

```text
/* Sig #12: client.dll site 0x1000ce27 decryptor 0x1000e4a0 K=0x40 F=48 L=47 */
```

### L113 ★

```text
/* Sig #13: client.dll site 0x1000657b decryptor 0x10006ce0 K=0x2D F=45 L=44 */
```

### L115 ★

```text
/* Sig #14: client.dll site 0x1000c6cb decryptor 0x1000e350 K=0x40 F=39 L=38 */
```

### L117 ★

```text
/* Sig #15: client.dll site 0x10005f56 decryptor 0x100073a0 K=0x2D F=38 L=37 */
```

### L119 ★

```text
/* Sig #16: netc.dll site 0x10020591 decryptor 0x100073a0 K=0x2D F=38 L=37 */
```

### L121 ★

```text
/* Sig #17: client.dll site 0x1000d062 decryptor 0x1000dd20 K=0x40 F=37 L=36 */
```

### L123 ★

```text
/* Sig #18: client.dll site 0x1000d463 decryptor 0x1000d5b0 K=0x40 F=34 L=33 */
```

### L125 ★

```text
/* Sig #19: client.dll site 0x10006684 decryptor 0x10006c00 K=0x2D F=26 L=25 */
```

### L127 ★

```text
/* Sig #20: client.dll site 0x1000d3c2 decryptor 0x10006c00 K=0x2D F=26 L=25 */
```

### L135

```text
/* F = L + 1 */
```

## `nrth_config.cpp`

### L1 ★

```text
/**
 * ============================================================================
 * nrth_config.cpp — Configuration loader/writer matching original NRTH.dll
 * ============================================================================
 * Evidence:
 *   - VA 0x1001fcff: decrypts "C:\Overwack\loader_config.cfg" (K=0x20)
 *   - VA 0x1001fdc5: decrypts " no_spoofer=%d" (K=0x20)
 *   - VA 0x1001fd7b: decrypts " menu_key=%d" (K=0x20, default 45 = VK_INSERT)
 *   - VA 0x100eb018: "OVRCFG" header in .ovr profile files
 * ============================================================================
 */
```

### L25

```text
/* menuKey = 45 (VK_INSERT) */
```

### L26

```text
/* noSpoofer = 0            */
```

### L27

```text
/* watermark                */
```

### L28

```text
/* notifications            */
```

### L62

```text
/* " no_spoofer=%d" */
```

### L63

```text
/* " menu_key=%d"   */
```

### L105

```text
/* " no_spoofer=%d" */
```

### L106

```text
/* " menu_key=%d"   */
```

## `nrth_config.h`

### L2 ★

```text
/**
 * ============================================================================
 * nrth_config.h — Configuration loader/writer matching original NRTH.dll
 * ============================================================================
 * Evidence:
 *   - Config path decrypted at VA 0x1001fcff (K=0x20): "C:\Overwack\loader_config.cfg"
 *   - Format tokens:
 *       " no_spoofer=%d" (VA 0x1001fdc5, K=0x20)
 *       " menu_key=%d"   (VA 0x1001fd7b, K=0x20, default 45 = VK_INSERT)
 *   - UI Config -> Save writes ".ovr" ("OVRCFG" header) + loader_config.cfg
 * ============================================================================
 */
```

### L26

```text
/* default 45 (VK_INSERT), parsed from " menu_key=%d"   */
```

### L27

```text
/* default 0, parsed from " no_spoofer=%d"              */
```

### L28

```text
/* UI Watermark toggle                                  */
```

### L29

```text
/* UI Notifications toggle                              */
```

### L35 ★

```text
/* Decrypts and returns "C:\Overwack\loader_config.cfg" (VA 0x1001fcff, K=0x20) */
```

### L38 ★

```text
/* Decrypts and returns " menu_key=%d" (VA 0x1001fd7b, K=0x20) */
```

### L41 ★

```text
/* Decrypts and returns " no_spoofer=%d" (VA 0x1001fdc5, K=0x20) */
```

### L44

```text
/* Loads config from `overridePath` if non-NULL, otherwise tries
 * "C:\Overwack\loader_config.cfg" then local "loader_config.cfg". */
```

### L48

```text
/* Saves config to `overridePath` if non-NULL, otherwise writes to
 * "C:\Overwack\loader_config.cfg" (creating C:\Overwack on Windows)
 * and mirrors to local "loader_config.cfg". */
```

### L53

```text
/* Parses raw text buffer containing " no_spoofer=%d" and/or " menu_key=%d" into *cfg */
```

### L56

```text
/* Formats *cfg into `outBuf` using the decrypted format tokens */
```

### L59

```text
/* Writes a named .ovr profile ("OVRCFG\n...") and updates loader_config.cfg */
```

## `nrth_dll.def`

### L1

```text
; NRTH.dll export definition (MinGW / MSVC compatible)
```

### L2 ★

```text
; Evidence: export ordinal 1, name "NVXHookProc" (RVA 0x0000B9E0 in the sample),
```

### L3

```text
; PE Export Directory internal module name "nvx.dll" (linked as nvx.dll, deployed as NRTH.dll).
```

### L4

```text
; Loader resolves the export via GetProcAddress(hMod, "NVXHookProc").
```

### L5

```text
; The alias maps the undecorated export name to the i386 stdcall symbol
```

### L6

```text
; (_NVXHookProc@12) produced by the compiler.
```

## `nrth_fonts.h`

### L2

```text
/**
 * ============================================================================
 * nrth_fonts.h — Embedded TrueType Fonts for DARKANARCHY (by XRAOUF)
 *   - kFontEnglishTTF : ChakraPetch-SemiBold.ttf (78,604 bytes, Latin/English UI)
 *   - kFontArabicTTF  : IBMPlexSansArabic-SemiBold.ttf (244,500 bytes, Arabic UI +
 *                       100% Arabic Presentation Forms-B U+FE70..U+FEFC)
 * ============================================================================
 */
```

## `nrth_hook.cpp`

### L1 ★

```text
/**
 * ============================================================================
 * NRTH.dll — Behavioral & Structural Reconstruction (Result Class R2)
 * Reconstructed from reverse engineering of native x86 library "NRTH.dll"
 * (SHA-256 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861)
 * ============================================================================
 * PURPOSE: authorized MTA:SA blue-team private-server validation & parity
 *          verification ONLY. Not for public-server use.
 *
 * Evidence map (original VAs / RVAs):
 *   NVXHookProc               VA 0x1000b9e0 (RVA 0x0b9e0)  export ordinal 1 (nvx.dll)
 *   DllMain                   VA 0x1000ba00 (RVA 0x0ba00)  pin + MainInitThread
 *   MainInitThread            VA 0x1000a850 (RVA 0x0a850)  config/ADS/probes + LdrLoadDll + D3D9 hook
 *   Hooked_LdrLoadDll         VA 0x1000a640 (RVA 0x0a640)  trigger on client.dll / netc.dll
 *   ResolvePattern_10002960   VA 0x10002960 (RVA 0x02960)  wildcard byte-pattern scanner
 *   ArmClient_10005b80        VA 0x10005b80 (RVA 0x05b80)  11 scans + 11 MH_CreateHook calls
 *     Handlers: 0x10002ff0, 0x100047b0, 0x100050a0, 0x10005290, 0x100052b0,
 *               0x10005620, 0x100056c0, 0x100056f0, 0x10005ab0, 0x10005b30, 0x10005b50
 *   ResolveClientOffsets      VA 0x1000c400 (RVA 0x0c400)  20 pattern scans, 0 hooks
 *   PatchByte_10011870        VA 0x10011870 (RVA 0x11870)  VirtualProtect(ptr,1,0x40) + list 0x101493e4
 *   ArmNetc_10020640          VA 0x10020640 (RVA 0x20640)  netc.dll scans + hooks + 0xC3 patches
 *   GetD3D9DeviceVTable       VA 0x10012980 (RVA 0x12980)  pattern scan C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86
 *   InstallD3D9Hooks          VA 0x10016300 (RVA 0x16300)  Present idx 17 / Reset idx 16 + Cursor hooks
 *   Hooked_Present            VA 0x10014d50 (RVA 0x14d50)  Dear ImGui 1.92.9 WIP overlay
 *   Hooked_Reset              VA 0x1001a3c0 (RVA 0x1a3c0)  device-loss handling
 *   Hooked_WndProc            VA 0x10015ed0 (RVA 0x15ed0)  SetWindowLongW subclass + VK_INSERT toggle
 * ============================================================================
 */
```

### L58 ★

```text
/* ===========================================================================
 * Exported hook procedure (export ordinal 1, name "NVXHookProc" in nvx.dll).
 * Placed at exact RVA 0x0000B9E0 (VA 0x1000B9E0) in the PE32 build when
 * nrth_hook.o is linked first after dllcrt2.o (0x10001010 + 0xA9D0 = 0x1000B9E0).
 * =========================================================================== */
```

### L86 ★

```text
/* ===========================================================================
 * Pattern compiler & scanner — matches original resolver VA 0x10002960
 * =========================================================================== */
```

### L166

```text
/* ===========================================================================
 * Decrypted pattern helpers (single-use gate L = F - 1 over kNrthEncryptedSigs)
 * =========================================================================== */
```

### L182 ★

```text
/* ===========================================================================
 * Global state: Lua VM bridge (0x1013bf04), Sync structs, Report channels
 * =========================================================================== */
```

### L238 ★

```text
/* ===========================================================================
 * Single-byte patch writer VA 0x10011870 & patch list VA 0x101493e4
 * =========================================================================== */
```

### L279 ★

```text
/* 0x40 */
```

### L299 ★

```text
/* ===========================================================================
 * 11 client.dll hook handlers (installed by ArmClient_10005b80 at 0x10005b80)
 * Decoded from NRTH.dll (0x10002ff0..0x10005b50) with exact calling conventions:
 *   #00 0x10002ff0: __thiscall (ret 0x18) — captures 6 client interface pointers
 *   #01 0x100047b0: __cdecl    (ret)      — luaL_loadbuffer / script loader hook
 *   #02 0x100050a0: __cdecl    (ret)      — TriggerServerEvent / event filter
 *   #03 0x100056f0: __cdecl    (ret)      — Lua debug / state hook
 *   #04 0x10005290: __thiscall (ret 0x1c) — captures CResourceManager thisPtr
 *   #05 0x100052b0: __thiscall (ret 0x1c) — CResource creation tracker
 *   #06 0x10005620: __thiscall (ret 0x04) — CResource removal tracker
 *   #07 0x100056c0: __thiscall (ret 0x20) — Anti-ScreenShot / screen capture guard
 *   #08 0x10005ab0: __thiscall (ret 0x18) — World/projectile Vec3 override
 *   #09 0x10005b30: __thiscall (ret 0x08) — Client pass-through hook
 *   #10 0x10005b50: __cdecl    (ret)      — Anti-ScreenShot secondary guard
 * =========================================================================== */
```

### L318 ★

```text
/* 14 Lua C API pointers resolved by ResolveClientOffsets_1000c390 (VA 0x1013c974..0x1013c9a8) */
```

### L342

```text
/* Scan #10 (Sig #12) */
```

### L343

```text
/* Scan #16 (Sig #7)  */
```

### L344

```text
/* Scan #15 (Extra #6)*/
```

### L345

```text
/* Scan #03 (Extra #0)*/
```

### L346

```text
/* Scan #00 (Sig #4)  */
```

### L347

```text
/* Scan #07 (Sig #8)  */
```

### L348

```text
/* Scan #05 (Sig #1)  */
```

### L349

```text
/* Scan #02 (Sig #14) */
```

### L350

```text
/* Scan #19 (Extra #7)*/
```

### L351

```text
/* Scan #18 (Sig #18) */
```

### L352

```text
/* Scan #13 (Sig #17) */
```

### L353

```text
/* Scan #04 (Extra #1)*/
```

### L354

```text
/* Scan #01 (Sig #11) */
```

### L355

```text
/* Scan #14 (Extra #5)*/
```

### L366 ★

```text
/* Custom Lua `api` closures registered by sub_10010ff0 (0x1000f920..0x100112a0) */
```

### L379

```text
/* LUA_TSTRING */
```

### L399

```text
/* LUA_TTABLE */
```

### L618 ★

```text
/* #00 0x10002ff0: __thiscall with 6 stack args (ret 0x18) */
```

### L638 ★

```text
/* #01 0x100047b0: __cdecl with 4 stack args (ret) — luaL_loadbuffer hook */
```

### L655 ★

```text
/* #02 0x100050a0: __cdecl with 7 stack args (ret) — TriggerServerEvent hook */
```

### L661 ★

```text
/* Matches 0x10005220: xor al, al when event is blocked */
```

### L671 ★

```text
/* #03 0x10005290: __thiscall with 7 stack args (ret 0x1c) */
```

### L686 ★

```text
/* #04 0x100052b0: __thiscall with 7 stack args (ret 0x1c) */
```

### L713 ★

```text
/* #05 0x10005620: __thiscall with 1 stack arg (ret 0x4) */
```

### L732 ★

```text
/* #06 0x100056c0: __thiscall with 8 stack args (ret 0x20) — Anti-ScreenShot guard */
```

### L749 ★

```text
/* #07 0x100056f0: __cdecl with 3 stack args (ret) — TriggerClientEvent / CMapEventManager::Call */
```

### L755 ★

```text
/* Matches 0x10005862: xor al, al */
```

### L765 ★

```text
/* #08 0x10005ab0: __thiscall with 6 stack args (ret 0x18) — Crasher position override */
```

### L780 ★

```text
/* Matches 0x10005ad5..0x10005afb: if bCrasher (0x1013c938) != 0, set vec3 to 0x4f800000 */
```

### L782 ★

```text
/* 0x4f800000 */
```

### L789 ★

```text
/* #09 0x10005b30: __thiscall with 2 stack args (ret 0x8) */
```

### L800 ★

```text
/* #10 0x10005b50: __cdecl with 1 stack arg (ret) — Anti-ScreenShot guard #2 */
```

### L815

```text
/* Headless / Linux verification mode */
```

### L834 ★

```text
/* All 11 patterns from 0x10005b80 in NRTH.dll (7 from kNrthEncryptedSigs + 4 full patterns) */
```

### L836

```text
/* Sig #10 */
```

### L837

```text
/* Sig #5  */
```

### L838

```text
/* Sig #3  */
```

### L839

```text
/* Sig #15 */
```

### L846

```text
/* Sig #6  */
```

### L850

```text
/* Sig #13 */
```

### L851

```text
/* Sig #19 */
```

### L871 ★

```text
/* ===========================================================================
 * 4 netc.dll hook handlers (installed by ArmNetc_10020640 at 0x10020640)
 * VAs: 0x1001dd30, 0x1001dd90, 0x1001df90, 0x1001fa80
 * =========================================================================== */
```

### L883

```text
/* Sig #16 */
```

### L915

```text
/* ===========================================================================
 * ArmClient_10005b80 — 11 pattern scans + 11 MH_CreateHook installations
 * =========================================================================== */
```

### L921 ★

```text
/* 0x10005c07 -> 0x10002ff0 */
```

### L922 ★

```text
/* 0x10005d28 -> 0x100047b0 */
```

### L923 ★

```text
/* 0x10005e54 -> 0x100050a0 */
```

### L924 ★

```text
/* 0x10005f56 -> 0x100056f0 */
```

### L925 ★

```text
/* 0x10006230 -> 0x10005620 */
```

### L926 ★

```text
/* 0x10006450 -> 0x10005ab0 */
```

### L927 ★

```text
/* 0x1000657b -> 0x10005b30 */
```

### L973 ★

```text
/* ===========================================================================
 * ResolveClientOffsets_1000c390 (VA 0x1000c400) — 20 pattern scans on client.dll
 * =========================================================================== */
```

### L980 ★

```text
/* Exact 20 pattern scans in Scan #00..#19 order decoded from 0x1000c400..0x1000d587 in NRTH.dll */
```

### L982 ★

```text
/* #00 0x1000c59e -> 0x1013c984 (lua_pushcclosure) */
```

### L984 ★

```text
/* #01 0x1000c66e -> 0x1013c9a4 (lua_setfield) */
```

### L986 ★

```text
/* #02 0x1000c73e -> 0x1013c990 (lua_gettop) */
```

### L988 ★

```text
/* #03 0x1000c80e -> 0x1013c980 (lua_tolstring) */
```

### L990 ★

```text
/* #04 0x1000c99f -> 0x1013c9a0 (lua_createtable) */
```

### L992 ★

```text
/* #05 0x1000cabe -> 0x1013c98c (lua_tonumber) */
```

### L994 ★

```text
/* #06 0x1000cba6 -> unused */
```

### L996 ★

```text
/* #07 0x1000cc82 -> 0x1013c988 (lua_type) */
```

### L998 ★

```text
/* #08 0x1000cd35 -> unused */
```

### L1000 ★

```text
/* #09 0x1000cdd9 -> unused */
```

### L1002 ★

```text
/* #10 0x1000ce7f -> 0x1013c974 (lua_pcall) */
```

### L1004 ★

```text
/* #11 0x1000cf36 -> unused */
```

### L1006 ★

```text
/* #12 0x1000d016 -> unused */
```

### L1008 ★

```text
/* #13 0x1000d0ba -> 0x1013c99c (lua_settop) */
```

### L1010 ★

```text
/* #14 0x1000d180 -> 0x1013c9a8 (lua_rawgeti) */
```

### L1012 ★

```text
/* #15 0x1000d29e -> 0x1013c97c (lua_rawseti) */
```

### L1014 ★

```text
/* #16 0x1000d367 -> 0x1013c978 (lua_objlen) */
```

### L1016 ★

```text
/* #17 0x1000d41a -> unused */
```

### L1018 ★

```text
/* #18 0x1000d4bb -> 0x1013c998 (lua_pushstring) */
```

### L1020 ★

```text
/* #19 0x1000d571 -> 0x1013c994 (lua_pushnumber) */
```

### L1033 ★

```text
/* Populate the 14 Lua C API pointers (0x1013c974..0x1013c9a8) in exact 0x1000c5d3..0x1000d587 order */
```

### L1055 ★

```text
/* ===========================================================================
 * ArmNetc_10020640 — 6 pattern scans (0x10023670..0x10023030) +
 *                    4 MH_CreateHook calls + 6 0xC3 prepare/write pairs
 * =========================================================================== */
```

### L1063 ★

```text
/* 0x10023670: "55 8B EC 53 56 57 8B 7D ? 33 F6 32 DB" */
```

### L1064 ★

```text
/* 0x10023530 */
```

### L1065 ★

```text
/* 0x100233f0 */
```

### L1066 ★

```text
/* 0x100232b0 */
```

### L1067 ★

```text
/* 0x10023170 */
```

### L1068 ★

```text
/* 0x10023030 */
```

### L1117 ★

```text
/* ===========================================================================
 * GetD3D9DeviceVTable — evidence VA 0x10012980
 * Scans d3d9.dll in memory for the CD3DBase constructor sequence:
 *   C7 06 <vtable_ptr32> 89 86 <disp32> 89 86
 * and dereferences the 32-bit vtable pointer at (match + 2).
 * =========================================================================== */
```

### L1154

```text
/* ===========================================================================
 * Accessors for verification & UI inspection
 * =========================================================================== */
```

### L1217 ★

```text
/* ===========================================================================
 * In-game feature execution & GTA:SA 1.0 US / MTA actions (0x10001d80..0x1002f370)
 * =========================================================================== */
```

### L1295 ★

```text
/* Matches Airbreak_10001d80 (VA 0x10001d80..0x100021f0 in NRTH.dll):
 * Reads camera heading at 0x00B6F258, current vehicle at 0x00BA18FC / local ped at 0x00B6F5F0,
 * and moves position along WASD + VK_SPACE / VK_CONTROL while zeroing velocity. */
```

### L1333 ★

```text
/* Forward / backward along camera heading (0x00B6F258) */
```

### L1351 ★

```text
/* Zero move speed (entity + 0x44..0x4C) and turn speed (entity + 0x54..0x5C) */
```

### L1365 ★

```text
/* Matches All Weapons button handler at VA 0x1002a5a7: calls GTA:SA CWeaponCheat (0x004385B0) */
```

### L1380 ★

```text
/* Matches Jetpack button handler at VA 0x1002a86c: calls GTA:SA CJetpackCheat (0x00439600) */
```

### L1395 ★

```text
/* Matches RepairCurrentVehicle at VA 0x1002f070 */
```

### L1411 ★

```text
/* Matches StartCurrentVehicleEngine at VA 0x1002f0f0 */
```

### L1427 ★

```text
/* Matches UnlockNearestVehicle at VA 0x1002eea0 */
```

### L1440 ★

```text
/* Matches Vehicle Stop button & Fast Stop at VA 0x10030306 */
```

### L1460 ★

```text
/* Matches Bomb Car / Destroy at VA 0x10030510 */
```

### L1533 ★

```text
/* Matches StopClientResource at VA 0x100054a0..0x10005618 in NRTH.dll:
 * Finds resName in s_activeResources, calls g_ClientHooks_10005b80[6].origTrampoline(g_ResourceMgr_1013c948, resPtr),
 * removes it from active resources, and records it in s_stoppedResources for api.StoppedResources(). */
```

### L1572 ★

```text
/* Matches per-frame game feature loop in Hooked_Present (VA 0x10015812..0x10015aa0) */
```

### L1576 ★

```text
/* Match 0x10015812 in NRTH.dll: do not touch GTA:SA memory until CClientGame (0x10148ee8) is active */
```

### L1586 ★

```text
/* 1. Direct GTA:SA global cheat flags (only written in-game at 0x10015a7a..0x10015a8a):
     *    0x00969160 = bDriveOnWater (0x10015a7a)
     *    0x00969152 = bCarsCanFly   (0x10015a8a) */
```

### L1596 ★

```text
/* 2. Local player ped (0x00B6F5F0): Give HP, Give Armor, GodMode */
```

### L1614 ★

```text
/* 3. Current vehicle (0x00BA18FC): Vehicle God-Mode, Fast Stop, Repair, Start Engine, Unlock */
```

### L1634 ★

```text
/* 4. AirBreak movement tick (0x10001d80) */
```

### L1641

```text
/* ===========================================================================
 * Windows-only runtime hooks (DllMain, MainInitThread, LdrLoadDll, D3D9, ImGui)
 * =========================================================================== */
```

### L1661 ★

```text
/* RVA 0x0a640 hook target */
```

### L1662 ★

```text
/* vtable slot 17 (0x44)   */
```

### L1663 ★

```text
/* vtable slot 16 (0x40)   */
```

### L1664 ★

```text
/* RVA 0x162c0             */
```

### L1665 ★

```text
/* RVA 0x16290             */
```

### L1666 ★

```text
/* RVA 0x16260             */
```

### L1703

```text
/* If loaded locally inside NORTH LOADER.exe, do not spawn game hook threads */
```

### L1775 ★

```text
/* ===========================================================================
 * Cursor lock hooks (VA 0x10016260, 0x10016290, 0x100162c0 in NRTH.dll)
 * While the menu is open (g_bMenuOpen == true), block GTA:SA / MTA from
 * recentering, hiding, or clipping the cursor.
 * =========================================================================== */
```

### L1841 ★

```text
/* ===========================================================================
 * Live netc.dll SendPacket & anti-cheat report detours (VA 0x1001da80..0x10020640)
 * =========================================================================== */
```

### L1859 ★

```text
/* Match 0x1001dbf6..0x1001dc2a in NRTH.dll: block packet IDs 0x5B, 0x5C, 0x5D */
```

### L1869

```text
/* Check UI packet log & per-packet block flag */
```

### L1900 ★

```text
/* 6 single-byte 0xC3 patch patterns decoded from 0x10020640 (0x1013b750..0x1013bc48) in NRTH.dll */
```

### L1902 ★

```text
/* #01 (0x10020681, 0x1013baa0) */
```

### L1904 ★

```text
/* #03 (0x1002083b, 0x1013b9b8) */
```

### L1906 ★

```text
/* #04 (0x100208af, 0x1013bc48) */
```

### L1908 ★

```text
/* #10 (0x10020ec8, 0x1013b8b8) */
```

### L1910 ★

```text
/* #13 (0x1002143f, 0x1013bb78) */
```

### L1912 ★

```text
/* #14 (0x10021573, 0x1013b750) */
```

### L1923 ★

```text
/* 7 guard detours + SendPacket detour (0x1001da80) decoded from 0x10020640 in NRTH.dll */
```

### L1927 ★

```text
/* #02 (0x100206f5, 0x1013b9d0) -> 0x1001dc30 */
```

### L1930 ★

```text
/* #05 (0x100209dd, inline 0x10021d30) -> 0x1001dc40 */
```

### L1933 ★

```text
/* #06 (0x10020ba8, 0x1013b808) -> 0x1001f500 */
```

### L1936 ★

```text
/* #07 (0x10020c42, 0x1013b860) -> 0x1001f500 */
```

### L1939 ★

```text
/* #08 (0x10020cdc, 0x1013bb54) -> 0x1001f500 */
```

### L1942 ★

```text
/* #09 (0x10020d76, 0x1013bd10) -> 0x1001dc50 */
```

### L1945 ★

```text
/* #11 (0x10020f4b, inline 0x10021bd0) -> 0x10001d20 */
```

### L1948 ★

```text
/* #12 (0x100211ee, inline 0x10022ac0) -> 0x1001da80 */
```

### L1997 ★

```text
/* Matches 0x1000a888..0x1000aca0 in NRTH.dll: ensure C:\NVX, C:\NVX\logs, C:\NVX\dump exist */
```

### L2002

```text
/* Load C:\NVX\loader_config.cfg or C:\Overwack\loader_config.cfg */
```

### L2011

```text
/* Decrypt "ntdll.dll" and "LdrLoadDll" (single-use gate L = F - 1) */
```

### L2034 ★

```text
/* Check if client.dll / netc.dll are already loaded (matches 0x1000ace9..0x1000ad34 in NRTH.dll) */
```

### L2037 ★

```text
/* Initialize D3D9 Present/Reset + Cursor hooks (matches 0x1000ad76 -> 0x10016300 in NRTH.dll) */
```

### L2049 ★

```text
/* Background watch loop (matches 0x1000a820 in NRTH.dll) */
```

### L2073 ★

```text
/* Matches 0x1000a640..0x1000a81d in NRTH.dll: check if ModuleFileName contains client.dll or netc.dll */
```

### L2124 ★

```text
/* Matches 0x10012980..0x10012bb5 in NRTH.dll:
     * Pattern-scan d3d9.dll (from base, up to min(SizeOfImage, 0x128000)) for
     * C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86 without creating a dummy D3D9 device/window. */
```

### L2169

```text
/* Hooks #2 & #3: Present (17) + Reset (16) */
```

### L2200 ★

```text
/* Matches Hooked_WndProc at VA 0x10015ed0 in NRTH.dll */
```

### L2212 ★

```text
/* Block mouse input from reaching GTA:SA while the menu is open (0x100161cb..0x10016220) */
```

### L2245 ★

```text
/* Matches 0x10014e8d..0x100154df in NRTH.dll: obtain focus window from D3DDEVICE_CREATION_PARAMETERS */
```

### L2271

```text
/* Load embedded DARKANARCHY fonts (nrth_fonts.h):
     *  - English: ChakraPetch-SemiBold.ttf
     *  - Arabic : IBMPlexSansArabic-SemiBold.ttf with full Presentation Forms-B */
```

### L2277

```text
/* Latin basics + supplements for mixed labels */
```

### L2278

```text
/* Arabic */
```

### L2279

```text
/* Arabic Supplement */
```

### L2280

```text
/* Arabic Extended-A */
```

### L2281

```text
/* Arabic Presentation Forms-A (ligatures) */
```

### L2282

```text
/* Arabic Presentation Forms-B */
```

### L2307 ★

```text
/* Subclass game window with SetWindowLongW (matches 0x100154df in NRTH.dll) */
```

### L2347 ★

```text
/* Matches 0x100155bf..0x100155d6 in NRTH.dll: check TestCooperativeLevel before rendering */
```

### L2369 ★

```text
/* Execute in-game feature logic on every frame (matches 0x10015812..0x10015aa0) */
```

### L2404

```text
/* _WIN32 && !NRTH_HEADLESS_TEST */
```

## `nrth_hook.h`

### L2 ★

```text
/**
 * ============================================================================
 * NRTH.dll — Interface, Resolver, Hook & State Reconstruction Header
 * Reverse engineered from native x86 library "NRTH.dll"
 * (SHA-256 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861)
 * ============================================================================
 */
```

### L30

```text
/* ---- Counts matching original NRTH.dll ----------------------------------- */
```

### L31 ★

```text
/* VA 0x10005b80: 11 scans + 11 hooks */
```

### L32 ★

```text
/* VA 0x10020640: 6 scans             */
```

### L33 ★

```text
/* VA 0x10020640: 4 hooks             */
```

### L34 ★

```text
/* VA 0x10020640: 6 0xC3 writes       */
```

### L35 ★

```text
/* VA 0x1000c390: 20 scans, 0 hooks   */
```

### L36

```text
/* 1 LdrLoadDll + 2 D3D9 + 11 + 4     */
```

### L37

```text
/* 11 + 6 + 20                        */
```

### L38 ★

```text
/* VA 0x1013bf04 table capacity       */
```

### L40 ★

```text
/* ---- Patch descriptor in list VA 0x101493e4 (written by 0x10011870) ------ */
```

### L42 ★

```text
/* mov byte ptr [ebp-disp8], 0xC3 site VA          */
```

### L43 ★

```text
/* call 0x10011870 site VA (prepVa + 11)           */
```

### L44 ★

```text
/* pattern buffer VA (0x10023670..0x10023030)      */
```

### L45

```text
/* resolved target address in netc.dll             */
```

### L46

```text
/* original prologue byte before write             */
```

### L47 ★

```text
/* written byte (0xC3 = RET)                       */
```

### L48

```text
/* 1 if written to targetAddr                      */
```

### L52 ★

```text
/* ---- Hook descriptor for client.dll (0x10005b80) & netc.dll (0x10020640) - */
```

### L55 ★

```text
/* Original handler VA (e.g. 0x10002ff0)        */
```

### L56 ★

```text
/* Original pattern construction site VA        */
```

### L57 ★

```text
/* Positional XOR key (0x2D / 0x20 / 0x40)      */
```

### L58 ★

```text
/* Wildcard byte pattern for 0x10002960         */
```

### L59

```text
/* Reconstructed detour function pointer        */
```

### L60

```text
/* Resolved address in target module            */
```

### L61

```text
/* MinHook original trampoline                  */
```

### L62

```text
/* True after MH_CreateHook + MH_EnableHook     */
```

### L65 ★

```text
/* ---- Lua VM registry slot at 0x1013bf04 (stride 0x1C, L at +0x18) -------- */
```

### L68 ★

```text
/* +0x00..+0x17 resource metadata             */
```

### L69 ★

```text
/* +0x18..+0x1B lua_State* (total = 0x1C)     */
```

### L91

```text
/* ---- Sync state structs (RTTI in .data: SPlayerHealthSync / SWeaponAimSync) */
```

### L93

```text
/* Give HP / GodMode target health                 */
```

### L94

```text
/* Give Armor target armor                         */
```

### L95

```text
/* Invulnerability flag                            */
```

### L96

```text
/* Infinite ammo flag                              */
```

### L97

```text
/* Zero weapon spread flag                         */
```

### L98

```text
/* High jump flag                                  */
```

### L99

```text
/* AirBreak speed                                  */
```

### L100

```text
/* AirBreak increment                              */
```

### L101

```text
/* AirBreak active                                 */
```

### L102

```text
/* Jetpack active                                  */
```

### L103

```text
/* Continuous/active Give HP                       */
```

### L104

```text
/* Continuous/active Give Armor                    */
```

### L105 ★

```text
/* Vehicle God-Mode (0x101490b3)                   */
```

### L106

```text
/* Anti Fall Bike                                  */
```

### L107 ★

```text
/* Fast Stop (0x101490b8)                          */
```

### L108 ★

```text
/* Flying Car (0x10148f10 -> 0x969152)             */
```

### L109 ★

```text
/* Drive Water (0x101490a0 -> 0x969160)            */
```

### L110 ★

```text
/* Vehicle Chaos (0x101490b9)                      */
```

### L111 ★

```text
/* Unlock Car (0x10149088)                         */
```

### L112 ★

```text
/* Repair Car (0x101490c9 / 0x101490b1)            */
```

### L113 ★

```text
/* Start Engine (0x10149110 / 0x10148f11)          */
```

### L114 ★

```text
/* Crasher (0x1013c938 -> 0x4f800000 in 0x10005ab0)*/
```

### L129 ★

```text
/* ---- Report channel state (netc.dll 0x1001dd30..0x1001fa80) -------------- */
```

### L131

```text
/* PLAYER_SCREENSHOT                         */
```

### L132

```text
/* PLAYER_TRANSGRESSION                      */
```

### L133

```text
/* PLAYER_DIAGNOSTIC                         */
```

### L134

```text
/* PLAYER_ACINFO                             */
```

### L135

```text
/* PACKET_ID_CHEAT_CHALLENGEMEMORY           */
```

### L136

```text
/* Anti-ScreenShot / report filter active    */
```

### L139 ★

```text
/* ---- Exported hook procedure (ordinal 1) --------------------------------- */
```

### L142

```text
/* ---- Exposed internal mechanisms (for UI & verification tests) ----------- */
```

### L152

```text
/* ---- Accessors for tables and runtime counters --------------------------- */
```

### L168 ★

```text
/* ---- In-game feature execution & GTA:SA/MTA actions (0x10001d80..0x1002f370) */
```

## `nrth_ui.cpp`

### L1

```text
/**
 * ============================================================================
 * nrth_ui.cpp — DARKANARCHY (by XRAOUF) — Bilingual Overlay UI (AR + EN)
 * ============================================================================
 * Design:
 *   - Dark anarchist theme: coal black surfaces, blood-red accents, bone text.
 *   - Embedded fonts (nrth_fonts.h):
 *       English : ChakraPetch-SemiBold.ttf
 *       Arabic  : IBMPlexSansArabic-SemiBold.ttf (Presentation Forms-B complete)
 *   - Arabic text is rendered via presentation forms with a full contextual
 *     joining shaper (isolated/final/initial/medial + lam-alef ligatures) and
 *     a simplified UAX#9 BiDi visual reorder (LTR base paragraph).
 *   - Branding: DARKANARCHY / by XRAOUF with a drawn anarchy-A circle logo.
 * ============================================================================
 */
```

### L36 ★

```text
/* ===========================================================================
 * MTA PACKET_ID_* catalogue (.rdata 0x100e9be4..0x100eaaa4 & 0x100eb6a8)
 * =========================================================================== */
```

### L103 ★

```text
/* VA 0x100eb6a8 */
```

### L114

```text
/* Report channel #1 */
```

### L115

```text
/* Report channel #2 */
```

### L116

```text
/* Report channel #3 */
```

### L117

```text
/* Report channel #4 */
```

### L129

```text
/* ===========================================================================
 * Bilingual core: language state, fonts, UTF-8 helpers
 * =========================================================================== */
```

### L178

```text
/* ===========================================================================
 * Arabic contextual shaping engine (U+0600..U+06FF -> Presentation Forms B)
 * =========================================================================== */
```

### L181

```text
/* Non / Right / Dual joining */
```

### L185

```text
/* ء  HAMZA              */
```

### L186

```text
/* آ  ALEF MADDA         */
```

### L187

```text
/* أ  ALEF HAMZA ABOVE   */
```

### L188

```text
/* ؤ  WAW HAMZA          */
```

### L189

```text
/* إ  ALEF HAMZA BELOW   */
```

### L190

```text
/* ئ  YEH HAMZA          */
```

### L191

```text
/* ا  ALEF               */
```

### L192

```text
/* ب  BEH                */
```

### L193

```text
/* ة  TEH MARBUTA        */
```

### L194

```text
/* ت  TEH                */
```

### L195

```text
/* ث  THEH               */
```

### L196

```text
/* ج  JEEM               */
```

### L197

```text
/* ح  HAH                */
```

### L198

```text
/* خ  KHAH               */
```

### L199

```text
/* د  DAL                */
```

### L200

```text
/* ذ  THAL               */
```

### L201

```text
/* ر  REH                */
```

### L202

```text
/* ز  ZAIN               */
```

### L203

```text
/* س  SEEN               */
```

### L204

```text
/* ش  SHEEN              */
```

### L205

```text
/* ص  SAD                */
```

### L206

```text
/* ض  DAD                */
```

### L207

```text
/* ط  TAH                */
```

### L208

```text
/* ظ  ZAH                */
```

### L209

```text
/* ع  AIN                */
```

### L210

```text
/* غ  GHAIN              */
```

### L211

```text
/* ـ  TATWEEL            */
```

### L212

```text
/* ف  FEH                */
```

### L213

```text
/* ق  QAF                */
```

### L214

```text
/* ك  KAF                */
```

### L215

```text
/* ل  LAM                */
```

### L216

```text
/* م  MEEM               */
```

### L217

```text
/* ن  NOON               */
```

### L218

```text
/* ه  HEH                */
```

### L219

```text
/* و  WAW                */
```

### L220

```text
/* ى  ALEF MAKSURA       */
```

### L221

```text
/* ي  YEH                */
```

### L232

```text
/* Harakat / marks / invisible controls: transparent for the joining rules */
```

### L240

```text
/**
 * Core shaper: logical codepoint stream -> presentation forms (logical order).
 * Handles isolated/final/initial/medial selection and the mandatory
 * LAM+ALEF ligatures (U+FEF5..U+FEFC).
 */
```

### L249

```text
/* previous emitted joinable char connects forward */
```

### L258

```text
/* next non-transparent char */
```

### L263

```text
/* A following letter connects backward when it is D or R (not N) */
```

### L266

```text
/* Mandatory LAM + ALEF ligature */
```

### L277

```text
/* keep harakat */
```

### L278

```text
/* ligature (alef tail) does not join forward */
```

### L295

```text
/* ===========================================================================
 * Simplified UAX#9 BiDi visual reorder (LTR base paragraph)
 *   RTL strong chars -> level 1, numbers inside RTL -> level 2,
 *   neutrals adjacent to RTL -> level 1, strong LTR -> level 0.
 *   L2: reverse contiguous runs of level >= k for k = maxLevel..1.
 * =========================================================================== */
```

### L331

```text
/* neutral: follow neighbouring RTL strength */
```

### L381

```text
/* Rotation buffers for translated UI labels */
```

### L395

```text
/* ===========================================================================
 * Feature state & sliders (shared between UI and SPlayerHealthSync/SWeaponAimSync)
 * =========================================================================== */
```

### L428

```text
/* Feature label translation map (keys remain English for the settings logic) */
```

### L493 ★

```text
/* Vehicle features (0x10148f10..0x10149110 in NRTH.dll) */
```

### L522

```text
/* ===========================================================================
 * Shared live hook state (Resources, Events, Packets, Dumper, Markers)
 * =========================================================================== */
```

### L528

```text
/* resource name parsed from the chunk name */
```

### L554 ★

```text
/* Matches RecordCapturedScript (VA 0x10004220..0x10004473 in NRTH.dll) */
```

### L589 ★

```text
/* Matches Hook_Client_100050a0 & Hook_Client_100056f0 (VA 0x100050a0 / 0x100056f0 in NRTH.dll) */
```

### L622 ★

```text
/* Matches Hook_Client_100052b0 (VA 0x100052b0..0x10005494 in NRTH.dll) */
```

### L639

```text
/* Matches Hook_Netc_SendPacket_1001da80 packet table lookup */
```

### L671 ★

```text
/* ===========================================================================
 * Lua VM Bridge execution (0x1013bf04 registry stride 0x1C, L at +0x18,
 * default_L 0x1013c95c, loadbuffer 0x1013c94c with "@custom", pcall 0x1013c974,
 * flag 0x1013c939, script buffer 0x1013beec, VirtualQuery guard)
 * =========================================================================== */
```

### L734

```text
/* ===========================================================================
 * Full Dear ImGui + Embedded Lua 5.4.6 UI (Windows build)
 * =========================================================================== */
```

### L776

```text
/* Bounded substring search (the buffer may not be NUL-terminated). */
```

### L785

```text
/*
 * Build a sandbox wrapper that executes the user's code inside the target
 * MTA Lua VM WITHOUT corrupting the resource's logic:
 *
 *   - the user chunk runs with a private environment:
 *       writes  -> the sandbox table (never the resource globals)
 *       reads   -> fall through to the resource environment (getfenv(1))
 *   - execution is pcall()-protected, so a runtime error in the user code
 *     cannot leave the VM in a bad state.
 *
 * The MTA client VMs are Lua 5.1, so loadstring/setfenv/getfenv exist there.
 * Lua 5.1 has only ONE long-string form (]]...]]); equals-level long
 * brackets are a Lua 5.2 feature and are NOT valid in the MTA VMs (verified
 * on a Lua 5.1 build: the level-1 opener fails to parse). The user code is
 * therefore embedded as a long string when it contains no close sequence,
 * and as an escaped short string otherwise.
 *
 * Returns false if the wrapped script exceeds the 64 KB bridge buffer cap.
 */
```

### L851

```text
/* Sandbox the user code before it touches an MTA VM: global writes from
     * injected code used to clobber the target resource's environment, which
     * broke that resource's logic after injection. */
```

### L862

```text
/* Fallback to the embedded Lua 5.4.6 VM (isolated, no resource involved) */
```

### L864

```text
/* Fallback to the embedded Lua 5.4.6 VM using "@custom" chunk name */
```

### L895

```text
/* "Default VM", "@custom" */
```

### L922

```text
/* ---------------------------------------------------------------------------
 * DARKANARCHY theme: coal black + blood red + bone white
 * ------------------------------------------------------------------------- */
```

### L991

```text
/* ---------------------------------------------------------------------------
 * Anarchy-A circle logo drawn with the ImGui foreground draw list
 * ------------------------------------------------------------------------- */
```

### L1001

```text
/* glow rings */
```

### L1005

```text
/* A shape: apex at top of circle, legs to the lower-left/right chord points */
```

### L1007

```text
/* 225 deg (lower-left) & 315 deg (lower-right) */
```

### L1014

```text
/* crossbar extending slightly past the legs (classic anarchy A) */
```

### L1445

```text
/* Sanitize a name for use as a folder/file name on NTFS (keeps the charset
 * NTFS + path rules are happy with; everything else is dropped or '_'). */
```

### L1478

```text
/* Best-effort name of the server the client is attached to, for the dump
 * folder: the MTA client window title carries the server name while
 * connected (e.g. "MTA:SA - <server>"). Pure Win32, no memory offsets.
 * Falls back to "unknown" when no usable title can be read. */
```

### L1504

```text
/* Write one captured script to disk under the per-server tree:
 *   C:\NVX\dump\<server name>\<resource name>\<script file>
 */
```

### L1729 ★

```text
/* Action buttons matching 0x1002a580..0x1002a880 in NRTH.dll */
```

### L1761 ★

```text
/* ======================================================================
     * CSX spoofer feature (new) — faithful replica of CSX.exe "Reset MTA
     * Serial" (workhorse 0x0040EFF0, UI wrapper 0x0040FA60, helpers
     * 0x0040EC10/0x0040E8C0). Sample SHA-256 d5ed9e6a57952d2a2d7876813376784868126e9295ee55ba01b45a395fc4ee556.
     * All original offsets and the step-by-step method are documented in
     * csx_spoof/csx_spoof.h (evidence block) and CSX_REPORT.md.
     * Result category R2: behavioral reconstruction, not byte-for-byte.
     * ==================================================================== */
```

### L1944

```text
/* Writes both <name>.ovr ("OVRCFG") and C:\Overwack\loader_config.cfg */
```

### L2053 ★

```text
/* Matches PollHotkeys at VA 0x10012250 in NRTH.dll */
```

### L2063

```text
/* Toggle */
```

### L2069

```text
/* Hold */
```

### L2082 ★

```text
/* Watermark — DARKANARCHY | FPS | Server (matches VA 0x10012bc0) */
```

### L2126 ★

```text
/* Floating keybind list (matches VA 0x100130a0) */
```

### L2163 ★

```text
/* Toast notifications (matches VA 0x10016990) */
```

### L2194

```text
/* clip text to the toast width so long Arabic messages wrap safely */
```

### L2212

```text
/* ---------------- Header: logo + brand + byline + language toggle --- */
```

### L2231

```text
/* Language toggle (right side of header) */
```

### L2245

```text
/* ---------------- End header ---------------------------------------- */
```

### L2252

```text
/* stable IDs across languages */
```

### L2328

```text
/* Headless / non-Win32 build for verification tests */
```

## `nrth_ui.h`

### L2

```text
/**
 * ============================================================================
 * nrth_ui.h — DARKANARCHY (by XRAOUF) Overlay UI & MTA Packet / Feature Sync
 * ============================================================================
 * Bilingual UI (Arabic العربية + English) with embedded TrueType fonts:
 *   - English TTF : ChakraPetch-SemiBold.ttf
 *   - Arabic TTF  : IBMPlexSansArabic-SemiBold.ttf (with contextual shaper & BiDi)
 * ============================================================================
 */
```

### L29

```text
/* Bilingual & Arabic contextual shaping API */
```

### L35

```text
/* Arabic presentation-form shaper & simplified UAX#9 BiDi reorder
 * (exposed for verification tests; both are pure functions) */
```

### L44 ★

```text
/* ---- Live hook callbacks (0x100047b0, 0x100050a0, 0x100052b0, 0x1001da80) */
```

## `nrth_vehicle_names.inc`

### L1 ★

```text
// Auto-extracted GTA:SA vehicle name table from NRTH.dll .rdata (offsets 0x0e8554-0x0e8df4)
```

### L2

```text
// Evidence: used by the "Vehicles List" combo (##vehicles_combo). Generated from analysis/strings_catalog.txt.
```

## `test_parity.cpp`

### L1

```text
/**
 * ============================================================================
 * test_parity.cpp — End-to-end verification suite for NRTH reconstruction
 * ============================================================================
 */
```

### L33

```text
/* Helper: build a minimal valid PE32 image with a .text section and .rdata section */
```

### L39

```text
/* DOS header */
```

### L45 ★

```text
/* NT headers at 0x80 */
```

### L48 ★

```text
/* FileHeader: Machine=0x014C (i386), NumberOfSections=2, SizeOfOptionalHeader=0xE0, Characteristics=0x2102 */
```

### L54

```text
/* OptionalHeader32 at peOff + 24 */
```

### L56 ★

```text
/* PE32 magic 0x10B */
```

### L57 ★

```text
/* EntryPoint RVA = 0x1000 */
```

### L59 ★

```text
/* ImageBase = 0x10000000 */
```

### L62 ★

```text
/* Section headers at opt + 0xE0 */
```

### L64 ★

```text
/* Section 0: .text at RVA 0x1000, raw 0x400, size 0x2000 */
```

### L67

```text
/* VirtualSize */
```

### L70

```text
/* SizeOfRawData */
```

### L74 ★

```text
/* Section 1: .rdata at RVA 0x3000, raw 0x2400, size 0x2000 */
```

### L93

```text
/* Instantiateconcrete bytes matching a wildcard pattern ("55 8B ? ...") */
```

### L106

```text
/* Mock Lua callbacks for testing NrthUI_ExecuteLuaViaBridge */
```

### L132

```text
/* 1. Built-in nrth_audit self-test */
```

### L137

```text
/* 2. Verify nrth_dll.def exports LIBRARY nvx.dll and NVXHookProc @1 */
```

### L150

```text
/* 3. Verify nrth_codec.h single-use gate (L = F - 1) and all 20 encrypted sigs */
```

### L184

```text
/* 4. Verify NrthFindHiddenSignatures discovers all 20 encrypted signatures in .rdata */
```

### L190

```text
/* 4-byte align */
```

### L203

```text
/* 5. Verify nrth_config.cpp: C:\Overwack\loader_config.cfg, menu_key=%d (45), no_spoofer=%d */
```

### L225 ★

```text
/* 6. Verify D3D9 vtable pattern scanner (VA 0x10012980: C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86) */
```

### L230 ★

```text
/* mov dword ptr [esi], 0x12345678 */
```

### L231

```text
/* mov [esi+10h], eax              */
```

### L232

```text
/* mov [esi+...], eax              */
```

### L240 ★

```text
/* 7. Verify 37 pattern scans, 18 hooks, 6 0xC3 patches, and A/B audit detection */
```

### L252 ★

```text
/* Verify all 6 prepare/call pairs have exact 11-byte delta and pattern VAs 0x10023670..0x10023030 */
```

### L264

```text
/* Build synthetic client.dll and netc.dll PE32 images containing all 20 catalog signatures
         * plus the additional patterns so all 37 scans resolve and patch/detour cleanly. */
```

### L314

```text
/* Execute the 3 arming/resolver blocks on the .text section of armedClientPe and armedNetcPe */
```

### L332

```text
/* Verify NrthAuditDiff detects the 7 client.dll DETOUR_JMP32 footprints and 1 netc.dll KILL_RET footprint */
```

### L345

```text
/* 8. Verify Packet Catalogue, Report Channels, Sync Structs, and Lua VM Bridge */
```

### L367

```text
/* Exercise in-game feature tick & GTA:SA/MTA action helpers */
```

### L382 ★

```text
/* Live hook callbacks (0x10004220, 0x100050a0, 0x100052b0, 0x100054a0, 0x1001da80) */
```

### L387

```text
/* PACKET_ID_PLAYER_SCREENSHOT blocked by default */
```

### L388

```text
/* PACKET_ID_COMMAND allowed by default */
```

### L403

```text
/* 9. Verify built PE32 x86 binaries on disk (bin/NRTH.dll, bin/NORTH LOADER.exe, bin/NRTH_audit.dll) */
```

### L435 ★

```text
/* Verify NVXHookProc export RVA in bin/NRTH.dll matches original NRTH.dll (0x0000B9E0) */
```

### L452

```text
/* 10. Verify DARKANARCHY bilingual fonts + Arabic shaping/BiDi engine */
```

### L454

```text
/* 10a. Embedded TTF payloads are valid TrueType fonts */
```

### L464

```text
/* 10b. Language switch round-trip */
```

### L470

```text
/* 10c. Contextual shaping: "سلام" contains a mandatory LAM-ALEF ligature:
         * [FEB3 FEFC FEE1] (seen initial + lam-alef final + meem isolated) */
```

### L481

```text
/* Lam-Alef ligature: "لا" -> FEFB (isolated) */
```

### L488

```text
/* Connected lam-alef: "ملا" -> meem initial FEE3 + lam-alef final FEFC */
```

### L495

```text
/* Right-joining alef never connects forward: "أب" ->
             * alef-hamza isolated FE83 + beh isolated FE8F */
```

### L503

```text
/* Dual-joining chain: "بب" -> beh initial FE91 + beh final FE90 */
```

### L511

```text
/* 10d. Public shaping API: UTF-8 -> shaped + visually reordered UTF-8.
         * "سلام" shaped [FEB3 FEFC FEE1], visual (reversed) [FEE1 FEFC FEB3]
         * in UTF-8: "\xEF\xBB\xA1\xEF\xBB\xBC\xEF\xBA\xB3" */
```

### L522

```text
/* 10e. BiDi visual reorder (LTR base): Arabic run is reversed IN PLACE,
         * Latin run stays. Logical [شجرة abc] -> visual [ةرجش abc]. */
```

### L526

```text
/* شجرة = 0634 062C 0631 0629 */
```

### L536

```text
/* 10f. ASCII-only strings pass through untouched */
```

### L544

```text
/* 10g. Feature label translation table has an Arabic entry for every feature */
```

### L547

```text
/* FeatureTr is internal; verify indirectly through public state:
             * toggling language must not corrupt feature state */
```

---

★ = التعليق يحمل دليلاً مرجعياً (عنوان VA/RVA، هاش، رقم إصدار، مرجع قسم في تقرير).
