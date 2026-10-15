# tools/winshim — parse-only Windows shim

This directory exists for one reason: **three of the translation units in this
repository are entirely wrapped in `#if defined(_WIN32)`-style guards**
(`north_loader.cpp`, `nrth_hook.cpp`, and the overlay body of `nrth_ui.cpp`), so
a default Linux build compiles them to almost nothing. A mistake inside those
guards — a Python-style string concatenation, a typo in an initializer, a
missing declaration — passes every Linux check silently.

These headers let the Windows-only bodies be **parsed** on Linux:

```sh
tools/check_windows_bodies.sh
```

That script runs `g++ -fsyntax-only -D_WIN32` with `-I tools/winshim` plus the
Dear ImGui, Lua and MinHook headers from `vendor.zip`, so the guarded code is
type-checked and syntax-checked exactly as the Windows compiler would see it.

## What this shim is NOT

* It is **not** the Windows SDK and **not** MinGW headers. It declares only what
  the sources in this repository use.
* It is **not linkable and not runnable**. It produces no behaviour. Never add it
  to a Windows or Linux build.
* It does **not** model exact ABI details (calling conventions, struct layouts,
  vtable order). `__stdcall`/`__thiscall` are neutralised because the host is
  x86-64 Linux. Code that depends on real binary layout must still be validated
  on Windows.
* `csx_spoof/csx_spoof.h` here is a **stub**. The real header is *not* in this
  repository, so the real Windows build cannot succeed from these sources alone;
  the stub only mirrors the two call sites in `nrth_ui.cpp`.

## Why it is checked in

Because it caught a real defect the moment it was introduced, and it costs
nothing to keep: `check_windows_bodies.sh` is the only gate in this repository
that looks at the Windows-only bodies at all.
