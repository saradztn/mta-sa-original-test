#!/bin/sh
# Parse-check the Windows-only translation units on a Linux host.
#
#   tools/check_windows_bodies.sh
#
# Uses tools/winshim (parse-only Win32/D3D9 declarations, see its README) plus
# the Dear ImGui / Lua / MinHook headers extracted from vendor.zip. Compiles
# nothing to an executable: -fsyntax-only, so it is safe on any machine.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if ! command -v g++ >/dev/null 2>&1; then
    echo "g++ not found" >&2
    exit 2
fi

vendor=$(mktemp -d)
trap 'rm -rf "$vendor"' EXIT

if [ -f vendor.zip ]; then
    python3 -c "import zipfile,sys; zipfile.ZipFile('vendor.zip').extractall(sys.argv[1])" "$vendor"
    echo "vendor headers extracted from vendor.zip"
else
    echo "vendor.zip missing - ImGui/Lua/MinHook headers unavailable" >&2
    exit 2
fi

incs="-I tools/winshim -I $vendor/imgui -I $vendor/lua -I $vendor/minhook/include -I ."
files="north_loader.cpp nrth_hook.cpp nrth_ui.cpp"
fail=0

for f in $files; do
    if g++ -std=c++17 -fsyntax-only -D_WIN32 $incs "$f" 2>"$vendor/err.txt"; then
        n=$(grep -c 'warning:' "$vendor/err.txt" || true)
        echo "  [ OK ] $f (windows body parsed, $n warnings)"
    else
        echo "  [FAIL] $f"
        grep 'error:' "$vendor/err.txt" | head -20
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    echo "windows-body parse check FAILED" >&2
    exit 1
fi
echo "windows-body parse check passed"
