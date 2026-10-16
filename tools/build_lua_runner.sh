#!/bin/sh
# Build the minimal Lua 5.4 host from the sources inside vendor.zip.
#
#   tools/build_lua_runner.sh          # writes build/lua_runner
#
# vendor.zip carries Lua 5.4.6 (PUC-Rio, MIT) but not lua.c, so tools/lua_runner.c
# provides the interpreter. build/ is git-ignored: this is a generated artefact.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

out=build
mkdir -p "$out/lua"

python3 - <<'PY'
import os, zipfile
z = zipfile.ZipFile('vendor.zip')
os.makedirs('build/lua', exist_ok=True)
for name in z.namelist():
    if name.startswith('lua/') and name.endswith(('.c', '.h')) and not name.endswith('/'):
        base = os.path.basename(name)
        if base in ('ltests.c', 'ltests.h', 'lua.c'):   # test helpers / standalone main
            continue
        with open(os.path.join('build/lua', base), 'wb') as fh:
            fh.write(z.read(name))
print("lua sources extracted to build/lua")
PY

cc=${CC:-gcc}
$cc -O2 -std=c99 -DLUA_USE_LINUX -Ibuild/lua -o "$out/lua_runner" \
    tools/lua_runner.c build/lua/*.c -lm -ldl
echo "built $out/lua_runner"
