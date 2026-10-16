#!/bin/sh
# Run the offline test suite for the ac_heuristics resource.
#
#   resources/ac_heuristics/tests/run.sh
#
# Builds the Lua host (tools/build_lua_runner.sh) if it is missing, then runs the
# suite against the real resource files inside tests/mta_mock.lua. Nothing here
# touches a game or a network.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
[ -x build/lua_runner ] || ./tools/build_lua_runner.sh >/dev/null
exec ./build/lua_runner resources/ac_heuristics/tests/test_ac_heuristics.lua "$root"
