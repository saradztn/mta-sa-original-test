/* ============================================================================
 *  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
 *  Security & Vulnerability Research Team — White Hat Hackers
 * ----------------------------------------------------------------------------
 *  MTA:SA security research test bed — mta-sa-original-test
 *  Internal security research material. All rights reserved by the team above.
 * ============================================================================
 * lua_runner.c - minimal Lua 5.4 host used to run the offline test suites.
 *
 * vendor.zip ships the Lua sources but not the standalone interpreter (lua.c),
 * so this is the interpreter: open the standard libraries, run one script with
 * arg[1] set to the repository root, forward its exit code.
 *
 *   tools/build_lua_runner.sh && build/lua_runner script.lua
 *
 * Not part of any shipped product: test tooling only.
 */
#include <stdio.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <script.lua> [args...]\n", argv[0]);
        return 2;
    }
    lua_State *L = luaL_newstate();
    if (!L) {
        fprintf(stderr, "cannot create Lua state\n");
        return 2;
    }
    luaL_openlibs(L);
    /* standard Lua convention: arg[0] is the script, arg[1..] the extra args */
    lua_newtable(L);
    for (int i = 1; i < argc; i++) {
        lua_pushstring(L, argv[i]);
        lua_rawseti(L, -2, i - 1);
    }
    lua_setglobal(L, "arg");
    if (luaL_dofile(L, argv[1]) != LUA_OK) {
        fprintf(stderr, "%s\n", lua_tostring(L, -1));
        lua_close(L);
        return 1;
    }
    int rc = 0;
    if (lua_isnumber(L, -1)) {
        rc = (int)lua_tointeger(L, -1);
    }
    lua_close(L);
    return rc;
}
