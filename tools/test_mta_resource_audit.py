#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
#  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
#  Security & Vulnerability Research Team — White Hat Hackers
# ----------------------------------------------------------------------------
#  MTA:SA security research test bed — mta-sa-original-test
#  Internal security research material. All rights reserved by the team above.
# ============================================================================
"""
test_mta_resource_audit.py - self-test for tools/mta_resource_audit.py.

Everything here runs offline on fixture resources generated in a temp dir:
masking, argument splitting, every rule that the demo tree exercises, the
false-positive guards, the JSON report and the CLI exit codes.

    python3 tools/test_mta_resource_audit.py
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mta_resource_audit as audit  # noqa: E402

PASSED = 0
FAILED = 0


def check(cond, desc):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print("  [PASS] %s" % desc)
    else:
        FAILED += 1
        print("  [FAIL] %s" % desc)


def counts(findings):
    out = {}
    for f in findings:
        out[f.rule] = out.get(f.rule, 0) + 1
    return out


def write_resource(root, name, files, meta=None):
    rdir = os.path.join(root, name)
    os.makedirs(rdir, exist_ok=True)
    if meta is not None:
        with io.open(os.path.join(rdir, "meta.xml"), "w", encoding="utf-8") as fh:
            fh.write(meta)
    for rel, body in files.items():
        path = os.path.join(rdir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with io.open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    return rdir


def test_masking():
    print("mask_lua")
    src = 'local a = 1 -- loadstring(x)\nlocal b = "-- not a comment"\n'
    masked = audit.mask_lua(src)
    check("loadstring" not in masked, "line comment is blanked out")
    check('"-- not a comment"' in masked, "a string that looks like a comment survives")

    src2 = 'local t = [[loadstring(y)]] --[[ hidden\nloadstring(z)\n]]\nlocal u = 2\n'
    masked2 = audit.mask_lua(src2)
    check("loadstring(y)" in masked2, "long string content is data, not a comment")
    check("loadstring(z)" not in masked2, "long comment is blanked out")
    check(masked2.count("\n") == src2.count("\n"), "line count is preserved")

    src3 = 'local v = 3 --[==[ deep\ncomment\n]==]\nlocal w = 4\n'
    masked3 = audit.mask_lua(src3)
    check("deep" not in masked3 and "local w = 4" in masked3,
          "--[==[ level-N long comment is handled")


def test_split_args():
    print("split_args")
    masked = audit.mask_lua('addEventHandler("evt", root, function(a) return a end)')
    start = masked.index("addEventHandler(") + len("addEventHandler(")
    args, _end = audit.split_args(masked, start)
    check(len(args) == 3, "three top-level arguments found")
    check(masked[args[2][0]:args[2][1]].strip().startswith("function"),
          "anonymous handler is argument 3")

    masked2 = audit.mask_lua('f(a, g(b, c), "d,e", h[i, j])')
    args2, _e2 = audit.split_args(masked2, masked2.index("(") + 1)
    check(len(args2) == 4, "nested calls, commas in strings and table indexes do not split")

    masked3 = audit.mask_lua('addEventHandler("evt", root, myHandler, true)')
    args3, _e3 = audit.split_args(masked3, masked3.index("(") + 1)
    check(masked3[args3[2][0]:args3[2][1]].strip() == "myHandler",
          "named handler is argument 3")


def test_demo_tree(tmp):
    print("demo tree (vulnerable + fixed twin)")
    audit.make_demo(tmp)
    bad = os.path.join(tmp, "demo_bad")
    good = os.path.join(tmp, "demo_good")

    f_bad = audit.analyse(bad)
    f_good = audit.analyse(good)
    c_bad = counts(f_bad)

    expected = {
        "MTA001": 3,   # buyItem->dbExec, saveNote->fileWrite, adminStuff->givePlayerMoney
        "MTA002": 1,   # SQL built by concatenation
        "MTA003": 1,   # loadstring(msg)
        "MTA004": 1,   # fileOpen("notes/" .. name)
        "MTA005": 1,   # os.execute
        "MTA006": 1,   # escaped blob + dynamic exec
        "MTA007": 1,   # exported giveCash without ACL check
        "MTA008": 1,   # addEvent("onPlayerChat", true)
        "MTA009": 1,   # payload.dll inside the resource
        "MTA011": 1,   # client-settable element data
    }
    for rule, want in expected.items():
        check(c_bad.get(rule, 0) == want,
              "%s fires exactly %d time(s) on demo_bad (got %d)"
              % (rule, want, c_bad.get(rule, 0)))
    check(sum(c_bad.values()) == sum(expected.values()),
          "no unexpected rule fired on demo_bad (got %s)" % sorted(c_bad))
    check(f_good == [], "demo_good is clean (got %s)" % sorted(counts(f_good)))
    check(audit.mask_lua("") == "", "mask_lua handles an empty file")

    # an unreferenced executable in a subfolder is not a delivery channel
    tmp2 = os.path.join(tmp, "unref")
    write_resource(tmp2, "with_tools",
                   {"x.lua": "return true\n", "tools/helper.sh": "#!/bin/sh\n"},
                   meta='<meta><script src="x.lua" type="server"/></meta>')
    f_unref = audit.analyse(tmp2)
    unref = [x for x in f_unref if x.rule == "MTA009"]
    check(len(unref) == 1 and unref[0].severity == "Low",
          "an executable nothing references is reported Low, not High")

    # severity: the planted binary and the exec-on-data must be High
    sev = {f.rule: f.severity for f in f_bad}
    check(sev.get("MTA003") == "High" and sev.get("MTA002") == "High",
          "dynamic exec and SQL concat are reported as High")


def test_cheat_markers(tmp):
    print("MTA010 cheat-family markers")
    root = os.path.join(tmp, "markers")
    write_resource(root, "evil_res", {"lua/x.lua": 'local k = "NVXHookProc"\n'},
                   meta='<meta><script src="lua/x.lua" type="server"/></meta>')
    f = audit.analyse(root)
    check(counts(f).get("MTA010") == 1, "NVXHookProc inside a resource is reported")

    root2 = os.path.join(tmp, "markers_clean")
    write_resource(root2, "ok_res", {"x.lua": 'print("hello")\n'},
                   meta='<meta><script src="x.lua" type="server"/></meta>')
    check(audit.analyse(root2) == [], "a clean resource produces no finding")


def test_structure(tmp):
    print("MTA012 structure")
    root = os.path.join(tmp, "struct")
    write_resource(root, "no_meta", {"x.lua": "return true\n"}, meta=None)
    write_resource(root, "missing_src",
                   {"x.lua": "return true\n"},
                   meta='<meta><script src="absent.lua" type="server"/></meta>')
    write_resource(root, "data_folder", {"notes/readme.txt": "just data\n"}, meta=None)
    f = audit.analyse(root)
    c = counts(f)
    check(c.get("MTA012") == 2,
          "one missing meta.xml and one missing referenced file are reported (got %d)"
          % c.get("MTA012", 0))
    check(all("no_meta" in x.path or "missing_src" in x.path for x in f),
          "a plain data folder is not reported as a broken resource")


def test_false_positives(tmp):
    print("false-positive guards")
    root = os.path.join(tmp, "fp")
    body = (
        '-- loadstring(msg) is only mentioned in a comment here\n'
        'local doc = "runString(payload)"\n'
        '--[[ loadstring(z)\n'
        '     os.execute("rm -rf /")\n'
        ']]\n'
        'local masked = doc\n'
    )
    write_resource(root, "cleanish", {"x.lua": body},
                   meta='<meta><script src="x.lua" type="server"/></meta>')
    f = audit.analyse(root)
    check(f == [], "commented and quoted mentions of dangerous calls are ignored (got %s)"
          % sorted(counts(f)))

    root2 = os.path.join(tmp, "fp2")
    good_handler = (
        'addEvent("safeDo", true)\n'
        'addEventHandler("safeDo", root, function(a)\n'
        '    if not client or type(a) ~= "number" then return false end\n'
        '    a = tonumber(a) or 0\n'
        '    dbExec(db, "UPDATE t SET v=? WHERE id=?", a, 1)\n'
        'end)\n'
    )
    write_resource(root2, "validated", {"x.lua": good_handler},
                   meta='<meta><script src="x.lua" type="server"/></meta>')
    f2 = audit.analyse(root2)
    check(f2 == [], "a validated client event is not reported (got %s)" % sorted(counts(f2)))


def test_cli(tmp):
    print("CLI: json report and exit codes")
    tree = os.path.join(tmp, "cli")
    audit.make_demo(tree)
    out_file = os.path.join(tmp, "report.json")
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "mta_resource_audit.py"), tree,
         "--format", "json", "--out", out_file],
        capture_output=True)
    check(proc.returncode == 1, "exit code 1 when a High finding exists")

    good = os.path.join(tree, "demo_good")
    proc2 = subprocess.run(
        [sys.executable, os.path.join(HERE, "mta_resource_audit.py"), good],
        capture_output=True)
    check(proc2.returncode == 0, "exit code 0 when nothing is found")

    with io.open(out_file, encoding="utf-8") as fh:
        data = json.load(fh)
    check(isinstance(data.get("findings"), list) and len(data["findings"]) == 12,
          "JSON report lists every finding (%d)" % len(data.get("findings", [])))
    check(all("rule" in x and "severity" in x and "title" in x for x in data["findings"]),
          "JSON findings carry rule, severity and Arabic+English titles")

    proc3 = subprocess.run(
        [sys.executable, os.path.join(HERE, "mta_resource_audit.py"), "--rules"],
        capture_output=True)
    check(proc3.returncode == 0 and b"MTA001" in proc3.stdout,
          "--rules prints the rule set")


def main():
    tmp = tempfile.mkdtemp(prefix="mta_audit_test_")
    try:
        print("=== mta_resource_audit self-test ===")
        test_masking()
        test_split_args()
        test_demo_tree(tmp)
        test_cheat_markers(tmp)
        test_structure(tmp)
        test_false_positives(tmp)
        test_cli(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("---------------------------------------------------")
    print("Summary: %d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
