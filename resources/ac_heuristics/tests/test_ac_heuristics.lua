-- ============================================================================
--  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
--  Security & Vulnerability Research Team — White Hat Hackers
-- ----------------------------------------------------------------------------
--  MTA:SA security research test bed — mta-sa-original-test
--  Internal security research material. All rights reserved by the team above.
--  NRTH-SEC-RESEARCH-HEADER
-- ============================================================================
-- test_ac_heuristics.lua — offline verification of the detection resource.
--
-- Runs the real resource files (config.lua, ac_core.lua, server.lua, client.lua)
-- inside tests/mta_mock.lua with a scripted clock, then drives them with an event
-- stream that represents honest play and with streams that represent the
-- statistical footprints a cheat leaves behind.
--
--   resources/ac_heuristics/tests/run.sh
--
-- What this proves: the signals fire on the intended footprints, stay silent on
-- honest play, ignore client reports the server did not corroborate, honour
-- sample-size and explosive-weapon exemptions, decay, and reach admins with a
-- readable reason. What it cannot prove: anything about a real game process.
-- ============================================================================

local root = arg and arg[1] or "."
local res = root .. "/resources/ac_heuristics"

local passed, failed = 0, 0
local function check(cond, desc)
    if cond then
        passed = passed + 1
        print("  [PASS] " .. desc)
    else
        failed = failed + 1
        print("  [FAIL] " .. desc)
    end
end

local M = dofile(res .. "/tests/mta_mock.lua")

-- --------------------------------------------------------------------------
-- load the resource exactly as MTA would: one VM, files in meta.xml order
-- --------------------------------------------------------------------------
local function loadResource()
    M.reset()
    dofile(res .. "/config.lua")
    dofile(res .. "/ac_core.lua")
    dofile(res .. "/server.lua")
    dofile(res .. "/client.lua")
end

loadResource()

local function alerts()
    local out = {}
    for _, line in ipairs(M.logs) do
        if line:find("ALERT", 1, true) then table.insert(out, line) end
    end
    return out
end

-- Distance in MTA comes from the two elements' positions, so the fixtures place
-- the players apart instead of passing a number the glue would ignore.
local function placeAt(attacker, victim, distance)
    attacker.x, attacker.y, attacker.z = 0, 0, 0
    victim.x, victim.y, victim.z = distance, 0, 0
end

-- --------------------------------------------------------------------------
print("wiring / event contract")
do
    check(M.events["acHeuristics:losReport"] ~= nil,
          "server registers the LOS report event")
    check(M.events["acHeuristics:losReport"].remote == true,
          "LOS report event is registered as client-triggerable (addEvent(..., true))")
    check(not M.events["acHeuristics:losReport"] and false or
          M.events["acHeuristics:losReport"] ~= nil and
          not ("acHeuristics:losReport"):match("^on[A-Z]"),
          "event name is namespaced, so it cannot shadow a native MTA event")
    check(M.handlers["onPlayerDamage"] ~= nil, "onPlayerDamage is handled")
    check(M.handlers["onPlayerWasted"] ~= nil, "onPlayerWasted is handled (lethal blow)")
    check(M.handlers["onPlayerQuit"] ~= nil, "onPlayerQuit is handled")
    check(M.handlers["onClientPlayerDamage"] ~= nil, "client sensor hooks onClientPlayerDamage")
    check(M.commands["accheck"] ~= nil, "/accheck command is registered")
end

-- --------------------------------------------------------------------------
print("honest play stays silent")
do
    loadResource()
    local honest = M.createPlayer("honest")
    local victims = {}
    for i = 1, 6 do
        victims[i] = M.createPlayer("victim" .. i)
        placeAt(honest, victims[i], 25)
    end
    for i = 1, 100 do
        local v = victims[((i - 1) % 6) + 1]
        M.fire("onPlayerDamage", v, honest, 22, (i % 10 == 0) and 9 or 3, 3.0)
        M.advance(800)   -- 4 hits per 3.2 s: no burst footprint
    end
    M.advance(8000)
    check(#alerts() == 0, "100 hits, 10% head shots, in reach, clear line of sight -> no alert")
    check(getAcReport(honest).level == "ok", "honest player is reported at level ok")
end

-- --------------------------------------------------------------------------
print("headshot bot")
do
    loadResource()
    local bot = M.createPlayer("hs_bot")
    local victim = M.createPlayer("v_hs")
    placeAt(bot, victim, 5)
    for i = 1, 40 do
        M.fire("onPlayerDamage", victim, bot, 22, (i <= 38) and 9 or 3, 12.5)
        M.advance(200)
    end
    M.advance(5000)
    local report = getAcReport(bot)
    check(report.reasons.headshot ~= nil, "headshot ratio signal fires (38/40 -> 95%)")
    check(report.level == "suspicious" or report.level == "confirmed",
          "level escalates to at least suspicious (got " .. tostring(report.level) .. ")")
    check(#alerts() >= 1 and alerts()[1]:find("hits to the head", 1, true) ~= nil,
          "alert explains the reason in words an admin can read")
end

-- --------------------------------------------------------------------------
print("sample-size guard")
do
    loadResource()
    local rookie = M.createPlayer("rookie")
    local victim = M.createPlayer("v_rookie")
    placeAt(rookie, victim, 5)
    for _ = 1, 5 do
        M.fire("onPlayerDamage", victim, rookie, 24, 9, 25.0)
        M.advance(400)
    end
    M.advance(5000)
    check(getAcReport(rookie).reasons.headshot == nil,
          "5 head shots out of 5 hits is below the sample floor -> no signal")
    check(getAcReport(rookie).level == "ok", "a short lucky streak does not raise the level")
end

-- --------------------------------------------------------------------------
print("reach violation")
do
    loadResource()
    local sniper = M.createPlayer("range_bot")
    local victim = M.createPlayer("v_range")
    placeAt(sniper, victim, 250)
    for _ = 1, 4 do
        M.fire("onPlayerDamage", victim, sniper, 22, 3, 12.5)
        M.advance(500)
    end
    M.advance(5000)
    local report = getAcReport(sniper)
    check(report.reasons.range ~= nil, "pistol damage at 250 m is flagged as impossible")
    check(report.worstRange >= 250, "the report keeps the worst distance (" ..
          tostring(report.worstRange) .. " m)")
end

-- --------------------------------------------------------------------------
print("burst on many victims")
do
    loadResource()
    local bot = M.createPlayer("burst_bot")
    for i = 1, 6 do
        local victim = M.createPlayer("v_burst" .. i)
        placeAt(bot, victim, 20)
    end
    for i = 1, 6 do
        local victim = M.players[#M.players - (6 - i)]
        M.fire("onPlayerDamage", victim, bot, 31, 3, 12.5)
        M.advance(400)
    end
    M.advance(5000)
    check(getAcReport(bot).reasons.burst ~= nil,
          "5 different victims inside 2.5 s of direct fire is flagged")
end

-- --------------------------------------------------------------------------
print("explosive exemption")
do
    loadResource()
    local nader = M.createPlayer("nader")
    local victim = M.createPlayer("v_nade")
    placeAt(nader, victim, 20)
    for _ = 1, 40 do
        M.fire("onPlayerDamage", victim, nader, 16, 9, 12.5)  -- grenade
        M.advance(150)
    end
    for _ = 1, 6 do
        M.fire("onPlayerDamage", victim, nader, 16, 3, 12.5)
        M.advance(300)
    end
    M.advance(5000)
    local report = getAcReport(nader)
    check(report.reasons.headshot == nil, "explosions never build the headshot ratio")
    check(report.reasons.burst == nil, "explosions never build the burst signal")
    check(report.reasons.range == nil, "grenades in reach do not trigger the reach signal")
end

-- --------------------------------------------------------------------------
print("lethal blow is counted")
do
    loadResource()
    local bot = M.createPlayer("kill_bot")
    local victim = M.createPlayer("v_kill")
    placeAt(bot, victim, 50)
    for _ = 1, 30 do
        M.fire("onPlayerWasted", victim, bot, 34, 9)   -- killing headshot with a sniper
        M.advance(300)
    end
    M.advance(5000)
    local report = getAcReport(bot)
    check(report.hits >= 30, "onPlayerWasted feeds the hit counter (" ..
          tostring(report.hits) .. " hits)")
    check(report.reasons.headshot ~= nil,
          "the killing blow counts towards the headshot ratio (it never raises onPlayerDamage)")
end

-- --------------------------------------------------------------------------
print("line-of-sight reports need server corroboration")
do
    loadResource()
    local bot = M.createPlayer("wall_bot")
    local victim = M.createPlayer("v_wall")
    local reporter = M.createPlayer("observer")
    placeAt(bot, victim, 15)

    -- 1) a client report with no matching damage must be ignored
    M.clientFire("acHeuristics:losReport", reporter, nil, bot, victim, 22, true)
    check(getAcReport(bot).losReported == 0,
          "an uncorroborated client report is dropped")

    -- 2) real hits, then the same reports arrive: now they count
    for _ = 1, 6 do
        M.fire("onPlayerDamage", victim, bot, 22, 3, 12.5)
        M.advance(300)
        M.clientFire("acHeuristics:losReport", reporter, nil, bot, victim, 22, true)
        M.advance(300)
    end
    local report = getAcReport(bot)
    check(report.losReported == 6, "corroborated reports are counted (" ..
          tostring(report.losReported) .. "/6)")
    check(report.reasons.los ~= nil, "6/6 blocked line-of-sight hits raise the LOS signal")

    -- 3) the reported attacker cannot report on their own behalf
    local before = getAcReport(bot).losReported
    M.advance(400)
    M.clientFire("acHeuristics:losReport", bot, nil, bot, victim, 22, true)
    check(getAcReport(bot).losReported == before,
          "a player's own client cannot pad that player's report")
end

-- --------------------------------------------------------------------------
print("client sensor")
do
    loadResource()
    local attacker = M.createPlayer("sensor_att", { x = 0, y = 0, z = 0 })
    local victim = M.createPlayer("sensor_vic", { x = 60, y = 0, z = 0 })
    M.losBlocked = false
    M.advance(1000)
    M.fire("onClientPlayerDamage", victim, attacker, 22, 3, 5.0)
    check(#M.remoteCalls == 0, "a hit with a clear line of sight reports nothing")

    M.losBlocked = true
    M.advance(1000)
    M.fire("onClientPlayerDamage", victim, attacker, 22, 3, 5.0)
    check(#M.remoteCalls == 1, "a hit through a wall reports once")
    local call = M.remoteCalls[1]
    check(call.name == "acHeuristics:losReport", "the report uses the namespaced event")
    check(call.args[1] == attacker and call.args[2] == victim and call.args[4] == true,
          "the report carries attacker, victim and the blocked verdict")

    local lastArgs = M.losCalls[#M.losCalls]
    check(lastArgs[7] == true and lastArgs[8] == false and lastArgs[9] == false and
          lastArgs[10] == true and lastArgs[11] == false and lastArgs[12] == true,
          "LOS is computed with buildings/objects checked and peds/vehicles ignored")

    M.losBlocked = true
    M.fire("onClientPlayerDamage", attacker, attacker, 22, 3, 5.0)
    check(#M.remoteCalls == 1, "self damage is never reported")
end

-- --------------------------------------------------------------------------
print("decay and sweep")
do
    loadResource()
    local bot = M.createPlayer("decay_bot")
    local victim = M.createPlayer("v_decay")
    placeAt(bot, victim, 250)
    for _ = 1, 4 do
        M.fire("onPlayerDamage", victim, bot, 22, 3, 12.5)
        M.advance(400)
    end
    local peak = getAcReport(bot).score
    check(peak > 0, "suspicion accumulates (" .. tostring(peak) .. ")")
    M.advance(70000)
    check(getAcReport(bot).score < peak,
          "suspicion decays over a minute of clean play (" ..
          tostring(getAcReport(bot).score) .. " < " .. tostring(peak) .. ")")
    M.advance(40000)
    check(getAcReport(bot).hits == 0,
          "counters roll over after the window, so old bursts stop counting")
end

-- --------------------------------------------------------------------------
print("admin access")
do
    loadResource()
    local cheater = M.createPlayer("suspect")
    local victim = M.createPlayer("v_admin")
    local admin = M.createPlayer("boss", { admin = true })
    local guest = M.createPlayer("guest", { guest = true })
    placeAt(cheater, victim, 250)
    for _ = 1, 4 do
        M.fire("onPlayerDamage", victim, cheater, 22, 3, 12.5)
        M.advance(400)
    end
    M.advance(5000)

    local before = #M.chat
    M.commands["accheck"](guest, "accheck")
    local denied = false
    for i = before + 1, #M.chat do
        if M.chat[i].text:find("ACL Admin", 1, true) then denied = true end
    end
    check(denied, "a player without ACL Admin rights is refused")

    local before2 = #M.chat
    M.commands["accheck"](admin, "accheck", "suspect")
    local sawReport, sawReason = false, false
    for i = before2 + 1, #M.chat do
        local text = M.chat[i].text
        if text:find("level=", 1, true) then sawReport = true end
        if text:find("beyond the weapon", 1, true) then sawReason = true end
    end
    check(sawReport, "/accheck prints the suspect's level and score")
    check(sawReason, "/accheck explains the reason and shows the evidence")

    M.commands["accheck"](admin, "accheck", "nobody")
    check(M.chat[#M.chat].text:find("no player named", 1, true) ~= nil,
          "/accheck handles an unknown player name")
end

-- --------------------------------------------------------------------------
print("exports")
do
    loadResource()
    local p = M.createPlayer("exportee")
    local report = getAcReport(p)
    check(type(report) == "table" and report.level == "ok",
          "getAcReport returns a report table for another resource")
    check(getAcReport(nil) == false, "getAcReport rejects a non-player argument")
    check(type(getAcConfig()) == "table" and getAcConfig().headshotRatio ~= nil,
          "getAcConfig exposes the active thresholds")
end

print("---------------------------------------------------")
print(string.format("Summary: %d passed, %d failed", passed, failed))
return failed == 0 and 0 or 1
