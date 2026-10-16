-- ============================================================================
--  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
--  Security & Vulnerability Research Team — White Hat Hackers
-- ----------------------------------------------------------------------------
--  MTA:SA security research test bed — mta-sa-original-test
--  Internal security research material. All rights reserved by the team above.
--  NRTH-SEC-RESEARCH-HEADER
-- ============================================================================
-- server.lua — MTA glue for the detection core.
--
-- Responsibilities, and nothing more:
--   * feed the core with what the server actually observes;
--   * receive line-of-sight reports from clients as *hints* and let the core
--     decide whether they are corroborated;
--   * log alerts and explain them to admins on request;
--   * expose the report to other resources (getAcReport) for a dashboard/ban UI.
--
-- This file never bans, kicks or damages anyone. Naming a player a cheater is a
-- decision for a human with the evidence in front of them; the resource only
-- makes sure the evidence exists.
-- ============================================================================

local cfg = (type(AC_CONFIG) == "table") and AC_CONFIG or {}
local ac = ACCore.new(cfg)

local LOS_EVENT = "acHeuristics:losReport"   -- namespaced: never a native event name
local CHECK_COMMAND = "accheck"

addEvent(LOS_EVENT, true)                    -- remotely triggerable, by design

local function isPlayer(e)
    return e ~= nil and isElement(e) and getElementType(e) == "player"
end

local function round1(v)
    return math.floor((v or 0) * 10 + 0.5) / 10
end

local function isAdmin(player)
    -- the documented way: ACL group membership, not a name or a flag
    local acc = getPlayerAccount(player)
    if not acc or isGuestAccount(acc) then return false end
    return isObjectInACLGroup("user." .. getAccountName(acc), aclGetGroup("Admin"))
end

local function notifyAdmins(text)
    for _, player in ipairs(getElementsByType("player")) do
        if isAdmin(player) then
            outputChatBox("[ac_heuristics] " .. text, player, 255, 170, 0, true)
        end
    end
end

local function describe(reasons)
    local parts = {}
    if reasons.headshot then table.insert(parts, reasons.headshot.text) end
    if reasons.los then table.insert(parts, reasons.los.text) end
    if reasons.range then table.insert(parts, reasons.range.text) end
    if reasons.burst then table.insert(parts, reasons.burst.text) end
    if #parts == 0 then return "no active reason" end
    return table.concat(parts, "; ")
end

-- ---------------------------------------------------------------------------
-- ingestion
-- ---------------------------------------------------------------------------
addEventHandler("onPlayerDamage", root, function(attacker, weapon, bodypart, loss)
    if not isPlayer(attacker) then return end
    ac:onDamage({
        time = getTickCount(),
        attacker = attacker,
        victim = source,
        weapon = weapon,
        bodypart = bodypart,
        loss = loss,
        distance = getDistanceBetweenPoints3D(attacker, source),
    })
end)

-- The killing blow does not raise onPlayerDamage, so count it here or the
-- deadliest hits would be invisible.
addEventHandler("onPlayerWasted", root, function(killer, weapon, bodypart)
    if not isPlayer(killer) then return end
    ac:onKill({
        time = getTickCount(),
        attacker = killer,
        victim = source,
        weapon = weapon,
        bodypart = bodypart,
        distance = getDistanceBetweenPoints3D(killer, source),
    })
end)

addEventHandler("onPlayerQuit", root, function()
    ac:onPlayerRemove(source)
end)

-- Unvalidated by design at this layer: the core refuses anything the server did
-- not already see, and the reporter is never trusted to be honest.
addEventHandler(LOS_EVENT, root, function(attacker, victim, weapon, blocked)
    if not isPlayer(attacker) or not isPlayer(victim) then return end
    if client == attacker then
        -- a player reporting their own hits only inflates themselves
        return
    end
    local ok, why = ac:onLosReport({
        time = getTickCount(),
        attacker = attacker, victim = victim, weapon = weapon,
        blocked = blocked and true or false,
    })
    if not ok and why == "flood" then
        outputServerLog("[ac_heuristics] LOS report flood from " .. tostring(getPlayerName(client)))
    end
end)

-- ---------------------------------------------------------------------------
-- alerting: a log line plus a chat ping to admins. No automatic punishment.
-- ---------------------------------------------------------------------------
local function flushAlerts()
    for _, alert in ipairs(ac:drainAlerts()) do
        local name = getPlayerName(alert.player) or tostring(alert.player)
        local line = string.format(
            "player=%s level=%s score=%d reason=[%s]",
            name, alert.level, alert.score, describe(alert.reasons))
        outputServerLog("[ac_heuristics] ALERT " .. line)
        notifyAdmins(string.format("%s -> %s (score %d): %s",
                                   name, alert.level, alert.score,
                                   describe(alert.reasons)))
    end
end

setTimer(flushAlerts, 4000, 0)
setTimer(function() ac:sweep(getTickCount()) end, 10000, 0)

-- ---------------------------------------------------------------------------
-- admin view + programmatic access
-- ---------------------------------------------------------------------------
local function renderReport(report, playerElem)
    local out = {}
    table.insert(out, string.format("[ac_heuristics] %s: level=%s score=%d",
                                    getPlayerName(playerElem), report.level, report.score))
    table.insert(out, string.format("  hits=%d head=%d (%.0f%%) los=%d/%d blocked range_violations=%d",
                                    report.hits, report.head, (report.headRatio or 0) * 100,
                                    report.losBlocked or 0, report.losReported or 0,
                                    report.rangeViolations or 0))
    table.insert(out, "  reasons: " .. describe(report.reasons or {}))
    if #report.evidence > 0 then
        table.insert(out, "  last events:")
        for i = #report.evidence, math.max(1, #report.evidence - 5), -1 do
            local e = report.evidence[i]
            if e.kind == "damage" or e.kind == "kill" then
                table.insert(out, string.format("    t=%d %s victim=%s weapon=%d bodypart=%s dist=%s loss=%s",
                                                e.t, e.kind, tostring(e.victim), e.weapon or 0,
                                                tostring(e.bodypart), tostring(round1(e.distance)),
                                                tostring(e.loss)))
            else
                table.insert(out, string.format("    t=%d los victim=%s blocked=%s",
                                                e.t, tostring(e.victim), tostring(e.blocked)))
            end
        end
    end
    return out
end

addCommandHandler(CHECK_COMMAND, function(player, _, target)
    if not isAdmin(player) then
        outputChatBox("[ac_heuristics] " .. CHECK_COMMAND .. " requires ACL Admin rights.",
                      player, 255, 80, 80, true)
        return
    end
    local victim = player
    if target and target ~= "" then
        victim = getPlayerFromName(target)
        if not isPlayer(victim) then
            outputChatBox("[ac_heuristics] no player named '" .. tostring(target) .. "'.",
                          player, 255, 80, 80, true)
            return
        end
    end
    for _, line in ipairs(renderReport(ac:getReport(victim), victim)) do
        outputChatBox(line, player, 220, 220, 220, true)
    end
end)

function getAcReport(playerElem)
    if not isPlayer(playerElem) then return false end
    return ac:getReport(playerElem)
end

function getAcConfig()
    return ac.cfg
end
