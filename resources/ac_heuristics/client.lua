-- ============================================================================
--  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
--  Security & Vulnerability Research Team — White Hat Hackers
-- ----------------------------------------------------------------------------
--  MTA:SA security research test bed — mta-sa-original-test
--  Internal security research material. All rights reserved by the team above.
--  NRTH-SEC-RESEARCH-HEADER
-- ============================================================================
-- client.lua — the line-of-sight sensor.
--
-- Why this has to run on the client at all: world geometry (buildings, the map)
-- only exists there. The server's isLineOfSightClear uses a simplified model of
-- script elements as spheres, so it cannot answer "was there a wall between
-- them". This script answers that question for hits it actually witnesses, and
-- reports only the verdict - four values - to the server.
--
-- What it does NOT do: it does not read memory, does not modify the game, does
-- not decide anything, and its reports are worth nothing until the server finds
-- the matching damage event of its own. A player who edits this script can, at
-- worst, add noise to their own suspicion score or pad another player's after a
-- real hit - the evidence log records the reporter, so that is visible.
-- ============================================================================

local THORSO_Z = 0.75   -- aim at the torso, not the feet or the head

local function losBlocked(attacker, victim)
    local ax, ay, az = getElementPosition(attacker)
    local vx, vy, vz = getElementPosition(victim)
    -- Buildings and objects count, peds and vehicles do not (the attacker's own
    -- body or a passer-by must not create a false wall), and fences/beach
    -- collisions flagged "shootthrough" are allowed to be shot through.
    return not isLineOfSightClear(ax, ay, az + THORSO_Z, vx, vy, vz + THORSO_Z,
                                  true,   -- checkBuildings
                                  false,  -- checkVehicles
                                  false,  -- checkPeds
                                  true,   -- checkObjects
                                  false,  -- checkDummies (unused in current MTA)
                                  true)   -- seeThroughStuff
end

addEventHandler("onClientPlayerDamage", root, function(attacker, weapon)
    if not attacker or getElementType(attacker) ~= "player" then return end
    if source == attacker then return end
    local blocked = losBlocked(attacker, source)
    if not blocked then return end          -- the common case, send nothing
    triggerServerEvent("acHeuristics:losReport", resourceRoot,
                       attacker, source, weapon, true)
end)

addEventHandler("onClientPlayerWasted", root, function(killer, weapon)
    if not killer or getElementType(killer) ~= "player" then return end
    if source == killer then return end
    if losBlocked(killer, source) then
        triggerServerEvent("acHeuristics:losReport", resourceRoot,
                           killer, source, weapon, true)
    end
end)
