-- ============================================================================
--  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
--  Security & Vulnerability Research Team — White Hat Hackers
-- ----------------------------------------------------------------------------
--  MTA:SA security research test bed — mta-sa-original-test
--  Internal security research material. All rights reserved by the team above.
--  NRTH-SEC-RESEARCH-HEADER
-- ============================================================================
-- ac_core.lua — detection core. Pure Lua: no MTA functions, no globals leaked.
--
-- What it does: turns an event stream (damage, kills, line-of-sight reports)
-- into a per-player suspicion score plus the evidence needed for a human to
-- review it. It never decides a ban: it labels and explains.
--
-- Signals, and how much each is worth trusting:
--   headshot_ratio  server-side, reliable: onPlayerDamage carries the bodypart
--   range_violation server-side, reliable: damage beyond a weapon's reach
--   burst           server-side, heuristic: many victims in a short window
--   los_blocked     CORROBORATED client report, weakest: the client is the only
--                   place where world geometry (buildings) is available, so a
--                   hit through a wall can only be *seen* there. Reports are
--                   therefore only counted when the server independently saw
--                   the same attacker->victim damage moments before.
--
-- Deliberately NOT implemented, because the server cannot see it:
--   camera/aim angle, snap-to-target, triggerbot timing, silent-aim offsets.
--   Those live in the client's memory or are client-authoritative. Any resource
--   claiming to detect them server-side alone is guessing.
-- ============================================================================

ACCore = {}
ACCore.__index = ACCore

local DEFAULTS = {
    windowMs           = 30000,  -- rolling window for the per-player counters
    minSamples         = 30,     -- total hits before ratio signals may fire
    headshotMinSamples = 25,
    headshotRatio      = 0.75,   -- >= this share of hits to the head
    losMinSamples      = 5,      -- corroborated LOS reports needed
    losBlockedRatio    = 0.5,    -- >= this share of them blocked
    corroborateMs      = 1500,   -- a client report must match server damage this close
    rangeSlack         = 1.15,   -- allow this much over the weapon's reach
    burstVictims       = 5,      -- distinct victims...
    burstWindowMs      = 2500,   -- ...within this window
    scoreSuspicious    = 25,
    scoreConfirmed     = 60,
    decayMs            = 60000,  -- suspicion halves over this period of clean play
    evidenceKeep       = 12,     -- events kept per player for the report
    losReportCooldownMs = 250,   -- flood guard for client reports per attacker
}

-- Approximate GTA:SA reach in metres. Generous on purpose: the point is to catch
-- the impossible, not the unusual. Tune per server, and add weapons you use.
local WEAPON_RANGE = {
    [22] = 40, [23] = 40, [24] = 45,          -- pistols
    [25] = 30, [26] = 30, [27] = 30,          -- shotguns
    [28] = 45, [29] = 45, [32] = 45,          -- smgs
    [30] = 60, [31] = 60,                     -- rifles
    [33] = 130, [34] = 130,                   -- sniper / country rifle
    [16] = 40, [18] = 30,                     -- thrown: grenade / molotov
    [35] = 300, [36] = 300, [37] = 60, [38] = 200,  -- rockets / flamer / minigun
}

-- Damage that is not aimed: explosions, fire, falls, drowning, vehicle hits.
-- These are excluded from the ratio and burst signals.
local EXPLOSIVE = {
    [16] = true, [18] = true, [19] = true, [20] = true,
    [35] = true, [36] = true, [37] = true, [38] = true, [39] = true, [40] = true,
    [49] = true, [50] = true, [51] = true, [52] = true, [53] = true, [54] = true,
    [55] = true, [56] = true, [57] = true, [58] = true, [59] = true, [60] = true,
    [61] = true, [62] = true, [63] = true,
}

local LEVEL_ORDER = { ok = 0, watch = 1, suspicious = 2, confirmed = 3 }

local function merge(defaults, overrides)
    local cfg = {}
    for k, v in pairs(defaults) do cfg[k] = v end
    for k, v in pairs(overrides or {}) do cfg[k] = v end
    return cfg
end

function ACCore.new(overrides)
    local self = setmetatable({}, ACCore)
    self.cfg = merge(DEFAULTS, overrides)
    self.players = {}
    self.alerts = {}
    self.losCooldown = {}
    return self
end

function ACCore:enabled()
    return self.cfg.enabled ~= false
end

local function blank_player(time)
    return {
        first = time,
        last = time,
        hits = 0,
        head = 0,
        rangeViolations = 0,
        worstRange = 0,
        losReported = 0,
        losBlocked = 0,
        byWeapon = {},
        victims = {},
        events = {},
        score = 0,
        lastDecay = time,
        level = "ok",
        alerted = 0,
        reasons = {},
    }
end

function ACCore:state(id, time)
    local p = self.players[id]
    if not p then
        p = blank_player(time)
        self.players[id] = p
    end
    return p
end

local function evidence(p, entry, keep)
    table.insert(p.events, entry)
    while #p.events > keep do
        table.remove(p.events, 1)
    end
end

local function bump_weapon(p, weapon)
    p.byWeapon[weapon] = (p.byWeapon[weapon] or 0) + 1
end

function ACCore:onDamage(ev)
    if not self:enabled() or not ev or not ev.attacker or ev.attacker == ev.victim then
        return
    end
    local time = ev.time or 0
    local p = self:state(ev.attacker, time)
    p.last = time

    local explosive = EXPLOSIVE[ev.weapon] == true
    p.hits = p.hits + 1
    bump_weapon(p, ev.weapon)
    if ev.bodypart == 9 and not explosive then
        p.head = p.head + 1
    end

    -- burst tracking (distinct victims in a short window, direct fire only)
    if not explosive then
        table.insert(p.victims, { t = time, v = ev.victim })
        while #p.victims > 0 and (time - p.victims[1].t) > self.cfg.burstWindowMs do
            table.remove(p.victims, 1)
        end
    end

    -- reach check
    local reach = WEAPON_RANGE[ev.weapon]
    if reach and ev.distance then
        local limit = reach * self.cfg.rangeSlack
        if ev.distance > limit then
            p.rangeViolations = p.rangeViolations + 1
            if ev.distance > p.worstRange then
                p.worstRange = ev.distance
            end
        end
    end

    evidence(p, {
        t = time, kind = "damage", victim = ev.victim, weapon = ev.weapon,
        bodypart = ev.bodypart, loss = ev.loss, distance = ev.distance,
    }, self.cfg.evidenceKeep)

    self:evaluate(ev.attacker, time)
    return p
end

-- onPlayerWasted: the killing blow does NOT raise onPlayerDamage, so without
-- this the highest-value hits (the lethal ones) would never be counted.
function ACCore:onKill(ev)
    if not self:enabled() or not ev or not ev.attacker or ev.attacker == ev.victim then
        return
    end
    local time = ev.time or 0
    local p = self:state(ev.attacker, time)
    local explosive = EXPLOSIVE[ev.weapon] == true
    p.hits = p.hits + 1
    p.last = time
    bump_weapon(p, ev.weapon)
    if ev.bodypart == 9 and not explosive then
        p.head = p.head + 1
    end
    evidence(p, {
        t = time, kind = "kill", victim = ev.victim, weapon = ev.weapon,
        bodypart = ev.bodypart, distance = ev.distance,
    }, self.cfg.evidenceKeep)
    self:evaluate(ev.attacker, time)
    return p
end

function ACCore:onLosReport(ev)
    if not self:enabled() or not ev or not ev.attacker then
        return false, "disabled"
    end
    local time = ev.time or 0
    local key = tostring(ev.attacker)
    local last = self.losCooldown[key] or -1e9
    if (time - last) < self.cfg.losReportCooldownMs then
        return false, "rate limited"
    end
    self.losCooldown[key] = time

    local p = self:state(ev.attacker, time)
    -- Corroboration: the server must have seen this same attacker -> victim
    -- damage within corroborateMs. A client cannot invent a detection.
    local matched = false
    for i = #p.events, 1, -1 do
        local e = p.events[i]
        if (time - e.t) > self.cfg.corroborateMs then
            break
        end
        if e.victim == ev.victim then
            matched = true
            break
        end
    end
    if not matched then
        return false, "uncorroborated"
    end

    p.losReported = p.losReported + 1
    if ev.blocked then
        p.losBlocked = p.losBlocked + 1
    end
    evidence(p, {
        t = time, kind = "los", victim = ev.victim, blocked = ev.blocked and true or false,
    }, self.cfg.evidenceKeep)
    self:evaluate(ev.attacker, time)
    return true
end

function ACCore:evaluate(id, time)
    local p = self.players[id]
    if not p then return nil end
    local cfg = self.cfg

    -- decay before recomputing, so clean play eventually clears suspicion
    while (time - p.lastDecay) >= cfg.decayMs do
        p.score = math.floor(p.score / 2)
        p.lastDecay = p.lastDecay + cfg.decayMs
    end

    local reasons = {}
    local score = 0

    if p.hits >= cfg.headshotMinSamples and p.hits >= cfg.minSamples then
        local ratio = p.head / p.hits
        if ratio >= cfg.headshotRatio then
            score = score + 30
            reasons.headshot = {
                ratio = ratio, head = p.head, hits = p.hits,
                text = string.format("%d/%d hits to the head (%.0f%%)", p.head, p.hits, ratio * 100),
            }
        end
    end

    if p.losReported >= cfg.losMinSamples then
        local ratio = p.losBlocked / p.losReported
        if ratio >= cfg.losBlockedRatio then
            score = score + 40
            reasons.los = {
                ratio = ratio, blocked = p.losBlocked, reported = p.losReported,
                text = string.format("%d/%d corroborated hits had no clear line of sight",
                                     p.losBlocked, p.losReported),
            }
        end
    end

    if p.rangeViolations > 0 then
        score = score + math.min(50, 25 * p.rangeViolations)
        reasons.range = {
            count = p.rangeViolations, worst = p.worstRange,
            text = string.format("%d hit(s) beyond the weapon's reach (worst %.1f m)",
                                 p.rangeViolations, p.worstRange),
        }
    end

    local distinct = {}
    local n = 0
    for _, entry in ipairs(p.victims) do
        if not distinct[entry.v] then
            distinct[entry.v] = true
            n = n + 1
        end
    end
    if n >= cfg.burstVictims then
        score = score + 35
        reasons.burst = {
            victims = n, windowMs = cfg.burstWindowMs,
            text = string.format("%d different players damaged within %.1f s",
                                 n, cfg.burstWindowMs / 1000),
        }
    end

    p.score = math.min(100, score)
    p.reasons = reasons

    local level = "ok"
    if p.score >= cfg.scoreConfirmed then
        level = "confirmed"
    elseif p.score >= cfg.scoreSuspicious then
        level = "suspicious"
    elseif p.score > 0 then
        level = "watch"
    end

    if LEVEL_ORDER[level] > LEVEL_ORDER[p.level] then
        p.level = level
        p.alerted = p.alerted + 1
        table.insert(self.alerts, {
            player = id, level = level, score = p.score, time = time,
            reasons = reasons, evidence = self:evidence(id),
        })
    elseif level ~= p.level then
        p.level = level
    end
    return level
end

function ACCore:evidence(id)
    local p = self.players[id]
    if not p then return {} end
    local copy = {}
    for i, e in ipairs(p.events) do
        local row = {}
        for k, v in pairs(e) do row[k] = v end
        copy[i] = row
    end
    return copy
end

function ACCore:getReport(id)
    local p = self.players[id]
    if not p then
        return { player = id, score = 0, level = "ok", reasons = {},
                 hits = 0, head = 0, evidence = {} }
    end
    return {
        player = id, score = p.score, level = p.level, reasons = p.reasons,
        hits = p.hits, head = p.head,
        headRatio = p.hits > 0 and (p.head / p.hits) or 0,
        losReported = p.losReported, losBlocked = p.losBlocked,
        rangeViolations = p.rangeViolations, worstRange = p.worstRange,
        byWeapon = p.byWeapon, evidence = self:evidence(id),
        firstSeen = p.first, lastSeen = p.last,
    }
end

function ACCore:drainAlerts()
    local out = self.alerts
    self.alerts = {}
    return out
end

function ACCore:onPlayerRemove(id)
    self.players[id] = nil
    self.losCooldown[tostring(id)] = nil
end

function ACCore:sweep(time)
    local cfg = self.cfg
    for id, p in pairs(self.players) do
        if (time - p.last) > cfg.windowMs then
            -- window rolled over: keep the score and the decay clock, drop the
            -- counters that describe a burst of activity that has ended
            p.hits, p.head = 0, 0
            p.rangeViolations, p.worstRange = 0, 0
            p.losReported, p.losBlocked = 0, 0
            p.victims = {}
            p.byWeapon = {}
        end
        while (time - p.lastDecay) >= cfg.decayMs do
            p.score = math.floor(p.score / 2)
            p.lastDecay = p.lastDecay + cfg.decayMs
        end
        if (time - p.last) > (cfg.windowMs * 4) and p.score == 0 then
            self.players[id] = nil
        end
    end
end

function ACCore.weaponReach(weapon)
    return WEAPON_RANGE[weapon]
end

function ACCore.isExplosive(weapon)
    return EXPLOSIVE[weapon] == true
end

return ACCore
