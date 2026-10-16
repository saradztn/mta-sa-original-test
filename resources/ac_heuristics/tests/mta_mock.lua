-- ============================================================================
--  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
--  Security & Vulnerability Research Team — White Hat Hackers
-- ----------------------------------------------------------------------------
--  MTA:SA security research test bed — mta-sa-original-test
--  Internal security research material. All rights reserved by the team above.
--  NRTH-SEC-RESEARCH-HEADER
-- ============================================================================
-- mta_mock.lua — a small, honest MTA server/client environment for tests.
--
-- It implements only the API surface this resource touches, with MTA's real
-- signatures, plus a scripted clock and a deterministic line-of-sight verdict.
-- Anything not implemented stays nil on purpose: if the resource ever calls an
-- API this mock does not model, the test fails loudly instead of passing by
-- accident.
--
-- Not part of the resource. Loaded only by tests/test_ac_heuristics.lua.
-- ============================================================================

local M = {}
M.clock = 0
M.logs = {}
M.chat = {}
M.events = {}      -- eventName -> { remote = bool }
M.handlers = {}    -- eventName -> { fn, ... }
M.commands = {}    -- commandName -> fn
M.timers = {}
M.players = {}
M.acl = { Admin = { name = "Admin" } }
M.losBlocked = false
M.losCalls = {}
M.remoteCalls = {}

-- sentinels ---------------------------------------------------------------
M.root = { __element = true, type = "root", name = "root" }
M.resourceRoot = { __element = true, type = "resource", name = "ac_heuristics" }
M.localPlayer = nil

function M.createPlayer(name, opts)
    opts = opts or {}
    local p = {
        __element = true, type = "player", name = name,
        x = opts.x or 0, y = opts.y or 0, z = opts.z or 0,
        account = opts.guest and nil or { name = name, guest = false },
    }
    if opts.admin then
        M.acl["user." .. name] = M.acl.Admin
    end
    table.insert(M.players, p)
    return p
end

function M.reset()
    M.clock = 0
    M.logs, M.chat, M.remoteCalls, M.losCalls = {}, {}, {}, {}
    M.events, M.handlers, M.commands, M.timers, M.players = {}, {}, {}, {}, {}
end

function M.advance(ms)
    local target = M.clock + ms
    while true do
        local nextTimer, nextIndex = nil, nil
        for i, t in ipairs(M.timers) do
            if t.nextAt <= target and (nextTimer == nil or t.nextAt < nextTimer.nextAt) then
                nextTimer, nextIndex = t, i
            end
        end
        if not nextTimer then break end
        M.clock = nextTimer.nextAt
        nextTimer.remaining = nextTimer.remaining - 1
        if nextTimer.remaining <= 0 then
            table.remove(M.timers, nextIndex)
        else
            nextTimer.nextAt = nextTimer.nextAt + nextTimer.interval
        end
        nextTimer.fn()
    end
    M.clock = target
end

function M.fire(eventName, sourceElem, ...)
    local prevSource = _G.source
    _G.source = sourceElem
    local list = M.handlers[eventName]
    if list then
        for _, fn in ipairs(list) do
            fn(...)
        end
    end
    _G.source = prevSource
end

-- report a client-side observation: runs every client handler for the event
-- with `client` set to the reporter, exactly as MTA would on the server side
function M.clientFire(eventName, reporter, sourceElem, ...)
    local prevClient = _G.client
    _G.client = reporter
    local list = M.handlers[eventName]
    if list then
        for _, fn in ipairs(list) do
            fn(...)
        end
    end
    _G.client = prevClient
end

-- globals the resource expects -------------------------------------------
_G.root = M.root
_G.resourceRoot = M.resourceRoot
_G.source = nil
_G.client = nil
_G.localPlayer = nil

function getTickCount() return M.clock end
function addEvent(name, remote)
    M.events[name] = { remote = remote and true or false }
end
function addEventHandler(name, element, fn)
    M.handlers[name] = M.handlers[name] or {}
    table.insert(M.handlers[name], fn)
end
function addCommandHandler(name, fn) M.commands[name] = fn end
function setTimer(fn, interval, times)
    local t = { fn = fn, interval = interval, nextAt = M.clock + interval,
                remaining = (times == 0) and math.huge or times }
    table.insert(M.timers, t)
    return t
end
function outputServerLog(text) table.insert(M.logs, text) end
function outputDebugString(text) table.insert(M.logs, "[debug] " .. text) end
function outputChatBox(text, player) table.insert(M.chat, { text = text, player = player }) end

function isElement(e) return type(e) == "table" and e.__element == true end
function getElementType(e)
    if type(e) == "table" and e.type then return e.type end
    return false
end
function getPlayerName(e)
    if type(e) == "table" and e.name then return e.name end
    return false
end
function getElementPosition(e)
    if type(e) == "table" then return e.x or 0, e.y or 0, e.z or 0 end
    return false
end
function getDistanceBetweenPoints3D(a, b, c, d, e, f)
    if isElement(a) and isElement(b) then
        local ax, ay, az = getElementPosition(a)
        local bx, by, bz = getElementPosition(b)
        return math.sqrt((ax - bx) ^ 2 + (ay - by) ^ 2 + (az - bz) ^ 2)
    end
    return math.sqrt((a - c) ^ 2 + (b - d) ^ 2 + (e - f) ^ 2)
end
function getElementsByType(t)
    if t ~= "player" then return {} end
    return M.players
end
function getPlayerFromName(name)
    for _, p in ipairs(M.players) do
        if p.name == name then return p end
    end
    return false
end
function getPlayerAccount(p) return p.account end
function isGuestAccount(acc) return acc == nil or acc.guest == true end
function getAccountName(acc) return acc and acc.name or false end
function aclGetGroup(name) return name == "Admin" and M.acl.Admin or false end
function isObjectInACLGroup(obj, group)
    if not group then return false end
    return M.acl[obj] ~= nil and M.acl[obj] == group
end

-- client-side API ---------------------------------------------------------
function isLineOfSightClear(sx, sy, sz, ex, ey, ez, b, v, p, o, d, s)
    table.insert(M.losCalls, { sx, sy, sz, ex, ey, ez, b, v, p, o, d, s })
    return not M.losBlocked
end
function triggerServerEvent(name, to, ...)
    table.insert(M.remoteCalls, { name = name, args = { ... } })
    local reporter = _G.client
    M.clientFire(name, reporter, nil, ...)
end

return M
