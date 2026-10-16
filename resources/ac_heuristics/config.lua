-- ============================================================================
--  فريق الحماية و استكشاف الثغرات - هاكرز ابيض
--  Security & Vulnerability Research Team — White Hat Hackers
-- ----------------------------------------------------------------------------
--  MTA:SA security research test bed — mta-sa-original-test
--  Internal security research material. All rights reserved by the team above.
--  NRTH-SEC-RESEARCH-HEADER
-- ============================================================================
-- config.lua — thresholds for ac_heuristics. Edit and restart the resource.
--
-- Every value here trades false positives against detection speed. The defaults
-- are deliberately conservative: it is better to miss a subtle cheater than to
-- label a good player as one. Tune them against *your* server's own logs.
-- ============================================================================

AC_CONFIG = {
    enabled = true,

    -- how long a burst of hits is remembered
    windowMs = 30000,

    -- ratio signals never fire below these sample sizes
    minSamples         = 30,
    headshotMinSamples = 25,
    headshotRatio      = 0.75,   -- 75% of hits to the head, over the sample above

    -- line-of-sight reports arrive from clients (the only place world geometry
    -- exists); they are counted only when the server saw the same hit
    losMinSamples   = 5,
    losBlockedRatio = 0.5,
    corroborateMs   = 1500,
    losReportCooldownMs = 250,

    -- damage beyond a weapon's reach
    rangeSlack = 1.15,

    -- several different victims in a very short time, direct fire only
    burstVictims  = 5,
    burstWindowMs = 2500,

    -- score thresholds: watch < suspicious < confirmed
    scoreSuspicious = 25,
    scoreConfirmed  = 60,

    -- suspicion decays by half over this period of clean play
    decayMs = 60000,

    -- events kept per player, shown in /accheck
    evidenceKeep = 12,
}
