---
name: sf6-match-history
description: Read and analyze Danny's Street Fighter 6 ranked match history on his own behalf, with no data handed over. Use for any request like "how did I do", "analyze my last session", "what's changed", "what matchups cost me MR", "my recent Ryu results", "which replays should I review", "am I on a streak", or any question about his CFN/Buckler results, sessions, sets, MR, opponents or matchups. Also use when asked whether the match data is current or whether collection is working. Not for matchup strategy advice (that is sf6-supercombo-matchup) and not for gameplay-mistake claims that need replay video.
---

# SF6 Match History

Built by Claude. Makes the match-history pipeline usable from a cold session with **one query**.

## Who and where

- Danny — CFN short_id `3999489225`, fighter name `wakeUpDPression`, main Ryu, Master rank.
- Data lives in Supabase project **`pfvsnprdvqbwflcemtqh`**. Read it with the Supabase
  connector's `execute_sql`. Every `execute_sql` call prompts Danny for approval, so **use
  as few as possible** — normally exactly one.
- The archive (`public.battles`) is collected every 30 minutes by a `pg_cron` job
  (`sf6-match-bridge-sync`, at :13 and :43) that reads Capcom's Buckler directly. Nothing
  needs Danny's PC or phone. Do not create another scheduler.

## Step 1 — the one query (do this first, always)

```sql
SELECT public.sf6_chat_context() AS context;
```

It returns one JSON object with everything an ordinary analysis needs:

| key | what it is |
|---|---|
| `health` | freshness and coverage — **read this before anything else** |
| `coaching` | current form (last 20 vs previous 80), latest session, streak, latest-session matchups |
| `recent_sessions` | the last five sessions with W/L, MR start/end/peak/trough, sets, opponents |
| `latest_session_matches` | every match of the latest session, replay IDs included |
| `latest_session_matchups` | per-character aggregates for the latest session |
| `pipeline` | the self-describing manifest: sources, invariants, operating rules |

For most questions this is the only query. Answer from it.

## Step 2 — the freshness gate (never skip)

Read `health` and say which of these you are in, in one plain sentence, before any numbers:

- **Current** — `health.sync_status = 'fresh'` AND `health.last_attempt_status = 'succeeded'`
  AND `health.source_currency = 'direct_source_retrieved'`. Analyze normally. Quote
  `health.minutes_since_sync` and `health.latest_match_at` so Danny knows the window.
- **Degraded** — succeeded, but `health.source_currency =
  'relay_cache_not_independently_verified'`. The Buckler session cookie has expired and the
  collector fell back to a third-party relay. Data is still flowing but its currency is not
  independently verified. Say so, analyze anyway, and give Danny this one line:
  > Your Buckler cookie has expired — collection still works via the relay, but to get it
  > direct again it's the 60-second paste: https://claude.ai/artifact/Amn3s8wz9icDpFsN4oog5A
- **Stale or failed** — `sync_status` is not `fresh`, or `last_attempt_status` is not
  `succeeded`. Report `last_attempt_error_code` / `last_attempt_error_detail` and the age.
  **Do not present the archive as current.** You may still analyze historical sessions if
  you label them as such.

Two more `health` fields to surface when relevant: `possible_gap` (collection may have missed
matches — say so) and `history_scope` (the archive is observed history from
`oldest_match_at`, **not** lifetime-complete — never claim it is).

Note: freshness is about the last *source check*, not the age of the latest match. Danny not
having played is not staleness.

## Step 3 — evidence rules (from Danny's brief)

- **Observed vs inferred MR.** `my_mr_before` is observed from match metadata. `my_mr_after`
  is inferred from the next match or a profile snapshot and may be `NULL`; 130 backfilled
  rows have it intentionally `NULL`. Never invent or interpolate it. When a session or
  matchup's `net_mr` is `NULL`, that means at least one delta is unknown — say "partial" and
  give the known count, don't silently drop it.
- **Sessions are inferred** from 30-minute gaps; **sets are inferred** from
  opponent/time/result patterns. Say "session" and "set" but don't claim they are official.
- **No gameplay-mistake claims** from metadata. "You lost 3 sets to Ed" is fine; "you're
  mashing DP on wakeup" needs replay evidence — say so and hand over the `replay_id`s.
- **Never coerce unknown to a number.** If a field is null, it's unknown.

## Deeper questions — second query only if needed

If `sf6_chat_context()` doesn't answer it, these views exist (all keyed to the same enriched
match table). One targeted `SELECT`, then stop:

| view | answers |
|---|---|
| `sf6_matchup_summary` | lifetime W/L, net MR, avg opponent MR **per opponent character** |
| `sf6_matchup_form` | the same, split recent vs baseline — "is X getting better or worse" |
| `sf6_opponent_summary` | per **opponent player** — recurrence, W/L, what they play |
| `sf6_sessions` / `sf6_sets` | every session / every inferred set |
| `sf6_session_matchups` | per-character results inside one session |
| `sf6_mr_curve` | MR before/after per match, for trend over time |
| `sf6_streak_runs` | win/loss streak runs |
| `sf6_recent_vs_baseline` | overall form shift |
| `sf6_matches_enriched` | the raw enriched rows if nothing else fits |

Reach for `public.battles` directly only as a last resort.

## Forcing a fresh collection (rare)

Data is at most ~30 minutes old by design. Only if Danny explicitly wants "right now" and
`minutes_since_sync` > 30: `SELECT public.sf6_trigger_sync(true);` then re-read
`sf6_chat_context()` after ~40 seconds. A queued request is not proof of success — check
`health.last_attempt_status` afterwards. This costs extra prompts; don't do it by default.

## Do not

- `SELECT` from `vault.*` — never pull secrets into chat.
- Run anything but `SELECT` (and `sf6_trigger_sync` above). No DDL, no `GRANT`.
- Re-grant `anon` on any `sf6_*` RPC. They were revoked deliberately by the other agent.
- Edit `public.sf6_project_contract` — it belongs to the other agent.
- Revive `tools/collect.mjs`, `collect.yml`, or the Android app in this repo. They are dead
  backups of a system that already works.

## Context another session would otherwise have to rediscover

- **Two agents share this database.** ChatGPT built the collector, the views,
  `sf6_chat_context()`, the health layer and the backfill. Claude built the cookie-intake
  endpoint (`claude-sf6-cookie-intake`) and this skill. Their `pipeline.operating_rules.upstream`
  line saying "no credential configured" is **stale** since 2026-09-17 14:09 — trust
  `health.source_currency` instead.
- The cookie was supplied once on 2026-09-17 14:09. Its lifetime is **unknown**; the gate
  above is how you find out it expired. Expiry is harmless — the collector falls back.
- 130 matches (2026-08-09 → 2026-09-16) are a backfill from SF6 Stats. They have observed
  `my_mr_before` and no `my_mr_after`. Live-collected rows since 2026-09-16 are richer.
