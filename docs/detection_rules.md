# Detection rules & scoring

Two mechanisms turn raw events into something an analyst acts on: **rules**
(discrete alerts for specific behaviours) and **scoring** (a continuous per-source
threat number). They answer different questions — "what happened?" vs. "who
should I look at first?" — and are described in turn below.

The engine is [`pipeline/detection/rules.py`](../pipeline/detection/rules.py);
the rules are [`pipeline/detection/rules.yaml`](../pipeline/detection/rules.yaml);
scoring is [`pipeline/detection/scoring.py`](../pipeline/detection/scoring.py).

---

## Rules

### Why YAML

Rules are data, not code, so adding or tuning a detection is a reviewable change
that doesn't require reading Python. The engine validates every rule on load and
**fails loud** on a malformed one — a detection that silently fails to load is
more dangerous than one that refuses to start.

### The sliding window — the key idea

Each rule has a `window_minutes`. That window **slides over the events
themselves**, not over "the last N minutes before now." A threshold rule fires
if *any* N-minute span in the data satisfies it.

This is the only semantics that is correct in both directions:

- Anchoring to wall-clock *now* means a rule can only ever fire on events from
  the last few minutes — so replaying yesterday's traffic, a seeded dataset, or
  an imported log detects **nothing**, and a scheduled run that lands a minute
  late silently misses the burst it exists to catch.
- Sliding the window makes detection a property of the **data**, which also
  makes it **reproducible**: the same events always produce the same alerts.

### Rule types

| `type` | Fires when | `threshold` means |
|--------|-----------|-------------------|
| `threshold` | ≥ N events in the window for one group | event count |
| `distinct` | ≥ N distinct values of `distinct_field` | distinct count |
| `match` | any event matches (no threshold) | — |
| `ratio` | numerator/total ≥ N | a fraction (needs `numerator_where`) |

### The `where` block

All conditions must hold. Supported forms:

```yaml
where:
  service: ssh                    # equality
  service: [ssh, telnet]          # membership
  command__contains: /etc/shadow  # case-insensitive substring
  tags__in_tags: mirai-signature  # tag present in the event's tag list
  threat_score__gte: 40           # numeric >=
  status_code__lte: 299           # numeric <=
  password__isnull: false         # null / not-null
```

### Deduplication

Each rule emits **one alert per `(rule_id, group_by value)`**, not one per
event. Re-firing bumps `hit_count` and `last_seen`. `hit_count` takes the *max*
on re-evaluation, not a sum — with sliding windows the incoming value is a
recomputed peak, so summing would inflate the count on every scheduled re-run.
The result is an idempotent detection pass and a triage queue that shows "brute
force from 10.0.0.5 ×400" as one row, not four hundred.

### Adding a rule

Append to `rules.yaml`:

```yaml
  - id: my_new_rule            # unique; also the dedupe namespace
    name: Human readable name
    severity: high             # info|low|medium|high|critical
    type: threshold
    window_minutes: 10
    group_by: src_ip
    threshold: 25
    where:
      service: http
      status_code__gte: 500
    mitre: [T1499]
    description: >
      What fired and why it matters. This is what the analyst reads.
```

Validate and dry-run it over existing data:

```bash
python -c "from pipeline.detection.rules import load_rules; load_rules()"   # validates
# then re-run detection from the dashboard's Alerts page, or:
python -c "from storage.db import session_scope; from pipeline.detection.rules import run_detection; \
           import contextlib; \
           [print(run_detection(db, since_hours=168)) for db in [session_scope().__enter__()]]"
```

### Shipped rules

21 rules across four groups — credential attacks, post-exploitation, web attacks,
and reconnaissance/behaviour. The full list with thresholds and MITRE mappings is
in [`rules.yaml`](../pipeline/detection/rules.yaml); the dashboard's Alerts page
also renders them live at `/api/alerts/rules`.

---

## Scoring

Each source gets a **0–100 threat score** and a **behavioural classification**,
recomputed by `rebuild_attackers()`.

### Why a transparent additive model, not ML

The score is a bounded sum of documented components. An analyst can always ask
"why is this IP an 82?" and get a component-by-component answer
(`score_breakdown` / the `/attackers/{ip}` explanation). A black-box classifier
that scores better on average but can't justify a single verdict is the wrong
tool for triage, where every output has to survive being questioned.

### Components

Each is bounded by a weight (the ceilings sum to more than 100 on purpose — the
total is clamped, so a source can top out several different ways):

| Component | Weight | Captures |
|-----------|-------:|----------|
| `post_exploitation` | 30 | shell access, commands, payload fetches, uploads |
| `severity` | 25 | worst-case severity seen, and how often high-sev recurred |
| `threat_intel` | 20 | indicator/UA/username match (the **max**, not the sum) |
| `credential_breadth` | 18 | distinct usernames/passwords tried (log-scaled) |
| `volume` | 15 | event count (log-scaled — 10→100 matters, 10k→100k doesn't) |
| `persistence` | 12 | time span and session count |
| `service_breadth` | 8 | number of distinct services touched |

The weights encode one judgement: **what an attacker did outweighs how much.**
One source that ran a command inside the shell outranks one that sent ten
thousand connection attempts — volume is cheap, access is not.

### Recency decay

The final score is multiplied by `exp(-age_days / 30)`, floored at 0.4. A source
that was noisy last month shouldn't sit atop today's queue forever, but history
still matters for attribution, so nothing decays below 40% of what it earned.

### Classifications

Checked in order, first match wins (most specific/serious first):

`botnet-loader` → `targeted-intrusion` → `exploit-attempt` →
`credential-bruteforce` → `web-scanner` → `recon-scanner` →
`opportunistic-probe` → `low-signal`.

The dashboard colours and groups sources by these, and the attacker profile shows
the full breakdown behind the number.
