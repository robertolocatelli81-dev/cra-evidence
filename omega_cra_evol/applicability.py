# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which CRA obligations are in force for whom, from which instant, and the horizons the Regulation counts in years
(Reg. (EU) 2024/2847). Contributed by Athena, the project's confined research agent (17/10/2026), reviewed by Noûs
(19/10/2026): every provision below re-read on the primary text.

Sources (read 19/10/2026):
- Regulation (EU) 2024/2847, OJ L, 2024/2847, 20.11.2024 — the Official Journal XHTML served by the Publications Office
  (publications.europa.eu/resource/celex/32024R2847, cellar 21b7d4eb-a6e2-11ef-85f0-01aa75ed71a1, sha256 fe0cca4a…71ed):
  - Art. 71(2): "This Regulation shall apply from 11 December 2027. However, Article 14 shall apply from 11 September
    2026 and Chapter IV (Articles 35 to 51) shall apply from 11 June 2026."
  - Art. 69(2): a product placed on the market before 11 December 2027 is subject to the requirements "only if, from that
    date, those products are subject to a substantial modification"; Art. 69(3): by derogation, Article 14 applies to all
    products in scope placed on the market before 11 December 2027.
  - Art. 24(3): Art. 14(1) applies to open-source software stewards "to the extent that they are involved in the
    development of the products with digital elements"; Art. 14(3) AND (8) "to the extent that severe incidents ... affect network and
    information systems provided by the open-source software stewards for the development of such products".
  - Art. 13(8) third subparagraph: the support period "shall be at least five years"; where the product is expected to
    be in use for less, it "shall correspond to the expected use time". Art. 13(9): each security update made available
    during the support period remains available "for a minimum of 10 years or for the remainder of the support period,
    whichever is longer". Art. 13(13): technical documentation and EU declaration of conformity kept "for at least 10
    years after the product ... has been placed on the market or for the support period, whichever is longer".
  - Art. 14(1): the manufacturer notifies "any actively exploited vulnerability ... that it becomes aware of";
    Art. 14(3): "any severe incident ... that it becomes aware of"; Art. 14(8): inform the impacted users — no hour count.
- Regulation (EEC, Euratom) No 1182/71 (publications.europa.eu/resource/celex/31971R1182, sha256 d04e0761…74a5):
  Art. 4(2): application "fixed at a given date shall occur at the beginning of the first hour of the day falling on
  that date"; Art. 3(1) second subparagraph and 3(2)(c): a period in years calculated from an event excludes the day of
  the event and ends "with the expiry of the last hour" of the day in the last year that falls on the same date (the
  last day of the month when that date does not exist). Neither article names a time zone. (1182/71 speaks of acts of
  the Council or Commission; its use for this Regulation of the Parliament and the Council is this tool's reading.)
- Commission guidance C(2026) 5252, annex (ec.europa.eu/newsroom/dae/redirection/document/131456, sha256 fe209c25…8234),
  §217, pp. 75–76 (the content of the DRAFT guidance, approved 27/07/2026; formal adoption not checked) — NON-BINDING
  interpretation: the obligation to report applies when the manufacturer becomes aware of
  ACTIVE EXPLOITATION; a vulnerability whose active exploitation it knew before 11 September 2026 is not reported
  retroactively; one known before that date whose exploitation becomes known after it is reported. §217 speaks of
  vulnerabilities. For a severe incident §211 ties the obligation to the awareness that it has occurred; that an
  incident known before 11 September 2026 is not reported is this tool's reading (§217 does not say it). The 84 pages name no time zone and no hour of the start.

The start instant of a date of the Regulation: Art. 4(2) of 1182/71 gives the hour (the beginning of the day), nothing
gives the time zone. Every date threshold is therefore computed under TWO readings — 00:00 UTC and 00:00 Europe/Brussels
(CET/CEST by the EU summer-time rule, Directive 2000/84/EC) — and both answers are returned. When they agree the result
is net; when they differ it is `depends_on_time_zone_reading`, with both answers: never one picked in silence. Net
means net between these two readings: other local times of the Union (UTC+3 in September in eight Member States, the
outermost regions from UTC-4 to UTC+4) are not computed.
Nothing here decides whether a product is in scope (Art. 2), whether a modification is substantial, whether a declared
shorter expected use is justified, or whether the steward's scope condition is met: recorded as given.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

from .vuln import add_months, parse_utc

# the dates of the Regulation (Art. 71(2), 69(2)-(3)); their start instants are computed per reading, never fixed in UTC
ART14_DATE = (2026, 9, 11)
FULL_APPLICATION_DATE = (2027, 12, 11)
CHAPTER_IV_DATE = (2026, 6, 11)
READINGS = ("utc", "europe_brussels")
ROLES = ("manufacturer", "open_source_steward")
STREAMS = ("vulnerability", "incident")
SUPPORT_PERIOD_MIN_YEARS = 5
UPDATE_AVAILABILITY_YEARS = 10
RETENTION_YEARS = 10
SUPPORT_STATUSES = ("meets_minimum", "shorter_declared", "below_minimum", "depends_on_time_zone_reading")
DEPENDS = "depends_on_time_zone_reading"
START_RULE = ("a date of the Regulation applies from the beginning of the first hour of that day (Reg. 1182/71 Art. 4(2)); "
              "no text names the time zone: computed at 00:00 UTC and at 00:00 Europe/Brussels, both returned")
PERIOD_RULE = ("a period in years from an event excludes the day of the event and ends at the expiry of the same date in "
               "the last year (Reg. 1182/71 Art. 3(1), 3(2)(c)); the day is read in UTC and in Europe/Brussels, both "
               "returned; the extension of Art. 3(4) (a last day on a Saturday, Sunday or public holiday) is NOT applied")
GUIDANCE = ("Commission guidance C(2026) 5252, annex §217, pp. 75-76 (non-binding): the obligation arises on awareness "
            "of active exploitation; exploitation known before 11 September 2026 is not reported retroactively; a "
            "vulnerability known before that date whose exploitation becomes known after it is reported")


def _last_sunday(y: int, m: int) -> datetime:
    d = datetime(y, m + 1, 1, tzinfo=timezone.utc) - timedelta(days=1) if m < 12 else datetime(y, 12, 31, tzinfo=timezone.utc)
    return d - timedelta(days=(d.weekday() + 1) % 7)


def brussels_offset(at: datetime) -> timedelta:
    """UTC offset of Europe/Brussels at the instant `at` (aware): CET +1 h, CEST +2 h from 01:00 UTC on the last Sunday of
    March to 01:00 UTC on the last Sunday of October (Directive 2000/84/EC). Equal to the IANA zone from 1996 (tested
    2000-2040); before 1996 Belgian summer time ended in September and this rule differs."""
    u = at.astimezone(timezone.utc)
    start = _last_sunday(u.year, 3).replace(hour=1)
    end = _last_sunday(u.year, 10).replace(hour=1)
    return timedelta(hours=2 if start <= u < end else 1)


def day_start(y: int, m: int, d: int, reading: str) -> datetime:
    """00:00 of the calendar day y-m-d under `reading`, as an aware UTC instant (no transition falls at midnight)."""
    if reading == "utc":
        return datetime(y, m, d, tzinfo=timezone.utc)
    if reading != "europe_brussels":
        raise ValueError(f"reading must be one of {READINGS}")
    local = datetime(y, m, d, tzinfo=timezone.utc)
    for h in (2, 1):
        cand = local - timedelta(hours=h)
        if brussels_offset(cand) == timedelta(hours=h):
            return cand
    raise AssertionError("unreachable: Brussels is UTC+1 or UTC+2")


def local_date(at: datetime, reading: str):
    """The calendar date of the instant `at` under `reading`."""
    u = at.astimezone(timezone.utc)
    return (u if reading == "utc" else u + brussels_offset(u)).date()


def add_years(d: datetime, years: int) -> datetime:
    """Calendar years; 29 February lands on 28 February in a year that has none (as add_months clamps the day)."""
    return add_months(d, 12 * years)


def _iso(d: datetime) -> str:
    return d.astimezone(timezone.utc).isoformat(timespec="seconds")


def _per_reading(fn: Callable[[str], Any]) -> Dict[str, Any]:
    return {r: fn(r) for r in READINGS}


def years_after(event: datetime, years: int, reading: str) -> datetime:
    """End of a period of `years` years from the instant `event` under 1182/71 Art. 3(1), 3(2)(c), the day read under
    `reading`: the expiry of the last hour of the same date `years` later (clamped to the month's last day), i.e. the
    start of the following day."""
    day = local_date(event, reading)
    last = add_years(datetime(day.year, day.month, day.day, tzinfo=timezone.utc), years) + timedelta(days=1)
    return day_start(last.year, last.month, last.day, reading)


def _starts(date) -> Dict[str, str]:
    return {r: _iso(day_start(*date, r)) for r in READINGS}


def _net(per: Dict[str, Any]) -> Optional[Any]:
    vals = list(per.values())
    return vals[0] if all(v == vals[0] for v in vals) else None


def reporting_in_force(role: str, at_utc: str, stream: str = "vulnerability") -> Dict[str, Any]:
    """Is the Art. 14 reporting obligation of `role` for `stream` in force at the instant `at_utc`, under each reading of
    the start day? For a steward the result also carries the scope condition of Art. 24(3), recorded and never checked."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if stream not in STREAMS:
        raise ValueError(f"stream must be one of {STREAMS}")
    at = parse_utc(at_utc)
    if role == "manufacturer":
        date, cond = ART14_DATE, None
        basis = ("Art. 14, applying from 11 September 2026 (Art. 71(2)), also to products placed on the market before "
                 "11 December 2027 (Art. 69(3))")
    else:
        date = FULL_APPLICATION_DATE
        basis = ("Art. 24(3), applying from 11 December 2027 (Art. 71(2)): Art. 14(1) for vulnerabilities; Art. 14(3) and "
                 "14(8) for severe incidents")
        cond = ("only to the extent the steward is involved in the development of the product (Art. 24(3))" if stream == "vulnerability"
                else "only where the severe incident affects the network and information systems the steward provides for the "
                     "development of the product (Art. 24(3)); Art. 14(8) (inform the users) under the same condition")
    per = _per_reading(lambda r: at >= day_start(*date, r))
    net = _net(per)
    return {"role": role, "stream": stream, "at_utc": _iso(at),
            "outcome": DEPENDS if net is None else ("in_force" if net else "not_in_force"), "in_force": net,
            "readings": {r: {"applies_from_utc": _starts(date)[r], "in_force": per[r]} for r in READINGS},
            "basis": basis, "scope_condition": cond, "scope_condition_checked": False, "start_rule": START_RULE}


def art14_obligation(trigger_awareness_utc: str, role: str = "manufacturer", stream: str = "vulnerability",
                     vulnerability_awareness_utc: Optional[str] = None) -> Dict[str, Any]:
    """Does the reporting obligation arise for this event? The trigger is the instant the reporter became aware of the
    ACTIVE EXPLOITATION of the vulnerability (stream `vulnerability`) or of the severe incident (stream `incident`) —
    NOT of the vulnerability itself (guidance §217). The obligation arises iff that awareness is at or after the start
    of the role's obligation; computed under both readings of the start day. `vulnerability_awareness_utc` (optional,
    vulnerability stream) is recorded and checked to precede the trigger; it never decides the outcome: a vulnerability
    known before 11 September 2026 whose exploitation becomes known after it is reported (§217)."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if stream not in STREAMS:
        raise ValueError(f"stream must be one of {STREAMS}")
    trig = parse_utc(trigger_awareness_utc)
    va = None
    if vulnerability_awareness_utc is not None:
        if stream != "vulnerability":
            raise ValueError("vulnerability_awareness_utc applies to the vulnerability stream only")
        va = parse_utc(vulnerability_awareness_utc)
        if va > trig:
            raise ValueError("vulnerability_awareness_utc later than the awareness of its active exploitation")
    date = ART14_DATE if role == "manufacturer" else FULL_APPLICATION_DATE
    per = _per_reading(lambda r: trig >= day_start(*date, r))
    net = _net(per)
    return {"role": role, "stream": stream,
            "trigger": "awareness of the active exploitation" if stream == "vulnerability" else "awareness of the severe incident",
            "trigger_awareness_utc": _iso(trig), "vulnerability_awareness_utc": _iso(va) if va else None,
            "outcome": DEPENDS if net is None else ("obligation" if net else "no_obligation"), "obligation": net,
            "readings": {r: {"obligation_from_utc": _starts(date)[r], "obligation": per[r]} for r in READINGS},
            "norm": ("Art. 14(1)/(3) (\"that it becomes aware of\"), applying from 11 September 2026 (Art. 71(2))" if role == "manufacturer"
                     else "Art. 24(3) with Art. 14(1)/(3), applying from 11 December 2027 (Art. 71(2))"),
            "interpretation": GUIDANCE + ("" if stream == "vulnerability" else "; §217 speaks of vulnerabilities: for a severe "
                                          "incident §211 ties the obligation to awareness, and no reporting of an incident "
                                          "known before 11 September 2026 is this tool's reading, not the guidance's"),
            "start_rule": START_RULE}


def legacy_product_scope(placed_on_market_utc: str, substantially_modified_utc: Optional[str] = None) -> Dict[str, Any]:
    """Art. 69(2)-(3) for a product in scope: do the essential requirements reach it, and does Art. 14? A substantial
    modification counts only from 11 December 2027 ("from that date"); whether one is substantial is not decided here."""
    placed = parse_utc(placed_on_market_utc)
    mod = parse_utc(substantially_modified_utc) if substantially_modified_utc else None
    if mod is not None and mod < placed:
        raise ValueError("substantially_modified_utc earlier than placed_on_market_utc")

    def req(r):
        full = day_start(*FULL_APPLICATION_DATE, r)
        return placed >= full or (mod is not None and mod >= full)
    per = _per_reading(req)
    net = _net(per)
    if net is None:
        basis = "depends on the time-zone reading of 11 December 2027: see readings"
    elif net and all(placed >= day_start(*FULL_APPLICATION_DATE, r) for r in READINGS):
        basis = "placed on the market from 11 December 2027: the Regulation applies (Art. 71(2))"
    elif net and placed >= day_start(*FULL_APPLICATION_DATE, "europe_brussels"):
        basis = ("placed on 11 December 2027 under the Europe/Brussels reading (the Regulation applies, Art. 71(2)) and on "
                 "10 December under the UTC reading, substantially modified from 11 December 2027 (Art. 69(2))")
    elif net:
        basis = "placed before 11 December 2027 and substantially modified from that date (Art. 69(2))"
    else:
        basis = ("placed before 11 December 2027 and not substantially modified from that date: the requirements do not "
                 "apply (Art. 69(2)); Article 14 does (Art. 69(3))")
    return {"placed_on_market_utc": _iso(placed), "substantially_modified_utc": _iso(mod) if mod else None,
            "outcome": DEPENDS if net is None else ("requirements_apply" if net else "requirements_do_not_apply"),
            "requirements_apply": net, "readings": {r: {"full_application_from_utc": _starts(FULL_APPLICATION_DATE)[r],
                                                        "requirements_apply": per[r]} for r in READINGS},
            "art14_applies": True, "art14_applies_from_utc": _starts(ART14_DATE), "basis": basis,
            "in_scope_checked": False, "substantial_checked": False, "start_rule": START_RULE}


def support_period(placed_on_market_utc: str, support_period_end_utc: str,
                   shorter_expected_use_reason: Optional[str] = None) -> Dict[str, Any]:
    """Art. 13(8): at least five years — counted here from the placing on the market given (the guidance's Example 52
    counts it so; the Regulation does not name the start) — shorter only where the product is expected to be in use for
    less. A shorter period WITH a declared reason is `shorter_declared` (recorded, not assessed); without one it is
    `below_minimum`. A reason given for a period that meets the minimum under both readings is refused."""
    placed, end = parse_utc(placed_on_market_utc), parse_utc(support_period_end_utc)
    if end <= placed:
        raise ValueError("support_period_end_utc must be later than placed_on_market_utc")
    reason = (shorter_expected_use_reason or "").strip() or None
    minimum = _per_reading(lambda r: years_after(placed, SUPPORT_PERIOD_MIN_YEARS, r))
    meets = {r: end >= minimum[r] for r in READINGS}
    if all(meets.values()):
        if reason:
            raise ValueError("shorter_expected_use_reason given for a support period that meets the five-year minimum")
        status = "meets_minimum"
    elif not any(meets.values()):
        status = "shorter_declared" if reason else "below_minimum"
    else:
        status = DEPENDS
    per = {r: ("meets_minimum" if meets[r] else ("shorter_declared" if reason else "below_minimum")) for r in READINGS}
    return {"status": status, "placed_on_market_utc": _iso(placed), "support_period_end_utc": _iso(end),
            "readings": {r: {"minimum_end_utc": _iso(minimum[r]), "status": per[r]} for r in READINGS},
            "shorter_expected_use_reason": reason, "reason_assessed": False, "period_rule": PERIOD_RULE,
            "basis": "support period at least five years, shorter only for a shorter expected use (Art. 13(8))"}


def _horizon(start: datetime, years: int, end: Optional[datetime]) -> Dict[str, Any]:
    ten = _per_reading(lambda r: years_after(start, years, r))
    per = {r: {"until_utc": _iso(end if (end is not None and end > ten[r]) else ten[r]),
               "governed_by": "support_period" if (end is not None and end > ten[r]) else "ten_years"} for r in READINGS}
    return {"readings": per, "latest_until_utc": max(p["until_utc"] for p in per.values()), "period_rule": PERIOD_RULE}


def retention_until(placed_on_market_utc: str, support_period_end_utc: Optional[str] = None) -> Dict[str, Any]:
    """Art. 13(13): 10 years after placing on the market, or the support period if that is longer. The horizon runs
    from the instant given: give the latest placing on the market you know of (an earlier one gives a shorter horizon).
    `latest_until_utc` is the later of the two readings (keeping until then satisfies both)."""
    h = _horizon(parse_utc(placed_on_market_utc), RETENTION_YEARS, parse_utc(support_period_end_utc) if support_period_end_utc else None)
    h["basis"] = "10 years after placing on the market or the support period, whichever is longer (Art. 13(13))"
    return h


def update_available_until(issued_utc: str, support_period_end_utc: Optional[str] = None) -> Dict[str, Any]:
    """Art. 13(9): a security update stays available at least 10 years after it is issued, or for the remainder of
    the support period if that is longer. `latest_until_utc`: the later of the two readings."""
    h = _horizon(parse_utc(issued_utc), UPDATE_AVAILABILITY_YEARS, parse_utc(support_period_end_utc) if support_period_end_utc else None)
    h["basis"] = "10 years after issue or the remainder of the support period, whichever is longer (Art. 13(9))"
    return h


def user_information(awareness_utc: str, users_informed_utc: Optional[str] = None) -> Dict[str, Any]:
    """Art. 14(8): the instant the impacted users were informed, as recorded. No deadline is computed: the Regulation
    gives no hour count for it (where the manufacturer does not inform them in a timely manner, the coordinating CSIRT
    may). `not_recorded` says only that no instant was given, never that the users were not informed."""
    aw = parse_utc(awareness_utc)
    inf = parse_utc(users_informed_utc) if users_informed_utc else None
    if inf is not None and inf < aw:
        raise ValueError("users_informed_utc earlier than awareness_utc")
    return {"status": "recorded" if inf else "not_recorded", "users_informed_utc": _iso(inf) if inf else None,
            "deadline_utc": None, "basis": "inform the impacted users, and where appropriate all users (Art. 14(8)); "
                                           "the Regulation sets no hour count: no deadline is computed"}
