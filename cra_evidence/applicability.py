# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which CRA obligations are in force for whom, and the horizons the Regulation counts in years (Reg. (EU) 2024/2847).

Read on 17/10/2026 (the Official Journal text as reproduced article by article on springlex.eu, OJ L 2024/2847 of
20.11.2024 — EUR-Lex served no text to the fetcher that day; ENISA's SRP FAQ, page updated 15/10/2026):
- Art. 71(2): the Regulation applies from 11 December 2027; Article 14 from 11 September 2026; Chapter IV (Art. 35-51,
  notification of conformity assessment bodies) from 11 June 2026.
- Art. 69(2)-(3): a product placed on the market before 11 December 2027 is subject to the Regulation only if it is
  substantially modified from that date — EXCEPT Article 14, which applies to every product in scope placed on the
  market before that date.
- Art. 24(3): Art. 14(1) applies to open-source software stewards to the extent they are involved in the development of
  the product; Art. 14(3) to the extent a severe incident affects the network and information systems they provide for
  that development. Art. 24 applies from 11 December 2027 (Art. 71(2)); the ENISA FAQ says the same.
- Art. 13(8): the support period is at least five years, shorter only where the product is expected to be in use for
  less. Art. 13(9): each security update stays available at least 10 years after it is issued, or for the remainder of
  the support period if that is longer. Art. 13(13): technical documentation and EU declaration of conformity kept at
  least 10 years after placing on the market, or for the support period if that is longer.
- Art. 14(8): inform the impacted users (and where appropriate all users) of an actively exploited vulnerability or a
  severe incident. The Regulation sets no hour count there: this module records the instant, it never computes a deadline.

The Regulation names days, not instants: "from 11 September 2026" is read here as 00:00:00 UTC of that day. That is a
CONVENTION of this tool (the Regulation names no time zone), and every result says so. Nothing here decides whether a
product is in scope (Art. 2), whether a modification is substantial, or whether a declared shorter expected use is
justified: those are the manufacturer's determinations, recorded as given.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from .vuln import add_months, parse_utc

ART14_APPLIES_FROM = "2026-09-11T00:00:00+00:00"
FULL_APPLICATION_FROM = "2027-12-11T00:00:00+00:00"
CHAPTER_IV_APPLIES_FROM = "2026-06-11T00:00:00+00:00"
DAY_CONVENTION = ("a date of the Regulation is read as 00:00:00 UTC of that day (convention of this tool: the Regulation "
                  "names no time zone)")
ROLES = ("manufacturer", "open_source_steward")
STREAMS = ("vulnerability", "incident")
SUPPORT_PERIOD_MIN_YEARS = 5
UPDATE_AVAILABILITY_YEARS = 10
RETENTION_YEARS = 10
SUPPORT_STATUSES = ("meets_minimum", "shorter_declared", "below_minimum")


def add_years(d: datetime, years: int) -> datetime:
    """Calendar years; 29 February lands on 28 February in a year that has none (as add_months clamps the day)."""
    return add_months(d, 12 * years)


def _iso(d: datetime) -> str:
    return d.isoformat(timespec="seconds")


def reporting_in_force(role: str, at_utc: str, stream: str = "vulnerability") -> Dict[str, Any]:
    """Is the Art. 14 reporting obligation of `role` for `stream` in force at the instant `at_utc`? For a steward the
    result also carries the scope condition of Art. 24(3), which this tool records and never checks."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if stream not in STREAMS:
        raise ValueError(f"stream must be one of {STREAMS}")
    at = parse_utc(at_utc)
    if role == "manufacturer":
        frm, cond = ART14_APPLIES_FROM, None
        basis = ("Art. 14, applying from 11 September 2026 (Art. 71(2)), also to products placed on the market before "
                 "11 December 2027 (Art. 69(3))")
    else:
        frm = FULL_APPLICATION_FROM
        basis = ("Art. 24(3), applying from 11 December 2027 (Art. 71(2)): Art. 14(1) for vulnerabilities, Art. 14(3) for "
                 "severe incidents, within the steward's scope")
        cond = ("only to the extent the steward is involved in the development of the product (Art. 24(3))" if stream == "vulnerability"
                else "only where the severe incident affects the network and information systems the steward provides for the "
                     "development of the product (Art. 24(3))")
    return {"role": role, "stream": stream, "at_utc": _iso(at), "in_force": at >= parse_utc(frm), "applies_from_utc": frm,
            "basis": basis, "scope_condition": cond, "scope_condition_checked": False, "convention": DAY_CONVENTION}


def legacy_product_scope(placed_on_market_utc: str, substantially_modified_utc: Optional[str] = None) -> Dict[str, Any]:
    """Art. 69(2)-(3) for a product in scope: do the essential requirements reach it, and does Art. 14? A substantial
    modification counts only from 11 December 2027 ("from that date"); whether one is substantial is not decided here."""
    placed, full = parse_utc(placed_on_market_utc), parse_utc(FULL_APPLICATION_FROM)
    mod = parse_utc(substantially_modified_utc) if substantially_modified_utc else None
    if mod is not None and mod < placed:
        raise ValueError("substantially_modified_utc earlier than placed_on_market_utc")
    if placed >= full:
        req, basis = True, "placed on the market from 11 December 2027: the Regulation applies (Art. 71(2))"
    elif mod is not None and mod >= full:
        req, basis = True, "placed before 11 December 2027 and substantially modified from that date (Art. 69(2))"
    else:
        req = False
        basis = ("placed before 11 December 2027 and not substantially modified from that date: the requirements do not "
                 "apply (Art. 69(2)); Article 14 does (Art. 69(3))")
    return {"placed_on_market_utc": _iso(placed), "substantially_modified_utc": _iso(mod) if mod else None,
            "requirements_apply": req, "art14_applies": True, "art14_applies_from_utc": ART14_APPLIES_FROM, "basis": basis,
            "in_scope_checked": False, "substantial_checked": False, "convention": DAY_CONVENTION}


def support_period(placed_on_market_utc: str, support_period_end_utc: str,
                   shorter_expected_use_reason: Optional[str] = None) -> Dict[str, Any]:
    """Art. 13(8): at least five years from placing on the market, shorter only where the product is expected to be in
    use for less. A shorter period WITH a declared reason is `shorter_declared` (the reason is recorded, not assessed);
    without one it is `below_minimum`. A reason given for a period that meets the minimum is refused (nothing to justify)."""
    placed, end = parse_utc(placed_on_market_utc), parse_utc(support_period_end_utc)
    if end <= placed:
        raise ValueError("support_period_end_utc must be later than placed_on_market_utc")
    reason = (shorter_expected_use_reason or "").strip() or None
    minimum = add_years(placed, SUPPORT_PERIOD_MIN_YEARS)
    if end >= minimum:
        if reason:
            raise ValueError("shorter_expected_use_reason given for a support period that meets the five-year minimum")
        status = "meets_minimum"
    else:
        status = "shorter_declared" if reason else "below_minimum"
    return {"status": status, "placed_on_market_utc": _iso(placed), "support_period_end_utc": _iso(end),
            "minimum_end_utc": _iso(minimum), "shorter_expected_use_reason": reason, "reason_assessed": False,
            "basis": "support period at least five years, shorter only for a shorter expected use (Art. 13(8))"}


def retention_until(placed_on_market_utc: str, support_period_end_utc: Optional[str] = None) -> Dict[str, Any]:
    """Art. 13(13): 10 years after placing on the market, or the support period if that is longer. The horizon runs
    from the instant given: give the latest placing on the market you know of (an earlier one gives a shorter horizon)."""
    placed = parse_utc(placed_on_market_utc)
    ten = add_years(placed, RETENTION_YEARS)
    end = parse_utc(support_period_end_utc) if support_period_end_utc else None
    by_support = end is not None and end > ten
    return {"retention_until_utc": _iso(end if by_support else ten), "governed_by": "support_period" if by_support else "ten_years",
            "basis": "10 years after placing on the market or the support period, whichever is longer (Art. 13(13))"}


def update_available_until(issued_utc: str, support_period_end_utc: Optional[str] = None) -> Dict[str, Any]:
    """Art. 13(9): a security update stays available at least 10 years after it is issued, or for the remainder of
    the support period if that is longer."""
    issued = parse_utc(issued_utc)
    ten = add_years(issued, UPDATE_AVAILABILITY_YEARS)
    end = parse_utc(support_period_end_utc) if support_period_end_utc else None
    by_support = end is not None and end > ten
    return {"available_until_utc": _iso(end if by_support else ten), "governed_by": "support_period" if by_support else "ten_years",
            "basis": "10 years after issue or the remainder of the support period, whichever is longer (Art. 13(9))"}


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
