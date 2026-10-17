"""Mathematical models for telemetry interval estimation, availability evidence
denominators, and deterministic multi-signal incident attribution.

Reference papers (RELIASTRA Research, September 2026):
  1. "Why an interval estimated from bucketed telemetry converges on the bucket length"
     https://reliastra.com/research/measurement-integrity/probe-interval-from-bucketed-telemetry
  2. "How much evidence stands behind a published availability figure?"
     https://reliastra.com/research/measurement-integrity/availability-record-audit
  3. "How RELIASTRA measures vendor reliability"
     https://reliastra.com/research/how-reliastra-measures-vendor-reliability
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class TelemetryBucket:
    """A single occupied time bucket returned by a timeline API."""

    bucket_start_epoch: int
    observation_count: int


@dataclass(frozen=True)
class WindowAggregate:
    """Published availability aggregate for a nominal observation window."""

    window_label: str
    window_seconds: int
    total_observations: int
    successful_observations: int
    mean_latency_ms: float
    p95_latency_ms: float

    @property
    def availability_pct(self) -> float | None:
        if self.total_observations <= 0:
            return None  # Insufficient data sentinel; never 100.0% on 0 samples
        return round((self.successful_observations / self.total_observations) * 100.0, 4)


def bucket_events(
    event_timestamps: Sequence[int],
    bucket_length_seconds: int,
) -> list[TelemetryBucket]:
    """Group raw probe timestamps into occupied buckets of width B.

    Only occupied buckets (count >= 1) are emitted, matching time-series APIs
    that omit empty intervals.
    """
    if bucket_length_seconds <= 0:
        raise ValueError("bucket_length_seconds must be positive")
    counts: dict[int, int] = {}
    for ts in sorted(event_timestamps):
        b_start = (ts // bucket_length_seconds) * bucket_length_seconds
        counts[b_start] = counts.get(b_start, 0) + 1
    return [TelemetryBucket(k, counts[k]) for k in sorted(counts)]


def estimate_interval_occupied_density(
    occupied_buckets: Sequence[TelemetryBucket],
    bucket_length_seconds: int,
) -> int | None:
    """Naive occupied-bucket density estimator:
        Delta_hat_naive(B) = round(B / mean_{b in O_B} c(b))

    Theorem (Resolution Saturation Bound):
        For any regular schedule with true interval Delta >= B, every occupied
        bucket holds exactly c(b) = 1 observation, so mean(c) = 1 and
        Delta_hat_naive(B) = B = min(Delta, B). The estimator is bounded above
        by the bucket resolution B and under-reports any schedule sparser than B.
    """
    if not occupied_buckets:
        return None
    mean_obs = sum(b.observation_count for b in occupied_buckets) / len(occupied_buckets)
    if mean_obs <= 0:
        return None
    return round(bucket_length_seconds / mean_obs)


def estimate_interval_median_delta(
    occupied_buckets: Sequence[TelemetryBucket],
) -> float | None:
    """Resolution-invariant estimator using the median inter-bucket start delta:
        Delta_hat_median = median_{i}(t_{i+1} - t_i) / median_i(c_i)
    Recovers the true probe cadence regardless of bucket width B <= Delta.
    """
    if len(occupied_buckets) < 2:
        return None
    ordered = sorted(occupied_buckets, key=lambda b: b.bucket_start_epoch)
    deltas = [
        ordered[i + 1].bucket_start_epoch - ordered[i].bucket_start_epoch
        for i in range(len(ordered) - 1)
    ]
    med_delta = float(statistics.median(deltas))
    med_count = float(statistics.median(b.observation_count for b in ordered))
    return round(med_delta / max(med_count, 1.0), 2)


@dataclass(frozen=True)
class AvailabilityAuditResult:
    """Result of the 3-check availability denominator audit across nested windows."""

    monotonicity_passed: bool
    duplicate_windows: tuple[tuple[str, str], ...]
    history_depth_seconds: int
    history_depth_hours: float
    densities_by_window: dict[str, float]
    binomial_upper_failure_bound_95: dict[str, float]


def clopper_pearson_upper_failure_bound(n_observations: int, confidence: float = 0.95) -> float:
    """Exact one-sided upper bound on failure probability p when 0 failures are
    observed across N independent Bernoulli trials:
        (1 - p_max)^N = 1 - confidence  =>  p_max = 1 - (1 - confidence)^(1 / N)
    Demonstrates why "100.0% availability" over N = 595 vs N = 25,920 carries a
    43.5x difference in the upper bound on true failure rate.
    """
    if n_observations <= 0:
        return 1.0
    alpha = 1.0 - confidence
    return 1.0 - (alpha ** (1.0 / n_observations))


def audit_availability_record(
    windows: Sequence[WindowAggregate],
    configured_interval_seconds: int = 300,
) -> AvailabilityAuditResult:
    """Execute the three availability-record integrity checks:
    1. Window monotonicity: strictly wider windows should not return identical
       sample counts + identical mean/p95 latencies unless history is shallow.
    2. History depth: D = max(N) * Delta.
    3. Observation density: rho(W) = N(W) / floor(W / Delta).
    """
    ordered = sorted(windows, key=lambda w: w.window_seconds)
    monotonic = True
    duplicates: list[tuple[str, str]] = []
    for i in range(len(ordered) - 1):
        curr, nxt = ordered[i], ordered[i + 1]
        if nxt.total_observations < curr.total_observations:
            monotonic = False
        if (
            nxt.total_observations == curr.total_observations
            and math.isclose(nxt.mean_latency_ms, curr.mean_latency_ms, abs_tol=1e-4)
            and math.isclose(nxt.p95_latency_ms, curr.p95_latency_ms, abs_tol=1e-4)
        ):
            duplicates.append((curr.window_label, nxt.window_label))

    max_obs = max((w.total_observations for w in ordered), default=0)
    depth_sec = max_obs * configured_interval_seconds
    densities: dict[str, float] = {}
    upper_bounds: dict[str, float] = {}
    for w in ordered:
        expected = max(w.window_seconds // configured_interval_seconds, 1)
        densities[w.window_label] = round(w.total_observations / expected, 4)
        upper_bounds[w.window_label] = round(
            clopper_pearson_upper_failure_bound(w.total_observations, 0.95), 6
        )

    return AvailabilityAuditResult(
        monotonicity_passed=monotonic and len(duplicates) == 0,
        duplicate_windows=tuple(duplicates),
        history_depth_seconds=depth_sec,
        history_depth_hours=round(depth_sec / 3600.0, 2),
        densities_by_window=densities,
        binomial_upper_failure_bound_95=upper_bounds,
    )


# ---------------------------------------------------------------------------
# Deterministic 5-Signal Incident Attribution & Single-Origin Ceiling
# ---------------------------------------------------------------------------

ATTRIBUTION_WEIGHTS: dict[str, float] = {
    "temporal": 0.20,
    "endpoint_overlap": 0.25,
    "latency_correlation": 0.25,
    "error_pattern": 0.15,
    "infrastructure_baseline": 0.15,
}

CORROBORATION_SIGNALS: tuple[str, ...] = ("temporal", "endpoint_overlap")


@dataclass(frozen=True)
class AttributionVerdict:
    """Deterministic attribution score, classification, and topology ceiling."""

    score: float
    max_achievable_score: float
    classification: str
    methodology_version: str = "v1.1"


def evaluate_attribution(
    signals: dict[str, float],
    single_origin_uncorroborated: bool = False,
    all_transport_inconclusive: bool = False,
) -> AttributionVerdict:
    """Compute the weighted attribution score S in [0, 100] and classification.

    Under a single observation point without corroborating incidents,
    `temporal` (0.20) and `endpoint_overlap` (0.25) are 0.0, bounding the
    maximum achievable score to:
        S_max = 100 * (0.25 + 0.15 + 0.15) = 55.0 < 75.0 (vendor_failure).
    """
    effective = dict(signals)
    if single_origin_uncorroborated:
        for sig in CORROBORATION_SIGNALS:
            effective[sig] = 0.0
    if all_transport_inconclusive:
        effective["infrastructure_baseline"] = 0.0

    raw = sum(
        ATTRIBUTION_WEIGHTS[k] * max(0.0, min(1.0, effective.get(k, 0.0)))
        for k in ATTRIBUTION_WEIGHTS
    )
    score = round(raw * 100.0, 2)
    max_achievable = (
        round(
            sum(w for k, w in ATTRIBUTION_WEIGHTS.items() if k not in CORROBORATION_SIGNALS)
            * 100.0,
            2,
        )
        if single_origin_uncorroborated
        else 100.0
    )

    if score >= 75.0:
        classification = "vendor_failure"
    elif score >= 50.0:
        classification = "multi_cause"
    elif all_transport_inconclusive:
        classification = "infrastructure_issue"
    else:
        classification = "unknown"

    return AttributionVerdict(
        score=score,
        max_achievable_score=max_achievable,
        classification=classification,
    )
