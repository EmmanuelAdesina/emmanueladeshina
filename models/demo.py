"""Executable demonstration of the portfolio's mathematical security models.

Usage:
    python3 -m models.demo
"""

from __future__ import annotations

from models.iam_authorization_model import (
    AuthorizationGraph,
    GraphEdge,
    PolicyLayer,
    PolicyStatement,
    PrincipalForm,
    RequestContext,
    evaluate_single_account,
)
from models.telemetry_integrity_model import (
    TelemetryBucket,
    WindowAggregate,
    audit_availability_record,
    estimate_interval_median_delta,
    estimate_interval_occupied_density,
    evaluate_attribution,
)


def _res_allow(form: PrincipalForm, sid: str) -> PolicyLayer:
    return PolicyLayer(
        attached=True,
        statements=(PolicyStatement(sid=sid, effect="Allow", named_principal_form=form),),
    )


def main() -> None:
    print("=" * 78)
    print("1. AWS IAM POLICY EVALUATION ALGEBRA & PRINCIPAL-TYPE BRANCH")
    print("=" * 78)
    for label, form in (
        ("M-05 (Resource policy names IAM Role ARN)", PrincipalForm.IAM_ROLE_ARN),
        ("M-04 (Resource policy names AssumedRole Session ARN)", PrincipalForm.IAM_ROLE_SESSION_ARN),
    ):
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            resource_policy=_res_allow(form, "BucketAllow"),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        verdict = "ALLOW" if dec.allowed else "DENY "
        print(f"  {label:<54} -> {verdict} [{dec.stage.value}]")

    print("\n" + "=" * 78)
    print("2. STRUCTURAL vs. EXECUTABLE REACHABILITY IN G = (V, E)")
    print("=" * 78)
    g = AuthorizationGraph()
    dev = "arn:aws:iam::111122223333:user/dev"
    role_sess = "arn:aws:sts::111122223333:assumed-role/pipeline/ci"
    vault_capped = "arn:aws:s3:::prod-vault-role-arn"
    vault_bypass = "arn:aws:s3:::prod-vault-session-arn"

    g.add_edge(
        GraphEdge(
            source=dev,
            target=role_sess,
            action="sts:AssumeRole",
            context=RequestContext(
                principal_form=PrincipalForm.IAM_USER_ARN,
                action="sts:AssumeRole",
                identity_policy=PolicyLayer.allow("AssumeRoleAllow"),
                resource_policy=_res_allow(PrincipalForm.IAM_USER_ARN, "TrustDev"),
            ),
        )
    )
    g.add_edge(
        GraphEdge(
            source=role_sess,
            target=vault_capped,
            action="s3:GetObject",
            context=RequestContext(
                principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
                action="s3:GetObject",
                resource_policy=_res_allow(PrincipalForm.IAM_ROLE_ARN, "RoleArnGrant"),
                permissions_boundary=PolicyLayer.silent(),
            ),
        )
    )
    g.add_edge(
        GraphEdge(
            source=role_sess,
            target=vault_bypass,
            action="s3:GetObject",
            context=RequestContext(
                principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
                action="s3:GetObject",
                resource_policy=_res_allow(PrincipalForm.IAM_ROLE_SESSION_ARN, "SessionArnGrant"),
                permissions_boundary=PolicyLayer.silent(),
            ),
        )
    )
    for target in (vault_capped, vault_bypass):
        s_path = g.structural_shortest_path(dev, target)
        e_path, _ = g.executable_shortest_path(dev, target)
        print(f"  Target: {target}")
        print(f"    Structural BFS path exists : {s_path is not None} ({len(s_path or []) - 1} hops)")
        print(f"    Executable IAM path exists : {e_path is not None}")

    print("\n" + "=" * 78)
    print("3. TELEMETRY INTERVAL BOUND & AVAILABILITY DENOMINATOR AUDIT")
    print("=" * 78)
    starts = [0, 300, 600, 900, 1200, 1500, 1860, 2160, 2460, 2760, 3060, 3360]
    series = [TelemetryBucket(ts, 1) for ts in starts]
    print(f"  Captured 1h series (12 points, true Delta = 300s):")
    print(f"    Naive occupied-bucket estimator at B=60s  : {estimate_interval_occupied_density(series, 60)}s")
    print(f"    Naive occupied-bucket estimator at B=300s : {estimate_interval_occupied_density(series, 300)}s")
    print(f"    Resolution-invariant median delta         : {estimate_interval_median_delta(series)}s")

    windows = [
        WindowAggregate("24h", 86_400, 277, 277, 542.10, 812.00),
        WindowAggregate("7d", 604_800, 595, 595, 570.67, 840.33),
        WindowAggregate("30d", 2_592_000, 595, 595, 570.67, 840.33),
        WindowAggregate("90d", 7_776_000, 595, 595, 570.67, 840.33),
    ]
    audit = audit_availability_record(windows, configured_interval_seconds=300)
    print(f"  Availability Record Audit (OpenAI public record, 2026-09-11):")
    print(f"    Window monotonicity passed : {audit.monotonicity_passed} (duplicates: {audit.duplicate_windows})")
    print(f"    Actual history depth       : {audit.history_depth_hours} hours (~2.1 days vs 90d label)")
    print(f"    Window densities           : {audit.densities_by_window}")

    verdict = evaluate_attribution(
        {"temporal": 1.0, "endpoint_overlap": 1.0, "latency_correlation": 1.0, "error_pattern": 1.0, "infrastructure_baseline": 1.0},
        single_origin_uncorroborated=True,
    )
    print(f"  Single-Origin Attribution Ceiling : score={verdict.score} / max={verdict.max_achievable_score} ({verdict.classification})")
    print("=" * 78)


if __name__ == "__main__":
    main()
