"""Automated verification suite for the portfolio's mathematical models.

Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest

from models.iam_authorization_model import (
    AuthorizationGraph,
    ConditionOperator,
    GraphEdge,
    PolicyLayer,
    PolicyStatement,
    PrincipalForm,
    RequestContext,
    Stage,
    evaluate_cross_account,
    evaluate_single_account,
)
from models.telemetry_integrity_model import (
    TelemetryBucket,
    WindowAggregate,
    audit_availability_record,
    bucket_events,
    clopper_pearson_upper_failure_bound,
    estimate_interval_median_delta,
    estimate_interval_occupied_density,
    evaluate_attribution,
)


def _resource_allow(form: PrincipalForm, sid: str = "ResourceAllow") -> PolicyLayer:
    return PolicyLayer(
        attached=True,
        statements=(
            PolicyStatement(
                sid=sid,
                effect="Allow",
                actions=("*",),
                named_principal_form=form,
            ),
        ),
    )


class TestAWSIAMDecisionMatrix(unittest.TestCase):
    """Verifies all 26 rows (M-01 to M-26) of Table 3 from:
    'AWS IAM policy evaluation logic: identity vs resource' (13 Sep 2026).
    """

    def test_m01_same_account_iam_user_identity_allow(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow("IdAllow"),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_5_IDENTITY_POLICY)

    def test_m02_same_account_user_arn_named_in_resource_policy(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            resource_policy=_resource_allow(PrincipalForm.IAM_USER_ARN),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_4_RESOURCE_POLICY)

    def test_m03_user_arn_named_in_resource_policy_survives_silent_boundary(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            resource_policy=_resource_allow(PrincipalForm.IAM_USER_ARN),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_4_RESOURCE_POLICY)

    def test_m04_role_session_arn_named_survives_silent_boundary_and_session(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            resource_policy=_resource_allow(PrincipalForm.IAM_ROLE_SESSION_ARN),
            permissions_boundary=PolicyLayer.silent(),
            session_policy=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_4_RESOURCE_POLICY)

    def test_m05_role_arn_named_is_capped_by_silent_boundary(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            resource_policy=_resource_allow(PrincipalForm.IAM_ROLE_ARN),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_6_PERMISSIONS_BOUNDARY)

    def test_m06_role_arn_named_with_identity_allow_still_capped_by_boundary(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            resource_policy=_resource_allow(PrincipalForm.IAM_ROLE_ARN),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_6_PERMISSIONS_BOUNDARY)

    def test_m07_role_session_identity_allow_and_boundary_allows(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            permissions_boundary=PolicyLayer.allow(),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_6_PERMISSIONS_BOUNDARY)

    def test_m08_role_session_identity_allow_and_boundary_silent(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_6_PERMISSIONS_BOUNDARY)

    def test_m09_role_session_passed_session_policy_silent(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            session_policy=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_7_SESSION_POLICY)

    def test_m10_role_session_default_session_policy_allows(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_7_SESSION_POLICY)

    def test_m11_explicit_deny_in_identity_policy_short_circuits_resource_allow(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer(
                attached=True,
                statements=(
                    PolicyStatement("Allow1", "Allow"),
                    PolicyStatement("Deny1", "Deny"),
                ),
            ),
            resource_policy=_resource_allow(PrincipalForm.IAM_USER_ARN),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertTrue(dec.explicit_deny)
        self.assertEqual(dec.stage, Stage.STAGE_1_EXPLICIT_DENY)

    def test_m12_explicit_deny_in_bucket_policy_short_circuits_identity_allow(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            resource_policy=PolicyLayer.deny("BucketDeny"),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertTrue(dec.explicit_deny)
        self.assertEqual(dec.stage, Stage.STAGE_1_EXPLICIT_DENY)

    def test_m13_scp_silent_denies_at_stage_3(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            scp=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_3_SCP)

    def test_m14_rcp_silent_denies_at_stage_2(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            rcp=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_2_RCP)

    def test_m15_rcp_full_aws_access_attached_passes_stage_2(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            rcp=PolicyLayer.allow("RCPFullAWSAccess"),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)

    def test_m16_nothing_grants_implicit_deny_at_stage_5(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertFalse(dec.explicit_deny)
        self.assertEqual(dec.stage, Stage.STAGE_5_IDENTITY_POLICY)

    def test_m17_wildcard_principal_with_principal_arn_condition_carve_out(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            resource_policy=_resource_allow(PrincipalForm.WILDCARD_PRINCIPAL_ARN_CONDITION),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_4_RESOURCE_POLICY)

    def test_m18_deny_with_not_principal_and_boundary_always_denies(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="s3:GetObject",
            identity_policy=PolicyLayer.allow(),
            resource_policy=PolicyLayer.deny("NotPrincipalDeny", not_principal=True),
            permissions_boundary=PolicyLayer.allow(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertTrue(dec.explicit_deny)
        self.assertEqual(dec.stage, Stage.STAGE_1_EXPLICIT_DENY)

    def test_m19_federated_user_arn_named_survives_silent_boundary(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.STS_FEDERATED_USER_ARN,
            action="s3:GetObject",
            resource_policy=_resource_allow(PrincipalForm.STS_FEDERATED_USER_ARN),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertTrue(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_4_RESOURCE_POLICY)

    def test_m20_federating_iam_user_arn_named_is_capped_by_boundary(self) -> None:
        ctx = RequestContext(
            principal_form=PrincipalForm.FEDERATING_IAM_USER_ARN,
            action="s3:GetObject",
            resource_policy=_resource_allow(PrincipalForm.FEDERATING_IAM_USER_ARN),
            permissions_boundary=PolicyLayer.silent(),
        )
        dec = evaluate_single_account(ctx)
        self.assertFalse(dec.allowed)
        self.assertEqual(dec.stage, Stage.STAGE_6_PERMISSIONS_BOUNDARY)

    def test_m21_to_m24_cross_account_conjunction(self) -> None:
        # M-21: Both sides allow -> ALLOW
        trusted_ok = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            principal_account="111111111111",
            resource_account="222222222222",
            identity_policy=PolicyLayer.allow("TrustedAllow"),
        )
        trusting_ok = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            principal_account="111111111111",
            resource_account="222222222222",
            resource_policy=_resource_allow(PrincipalForm.IAM_ROLE_ARN, "TrustingAllow"),
        )
        self.assertTrue(evaluate_cross_account(trusted_ok, trusting_ok).allowed)

        # M-22: Trusting account grants nothing -> DENY
        trusting_silent = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            principal_account="111111111111",
            resource_account="222222222222",
        )
        dec_m22 = evaluate_cross_account(trusted_ok, trusting_silent)
        self.assertFalse(dec_m22.allowed)
        self.assertEqual(dec_m22.stage, Stage.CROSS_ACCOUNT_CONJUNCTION)

        # M-23: Trusted account grants nothing -> DENY
        trusted_silent = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            principal_account="111111111111",
            resource_account="222222222222",
        )
        dec_m23 = evaluate_cross_account(trusted_silent, trusting_ok)
        self.assertFalse(dec_m23.allowed)
        self.assertEqual(dec_m23.stage, Stage.CROSS_ACCOUNT_CONJUNCTION)

        # M-24: SCP in trusting account explicitly denies -> Stage 1 explicit deny
        trusting_scp_deny = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:GetObject",
            principal_account="111111111111",
            resource_account="222222222222",
            resource_policy=_resource_allow(PrincipalForm.IAM_ROLE_ARN),
            scp=PolicyLayer.deny("TrustingSCPDeny"),
        )
        dec_m24 = evaluate_cross_account(trusted_ok, trusting_scp_deny)
        self.assertFalse(dec_m24.allowed)
        self.assertTrue(dec_m24.explicit_deny)
        self.assertEqual(dec_m24.stage, Stage.STAGE_1_EXPLICIT_DENY)

    def test_m25_and_m26_union_exceptions_assume_role_and_kms(self) -> None:
        # M-25: sts:AssumeRole with identity Allow but silent trust policy -> DENY
        ctx_sts = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="sts:AssumeRole",
            identity_policy=PolicyLayer.allow(),
        )
        dec_m25 = evaluate_single_account(ctx_sts)
        self.assertFalse(dec_m25.allowed)
        self.assertEqual(dec_m25.stage, Stage.EXCEPTION_TRUST_POLICY)

        # M-26: kms:Decrypt with identity Allow but silent key policy -> DENY
        ctx_kms = RequestContext(
            principal_form=PrincipalForm.IAM_USER_ARN,
            action="kms:Decrypt",
            identity_policy=PolicyLayer.allow(),
        )
        dec_m26 = evaluate_single_account(ctx_kms)
        self.assertFalse(dec_m26.allowed)
        self.assertEqual(dec_m26.stage, Stage.EXCEPTION_KMS_KEY_POLICY)

    def test_bool_vs_bool_if_exists_on_missing_mfa_key(self) -> None:
        # A Deny written with Bool on aws:MultiFactorAuthPresent=false does NOT
        # fire when the key is absent from the request context.
        ctx_bool = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:DeleteBucket",
            identity_policy=PolicyLayer(
                attached=True,
                statements=(
                    PolicyStatement("AllowAll", "Allow"),
                    PolicyStatement(
                        "DenyWithoutMFA_Bool",
                        "Deny",
                        condition_op=ConditionOperator.BOOL,
                        condition_key="aws:MultiFactorAuthPresent",
                        condition_expected=False,
                    ),
                ),
            ),
            context_keys={},  # MFA key absent!
        )
        self.assertTrue(evaluate_single_account(ctx_bool).allowed)

        # Written with BoolIfExists, the absent key matches and the Deny fires.
        ctx_bool_if_exists = RequestContext(
            principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
            action="s3:DeleteBucket",
            identity_policy=PolicyLayer(
                attached=True,
                statements=(
                    PolicyStatement("AllowAll", "Allow"),
                    PolicyStatement(
                        "DenyWithoutMFA_BoolIfExists",
                        "Deny",
                        condition_op=ConditionOperator.BOOL_IF_EXISTS,
                        condition_key="aws:MultiFactorAuthPresent",
                        condition_expected=False,
                    ),
                ),
            ),
            context_keys={},
        )
        dec = evaluate_single_account(ctx_bool_if_exists)
        self.assertFalse(dec.allowed)
        self.assertTrue(dec.explicit_deny)


class TestAuthorizationGraphReachability(unittest.TestCase):
    """Tests structural vs. semantically executable paths in G = (V, E)."""

    def test_structural_path_blocked_by_permissions_boundary_vs_session_arn_bypass(self) -> None:
        g = AuthorizationGraph()

        # Edge 1: DevUser -> PipelineRole via sts:AssumeRole (allowed by both identity and trust)
        g.add_edge(
            GraphEdge(
                source="arn:aws:iam::111122223333:user/dev",
                target="arn:aws:sts::111122223333:assumed-role/pipeline/ci",
                action="sts:AssumeRole",
                context=RequestContext(
                    principal_form=PrincipalForm.IAM_USER_ARN,
                    action="sts:AssumeRole",
                    identity_policy=PolicyLayer.allow("AssumePipeline"),
                    resource_policy=_resource_allow(PrincipalForm.IAM_USER_ARN, "TrustDev"),
                ),
            )
        )

        # Edge 2a (Blocked): PipelineRole tries to read ProductionVault via Role ARN grant
        # while a restrictive permissions boundary is silent on s3:GetObject.
        g.add_edge(
            GraphEdge(
                source="arn:aws:sts::111122223333:assumed-role/pipeline/ci",
                target="arn:aws:s3:::prod-vault-capped",
                action="s3:GetObject",
                context=RequestContext(
                    principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
                    action="s3:GetObject",
                    resource_policy=_resource_allow(PrincipalForm.IAM_ROLE_ARN, "BucketGrantRoleArn"),
                    permissions_boundary=PolicyLayer.silent(),
                ),
            )
        )

        # Edge 2b (Executable): PipelineRole reads ProductionVaultSessionNamed because
        # the bucket policy names the AssumedRole session ARN directly (Row M-04).
        g.add_edge(
            GraphEdge(
                source="arn:aws:sts::111122223333:assumed-role/pipeline/ci",
                target="arn:aws:s3:::prod-vault-session-named",
                action="s3:GetObject",
                context=RequestContext(
                    principal_form=PrincipalForm.IAM_ROLE_SESSION_ARN,
                    action="s3:GetObject",
                    resource_policy=_resource_allow(
                        PrincipalForm.IAM_ROLE_SESSION_ARN, "BucketGrantSessionArn"
                    ),
                    permissions_boundary=PolicyLayer.silent(),
                ),
            )
        )

        # Structural reachability finds a path to prod-vault-capped:
        struct_path = g.structural_shortest_path(
            "arn:aws:iam::111122223333:user/dev",
            "arn:aws:s3:::prod-vault-capped",
        )
        self.assertEqual(len(struct_path or []), 3)

        # Executable reachability proves prod-vault-capped is UNREACHABLE (capped at Stage 6):
        exec_path_capped, _ = g.executable_shortest_path(
            "arn:aws:iam::111122223333:user/dev",
            "arn:aws:s3:::prod-vault-capped",
        )
        self.assertIsNone(exec_path_capped)

        # Executable reachability proves prod-vault-session-named IS reachable (Stage 4 bypass):
        exec_path_bypass, _ = g.executable_shortest_path(
            "arn:aws:iam::111122223333:user/dev",
            "arn:aws:s3:::prod-vault-session-named",
        )
        self.assertEqual(
            exec_path_bypass,
            [
                "arn:aws:iam::111122223333:user/dev",
                "arn:aws:sts::111122223333:assumed-role/pipeline/ci",
                "arn:aws:s3:::prod-vault-session-named",
            ],
        )


class TestTelemetryAndAvailabilityMathematics(unittest.TestCase):
    """Verifies the telemetry interval estimator bound, availability denominator
    audit, and deterministic 5-signal attribution ceiling.
    """

    def test_bucketed_estimator_resolution_saturation_bound(self) -> None:
        # True probe interval Delta = 300s over a 1-hour window (12 probes)
        timestamps = [i * 300 for i in range(12)]
        buckets_1m = bucket_events(timestamps, bucket_length_seconds=60)
        buckets_5m = bucket_events(timestamps, bucket_length_seconds=300)

        # At 1-minute resolution (B=60), naive estimator saturates at min(300, 60) = 60s
        self.assertEqual(estimate_interval_occupied_density(buckets_1m, 60), 60)
        # At 5-minute resolution (B=300), naive estimator returns min(300, 300) = 300s
        self.assertEqual(estimate_interval_occupied_density(buckets_5m, 300), 300)

        # Median inter-bucket delta is resolution-invariant: returns 300.0s on both!
        self.assertEqual(estimate_interval_median_delta(buckets_1m), 300.0)
        self.assertEqual(estimate_interval_median_delta(buckets_5m), 300.0)

    def test_captured_2026_09_11_openai_timeline_fixture(self) -> None:
        # Captured series from 2026-09-11T10:39:46Z -> 11:39:46Z:
        # 12 points, each observation_count=1, 10 deltas of 300s and 1 delta of 360s
        starts = [0, 300, 600, 900, 1200, 1500, 1860, 2160, 2460, 2760, 3060, 3360]
        captured = [TelemetryBucket(ts, 1) for ts in starts]
        self.assertEqual(estimate_interval_occupied_density(captured, 60), 60)
        self.assertEqual(estimate_interval_median_delta(captured), 300.0)

    def test_availability_record_denominator_audit(self) -> None:
        # Captured metrics from 11 September 2026 audit
        windows = [
            WindowAggregate("24h", 86_400, 277, 277, 542.10, 812.00),
            WindowAggregate("7d", 604_800, 595, 595, 570.67, 840.33),
            WindowAggregate("30d", 2_592_000, 595, 595, 570.67, 840.33),
            WindowAggregate("90d", 7_776_000, 595, 595, 570.67, 840.33),
        ]
        audit = audit_availability_record(windows, configured_interval_seconds=300)
        self.assertFalse(audit.monotonicity_passed)
        self.assertEqual(audit.duplicate_windows, (("7d", "30d"), ("30d", "90d")))
        self.assertAlmostEqual(audit.history_depth_hours, 49.58, places=2)
        self.assertAlmostEqual(audit.densities_by_window["24h"], 0.9618, places=4)
        self.assertAlmostEqual(audit.densities_by_window["7d"], 0.2951, places=4)
        self.assertAlmostEqual(audit.densities_by_window["90d"], 0.0230, places=4)

        # Compare 95% upper failure bound for N=595 vs full 90-day N=25,920:
        p_max_595 = clopper_pearson_upper_failure_bound(595, 0.95)
        p_max_25920 = clopper_pearson_upper_failure_bound(25_920, 0.95)
        self.assertAlmostEqual(p_max_595 / p_max_25920, 43.46, delta=0.2)

    def test_five_signal_attribution_and_single_origin_ceiling(self) -> None:
        # Single-origin uncorroborated incident: temporal & endpoint_overlap forced to 0
        verdict_single = evaluate_attribution(
            {
                "temporal": 1.0,
                "endpoint_overlap": 1.0,
                "latency_correlation": 1.0,
                "error_pattern": 1.0,
                "infrastructure_baseline": 1.0,
            },
            single_origin_uncorroborated=True,
        )
        self.assertEqual(verdict_single.score, 55.0)
        self.assertEqual(verdict_single.max_achievable_score, 55.0)
        self.assertEqual(verdict_single.classification, "multi_cause")

        # Corroborated multi-signal incident:
        verdict_corroborated = evaluate_attribution(
            {
                "temporal": 0.9,
                "endpoint_overlap": 1.0,
                "latency_correlation": 0.88,
                "error_pattern": 1.0,
                "infrastructure_baseline": 1.0,
            },
            single_origin_uncorroborated=False,
        )
        self.assertEqual(verdict_corroborated.score, 95.0)
        self.assertEqual(verdict_corroborated.classification, "vendor_failure")

        # Transport-inconclusive failure (DNS/TLS/timeout with no HTTP response):
        verdict_transport = evaluate_attribution(
            {
                "temporal": 0.0,
                "endpoint_overlap": 0.0,
                "latency_correlation": 0.5,
                "error_pattern": 0.5,
                "infrastructure_baseline": 1.0,
            },
            single_origin_uncorroborated=True,
            all_transport_inconclusive=True,
        )
        self.assertEqual(verdict_transport.score, 20.0)
        self.assertEqual(verdict_transport.classification, "infrastructure_issue")


if __name__ == "__main__":
    unittest.main()
