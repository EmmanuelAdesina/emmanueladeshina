"""Formal algebraic model of AWS IAM policy evaluation and authorization graphs.

Implements the deterministic 7-stage single-account decision procedure, the
cross-account evaluation conjunction, the principal-type ceiling survival
branch, documented service/condition exceptions, and executable vs. structural
reachability over a directed authorization graph G = (V, E).

Reference paper:
    Adeshina Emmanuel, "AWS IAM policy evaluation logic: identity vs resource",
    RELIASTRA Research, 13 September 2026.
    https://reliastra.com/research/cloud-security/aws-iam-policy-evaluation-order
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Sequence


class Stage(str, Enum):
    """The stages of AWS IAM policy evaluation in documented order."""

    DEFAULT_ROOT = "stage_0_root_default"
    STAGE_1_EXPLICIT_DENY = "stage_1_explicit_deny"
    STAGE_2_RCP = "stage_2_organizations_rcp"
    STAGE_3_SCP = "stage_3_organizations_scp"
    STAGE_4_RESOURCE_POLICY = "stage_4_resource_based_policy"
    STAGE_5_IDENTITY_POLICY = "stage_5_identity_based_policy"
    STAGE_6_PERMISSIONS_BOUNDARY = "stage_6_permissions_boundary"
    STAGE_7_SESSION_POLICY = "stage_7_session_policy"
    EXCEPTION_TRUST_POLICY = "exception_role_trust_policy"
    EXCEPTION_KMS_KEY_POLICY = "exception_kms_key_policy"
    CROSS_ACCOUNT_CONJUNCTION = "cross_account_conjunction"


class PrincipalForm(str, Enum):
    """Principal form making the request or named in a resource-based grant.

    In AWS IAM, whether a same-account resource-based Allow survives an implicit
    deny in a permissions boundary or session policy is a function of the
    principal form named in the resource-based policy (Table 2 of the paper).
    """

    ACCOUNT_ROOT = "account_root"
    IAM_USER_ARN = "iam_user_arn"
    IAM_ROLE_ARN = "iam_role_arn"
    IAM_ROLE_SESSION_ARN = "iam_role_session_arn"
    WILDCARD_PRINCIPAL_ARN_CONDITION = "wildcard_principal_arn_condition"
    STS_FEDERATED_USER_ARN = "sts_federated_user_arn"
    FEDERATING_IAM_USER_ARN = "federating_iam_user_arn"
    SERVICE_LINKED_ROLE = "service_linked_role"


class ConditionOperator(str, Enum):
    """Subset of IAM condition operators that alter missing-key semantics."""

    NONE = "None"
    BOOL = "Bool"
    BOOL_IF_EXISTS = "BoolIfExists"
    ARN_EQUALS = "ArnEquals"
    ARN_NOT_EQUALS = "ArnNotEquals"


@dataclass(frozen=True)
class PolicyStatement:
    """A single policy statement participating in an evaluation context."""

    sid: str
    effect: str  # "Allow" or "Deny"
    actions: tuple[str, ...] = ("*",)
    resources: tuple[str, ...] = ("*",)
    named_principal_form: PrincipalForm | None = None
    not_principal: bool = False
    condition_op: ConditionOperator = ConditionOperator.NONE
    condition_key: str | None = None
    condition_expected: bool | str | None = None
    delegates_to_account_iam: bool = False

    def matches_action(self, action: str) -> bool:
        for pat in self.actions:
            if pat == "*" or pat == action:
                return True
            if pat.endswith(":*") and action.startswith(pat[:-1]):
                return True
        return False

    def matches_condition(self, context_keys: dict[str, bool | str]) -> bool:
        if self.condition_op == ConditionOperator.NONE or self.condition_key is None:
            return True
        key_present = self.condition_key in context_keys
        if self.condition_op == ConditionOperator.BOOL:
            # Bool treats an absent context key as NO match.
            if not key_present:
                return False
            return context_keys[self.condition_key] == self.condition_expected
        if self.condition_op == ConditionOperator.BOOL_IF_EXISTS:
            # BoolIfExists treats an absent context key as a MATCH.
            if not key_present:
                return True
            return context_keys[self.condition_key] == self.condition_expected
        if self.condition_op == ConditionOperator.ARN_EQUALS:
            return key_present and context_keys[self.condition_key] == self.condition_expected
        if self.condition_op == ConditionOperator.ARN_NOT_EQUALS:
            return not key_present or context_keys[self.condition_key] != self.condition_expected
        return False


@dataclass(frozen=True)
class PolicyLayer:
    """A policy class attached to an entity or organization."""

    attached: bool = False
    statements: tuple[PolicyStatement, ...] = ()

    @classmethod
    def allow(cls, sid: str = "AllowStmt", actions: Sequence[str] = ("*",)) -> PolicyLayer:
        return cls(
            attached=True,
            statements=(PolicyStatement(sid=sid, effect="Allow", actions=tuple(actions)),),
        )

    @classmethod
    def silent(cls) -> PolicyLayer:
        """Attached ceiling/policy that contains no matching Allow (implicit deny)."""
        return cls(attached=True, statements=())

    @classmethod
    def deny(
        cls,
        sid: str = "DenyStmt",
        actions: Sequence[str] = ("*",),
        not_principal: bool = False,
        condition_op: ConditionOperator = ConditionOperator.NONE,
        condition_key: str | None = None,
        condition_expected: bool | str | None = None,
    ) -> PolicyLayer:
        return cls(
            attached=True,
            statements=(
                PolicyStatement(
                    sid=sid,
                    effect="Deny",
                    actions=tuple(actions),
                    not_principal=not_principal,
                    condition_op=condition_op,
                    condition_key=condition_key,
                    condition_expected=condition_expected,
                ),
            ),
        )


@dataclass(frozen=True)
class RequestContext:
    """Complete request context for single-account or per-side evaluation."""

    principal_form: PrincipalForm
    action: str
    principal_account: str = "111122223333"
    resource_account: str = "111122223333"
    rcp: PolicyLayer = field(default_factory=PolicyLayer)
    scp: PolicyLayer = field(default_factory=PolicyLayer)
    resource_policy: PolicyLayer = field(default_factory=PolicyLayer)
    identity_policy: PolicyLayer = field(default_factory=PolicyLayer)
    permissions_boundary: PolicyLayer = field(default_factory=PolicyLayer)
    session_policy: PolicyLayer = field(default_factory=PolicyLayer)
    context_keys: dict[str, bool | str] = field(default_factory=dict)

    @property
    def is_cross_account(self) -> bool:
        return self.principal_account != self.resource_account

    @property
    def is_session_principal(self) -> bool:
        return self.principal_form in {
            PrincipalForm.IAM_ROLE_ARN,
            PrincipalForm.IAM_ROLE_SESSION_ARN,
            PrincipalForm.STS_FEDERATED_USER_ARN,
            PrincipalForm.FEDERATING_IAM_USER_ARN,
            PrincipalForm.WILDCARD_PRINCIPAL_ARN_CONDITION,
        }


@dataclass(frozen=True)
class Decision:
    """Auditable authorization verdict carrying the deciding stage and reason."""

    allowed: bool
    stage: Stage
    explicit_deny: bool
    statement_id: str = ""
    reason: str = ""


def _first_matching_deny(ctx: RequestContext, layers: Iterable[PolicyLayer]) -> PolicyStatement | None:
    """Stage 1 short-circuit: search all applicable policy layers for an explicit Deny."""
    has_boundary = ctx.permissions_boundary.attached
    for layer in layers:
        if not layer.attached:
            continue
        for stmt in layer.statements:
            if stmt.effect != "Deny" or not stmt.matches_action(ctx.action):
                continue
            # Documented AWS interaction: a resource-based Deny with NotPrincipal
            # always denies a principal that has a permissions boundary attached.
            if stmt.not_principal and has_boundary:
                return stmt
            if stmt.matches_condition(ctx.context_keys):
                return stmt
    return None


def _first_matching_allow(ctx: RequestContext, layer: PolicyLayer) -> PolicyStatement | None:
    if not layer.attached:
        return None
    for stmt in layer.statements:
        if (
            stmt.effect == "Allow"
            and stmt.matches_action(ctx.action)
            and stmt.matches_condition(ctx.context_keys)
        ):
            return stmt
    return None


def requires_explicit_resource_allow(action: str) -> bool:
    """Documented exceptions where the same-account union rule does not apply."""
    if action in {"sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"}:
        return True
    if action.startswith("kms:"):
        return True
    return False


def resource_grant_bypasses_ceilings(named_form: PrincipalForm | None) -> bool:
    """Table 2 predicate: whether a same-account resource-based Allow survives
    an implicit deny in a permissions boundary or session policy.
    """
    return named_form in {
        PrincipalForm.IAM_USER_ARN,
        PrincipalForm.IAM_ROLE_SESSION_ARN,
        PrincipalForm.WILDCARD_PRINCIPAL_ARN_CONDITION,
        PrincipalForm.STS_FEDERATED_USER_ARN,
    }


def evaluate_single_account(ctx: RequestContext) -> Decision:
    """Execute the 7-stage single-account AWS IAM policy evaluation algebra."""
    all_layers = (
        ctx.rcp,
        ctx.scp,
        ctx.resource_policy,
        ctx.identity_policy,
        ctx.permissions_boundary,
        ctx.session_policy,
    )

    # Stage 1: Explicit Deny short-circuits across all applicable policy classes.
    deny_stmt = _first_matching_deny(ctx, all_layers)
    if deny_stmt is not None:
        return Decision(
            allowed=False,
            stage=Stage.STAGE_1_EXPLICIT_DENY,
            explicit_deny=True,
            statement_id=deny_stmt.sid,
            reason="Explicit Deny short-circuits all granting and capping classes.",
        )

    # Account root user exception: outside implicit deny when no ceiling blocks.
    if ctx.principal_form == PrincipalForm.ACCOUNT_ROOT:
        if ctx.rcp.attached and _first_matching_allow(ctx, ctx.rcp) is None:
            return Decision(False, Stage.STAGE_2_RCP, False, reason="RCP ceiling implicit deny.")
        if ctx.scp.attached and _first_matching_allow(ctx, ctx.scp) is None:
            return Decision(False, Stage.STAGE_3_SCP, False, reason="SCP ceiling implicit deny.")
        return Decision(True, Stage.DEFAULT_ROOT, False, reason="Account root default allow.")

    # Stage 2: Organizations Resource Control Policies (resource-side ceiling).
    if ctx.rcp.attached and _first_matching_allow(ctx, ctx.rcp) is None:
        return Decision(
            allowed=False,
            stage=Stage.STAGE_2_RCP,
            explicit_deny=False,
            reason="Applicable RCP contains no matching Allow.",
        )

    # Stage 3: Organizations Service Control Policies (principal-side ceiling).
    # Service-linked roles are exempt from SCP restrictions.
    if (
        ctx.principal_form != PrincipalForm.SERVICE_LINKED_ROLE
        and ctx.scp.attached
        and _first_matching_allow(ctx, ctx.scp) is None
    ):
        return Decision(
            allowed=False,
            stage=Stage.STAGE_3_SCP,
            explicit_deny=False,
            reason="Applicable SCP contains no matching Allow.",
        )

    # Documented Exceptions to Same-Account Union:
    # 1. IAM role trust policy must explicitly allow sts:AssumeRole*.
    # 2. KMS key policy must explicitly allow kms:* (or delegate to account IAM).
    resource_allow = _first_matching_allow(ctx, ctx.resource_policy)
    if requires_explicit_resource_allow(ctx.action):
        if resource_allow is None:
            exc_stage = (
                Stage.EXCEPTION_TRUST_POLICY
                if ctx.action.startswith("sts:AssumeRole")
                else Stage.EXCEPTION_KMS_KEY_POLICY
            )
            return Decision(
                allowed=False,
                stage=exc_stage,
                explicit_deny=False,
                reason=f"Action {ctx.action} requires an explicit resource/trust/key policy Allow.",
            )

    # Stage 4: Resource-based policy grant and Principal-Type Branch (Table 2).
    if resource_allow is not None:
        named_form = resource_allow.named_principal_form or ctx.principal_form
        if resource_grant_bypasses_ceilings(named_form) and not resource_allow.delegates_to_account_iam:
            return Decision(
                allowed=True,
                stage=Stage.STAGE_4_RESOURCE_POLICY,
                explicit_deny=False,
                statement_id=resource_allow.sid,
                reason=f"Resource-based grant to {named_form.value} survives boundary/session implicit deny.",
            )

    # Stage 5: Identity-based policy grant.
    identity_allow = _first_matching_allow(ctx, ctx.identity_policy)
    # Inside one account, either an identity Allow or a resource Allow (even if
    # named against IAM_ROLE_ARN or FEDERATING_IAM_USER_ARN) supplies a grant
    # before Stages 6 and 7 cap it.
    effective_grant = identity_allow or resource_allow
    if effective_grant is None:
        return Decision(
            allowed=False,
            stage=Stage.STAGE_5_IDENTITY_POLICY,
            explicit_deny=False,
            reason="Implicit deny: neither resource-based nor identity-based policy granted the action.",
        )

    # Stage 6: Permissions boundary (ceiling on IAM user/role).
    if ctx.permissions_boundary.attached and _first_matching_allow(ctx, ctx.permissions_boundary) is None:
        return Decision(
            allowed=False,
            stage=Stage.STAGE_6_PERMISSIONS_BOUNDARY,
            explicit_deny=False,
            reason="Permissions boundary ceiling silent (implicit deny).",
        )

    # Stage 7: Session policy (ceiling on session principals).
    if not ctx.is_session_principal:
        return Decision(
            allowed=True,
            stage=Stage.STAGE_5_IDENTITY_POLICY,
            explicit_deny=False,
            statement_id=effective_grant.sid,
            reason="Non-session principal allowed after passing applicable ceilings.",
        )

    if ctx.session_policy.attached and _first_matching_allow(ctx, ctx.session_policy) is None:
        return Decision(
            allowed=False,
            stage=Stage.STAGE_7_SESSION_POLICY,
            explicit_deny=False,
            reason="Passed session policy ceiling silent (implicit deny).",
        )

    deciding_stage = (
        Stage.STAGE_7_SESSION_POLICY
        if ctx.is_session_principal and (ctx.session_policy.attached or not ctx.permissions_boundary.attached)
        else Stage.STAGE_6_PERMISSIONS_BOUNDARY
    )
    return Decision(
        allowed=True,
        stage=deciding_stage,
        explicit_deny=False,
        statement_id=effective_grant.sid,
        reason="Session principal allowed across all applicable ceilings.",
    )


def evaluate_cross_account(
    trusted_principal_ctx: RequestContext,
    trusting_resource_ctx: RequestContext,
) -> Decision:
    """Evaluate a cross-account request as the conjunction of two independent
    evaluations across the account trust boundary:
        Eval_cross(q) = Eval_trusted(q) AND Eval_trusting(q)
    """
    verdict_trusted = evaluate_single_account(trusted_principal_ctx)
    if not verdict_trusted.allowed:
        if verdict_trusted.explicit_deny:
            return verdict_trusted
        return Decision(
            allowed=False,
            stage=Stage.CROSS_ACCOUNT_CONJUNCTION,
            explicit_deny=False,
            reason=f"Denied in trusted (principal) account at {verdict_trusted.stage.value}.",
        )

    verdict_trusting = evaluate_single_account(trusting_resource_ctx)
    if not verdict_trusting.allowed:
        if verdict_trusting.explicit_deny:
            return verdict_trusting
        return Decision(
            allowed=False,
            stage=Stage.CROSS_ACCOUNT_CONJUNCTION,
            explicit_deny=False,
            reason=f"Denied in trusting (resource) account at {verdict_trusting.stage.value}.",
        )

    return Decision(
        allowed=True,
        stage=Stage.CROSS_ACCOUNT_CONJUNCTION,
        explicit_deny=False,
        statement_id=f"{verdict_trusted.statement_id}+{verdict_trusting.statement_id}",
        reason="Both trusted and trusting account evaluations returned Allow.",
    )


# ---------------------------------------------------------------------------
# Directed Authorization Graph G = (V, E)
# Distinguishing Structural Reachability from Executable Reachability
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphEdge:
    """A modeled transition edge u -> v in G = (V, E).

    An edge exists structurally when an identity or resource policy statement
    mentions the transition (e.g., sts:AssumeRole, iam:PassRole, s3:GetObject).
    Whether the edge is *executable* requires evaluating the full 7-stage
    request context at hop time.
    """

    source: str
    target: str
    action: str
    context: RequestContext
    trusting_context: RequestContext | None = None

    def is_executable(self) -> tuple[bool, Decision]:
        if self.trusting_context is not None or self.context.is_cross_account:
            if self.trusting_context is None:
                dec = Decision(False, Stage.CROSS_ACCOUNT_CONJUNCTION, False, reason="Missing trusting context.")
                return False, dec
            dec = evaluate_cross_account(self.context, self.trusting_context)
            return dec.allowed, dec
        dec = evaluate_single_account(self.context)
        return dec.allowed, dec


class AuthorizationGraph:
    """Directed authorization graph G = (V, E) with cycle-safe BFS traversal.

    Complexity:
        Graph construction: O(|V| + |E|)
        Shortest-path reachability (structural or executable):
            O(|V| + |E| * C_eval) time, O(|V|) auxiliary space,
            where C_eval is the per-edge policy evaluation cost across at most
            7 policy classes.
    """

    def __init__(self) -> None:
        self._adj: dict[str, list[GraphEdge]] = {}
        self._nodes: set[str] = set()

    def add_edge(self, edge: GraphEdge) -> None:
        self._nodes.add(edge.source)
        self._nodes.add(edge.target)
        self._adj.setdefault(edge.source, []).append(edge)
        self._adj.setdefault(edge.target, [])

    @property
    def vertices(self) -> set[str]:
        return set(self._nodes)

    def structural_shortest_path(self, start: str, goal: str) -> list[str] | None:
        """Find shortest path in G ignoring ceiling/condition evaluation."""
        if start not in self._nodes or goal not in self._nodes:
            return None
        queue: deque[list[str]] = deque([[start]])
        visited: set[str] = {start}
        while queue:
            path = queue.popleft()
            curr = path[-1]
            if curr == goal:
                return path
            for edge in self._adj.get(curr, ()):
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append(path + [edge.target])
        return None

    def executable_shortest_path(
        self, start: str, goal: str
    ) -> tuple[list[str] | None, list[ tuple[GraphEdge, Decision] ]]:
        """Find shortest path in G where every hop satisfies the 7-stage
        AWS IAM evaluation procedure. Also returns the audit trace of all
        evaluated edges (including hops blocked by ceilings or exceptions).
        """
        if start not in self._nodes or goal not in self._nodes:
            return None, []
        queue: deque[list[str]] = deque([[start]])
        visited: set[str] = {start}
        trace: list[tuple[GraphEdge, Decision]] = []
        while queue:
            path = queue.popleft()
            curr = path[-1]
            if curr == goal:
                return path, trace
            for edge in self._adj.get(curr, ()):
                ok, decision = edge.is_executable()
                trace.append((edge, decision))
                if ok and edge.target not in visited:
                    visited.add(edge.target)
                    queue.append(path + [edge.target])
        return None, trace
