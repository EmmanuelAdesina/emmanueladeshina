package graph_test

import (
	"testing"

	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/graph"
	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/iam"
	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/model"
)

func TestExecutableVsStructuralEscalationPath(t *testing.T) {
	allowAssumeAll, err := iam.ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}]
	}`))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	silentBoundary, err := iam.ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
	}`))
	if err != nil {
		t.Fatalf("parse boundary: %v", err)
	}
	trustAccountRoot, err := iam.ParsePolicy([]byte(`{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "sts:AssumeRole"}]
	}`))
	if err != nil {
		t.Fatalf("parse trust: %v", err)
	}

	devCapped := model.Identity{
		ARN:                 "arn:aws:iam::111122223333:user/dev-capped",
		AccountID:           "111122223333",
		Type:                model.PrincipalIAMUser,
		AttachedPolicies:    []model.PolicyDocument{*allowAssumeAll},
		PermissionsBoundary: silentBoundary, // blocks sts:AssumeRole at Stage 6!
	}
	devUncapped := model.Identity{
		ARN:              "arn:aws:iam::111122223333:user/dev-uncapped",
		AccountID:        "111122223333",
		Type:             model.PrincipalIAMUser,
		AttachedPolicies: []model.PolicyDocument{*allowAssumeAll},
	}
	adminRole := model.Identity{
		ARN:          "arn:aws:iam::111122223333:role/AdminRole",
		AccountID:    "111122223333",
		Type:         model.PrincipalIAMRole,
		IsPrivileged: true,
		TrustPolicy:  trustAccountRoot,
	}

	g := graph.BuildFromIdentities([]model.Identity{devCapped, devUncapped, adminRole})

	// Structural path exists for dev-capped, but executable path is blocked at Stage 6
	if got := len(g.ShortestReachablePaths(devCapped.ARN, false)); got != 1 {
		t.Fatalf("expected 1 structural path for dev-capped, got %d", got)
	}
	if got := len(g.ShortestReachablePaths(devCapped.ARN, true)); got != 0 {
		t.Fatalf("expected 0 executable paths for dev-capped (blocked by boundary), got %d", got)
	}

	// Both structural and executable paths exist for dev-uncapped
	if got := len(g.ShortestReachablePaths(devUncapped.ARN, true)); got != 1 {
		t.Fatalf("expected 1 executable path for dev-uncapped, got %d", got)
	}
}
