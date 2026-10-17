// Package detection correlates CloudTrail control-plane events against
// high-risk IAM privilege escalation patterns and maps them to MITRE ATT&CK.
package detection

import (
	"fmt"

	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/model"
)

// EvaluateEvent inspects a CloudTrailEvent and returns a SecurityFinding when
// a privilege-escalation or trust-mutation primitive is observed.
func EvaluateEvent(ev model.CloudTrailEvent) *model.SecurityFinding {
	switch ev.EventName {
	case "PassRole":
		return &model.SecurityFinding{
			ID:             "DET-IAM-001",
			Title:          "IAM PassRole Execution to Compute Service",
			Severity:       "HIGH",
			MITRETechnique: "T1548",
			SourceARN:      ev.PrincipalARN,
			TargetARN:      ev.RequestParams["roleArn"],
			HopCount:       1,
			BlastRadius:    "Workload Role Inheritance",
			DecidingStage:  "cloudtrail_userIdentity:" + ev.UserIdentityType,
			Evidence:       fmt.Sprintf("eventID=%s principalType=%s", ev.EventID, ev.UserIdentityType),
		}
	case "AttachRolePolicy", "PutRolePolicy":
		return &model.SecurityFinding{
			ID:             "DET-IAM-002",
			Title:          "Direct IAM Role Policy Escalation",
			Severity:       "CRITICAL",
			MITRETechnique: "T1098.001",
			SourceARN:      ev.PrincipalARN,
			TargetARN:      ev.RequestParams["roleName"],
			HopCount:       1,
			BlastRadius:    "Account-Wide Role Elevation",
			DecidingStage:  "cloudtrail_userIdentity:" + ev.UserIdentityType,
			Evidence:       fmt.Sprintf("eventID=%s policyArn=%s", ev.EventID, ev.RequestParams["policyArn"]),
		}
	case "UpdateAssumeRolePolicy":
		return &model.SecurityFinding{
			ID:             "DET-IAM-003",
			Title:          "Role Trust Policy Mutation (Persistence / Lateral Trust)",
			Severity:       "CRITICAL",
			MITRETechnique: "T1098.001",
			SourceARN:      ev.PrincipalARN,
			TargetARN:      ev.RequestParams["roleName"],
			HopCount:       1,
			BlastRadius:    "Cross-Principal or Cross-Account Trust Boundary",
			DecidingStage:  "cloudtrail_userIdentity:" + ev.UserIdentityType,
			Evidence:       fmt.Sprintf("eventID=%s sourceIP=%s", ev.EventID, ev.SourceIPAddress),
		}
	default:
		return nil
	}
}
