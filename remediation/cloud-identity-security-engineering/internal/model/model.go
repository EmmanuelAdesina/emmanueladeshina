// Package model defines the dependency-free domain types for AWS IAM
// principals, policy statements, permissions, and CloudTrail events.
package model

import "time"

// PrincipalType classifies a node in the AWS identity and resource graph.
type PrincipalType string

const (
	PrincipalIAMUser          PrincipalType = "IAMUser"
	PrincipalIAMRole          PrincipalType = "IAMRole"
	PrincipalRoleSession      PrincipalType = "AssumedRoleSession"
	PrincipalAWSService       PrincipalType = "AWSService"
	PrincipalExternalAccount  PrincipalType = "ExternalAccount"
	PrincipalResourceS3Bucket PrincipalType = "S3Bucket"
	PrincipalResourceKMSKey   PrincipalType = "KMSKey"
)

// Identity represents a node v in V within the authorization graph G = (V, E).
type Identity struct {
	ARN                 string            `json:"arn"`
	Name                string            `json:"name"`
	AccountID           string            `json:"account_id"`
	Type                PrincipalType     `json:"type"`
	IsPrivileged        bool              `json:"is_privileged"`
	PermissionsBoundary *PolicyDocument   `json:"permissions_boundary,omitempty"`
	AttachedPolicies    []PolicyDocument  `json:"attached_policies,omitempty"`
	TrustPolicy         *PolicyDocument   `json:"trust_policy,omitempty"`
	Tags                map[string]string `json:"tags,omitempty"`
}

// PolicyDocument represents an AWS IAM JSON policy (identity, resource, trust, or boundary).
type PolicyDocument struct {
	Version    string      `json:"Version"`
	Statements []Statement `json:"Statement"`
}

// Statement represents a single IAM policy statement after normalization.
type Statement struct {
	Sid          string                       `json:"Sid,omitempty"`
	Effect       string                       `json:"Effect"` // "Allow" or "Deny"
	Principals   []string                     `json:"Principals,omitempty"`
	NotPrincipal bool                         `json:"NotPrincipal,omitempty"`
	Actions      []string                     `json:"Action"`
	Resources    []string                     `json:"Resource"`
	Conditions   map[string]map[string]string `json:"Condition,omitempty"`
}

// EdgeKind classifies a directed authorization edge e = (u, v) in E.
type EdgeKind string

const (
	EdgeAssumeRole          EdgeKind = "sts:AssumeRole"
	EdgePassRole            EdgeKind = "iam:PassRole"
	EdgeAttachRolePolicy    EdgeKind = "iam:AttachRolePolicy"
	EdgeUpdateAssumeRole    EdgeKind = "iam:UpdateAssumeRolePolicy"
	EdgePutRolePolicy       EdgeKind = "iam:PutRolePolicy"
	EdgeResourcePolicyGrant EdgeKind = "resource:DirectGrant"
)

// CloudTrailEvent models a subset of an AWS CloudTrail control-plane record.
type CloudTrailEvent struct {
	EventID          string            `json:"eventID"`
	EventTime        time.Time         `json:"eventTime"`
	EventSource      string            `json:"eventSource"`
	EventName        string            `json:"eventName"`
	AWSRegion        string            `json:"awsRegion"`
	SourceIPAddress  string            `json:"sourceIPAddress"`
	UserIdentityType string            `json:"userIdentityType"` // IAMUser, AssumedRole, FederatedUser, Root
	PrincipalARN     string            `json:"principalArn"`
	RequestParams    map[string]string `json:"requestParameters,omitempty"`
	ErrorCode        string            `json:"errorCode,omitempty"`
}

// SecurityFinding represents an auditable escalation path or detection alert.
type SecurityFinding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	MITRETechnique string   `json:"mitre_technique"`
	SourceARN      string   `json:"source_arn"`
	TargetARN      string   `json:"target_arn"`
	Path           []string `json:"path"`
	HopCount       int      `json:"hop_count"`
	BlastRadius    string   `json:"blast_radius"`
	DecidingStage  string   `json:"deciding_stage"`
	Evidence       string   `json:"evidence"`
}
