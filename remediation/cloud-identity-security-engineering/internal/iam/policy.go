// Package iam implements AWS IAM policy parsing, wildcard action matching,
// and the 7-stage single-account / cross-account evaluation logic.
package iam

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/model"
)

// rawStatement handles AWS IAM's polymorphic JSON fields (string vs []string).
type rawStatement struct {
	Sid          string                       `json:"Sid"`
	Effect       string                       `json:"Effect"`
	Principal    any                          `json:"Principal"`
	NotPrincipal any                          `json:"NotPrincipal"`
	Action       any                          `json:"Action"`
	Resource     any                          `json:"Resource"`
	Condition    map[string]map[string]string `json:"Condition"`
}

type rawPolicy struct {
	Version   string          `json:"Version"`
	Statement json.RawMessage `json:"Statement"`
}

// ParsePolicy parses raw AWS IAM policy JSON into a normalized PolicyDocument.
func ParsePolicy(data []byte) (*model.PolicyDocument, error) {
	var rp rawPolicy
	if err := json.Unmarshal(data, &rp); err != nil {
		return nil, fmt.Errorf("unmarshal policy: %w", err)
	}
	var rawStmts []rawStatement
	if len(rp.Statement) > 0 && rp.Statement[0] == '[' {
		if err := json.Unmarshal(rp.Statement, &rawStmts); err != nil {
			return nil, fmt.Errorf("unmarshal statement slice: %w", err)
		}
	} else if len(rp.Statement) > 0 {
		var single rawStatement
		if err := json.Unmarshal(rp.Statement, &single); err != nil {
			return nil, fmt.Errorf("unmarshal single statement: %w", err)
		}
		rawStmts = []rawStatement{single}
	}

	doc := &model.PolicyDocument{
		Version:    rp.Version,
		Statements: make([]model.Statement, 0, len(rawStmts)),
	}
	for _, rs := range rawStmts {
		stmt := model.Statement{
			Sid:          rs.Sid,
			Effect:       rs.Effect,
			Principals:   extractPrincipals(rs.Principal),
			NotPrincipal: rs.NotPrincipal != nil,
			Actions:      toStringSlice(rs.Action),
			Resources:    toStringSlice(rs.Resource),
			Conditions:   rs.Condition,
		}
		doc.Statements = append(doc.Statements, stmt)
	}
	return doc, nil
}

func toStringSlice(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func extractPrincipals(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case map[string]any:
		var out []string
		for _, sub := range val {
			out = append(out, toStringSlice(sub)...)
		}
		return out
	default:
		return nil
	}
}

// ActionMatches returns true if pattern (supporting '*' and 'service:*') matches action.
func ActionMatches(pattern, action string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	a := strings.ToLower(strings.TrimSpace(action))
	if p == "*" || p == a {
		return true
	}
	if strings.HasSuffix(p, "*") {
		return strings.HasPrefix(a, strings.TrimSuffix(p, "*"))
	}
	return false
}

// ResourceMatches returns true if pattern matches targetARN.
func ResourceMatches(pattern, targetARN string) bool {
	if pattern == "*" || pattern == targetARN {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(targetARN, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

// EvaluateIdentityAccess checks whether an identity's attached policies and
// optional permissions boundary permit (action, resourceARN).
// Enforces: Stage 1 (Explicit Deny) -> Stage 5 (Identity Grant) -> Stage 6 (Permissions Boundary).
func EvaluateIdentityAccess(id model.Identity, action, resourceARN string) (allowed bool, stage string) {
	// Stage 1: Explicit Deny across attached policies and boundary
	for _, pol := range id.AttachedPolicies {
		for _, s := range pol.Statements {
			if strings.EqualFold(s.Effect, "Deny") && matchesActionAndResource(s, action, resourceARN) {
				return false, "stage_1_explicit_deny"
			}
		}
	}
	if id.PermissionsBoundary != nil {
		for _, s := range id.PermissionsBoundary.Statements {
			if strings.EqualFold(s.Effect, "Deny") && matchesActionAndResource(s, action, resourceARN) {
				return false, "stage_1_explicit_deny"
			}
		}
	}

	// Stage 5: Identity-based Allow
	granted := false
	for _, pol := range id.AttachedPolicies {
		for _, s := range pol.Statements {
			if strings.EqualFold(s.Effect, "Allow") && matchesActionAndResource(s, action, resourceARN) {
				granted = true
				break
			}
		}
	}
	if !granted {
		return false, "stage_5_identity_implicit_deny"
	}

	// Stage 6: Permissions boundary ceiling (if attached, must also explicitly Allow)
	if id.PermissionsBoundary != nil {
		boundaryAllows := false
		for _, s := range id.PermissionsBoundary.Statements {
			if strings.EqualFold(s.Effect, "Allow") && matchesActionAndResource(s, action, resourceARN) {
				boundaryAllows = true
				break
			}
		}
		if !boundaryAllows {
			return false, "stage_6_permissions_boundary_ceiling"
		}
	}

	return true, "stage_6_allowed"
}

func matchesActionAndResource(s model.Statement, action, resourceARN string) bool {
	actOK := false
	for _, a := range s.Actions {
		if ActionMatches(a, action) {
			actOK = true
			break
		}
	}
	if !actOK {
		return false
	}
	for _, r := range s.Resources {
		if ResourceMatches(r, resourceARN) {
			return true
		}
	}
	return false
}
