// Package graph constructs the directed IAM authorization graph G = (V, E)
// and implements cycle-safe BFS escalation path enumeration.
// Hard architecture constraint: < 300 LOC across identity_graph.go + traversal.go.
package graph

import (
	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/iam"
	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/model"
)

// Edge represents a directed authorization transition u -> v in G = (V, E).
type Edge struct {
	From       string         `json:"from"`
	To         string         `json:"to"`
	Kind       model.EdgeKind `json:"kind"`
	Executable bool           `json:"executable"`
	Stage      string         `json:"stage"`
}

// IdentityGraph stores vertices V and adjacency list E for IAM reachability analysis.
type IdentityGraph struct {
	Nodes map[string]model.Identity
	Edges map[string][]Edge
}

// New creates an empty IdentityGraph.
func New() *IdentityGraph {
	return &IdentityGraph{
		Nodes: make(map[string]model.Identity),
		Edges: make(map[string][]Edge),
	}
}

// AddIdentity registers a vertex v in V.
func (g *IdentityGraph) AddIdentity(id model.Identity) {
	g.Nodes[id.ARN] = id
}

// AddEdge registers a directed transition e = (u, v) in E.
func (g *IdentityGraph) AddEdge(e Edge) {
	g.Edges[e.From] = append(g.Edges[e.From], e)
}

// BuildFromIdentities derives both structural and semantically executable
// escalation edges across a set of IAM identities and roles.
func BuildFromIdentities(identities []model.Identity) *IdentityGraph {
	g := New()
	for _, id := range identities {
		g.AddIdentity(id)
	}
	escalationActions := []model.EdgeKind{
		model.EdgeAssumeRole,
		model.EdgePassRole,
		model.EdgeAttachRolePolicy,
		model.EdgeUpdateAssumeRole,
		model.EdgePutRolePolicy,
	}
	for _, src := range identities {
		for _, dst := range identities {
			if src.ARN == dst.ARN {
				continue
			}
			for _, kind := range escalationActions {
				action := string(kind)
				if !hasStructuralMention(src, action, dst.ARN) {
					continue
				}
				exec, stage := iam.EvaluateIdentityAccess(src, action, dst.ARN)
				if exec && kind == model.EdgeAssumeRole && !trustPolicyAllows(dst, src) {
					exec = false
					stage = "exception_trust_policy_silent"
				}
				g.AddEdge(Edge{
					From:       src.ARN,
					To:         dst.ARN,
					Kind:       kind,
					Executable: exec,
					Stage:      stage,
				})
			}
		}
	}
	return g
}

func hasStructuralMention(id model.Identity, action, targetARN string) bool {
	for _, pol := range id.AttachedPolicies {
		for _, s := range pol.Statements {
			if s.Effect != "Allow" {
				continue
			}
			for _, a := range s.Actions {
				if iam.ActionMatches(a, action) {
					for _, r := range s.Resources {
						if iam.ResourceMatches(r, targetARN) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func trustPolicyAllows(targetRole, caller model.Identity) bool {
	if targetRole.TrustPolicy == nil {
		return false
	}
	rootARN := "arn:aws:iam::" + caller.AccountID + ":root"
	for _, s := range targetRole.TrustPolicy.Statements {
		if s.Effect != "Allow" {
			continue
		}
		for _, p := range s.Principals {
			if p == "*" || p == caller.ARN || p == rootARN {
				return true
			}
		}
	}
	return false
}

// ShortestReachablePaths performs cycle-safe BFS from startARN to any privileged
// identity in G. When executableOnly is true, edges blocked by a permissions
// boundary, explicit deny, or missing trust policy are pruned.
func (g *IdentityGraph) ShortestReachablePaths(startARN string, executableOnly bool) [][]Edge {
	type state struct {
		arn  string
		path []Edge
	}
	queue := []state{{arn: startARN, path: nil}}
	visited := map[string]bool{startARN: true}
	var findings [][]Edge

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.arn != startARN {
			if node, ok := g.Nodes[curr.arn]; ok && node.IsPrivileged {
				findings = append(findings, curr.path)
				continue
			}
		}
		for _, edge := range g.Edges[curr.arn] {
			if executableOnly && !edge.Executable {
				continue
			}
			if !visited[edge.To] {
				visited[edge.To] = true
				nextPath := make([]Edge, len(curr.path)+1)
				copy(nextPath, curr.path)
				nextPath[len(curr.path)] = edge
				queue = append(queue, state{arn: edge.To, path: nextPath})
			}
		}
	}
	return findings
}
