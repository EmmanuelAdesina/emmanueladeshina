package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/graph"
	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/model"
)

func main() {
	inputPath := flag.String("input", "", "Path to JSON slice of model.Identity records")
	startARN := flag.String("start", "", "Starting principal ARN for escalation search")
	execOnly := flag.Bool("executable-only", true, "Prune paths blocked by permissions boundaries or silent trust policies")
	flag.Parse()

	if *inputPath == "" {
		fmt.Fprintln(os.Stderr, "usage: attackpath --input <identities.json> [--start <arn>] [--executable-only=true]")
		os.Exit(1)
	}
	raw, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}
	var ids []model.Identity
	if err := json.Unmarshal(raw, &ids); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal identities: %v\n", err)
		os.Exit(2)
	}
	g := graph.BuildFromIdentities(ids)
	out := make(map[string][][]graph.Edge)
	for _, id := range ids {
		if *startARN != "" && id.ARN != *startARN {
			continue
		}
		paths := g.ShortestReachablePaths(id.ARN, *execOnly)
		if len(paths) > 0 {
			out[id.ARN] = paths
		}
	}
	enc, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(enc))
}
