package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/EmmanuelAdesina/cloud-identity-security-engineering/internal/iam"
)

func main() {
	policyPath := flag.String("policy", "", "Path to AWS IAM JSON policy document")
	flag.Parse()

	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: policyparser --policy <path-to-policy.json>")
		os.Exit(1)
	}
	raw, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read policy: %v\n", err)
		os.Exit(1)
	}
	doc, err := iam.ParsePolicy(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid IAM policy: %v\n", err)
		os.Exit(2)
	}
	enc, _ := json.MarshalIndent(doc, "", "  ")
	fmt.Println(string(enc))
}
