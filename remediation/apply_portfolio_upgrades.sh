#!/usr/bin/env bash
# ==============================================================================
# apply_portfolio_upgrades.sh
#
# Actionable script to apply cross-repository improvements discovered during the
# portfolio engineering audit (outside the EmmanuelAdesina/emmanueladeshina
# profile repository branch managed by Arena):
#   1. Populates EmmanuelAdesina/cloud-identity-security-engineering with the
#      working Go implementation in remediation/cloud-identity-security-engineering/
#      (replacing the 0-byte scaffold files).
#   2. Updates GitHub repository descriptions and topics across key repositories
#      to reflect verified implementation scope.
#   3. Updates GitHub profile bio and location metadata (removing "Planning
#      moves to Finland" in favor of accurate location "Nigeria").
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/3] Updating GitHub repository descriptions & topics..."

gh repo edit EmmanuelAdesina/emmanueladeshina \
  --description "Systems Security Engineer — Secure systems architecture, AWS IAM authorization algebra, verifiable infrastructure (RELIASTRA), security research, and mathematical systems modeling." \
  --homepage "https://reliastra.com"

gh repo edit EmmanuelAdesina/cloud-identity-security-engineering \
  --description "Go-based AWS IAM authorization graph analysis, 7-stage policy evaluation modeling, privilege-escalation reachability, and CloudTrail detection engineering." \
  --homepage "https://reliastra.com/research/cloud-security/aws-iam-policy-evaluation-order"

gh repo edit EmmanuelAdesina/aws-iam-attack-paths \
  --description "Cloud security threat modeling of AWS IAM as a directed trust graph G=(V,E): sts:AssumeRole chains, iam:PassRole injection, resource policies, and cross-account trust boundaries." \
  --homepage "https://reliastra.com/research/cloud-security/aws-iam-policy-evaluation-order"

gh repo edit EmmanuelAdesina/fintech-browser-security-observations \
  --description "Passive observational security study of browser trust-boundary consistency (CSP, HSTS, frame protection, permissions policy) across 9 production fintech platforms."

gh repo edit EmmanuelAdesina/CloudVitals \
  --description "Go + Python AWS security posture CLI scanner with concurrent check execution, weighted severity scoring, and mock/live provider interfaces."

echo "[2/3] Updating GitHub user profile metadata..."
gh api -X PATCH /user \
  -f bio="Systems Security Engineer · Founder & Principal Engineer @ RELIASTRA · Cloud Identity (AWS IAM), Secure Infrastructure & Mathematical Systems Modeling" \
  -f company="RELIASTRA" \
  -f blog="https://reliastra.com" \
  -f location="Nigeria" >/dev/null

echo "[3/3] Populating EmmanuelAdesina/cloud-identity-security-engineering..."
WORK_TMP="$(mktemp -d)"
trap 'rm -rf "$WORK_TMP"' EXIT

git clone "https://github.com/EmmanuelAdesina/cloud-identity-security-engineering.git" "$WORK_TMP/cise"
cp -R "$SCRIPT_DIR/cloud-identity-security-engineering/." "$WORK_TMP/cise/"
cd "$WORK_TMP/cise"
git add .
if ! git diff --cached --quiet; then
  git commit -m "feat: implement Go IAM policy parser, authorization graph (<300 LOC), and CloudTrail detection rules"
  git push origin main
  echo "Pushed working Go implementation to EmmanuelAdesina/cloud-identity-security-engineering."
else
  echo "No changes to commit in cloud-identity-security-engineering."
fi

echo "Done. Remember to pin the 6 recommended repositories in GitHub Profile Settings -> Customize your pins:"
echo "  1. ReliaAstra/Reliastra"
echo "  2. EmmanuelAdesina/chimera"
echo "  3. EmmanuelAdesina/aws-iam-attack-paths"
echo "  4. EmmanuelAdesina/hunter"
echo "  5. EmmanuelAdesina/headershield"
echo "  6. EmmanuelAdesina/cloud-identity-security-engineering"
