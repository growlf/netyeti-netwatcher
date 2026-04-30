#!/bin/bash
# setup-branch-protection.sh
#
# Applies recommended branch protection rules to the 'main' branch of
# growlf/netyeti-netwatcher using the GitHub CLI (gh).
#
# Requirements:
#   - gh CLI installed and authenticated as a repository admin
#     https://cli.github.com/
#
# Usage:
#   bash tools/setup-branch-protection.sh
#   bash tools/setup-branch-protection.sh --repo owner/repo  # override repo
#   bash tools/setup-branch-protection.sh --branch develop   # override branch

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
REPO="${GITHUB_REPOSITORY:-growlf/netyeti-netwatcher}"
BRANCH="main"

# ── Argument parsing ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)   REPO="$2";   shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── Pre-flight checks ──────────────────────────────────────────────────────────
if ! command -v gh &>/dev/null; then
  echo "ERROR: gh CLI is not installed. See https://cli.github.com/" >&2
  exit 1
fi

if ! gh auth status &>/dev/null; then
  echo "ERROR: Not authenticated with gh CLI. Run: gh auth login" >&2
  exit 1
fi

echo "================================================================="
echo "  Branch Protection Setup"
echo "  Repository : $REPO"
echo "  Branch     : $BRANCH"
echo "================================================================="
echo ""
echo "This will apply the following rules:"
echo "  • Require 1 pull-request review before merging"
echo "  • Require code-owner review (CODEOWNERS file)"
echo "  • Dismiss stale reviews when new commits are pushed"
echo "  • Require status checks to pass:"
echo "      - Lint & Test (Python 3.10)"
echo "      - Lint & Test (Python 3.11)"
echo "      - Build Docker image"
echo "      - Analyze Python  (CodeQL)"
echo "  • Require branch to be up-to-date before merging"
echo "  • Require conversation resolution before merging"
echo "  • Do NOT allow force-pushes"
echo "  • Do NOT allow branch deletion"
echo ""
read -rp "Apply these rules to '$BRANCH'? (y/N) " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

echo ""
echo "Applying branch protection rules..."

gh api \
  --method PUT \
  "repos/${REPO}/branches/${BRANCH}/protection" \
  --header "Accept: application/vnd.github+json" \
  --field "required_status_checks[strict]=true" \
  --field "required_status_checks[contexts][]=Lint & Test (Python 3.10)" \
  --field "required_status_checks[contexts][]=Lint & Test (Python 3.11)" \
  --field "required_status_checks[contexts][]=Build Docker image" \
  --field "required_status_checks[contexts][]=Analyze Python" \
  --field "enforce_admins=true" \
  --field "required_pull_request_reviews[dismiss_stale_reviews]=true" \
  --field "required_pull_request_reviews[require_code_owner_reviews]=true" \
  --field "required_pull_request_reviews[required_approving_review_count]=1" \
  --field "required_conversation_resolution=true" \
  --field "allow_force_pushes=false" \
  --field "allow_deletions=false" \
  --silent

echo ""
echo "✔  Branch protection rules applied successfully to '${BRANCH}'."
echo ""
echo "Verify in GitHub: https://github.com/${REPO}/settings/branches"
