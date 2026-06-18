#!/usr/bin/env bash
# Copyright Landy Bible <landy@ljb2of3.net> 2026
# SPDX-License-Identifier: MPL-2.0

# Apply branch protection ruleset to `main`.
# GitHub blocks rulesets on PRIVATE repos unless you have Pro, so run this AFTER
# the repo is public (`gh repo edit --visibility public`) or after upgrading to Pro.
#
# Rules: require a PR before merging, require signed commits, require the CI
# checks to pass, block force-push and deletion on main. Admin bypass left on
# (enforcement gate is org-only anyway).
set -euo pipefail
REPO="ljb2of3/vault-plugin-secrets-netbox"

gh api -X POST "repos/$REPO/rulesets" --input - <<'JSON'
{
  "name": "protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/heads/main"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_signatures" },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "test (-race)", "integration_id": 15368 },
          { "context": "golangci-lint", "integration_id": 15368 },
          { "context": "gofmt", "integration_id": 15368 },
          { "context": "govulncheck", "integration_id": 15368 },
          { "context": "license headers", "integration_id": 15368 }
        ]
      }
    },
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["merge", "squash", "rebase"]
      }
    }
  ]
}
JSON
echo "Ruleset applied. Verify: gh api repos/$REPO/rulesets --jq '.[].name'"
