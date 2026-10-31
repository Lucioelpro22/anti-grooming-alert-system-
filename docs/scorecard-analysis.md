# Scorecard analysis modes

The pinned Scorecard action v2.5.0 uses two different analysis modes by design:

- On `pull_request`, it scans the checked-out local files and produces the
  `supply-chain/local` SARIF configuration.
- On main pushes and scheduled runs, it scans the repository and also produces
  `supply-chain/branch-protection` and `supply-chain/online-scm` configurations.

Consequently, GitHub Code Scanning can report a neutral Scorecard check on a PR
with "2 configurations not found", even when scanning and uploading succeeded.
This comparison is incomplete; it does not mean the online checks passed on that
PR. It also does not mean those checks have been removed from main. The main run
after merge #83 (commit `6fc884efce47c3218ea9472e984f083fb984a648`) produced all
three configurations successfully.

When reviewing an update, inspect the PR's local findings and the last complete
main analysis. After merging, verify that the main run produces all three SARIF
configurations and inspect its findings. A successful workflow means the tool
executed; it does not mean every Scorecard check received a perfect score.

Do not filter SARIF results, drop configurations, dismiss alerts, or add a
privileged token merely to make the PR comparison green. Setting upload-sarif's
`category` cannot repair this comparison: Scorecard supplies its own
`automationDetails.id`, which the uploader preserves.

## Evidence

- [Pinned action event-specific mode selection](https://github.com/ossf/scorecard-action/blob/fa7117db83c52d787ae5a89f350999701505d78e/options/options.go).
- [Scorecard SARIF configuration IDs](https://github.com/ossf/scorecard/blob/61e84743356275f6ffca23b1b2f2cb945e19eb96/pkg/scorecard/sarif.go#L427).
- [Uploader preservation of existing IDs](https://github.com/github/codeql-action/blob/24c54180a607b1449ed407dd24f251e4e9147c8d/src/upload-lib.ts#L191).
- [Main analysis after merge #83](https://github.com/Lucioelpro22/anti-grooming-alert-system-/actions/runs/41209739369).
