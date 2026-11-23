# GitHub automation

![Made with AI](https://raw.githubusercontent.com/ajsem1337/ajsem1337/main/assets/made-with-ai.svg)

Automatically collects dependency updates, security alerts and automation failures from repositories and updates their statuses on a GitHub Projects board.

## Scope

New active repositories owned by the account are discovered automatically.
Use `--exclude-repo OWNER/REPO` to skip a repository without closing or dismissing
its alerts; the option can be repeated. Exclusions appear on the private monitor
health card, rather than in the public log.

The single `monitor:health` card reports source counts (`ok`, `degraded`,
`unavailable`, `unsupported`), the last completed sync, and each non-ok source's
reason and last successful check. Successful empty lists count as `ok`; 403/404
means unavailable, not unsupported. Use `--unsupported-source OWNER/REPO:SOURCE`
(for example `OWNER/REPO:code-scanning-alerts`) to report a capability the owner
knows is unavailable as `unsupported` while it cannot be read; a successful read
still counts as `ok`. A hidden JSON block preserves successful
timestamps between syncs; missing history is shown as unknown. The card is
written after finding updates succeed.

“No open findings observed” only describes the sources read successfully.
“All supported sources checked” requires every monitored source to be `ok` or
owner-marked `unsupported`. Existing open
findings from non-ok sources are counted as unverified and retain their state.
Each workflow is checked independently across at most three pages of 100
completed runs, on the default branch (any branch for GitHub dynamic scans).
Cancelled, skipped and neutral runs are skipped; an unknown or missing conclusion
preserves the finding. Only explicit success resolves a workflow finding.
Exhausted history, disabled workflows and workflows absent from inventory preserve
existing findings and appear on the health card. Reusable workflows whose only
trigger is `workflow_call` record no runs of their own and are skipped when they
have no runs.

At the owner's request, the scheduled workflow excludes the unused
`ajsem1337/community-plugins` fork, which contains the full catalog of third-party
plugins, and the deleted `ajsem1337/system-health` repository, whose last findings
stay in the Project unchanged. The owner's `ajsem1337/system-menu` repository
remains monitored. Code and secret scanning in the private `obs-setup` and
`webapp` repositories, and Dependabot PRs in the profile repository (pull
requests disabled), are marked unsupported.

## Private repositories

The reusable `.github/workflows/secret-check.yml` workflow runs Gitleaks when
native GitHub secret scanning is unavailable on a repository's plan.
Calling repositories pin the workflow to a full commit SHA, grant only
`contents: read` and pass no secrets. The scan covers the fetched Git history.

The Gitleaks binary has a pinned version and a verified SHA-256 checksum.
The report is redacted and is not published as an artifact; finding details in
the log are limited to the rule ID, file, line and commit. A finding or scanner
error fails the workflow, which the existing monitor records in the private
project. This does not replace CodeQL or create native Secret Scanning alerts.

## Project status names

The monitor requires an existing private user project. Keep these literal
option values in its `Status` field; the code matches their Polish names exactly:

| Value | Meaning |
| --- | --- |
| `Do zrobienia` | To do: new or reopened findings |
| `W trakcie` | In progress: the active monitor health card |
| `Gotowe` | Done: resolved, closed or merged source items |

An open finding keeps its existing board status unless its source was previously
resolved, closed or merged, or it has no board status. The source-state values are `Otwarte`
(open), `Aktywny` (active), `Rozwiązane` (resolved), `Zamknięte` (closed) and
`Scalone` (merged).

The text fields also retain their exact names: `ID monitora` (monitor ID),
`Repozytorium` (repository), `Typ zgłoszenia` (finding type), `Stan źródła`
(source state) and `Ważność` (severity).

---

<p align="center"><sub>Built by <a href="https://github.com/ajsem1337">ajsem</a> with AI assistance.</sub></p>
