#!/usr/bin/env python3
"""Synchronize security metadata to a PRIVATE user Project. Python stdlib + gh CLI."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import os
import random
import re
import subprocess
import time
from urllib.parse import urlencode


class APIError(RuntimeError):
    def __init__(self, status="API"):
        status = str(status)
        known = r"[1-5]\d{2}|timeout|request failed|invalid response|GraphQL errors|rate limited"
        self.status = status if re.fullmatch(known, status) else "request failed"
        super().__init__(f"GitHub API: {self.status}")


class GitHub:
    READ_ATTEMPTS = 3
    READ_BUDGET = 90

    def call(self, endpoint, payload=None, paginate=False):
        # gh credentials stay in the existing credential store or GH_TOKEN.
        args = ["gh", "api", "--hostname", "github.com", endpoint,
                "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: 2022-11-28", "--include"]
        if payload is not None:
            args += ["--input", "-"]
        if paginate:
            args += ["--paginate"]
        # GraphQL uses POST for both queries and mutations. Only queries are reads.
        read = payload is None or (endpoint == "graphql" and bool(re.match(
            r"\s*(?:#[^\n]*\n\s*)*(?:query\b|\{)", payload.get("query", ""))))
        deadline = time.monotonic() + self.READ_BUDGET
        for attempt in range(self.READ_ATTEMPTS if read else 1):
            retry_after = None
            try:
                result = subprocess.run(
                    args, input=json.dumps(payload) if payload is not None else None,
                    capture_output=True, text=True,
                    timeout=min(30, max(0.01, deadline - time.monotonic())) if read else 90,
                    check=False)
            except subprocess.TimeoutExpired:
                error = APIError("timeout")
                transient = True
            else:
                # Inspect headers/error categories, but never expose response bodies or stderr.
                match = re.search(r"HTTP(?:/\S+)?\s+(\d{3})", result.stderr)
                headers = re.findall(r"(?m)^HTTP/\S+\s+(\d{3})", result.stdout)
                status = match.group(1) if match else (headers[-1] if headers else "")
                secondary = "secondary rate limit" in (result.stderr + result.stdout).lower()
                retry_after = self.retry_after(result.stdout)
                if result.returncode or (status and int(status) >= 400):
                    # The explicit no-retry rule for 401/403/404 takes precedence.
                    denied = status in {"401", "403", "404"}
                    error = APIError("rate limited" if secondary and not denied else status or "request failed")
                    transient = (status == "429" or status.startswith("5") or
                                 (secondary and not denied))
                else:
                    data = self.decode(result.stdout, paginate)
                    if isinstance(data, dict) and data.get("errors"):
                        error = APIError("rate limited" if secondary else "GraphQL errors")
                        transient = secondary
                    else:
                        if endpoint == "graphql" and (not isinstance(data, dict) or not isinstance(data.get("data"), dict)):
                            raise APIError("invalid response")
                        return data
            if not read or not transient or attempt == self.READ_ATTEMPTS - 1:
                raise error from None
            delay = max(0.5 * 2 ** attempt + random.uniform(0, 0.25), retry_after or 0)
            if delay >= deadline - time.monotonic():
                raise error from None
            time.sleep(delay)

    @staticmethod
    def retry_after(output):
        match = re.search(r"(?im)^Retry-After:\s*([^\r\n]+)", output)
        if not match:
            return None
        value = match.group(1).strip()
        if value.isdigit():
            return int(value)
        try:
            return max(0, (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None

    @staticmethod
    def decode(output, paginate):
        # --include exposes Retry-After. Decode each gh page after its HTTP headers.
        pages = []
        remaining = output.replace("\r\n", "\n").strip()
        try:
            while remaining:
                if remaining.startswith("HTTP/"):
                    _, separator, remaining = remaining.partition("\n\n")
                    if not separator:
                        raise ValueError
                    remaining = remaining.lstrip()
                page, end = json.JSONDecoder().raw_decode(remaining)
                if not isinstance(page, (dict, list)):
                    raise ValueError
                pages.append(page)
                remaining = remaining[end:].lstrip()
            if not pages or (not paginate and len(pages) != 1):
                raise ValueError
        except ValueError:
            raise APIError("invalid response") from None
        return pages if paginate else pages[0]

    def gql(self, query, **variables):
        return self.call("graphql", {"query": query, "variables": variables})["data"]

    def pages(self, endpoint, key=None, **params):
        # Let gh follow Link headers, including cursor pagination (Dependabot
        # explicitly rejects the numeric page parameter).
        pages = self.call(endpoint + "?" + urlencode(dict(params, per_page=100)), paginate=True)
        try:
            return [row for page in pages for row in records(page[key] if key else page)]
        except (KeyError, TypeError):
            raise APIError("invalid response") from None


# Live Project field names and option/state values must keep their exact Polish spelling.
MONITOR_ID_FIELD, REPO_FIELD, KIND_FIELD, SOURCE_STATE_FIELD, SEVERITY_FIELD = (
    "ID monitora", "Repozytorium", "Typ zgłoszenia", "Stan źródła", "Ważność")
STATUS_FIELD = "Status"
TODO, IN_PROGRESS, COMPLETE = "Do zrobienia", "W trakcie", "Gotowe"
OPEN = "Otwarte"
ACTIVE = "Aktywny"
DONE = "Rozwiązane"
CLOSED, MERGED = "Zamknięte", "Scalone"
INFO, UNKNOWN = "Informacja", "Nieznana"
TERMINAL = {DONE, CLOSED, MERGED}
FIELDS = [MONITOR_ID_FIELD, REPO_FIELD, KIND_FIELD, SOURCE_STATE_FIELD, SEVERITY_FIELD]
SEVERITY = {"critical": "Krytyczna", "high": "Wysoka", "medium": "Średnia", "low": "Niska"}
SOURCES = {"dependabot": "Dependabot alert", "code-scanning": "CodeQL / code scanning",
           "secret-scanning": "Secret scanning"}
BAD_CONCLUSIONS = {"failure", "timed_out", "action_required", "startup_failure", "stale"}
IGNORED_CONCLUSIONS = {"cancelled", "skipped", "neutral"}
HEALTH_KEY = "monitor:health"
STATE_MARKER = "security-project-source-state:v1"
SOURCE_STATES = ("ok", "degraded", "unavailable", "unsupported")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class SourceState:
    source_id: str
    state: str = "ok"
    reason: str = "checked"
    last_attempt_at: str = field(default_factory=utc_now)
    last_success_at: str = ""

    def __post_init__(self):
        if self.state == "ok" and not self.last_success_at:
            self.last_success_at = self.last_attempt_at


def failed_source(source_id, error):
    reason = {"404": "missing_or_inaccessible", "timeout": "timeout",
              "request failed": "request_failed", "invalid response": "invalid_response",
              "GraphQL errors": "graphql_errors", "rate limited": "rate_limited"}.get(
                  error.status, "http_" + error.status)
    return SourceState(source_id, "degraded" if error.status == "invalid response" else "unavailable", reason)


def records(value):
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise APIError("invalid response")
    return value


def source_for_key(key):
    parts = key.split(":", 2)
    if len(parts) != 3:
        return None
    kind, repo, number = parts
    if kind == "workflow":
        return f"{repo}:workflow:{number}"
    if kind == "pr":
        return f"{repo}:dependabot-prs"
    if kind in SOURCES:
        return f"{repo}:{kind}-alerts"
    return None


def source_history(body):
    match = re.search(r"<!-- " + STATE_MARKER + r"\s+(.*?)\s*-->", body, re.DOTALL)
    if not match:
        return {}
    try:
        history = json.loads(match.group(1))
        if not isinstance(history, dict):
            return {}
        valid = {}
        for source, timestamp in history.items():
            if not isinstance(timestamp, str) or not timestamp:
                continue
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.utcoffset() == timezone.utc.utcoffset(None):
                valid[source] = timestamp
        return valid
    except (ValueError, TypeError):
        return {}


@dataclass
class Finding:
    key: str
    repo: str
    kind: str
    title: str
    body: str
    state: str = OPEN
    severity: str = INFO
    content_id: str = ""

    def draft_body(self):
        # Marker permits recovery after a run interrupted before custom fields were saved.
        return self.body + f"\n\n<!-- security-project-monitor:v1 {self.key} -->"

    def fields(self):
        return dict(zip(FIELDS, (self.key, self.repo, self.kind, self.state, self.severity)))


def alert_finding(repo, source, alert):
    number = alert["number"]
    state = alert["state"]
    resolved = DONE if state in {"fixed", "resolved"} else CLOSED
    severity = UNKNOWN
    # Deliberately whitelist metadata. Do NOT copy secret, locations, code snippets,
    # tool messages, advisory summaries or other free-form alert payloads.
    if source == "secret-scanning":
        detail = "Type: " + alert.get("secret_type_display_name", "Secret")
        severity = SEVERITY["high"]
    elif source == "dependabot":
        advisory = alert.get("security_advisory") or {}
        severity = SEVERITY.get(advisory.get("severity"), UNKNOWN)
        dependency = alert.get("dependency") or {}
        package = dependency.get("package") or {}
        detail = f"Package: {package.get('ecosystem', '?')} / {package.get('name', '?')}\n\n"
        detail += f"Identifier: {advisory.get('ghsa_id', '?')}\n\n"
        detail += f"Classification: {advisory.get('classification', 'general')}"
    else:
        rule = alert.get("rule") or {}
        detail = "Rule: " + rule.get("id", "?")
        severity = SEVERITY.get(rule.get("security_severity_level"), INFO)
    url = alert["html_url"]
    return Finding(f"{source}:{repo}:{number}", repo, SOURCES[source],
                   f"[{repo.split('/')[-1]}] {SOURCES[source]} #{number}",
                   f"{detail}\n\nSource: {url}\n\n"
                   "Details and triage remain in the repository's Security tab.\n"
                   "This item contains metadata only, without secret values.",
                   OPEN if state == "open" else resolved, severity)


def pull_finding(repo, pull):
    state = OPEN if pull["state"] == "open" else (MERGED if pull.get("merged_at") else CLOSED)
    return Finding(f"pr:{repo}:{pull['number']}", repo, "Dependabot PR", "", "",
                   state, content_id=pull["node_id"])


def workflow_finding(repo, workflow, run):
    conclusion = run.get("conclusion")
    if conclusion not in BAD_CONCLUSIONS | {"success"}:
        return None
    return Finding(f"workflow:{repo}:{workflow['id']}", repo, "Automation failure",
                   f"[{repo.split('/')[-1]}] Workflow: {workflow['name']}",
                   f"Workflow: {workflow['name']}\n\nConclusion: {conclusion}\n\n"
                   f"Run: {run['html_url']}\n\n"
                   "Tracks completed runs on the default branch, or any branch for GitHub dynamic scans.\n"
                   "Only an explicit successful run resolves this finding.",
                   DONE if conclusion == "success" else OPEN)


def collect_workflow(api, repo, workflow):
    name, workflow_id = repo["full_name"], workflow["id"]
    source_id = f"{name}:workflow:{workflow_id}"
    if workflow.get("state") != "active":
        return None, SourceState(source_id, "degraded", "workflow_disabled")
    params = {"status": "completed", "per_page": 100}
    if not workflow["path"].startswith("dynamic/"):
        params["branch"] = repo["default_branch"]
    for page in range(1, 4):
        data = api.call(f"repos/{name}/actions/workflows/{workflow_id}/runs?" + urlencode(dict(params, page=page)))
        runs = records(data["workflow_runs"])
        for run in runs:
            if run.get("conclusion") in IGNORED_CONCLUSIONS:
                continue
            finding = workflow_finding(name, workflow, run)
            if finding is None:
                return None, SourceState(source_id, "degraded", "unknown_conclusion")
            return finding, SourceState(source_id)
        if len(runs) < 100:
            return None, SourceState(source_id, "degraded", "no_qualifying_run")
    return None, SourceState(source_id, "degraded", "history_cap_exhausted")


def collect_repo(api, repo):
    name = repo["full_name"]
    found, states = [], []
    prefix = f"repos/{name}"
    try:
        found.extend([pull_finding(name, pull) for pull in api.pages(prefix + "/pulls", state="open")
                      if pull.get("user", {}).get("login") == "dependabot[bot]"])
        states.append(SourceState(f"{name}:dependabot-prs"))
    except APIError as exc:
        states.append(failed_source(f"{name}:dependabot-prs", exc))
    except (KeyError, TypeError, ValueError):
        states.append(failed_source(f"{name}:dependabot-prs", APIError("invalid response")))
    for source in SOURCES:
        try:
            found.extend([alert_finding(name, source, alert)
                          for alert in api.pages(f"{prefix}/{source}/alerts", state="open")])
            states.append(SourceState(f"{name}:{source}-alerts"))
        except APIError as exc:
            states.append(failed_source(f"{name}:{source}-alerts", exc))
        except (KeyError, TypeError, ValueError):
            states.append(failed_source(f"{name}:{source}-alerts", APIError("invalid response")))
    try:
        workflows = records(api.pages(prefix + "/actions/workflows", key="workflows"))
        if any(not isinstance(w.get("id"), int) for w in workflows):
            raise APIError("invalid response")
        states.append(SourceState(f"{name}:workflows"))
    except APIError as exc:
        states.append(failed_source(f"{name}:workflows", exc))
        workflows = []
    for workflow in workflows:
        # A failed workflow read must never prevent checking the remaining workflows.
        source_id = f"{name}:workflow:{workflow['id']}"
        try:
            finding, state = collect_workflow(api, repo, workflow)
            if finding:
                found.append(finding)
            states.append(state)
        except APIError as exc:
            states.append(failed_source(source_id, exc))
        except (KeyError, TypeError, ValueError):
            states.append(failed_source(source_id, APIError("invalid response")))
    return found, states


PROJECT_QUERY = """query($owner:String!, $number:Int!) {
  user(login:$owner) { projectV2(number:$number) {
    id public title
    fields(first:100) { nodes {
      ... on ProjectV2Field { id name dataType }
      ... on ProjectV2SingleSelectField { id name options { id name } }
    } }
  } }
}"""
ITEMS_QUERY = """query($id:ID!, $cursor:String) {
  node(id:$id) { ... on ProjectV2 { items(first:100, after:$cursor) {
    nodes { id content {
      ... on DraftIssue { id title body }
      ... on PullRequest { id title url }
      ... on Issue { id title url }
    } fieldValues(first:100) { nodes {
      ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2Field { name } } }
      ... on ProjectV2ItemFieldSingleSelectValue { name field { ... on ProjectV2SingleSelectField { name } } }
    } } }
    pageInfo { hasNextPage endCursor }
  } } }
}"""


def item_values(item):
    return {row["field"]["name"]: row.get("text", row.get("name"))
            for row in item["fieldValues"]["nodes"] if row.get("field")}


def managed_key(item):
    key = item_values(item).get(MONITOR_ID_FIELD)
    if key:
        return key
    body = (item.get("content") or {}).get("body", "")
    match = re.search(r"<!-- security-project-monitor:v1 ([^\s<>]+) -->", body)
    return match.group(1) if match else None


def desired_status(old, state, todo=TODO, done=COMPLETE):
    if state == ACTIVE:
        return IN_PROGRESS
    if state in TERMINAL:
        return done
    if old.get(SOURCE_STATE_FIELD) in TERMINAL or not old.get(STATUS_FIELD):
        return todo
    return old[STATUS_FIELD]


class Project:
    def __init__(self, api, owner, number, apply=False):
        self.api, self.apply = api, apply
        self.data = api.gql(PROJECT_QUERY, owner=owner, number=number)["user"]["projectV2"]
        if not self.data or self.data["public"]:
            raise RuntimeError("Monitoring requires an existing PRIVATE Project.")
        self.id = self.data["id"]
        self.fields = {f["name"]: f for f in self.data["fields"]["nodes"] if f}
        self.items = []
        cursor = None
        while True:
            page = api.gql(ITEMS_QUERY, id=self.id, cursor=cursor)["node"]["items"]
            self.items.extend(page["nodes"])
            if not page["pageInfo"]["hasNextPage"]:
                break
            cursor = page["pageInfo"]["endCursor"]
        self.managed = {managed_key(i): i for i in self.items if managed_key(i)}
        self.content_ids = {i["content"]["id"] for i in self.items if i.get("content")}

    def setup(self):
        status = self.fields.get(STATUS_FIELD, {})
        self.status_options = {o["name"]: o["id"] for o in status.get("options", [])}
        if not {TODO, IN_PROGRESS, COMPLETE} <= self.status_options.keys():
            raise RuntimeError("Required Project status options are missing; no changes made.")
        for name in FIELDS:
            if name in self.fields:
                if self.fields[name].get("dataType") != "TEXT":
                    raise RuntimeError("A monitor field has the wrong type; no changes made.")
            elif self.apply:
                data = self.api.gql("""mutation($input:CreateProjectV2FieldInput!) {
                  createProjectV2Field(input:$input) { projectV2Field { ... on ProjectV2Field { id name dataType } } }
                }""", input={"projectId": self.id, "name": name, "dataType": "TEXT"})
                self.fields[name] = data["createProjectV2Field"]["projectV2Field"]

    def upsert(self, finding):
        item = self.managed.get(finding.key)
        if not item and finding.state in TERMINAL:
            return "ignored"
        # Keep existing manually managed PRs/issues untouched.
        if not item and finding.content_id and finding.content_id in self.content_ids:
            return "manual"
        if not self.apply:
            return "updated" if item else "created"
        if not item:
            if finding.content_id:
                data = self.api.gql("""mutation($input:AddProjectV2ItemByIdInput!) {
                  addProjectV2ItemById(input:$input) { item { id } }
                }""", input={"projectId": self.id, "contentId": finding.content_id})
                item = data["addProjectV2ItemById"]["item"]
            else:
                data = self.api.gql("""mutation($input:AddProjectV2DraftIssueInput!) {
                  addProjectV2DraftIssue(input:$input) { projectItem { id content { ... on DraftIssue { id title body } } } }
                }""", input={"projectId": self.id, "title": finding.title, "body": finding.draft_body()})
                item = data["addProjectV2DraftIssue"]["projectItem"]
            item["fieldValues"] = {"nodes": []}
            created = True
        else:
            created = False
        old = item_values(item)
        content = item.get("content") or {}
        if not finding.content_id and content.get("id") and (content.get("title"), content.get("body")) != (finding.title, finding.draft_body()):
            self.api.gql("""mutation($input:UpdateProjectV2DraftIssueInput!) {
              updateProjectV2DraftIssue(input:$input) { draftIssue { id } }
            }""", input={"draftIssueId": content["id"], "title": finding.title, "body": finding.draft_body()})
        values = finding.fields()
        values[STATUS_FIELD] = desired_status(old, finding.state)
        for name, value in values.items():
            if old.get(name) == value:
                continue
            field_value = {"singleSelectOptionId": self.status_options[value]} if name == STATUS_FIELD else {"text": value}
            self.api.gql("""mutation($input:UpdateProjectV2ItemFieldValueInput!) {
              updateProjectV2ItemFieldValue(input:$input) { projectV2Item { id } }
            }""", input={"projectId": self.id, "itemId": item["id"],
                         "fieldId": self.fields[name]["id"], "value": field_value})
        self.managed[finding.key] = item
        if finding.content_id:
            self.content_ids.add(finding.content_id)
        return "created" if created else "updated"


def refresh_missing(api, key):
    # Missing list results never mean resolved. Read the individual source instead.
    source, repo, number = key.split(":", 2)
    if source == "pr":
        return pull_finding(repo, api.call(f"repos/{repo}/pulls/{int(number)}"))
    if source in SOURCES:
        return alert_finding(repo, source, api.call(f"repos/{repo}/{source}/alerts/{int(number)}"))
    return None


def health_finding(states, findings, history, completed_at, repo_count, excluded_repos, unverified):
    history = dict(history)
    for source in states.values():
        if source.state != "ok":
            source.last_success_at = history.get(source.source_id, "")
        history[source.source_id] = source.last_success_at
    counts = Counter(source.state for source in states.values())
    body = "Collection health; this card does not require completion.\n\n"
    body += f"Last completed sync: {completed_at}\n\nRepositories: {repo_count}\n\n"
    body += "Sources: " + "; ".join(f"{state}: {counts[state]}" for state in SOURCE_STATES) + "\n\n"
    open_count = sum(f.state == OPEN for f in findings)
    body += f"Open findings observed: {open_count}.\n"
    if not open_count:
        body += "No open findings observed in successfully read sources.\n"
    all_checked = all(source.state == "ok" for source in states.values())
    body += f"All sources checked: {'yes' if all_checked else 'no'}.\n"
    body += f"Unverified existing open findings: {unverified}.\n\n"
    body += "Non-ok sources (source; state; reason; last success):\n"
    non_ok = [source for source in states.values() if source.state != "ok"]
    body += "\n".join(
        f"- {source.source_id}; {source.state}; {source.reason}; {source.last_success_at or 'unknown'}"
        for source in sorted(non_ok, key=lambda source: source.source_id)) or "None."
    if excluded_repos:
        body += "\n\nRepositories excluded by the owner: " + ", ".join(sorted(excluded_repos))
    body += ("\n\n403/404 means unavailable, including missing or inaccessible sources. "
             "This does not mean there are no vulnerabilities. Failed reads preserve existing findings. "
             "New alerts and PRs appear as separate to-do items for review. "
             "The monitor stores metadata and links without copying secrets.\n")
    body += f"\n<!-- {STATE_MARKER}\n" + json.dumps(history, sort_keys=True) + "\n-->"
    return Finding(HEALTH_KEY, "", "Monitor health", "Security monitoring — health", body, state=ACTIVE)


def synchronize(api, owner, number, apply=False, excluded_repos=()):
    excluded_repos = {name.lower() for name in excluded_repos}
    project = Project(api, owner, number, apply)
    health_item = project.managed.get(HEALTH_KEY, {})
    history = source_history((health_item.get("content") or {}).get("body", ""))
    states = {}

    def record(source):
        previous = states.get(source.source_id)
        # A successful individual refresh cannot repair a failed collection read.
        if previous is None or source.state != "ok":
            states[source.source_id] = source

    try:
        repos = [r for r in api.pages("user/repos", affiliation="owner")
                 if r["owner"]["login"].lower() == owner.lower() and not r["archived"] and not r["disabled"]
                 and r["full_name"].lower() not in excluded_repos]
        record(SourceState("repos"))
    except APIError as exc:
        repos = []
        record(failed_source("repos", exc))
    except (KeyError, TypeError, ValueError):
        repos = []
        record(failed_source("repos", APIError("invalid response")))
    project.setup()
    findings = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for rows, sources in pool.map(lambda r: collect_repo(api, r), repos):
            findings.extend(rows)
            for source in sources:
                record(source)
    present = {f.key for f in findings}
    active_repos = {r["full_name"]: r for r in repos}
    existing = []
    for key, item in project.managed.items():
        source_id = source_for_key(key)
        if source_id is None:
            continue
        old = item_values(item)
        kind, repo, number_id = key.split(":", 2)
        if repo.lower() in excluded_repos or (old.get(REPO_FIELD) or "").lower() in excluded_repos:
            continue
        existing.append((key, source_id, old.get(SOURCE_STATE_FIELD, OPEN)))
        if key in present:
            continue
        # Removed/archived/inaccessible repositories keep their last known state.
        if repo not in active_repos:
            record(SourceState(source_id, "unavailable", "repository_inactive_or_inaccessible"))
            continue
        if kind == "workflow":
            # Known workflows absent from inventory need an individual read, even if resolved.
            if source_id in states:
                continue
            try:
                workflow = api.call(f"repos/{repo}/actions/workflows/{int(number_id)}")
                if workflow["id"] != int(number_id):
                    raise APIError("invalid response")
                reason = "workflow_not_in_inventory" if workflow["state"] == "active" else "workflow_disabled"
                record(SourceState(source_id, "degraded", reason))
            except APIError as exc:
                record(failed_source(source_id, exc))
            except (KeyError, TypeError, ValueError):
                record(failed_source(source_id, APIError("invalid response")))
            continue
        if old.get(SOURCE_STATE_FIELD) in TERMINAL:
            continue
        try:
            refreshed = refresh_missing(api, key)
            if refreshed:
                findings.append(refreshed)
                record(SourceState(source_id))
        except APIError as exc:
            record(failed_source(source_id, exc))
        except (KeyError, TypeError, ValueError):
            record(failed_source(source_id, APIError("invalid response")))
    observed = {finding.key: finding.state for finding in findings}
    unverified = sum(observed.get(key, old_state) == OPEN and
                     (source_id not in states or states[source_id].state != "ok")
                     for key, source_id, old_state in existing)
    counts = Counter()
    for finding in findings:
        counts[project.upsert(finding)] += 1
    # Finalize history and publish health only after all finding writes succeeded.
    project.upsert(health_finding(states, findings, history, utc_now(), len(repos), excluded_repos, unverified))
    # Only counts go to public workflow logs; repository names/details stay private.
    print(json.dumps({"mode": "apply" if apply else "preview", "repositories": len(repos),
                      "items": dict(counts), "sources": dict(Counter(s.state for s in states.values())),
                      "unverified_findings": unverified, "excluded_repositories": len(excluded_repos)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="ajsem1337")
    parser.add_argument("--project", type=int, default=1)
    parser.add_argument("--apply", action="store_true", help="Write to Project; default is read-only preview")
    parser.add_argument("--exclude-repo", action="append", default=[], metavar="OWNER/REPO",
                        help="Exclude a repository without dismissing its alerts; may be repeated")
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") == "true" and not os.environ.get("GH_TOKEN"):
        raise RuntimeError("Add the SECURITY_PROJECT_TOKEN secret in the repository Actions settings.")
    synchronize(GitHub(), args.owner, args.project, args.apply, args.exclude_repo)


if __name__ == "__main__":
    try:
        main()
    except (APIError, RuntimeError) as error:
        # Exceptions above deliberately contain no API payloads.
        print(str(error))
        raise SystemExit(1) from None
