#!/usr/bin/env python3
"""Synchronize security metadata to a PRIVATE user Project. Python stdlib + gh CLI."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
import re
import subprocess
from urllib.parse import urlencode


class APIError(RuntimeError):
    def __init__(self, status="API"):
        self.status = str(status)
        super().__init__(f"GitHub API: {self.status}")


class GitHub:
    def call(self, endpoint, payload=None, paginate=False):
        # gh credentials stay in the existing credential store or GH_TOKEN.
        args = ["gh", "api", "--hostname", "github.com", endpoint,
                "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: 2022-11-28"]
        if payload is not None:
            args += ["--input", "-"]
        if paginate:
            args += ["--paginate", "--slurp"]
        try:
            result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                                    capture_output=True, text=True, timeout=90, check=False)
        except subprocess.TimeoutExpired:
            raise APIError("timeout") from None
        if result.returncode:
            match = re.search(r"HTTP (\d{3})", result.stderr)
            # Never include API response bodies: secret-scanning responses contain secrets.
            raise APIError(match.group(1) if match else "request failed")
        try:
            data = json.loads(result.stdout)
        except ValueError:
            raise APIError("invalid response") from None
        if isinstance(data, dict) and data.get("errors"):
            raise APIError("GraphQL errors")
        return data

    def gql(self, query, **variables):
        return self.call("graphql", {"query": query, "variables": variables})["data"]

    def pages(self, endpoint, key=None, **params):
        # Let gh follow Link headers, including cursor pagination (Dependabot
        # explicitly rejects the numeric page parameter).
        pages = self.call(endpoint + "?" + urlencode(dict(params, per_page=100)), paginate=True)
        return [row for page in pages for row in (page[key] if key else page)]


OPEN = "Otwarte"
ACTIVE = "Aktywny"
DONE = "Rozwiązane"
TERMINAL = {DONE, "Zamknięte", "Scalone"}
FIELDS = ["ID monitora", "Repozytorium", "Typ zgłoszenia", "Stan źródła", "Ważność"]
SEVERITY = {"critical": "Krytyczna", "high": "Wysoka", "medium": "Średnia", "low": "Niska"}
SOURCES = {"dependabot": "Dependabot alert", "code-scanning": "CodeQL / code scanning",
           "secret-scanning": "Sekrety"}


@dataclass
class Finding:
    key: str
    repo: str
    kind: str
    title: str
    body: str
    state: str = OPEN
    severity: str = "Informacja"
    content_id: str = ""

    def draft_body(self):
        # Marker permits recovery after a run interrupted before custom fields were saved.
        return self.body + f"\n\n<!-- security-project-monitor:v1 {self.key} -->"

    def fields(self):
        return dict(zip(FIELDS, (self.key, self.repo, self.kind, self.state, self.severity)))


def alert_finding(repo, source, alert):
    number = alert["number"]
    state = alert["state"]
    resolved = DONE if state in {"fixed", "resolved"} else "Zamknięte"
    severity = "Nieznana"
    # Deliberately whitelist metadata. Do NOT copy secret, locations, code snippets,
    # tool messages, advisory summaries or other free-form alert payloads.
    if source == "secret-scanning":
        detail = "Rodzaj: " + alert.get("secret_type_display_name", "Sekret")
        severity = "Wysoka"
    elif source == "dependabot":
        advisory = alert.get("security_advisory") or {}
        severity = SEVERITY.get(advisory.get("severity"), "Nieznana")
        dependency = alert.get("dependency") or {}
        package = dependency.get("package") or {}
        detail = f"Pakiet: {package.get('ecosystem', '?')} / {package.get('name', '?')}\n\n"
        detail += f"Identyfikator: {advisory.get('ghsa_id', '?')}\n\n"
        detail += f"Klasyfikacja: {advisory.get('classification', 'general')}"
    else:
        rule = alert.get("rule") or {}
        detail = "Reguła: " + rule.get("id", "?")
        severity = SEVERITY.get(rule.get("security_severity_level"), "Informacja")
    url = alert["html_url"]
    return Finding(f"{source}:{repo}:{number}", repo, SOURCES[source],
                   f"[{repo.split('/')[-1]}] {SOURCES[source]} #{number}",
                   f"{detail}\n\nŹródło: {url}\n\n"
                   "Szczegóły i obsługa zgłoszenia pozostają w zakładce Security repozytorium.\n"
                   "Ten wpis zawiera wyłącznie metadane, bez wartości sekretów.",
                   OPEN if state == "open" else resolved, severity)


def pull_finding(repo, pull):
    state = OPEN if pull["state"] == "open" else ("Scalone" if pull.get("merged_at") else "Zamknięte")
    return Finding(f"pr:{repo}:{pull['number']}", repo, "Dependabot PR", "", "",
                   state, content_id=pull["node_id"])


def workflow_finding(repo, workflow, run):
    bad = run.get("conclusion") in {"failure", "timed_out", "action_required", "startup_failure", "stale"}
    return Finding(f"workflow:{repo}:{workflow['id']}", repo, "Błąd automatyzacji",
                   f"[{repo.split('/')[-1]}] Workflow: {workflow['name']}",
                   f"Workflow: {workflow['name']}\n\nWynik: {run.get('conclusion', '?')}\n\n"
                   f"Uruchomienie: {run['html_url']}\n\n"
                   "Śledzony jest ostatni zakończony, nieanulowany przebieg: "
                   "na gałęzi domyślnej lub — dla dynamicznych skanów GitHuba — na dowolnej gałęzi.\n"
                   "Kolejny udany przebieg oznaczy wpis jako rozwiązany.",
                   OPEN if bad else DONE)


def collect_repo(api, repo):
    name = repo["full_name"]
    found, coverage = [], []
    prefix = f"repos/{name}"
    try:
        for pull in api.pages(prefix + "/pulls", state="open"):
            if pull.get("user", {}).get("login") == "dependabot[bot]":
                found.append(pull_finding(name, pull))
    except APIError as exc:
        coverage.append((name, "Dependabot PR", exc.status))
    for source in SOURCES:
        try:
            for alert in api.pages(f"{prefix}/{source}/alerts", state="open"):
                found.append(alert_finding(name, source, alert))
        except APIError as exc:
            coverage.append((name, SOURCES[source], exc.status))
    try:
        workflows = api.pages(prefix + "/actions/workflows", key="workflows")
        for workflow in workflows:
            if workflow.get("state") != "active":
                continue
            params = {"status": "completed", "per_page": 20}
            if not workflow["path"].startswith("dynamic/"):
                params["branch"] = repo["default_branch"]
            data = api.call(f"{prefix}/actions/workflows/{workflow['id']}/runs?" + urlencode(params))
            run = next((r for r in data["workflow_runs"]
                        if r.get("conclusion") not in {"cancelled", "skipped", "neutral"}), None)
            if run:
                found.append(workflow_finding(name, workflow, run))
    except APIError as exc:
        coverage.append((name, "GitHub Actions", exc.status))
    return found, coverage


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
    key = item_values(item).get("ID monitora")
    if key:
        return key
    body = (item.get("content") or {}).get("body", "")
    match = re.search(r"<!-- security-project-monitor:v1 ([^\s<>]+) -->", body)
    return match.group(1) if match else None


def desired_status(old, state, todo="Do zrobienia", done="Gotowe"):
    if state == ACTIVE:
        return "W trakcie"
    if state in TERMINAL:
        return done
    if old.get("Stan źródła") in TERMINAL or not old.get("Status"):
        return todo
    return old["Status"]


class Project:
    def __init__(self, api, owner, number, apply=False):
        self.api, self.apply = api, apply
        self.data = api.gql(PROJECT_QUERY, owner=owner, number=number)["user"]["projectV2"]
        if not self.data or self.data["public"]:
            raise RuntimeError("Monitoring wymaga istniejącego PRYWATNEGO projektu.")
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
        status = self.fields.get("Status", {})
        self.status_options = {o["name"]: o["id"] for o in status.get("options", [])}
        if not {"Do zrobienia", "W trakcie", "Gotowe"} <= self.status_options.keys():
            raise RuntimeError("Brakuje statusów Do zrobienia / W trakcie / Gotowe; bez zmian.")
        for name in FIELDS:
            if name in self.fields:
                if self.fields[name].get("dataType") != "TEXT":
                    raise RuntimeError("Pole monitora ma niewłaściwy typ; bez zmian.")
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
        values["Status"] = desired_status(old, finding.state)
        for name, value in values.items():
            if old.get(name) == value:
                continue
            field_value = {"singleSelectOptionId": self.status_options[value]} if name == "Status" else {"text": value}
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


def synchronize(api, owner, number, apply=False):
    project = Project(api, owner, number, apply)
    repos = [r for r in api.pages("user/repos", affiliation="owner")
             if r["owner"]["login"].lower() == owner.lower() and not r["archived"] and not r["disabled"]]
    project.setup()
    findings, coverage = [], []
    with ThreadPoolExecutor(max_workers=4) as pool:
        for rows, errors in pool.map(lambda r: collect_repo(api, r), repos):
            findings.extend(rows)
            coverage.extend(errors)
    present = {f.key for f in findings}
    active_repos = {r["full_name"] for r in repos}
    for key, item in project.managed.items():
        if key in present or key == "monitor:health":
            continue
        old = item_values(item)
        if old.get("Stan źródła") in TERMINAL:
            continue
        # Removed/archived/inaccessible repositories keep their last known state.
        if old.get("Repozytorium") not in active_repos:
            coverage.append((old.get("Repozytorium", "?"), "repozytorium pominięte", "brak dostępu / nieaktywne"))
            continue
        try:
            refreshed = refresh_missing(api, key)
            if refreshed:
                findings.append(refreshed)
        except (APIError, ValueError) as exc:
            coverage.append((old.get("Repozytorium", "?"), old.get("Typ zgłoszenia", "?"), getattr(exc, "status", "format ID")))
    counts = Counter()
    for finding in findings:
        counts[project.upsert(finding)] += 1
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = "To karta stanu monitora. Nie wymaga oznaczania jako wykonana.\n\n"
    body += f"Ostatnie odświeżenie: {timestamp}\n\nRepozytoria: {len(repos)}\n\n"
    body += "Otwarte zgłoszenia w odczytanych źródłach:\n"
    open_counts = Counter(f.kind for f in findings if f.state == OPEN)
    for kind, count in sorted(open_counts.items()):
        body += f"- {kind}: {count}\n"
    if not open_counts:
        body += "Brak otwartych zgłoszeń w źródłach, które udało się odczytać.\n"
    body += ("\nCo dalej: harmonogram odświeża tę kartę co 6 godzin. Nowe PR-y i alerty "
             "pojawią się jako osobne pozycje Do zrobienia, do przejrzenia i decyzji o poprawce.\n")
    body += "\nOgraniczenia zakresu / błędy odczytu:\n"
    body += "\n".join(f"- {repo}: {source} — {status}" for repo, source, status in sorted(set(coverage))) or "Brak błędów odczytu."
    body += ("\n\n403/404 oznacza brak dostępu, wyłączoną funkcję albo funkcję niedostępną w planie. "
             "To NIE oznacza braku podatności. Błąd odczytu nie zamyka istniejących pozycji.\n\n"
             "Monitoring zapisuje metadane i linki. Nie kopiuje sekretów, nie scala PR-ów, "
             "nie zmienia kodu ani nie odrzuca alertów. Historia pozostaje w projekcie. "
             "Alert i naprawiający go PR mogą być osobnymi pozycjami.\n\n"
             "Uruchomienia: https://github.com/ajsem1337/github-automation/actions/workflows/security-project.yml")
    project.upsert(Finding("monitor:health", "", "Stan monitoringu", "Monitoring bezpieczeństwa — stan", body, state=ACTIVE))
    # Only counts go to public workflow logs; repository names/details stay private.
    print(json.dumps({"mode": "apply" if apply else "preview", "repositories": len(repos),
                      "items": dict(counts), "unavailable_sources": len(coverage)}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="ajsem1337")
    parser.add_argument("--project", type=int, default=1)
    parser.add_argument("--apply", action="store_true", help="Write to Project; default is read-only preview")
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") == "true" and not os.environ.get("GH_TOKEN"):
        raise RuntimeError("Dodaj sekret SECURITY_PROJECT_TOKEN w ustawieniach Actions repozytorium.")
    synchronize(GitHub(), args.owner, args.project, args.apply)


if __name__ == "__main__":
    try:
        main()
    except (APIError, RuntimeError) as error:
        # Exceptions above deliberately contain no API payloads.
        print(str(error))
        raise SystemExit(1) from None


