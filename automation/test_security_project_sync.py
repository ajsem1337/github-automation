import base64
import json
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from security_project_sync import (
    ACTIVE, APIError, DONE, Finding, GitHub, OPEN, Project, alert_finding,
    desired_status, managed_key, refresh_missing, workflow_finding,
    SOURCE_STATES, STATE_MARKER, SourceState, collect_repo, collect_workflow,
    failed_source, health_finding, reusable_only, source_history, synchronize,
    AT_RISK, CLOSED, COMPLETE, FIELDS, HEALTH_KEY, MERGED, OFF_TRACK, ON_TRACK,
    STATUS_MARKER, STATUS_UPDATES_QUERY, overall_status,
)


def project_with_items(items=(), apply=True):
    api = Mock()
    fields = [{"id": name, "name": name, "dataType": "TEXT"} for name in FIELDS]
    fields.append({"id": "status", "name": "Status", "options": [
        {"id": value, "name": value} for value in ("Do zrobienia", "W trakcie", COMPLETE)]})
    api.gql.side_effect = [
        {"user": {"projectV2": {"id": "project", "public": False, "fields": {"nodes": fields}}}},
        {"node": {"items": {"nodes": list(items), "pageInfo": {"hasNextPage": False}}}},
    ]
    project = Project(api, "o", 1, apply)
    project.setup()
    api.gql.reset_mock(side_effect=True)
    api.gql.return_value = {}
    return project


def completed_item(key="dependabot:o/private:1", state=DONE, status=COMPLETE,
                   updated_at="2026-10-23T12:00:00Z", archived=False):
    finding = Finding(key or "manual", "o/private", "Dependabot alert", "title", "body", state=state)
    values = dict(finding.fields(), Status=status)
    if key is None:
        del values["ID monitora"]
    return {"id": key or "manual", "isArchived": archived, "updatedAt": updated_at,
            "content": {"id": "draft:" + (key or "manual"), "title": finding.title,
                        "body": finding.draft_body() if key else "Manual card"},
            "fieldValues": {"nodes": [
                {"field": {"name": name}, "name" if name == "Status" else "text": value}
                for name, value in values.items()]}}


class SecurityTests(unittest.TestCase):
    def test_secret_response_is_reduced_to_metadata(self):
        alert = {"number": 8, "state": "open", "html_url": "https://github.com/o/r/security/secret-scanning/8",
                 "secret_type_display_name": "GitHub token", "secret": "DONT_COPY_THIS_VALUE",
                 "locations": [{"secret": "ALSO_SENSITIVE"}], "resolution_comment": "PRIVATE_COMMENT"}
        card = alert_finding("o/r", "secret-scanning", alert)
        text = json.dumps(card.__dict__)
        for forbidden in ("DONT_COPY_THIS_VALUE", "ALSO_SENSITIVE", "PRIVATE_COMMENT"):
            self.assertNotIn(forbidden, text)
        self.assertIn("GitHub token", card.body)

    def test_api_errors_never_include_response_or_stderr(self):
        result = subprocess.CompletedProcess([], 1, '{"secret":"PRIVATE"}', "gh: PRIVATE (HTTP 403)")
        with patch("security_project_sync.subprocess.run", return_value=result):
            with self.assertRaises(APIError) as error:
                GitHub().call("repos/o/r/secret-scanning/alerts")
        self.assertEqual(str(error.exception), "GitHub API: 403")

    def test_cursor_pagination_uses_link_headers_without_numeric_page(self):
        result = subprocess.CompletedProcess([], 0, '[{"number":1}]\n[{"number":2}]', '')
        with patch("security_project_sync.subprocess.run", return_value=result) as run:
            rows = GitHub().pages("repos/o/r/dependabot/alerts", state="open")
        self.assertEqual([r['number'] for r in rows], [1, 2])
        command = run.call_args.args[0]
        self.assertIn("--paginate", command)
        self.assertNotIn("&page=", command[4])

    def test_owner_workflow_status_is_preserved_and_reopening_resets(self):
        self.assertEqual(desired_status({"Status": "W trakcie", "Stan źródła": OPEN}, OPEN), "W trakcie")
        self.assertEqual(desired_status({"Status": "W trakcie", "Stan źródła": OPEN}, DONE), "Gotowe")
        self.assertEqual(desired_status({"Status": "Gotowe", "Stan źródła": DONE}, OPEN), "Do zrobienia")

    def test_monitor_card_stays_in_progress_instead_of_becoming_a_todo(self):
        for previous in ({}, {"Status": "Do zrobienia", "Stan źródła": OPEN},
                         {"Status": "Gotowe", "Stan źródła": DONE}):
            with self.subTest(previous=previous):
                self.assertEqual(desired_status(previous, ACTIVE), "W trakcie")

    def test_unavailable_source_does_not_become_resolved(self):
        api = Mock()
        api.call.side_effect = APIError("403")
        with self.assertRaises(APIError):
            refresh_missing(api, "secret-scanning:o/r:8")

    def test_partial_sync_keeps_existing_alert_and_reports_missing_access_privately(self):
        api = Mock()
        api.pages.return_value = [{"full_name": "o/private", "owner": {"login": "o"},
                                   "archived": False, "disabled": False}]
        old = {"Repozytorium": "o/private", "Stan źródła": OPEN, "Typ zgłoszenia": "Sekrety"}
        item = {"fieldValues": {"nodes": [{"text": value, "field": {"name": name}} for name, value in old.items()]}}
        project = Mock()
        project.archive_completed.return_value = 0
        project.update_status.return_value = True
        project.managed = {"secret-scanning:o/private:8": item}
        with patch("security_project_sync.Project", return_value=project), \
             patch("security_project_sync.collect_repo", return_value=([], [
                 failed_source("o/private:secret-scanning-alerts", APIError("403"))])), \
             patch("security_project_sync.refresh_missing", side_effect=APIError("403")), \
             patch("builtins.print") as public_log:
            synchronize(api, "o", 1, True)
        self.assertEqual(project.upsert.call_count, 1)
        health = project.upsert.call_args.args[0]
        self.assertEqual(health.key, "monitor:health")
        self.assertEqual(health.state, ACTIVE)
        self.assertIn("No open findings observed in successfully read sources.", health.body)
        self.assertIn("403", health.body)
        self.assertIn("This does not mean there are no vulnerabilities", health.body)
        self.assertIn("separate to-do items", health.body)
        self.assertIn("o/private", health.body)
        self.assertNotIn("o/private", public_log.call_args.args[0])

    def test_draft_marker_survives_interrupted_field_updates(self):
        finding = Finding("dependabot:o/r:1", "o/r", "Dependabot", "title", "body")
        item = {"content": {"body": finding.draft_body()}, "fieldValues": {"nodes": []}}
        self.assertEqual(managed_key(item), finding.key)
        self.assertIsNone(managed_key({"content": {"body": "manual task"}, "fieldValues": {"nodes": []}}))

    def test_excluded_repository_is_not_collected_or_refreshed(self):
        api = Mock()
        api.pages.return_value = [
            {"full_name": "o/kept", "owner": {"login": "o"}, "archived": False, "disabled": False},
            {"full_name": "o/excluded", "owner": {"login": "o"}, "archived": False, "disabled": False},
        ]
        old = {"Repozytorium": "o/excluded", "Stan źródła": OPEN}
        item = {"fieldValues": {"nodes": [
            {"text": value, "field": {"name": name}} for name, value in old.items()
        ]}}
        project = Mock()
        project.archive_completed.return_value = 0
        project.update_status.return_value = True
        project.managed = {
            "code-scanning:o/excluded:1": item,
            # An interrupted draft may have its marker but no custom fields yet.
            "code-scanning:o/excluded:2": {"fieldValues": {"nodes": []}},
        }
        with patch("security_project_sync.Project", return_value=project), \
                patch("security_project_sync.collect_repo", return_value=([], [])) as collect, \
                patch("security_project_sync.refresh_missing") as refresh, \
                patch("builtins.print") as public_log:
            synchronize(api, "o", 1, True, excluded_repos=["O/EXCLUDED"])
        collect.assert_called_once_with(api, api.pages.return_value[0])
        refresh.assert_not_called()
        project.upsert.assert_called_once()
        health = project.upsert.call_args.args[0]
        self.assertEqual(health.key, "monitor:health")
        self.assertIn("## Excluded repositories", health.body)
        self.assertIn("o/excluded", health.body)
        self.assertNotIn("repository_inactive_or_inaccessible", health.body)
        counts = json.loads(public_log.call_args.args[0])
        self.assertEqual(counts["repositories"], 1)
        self.assertEqual(counts["excluded_repositories"], 1)
        self.assertNotIn("o/excluded", public_log.call_args.args[0])

    def test_public_project_is_rejected_before_writes(self):
        api = Mock()
        api.gql.return_value = {"user": {"projectV2": {"public": True}}}
        with self.assertRaises(RuntimeError):
            Project(api, "owner", 1, True)
        self.assertEqual(api.gql.call_count, 1)

    def test_manual_native_items_are_not_adopted(self):
        project = object.__new__(Project)
        project.apply = True
        project.managed = {}
        project.content_ids = {"existing-pr"}
        project.api = Mock()
        finding = Finding("pr:o/r:1", "o/r", "Dependabot PR", "", "", content_id="existing-pr")
        self.assertEqual(project.upsert(finding), "manual")
        project.api.gql.assert_not_called()

    def test_existing_finding_is_updated_without_adding_duplicate(self):
        project = object.__new__(Project)
        project.apply = True
        finding = Finding("dependabot:o/r:8", "o/r", "Dependabot alert", "title", "body")
        fields = dict(finding.fields(), Status="Do zrobienia")
        project.managed = {finding.key: {"id": "item", "content": {
            "id": "draft", "title": finding.title, "body": finding.draft_body()},
            "fieldValues": {"nodes": [{"text": value, "field": {"name": name}} for name, value in fields.items()]}}}
        project.api = Mock()
        self.assertEqual(project.upsert(finding), "updated")
        project.api.gql.assert_not_called()

    def test_successful_run_resolves_failed_workflow(self):
        workflow = {"id": 99, "name": "CodeQL"}
        failed = workflow_finding("o/r", workflow, {"conclusion": "failure", "html_url": "https://github.com/1"})
        success = workflow_finding("o/r", workflow, {"conclusion": "success", "html_url": "https://github.com/2"})
        self.assertEqual(failed.key, success.key)
        self.assertEqual((failed.state, success.state), (OPEN, DONE))


class SourceStateTests(unittest.TestCase):
    @staticmethod
    def repo():
        return {"full_name": "o/private", "owner": {"login": "o"}, "archived": False,
                "disabled": False, "default_branch": "main"}

    @staticmethod
    def workflow(number=1, state="active", path=".github/workflows/check.yml"):
        return {"id": number, "name": "Check", "state": state, "path": path}

    @staticmethod
    def workflow_run(conclusion):
        return {"conclusion": conclusion, "html_url": "https://github.com/o/private/actions/runs/1"}

    @staticmethod
    def item(state=OPEN, body=""):
        return {"content": {"body": body}, "fieldValues": {"nodes": [
            {"field": {"name": "Repozytorium"}, "text": "o/private"},
            {"field": {"name": "Stan źródła"}, "text": state},
        ]}}

    def api(self, workflows=()):
        api = Mock()
        api.pages.side_effect = lambda endpoint, **params: (
            [self.repo()] if endpoint == "user/repos" else
            list(workflows) if endpoint.endswith("/actions/workflows") else [])
        api.call.return_value = {"workflow_runs": [self.workflow_run("failure")]}
        return api

    def sync(self, api, managed=None):
        project = Mock()
        project.archive_completed.return_value = 0
        project.update_status.return_value = True
        project.managed = dict(managed or {})
        project.upsert.return_value = "updated"
        with patch("security_project_sync.Project", return_value=project), patch("builtins.print") as public_log:
            synchronize(api, "o", 1, True)
        health = project.upsert.call_args.args[0]
        self.assertEqual(health.key, "monitor:health")
        return project, health, json.loads(public_log.call_args.args[0])

    def test_each_workflow_is_isolated(self):
        for response, expected in ((APIError("503"), "unavailable"), ({"wrong": []}, "degraded")):
            with self.subTest(expected=expected):
                api = self.api([self.workflow(1), self.workflow(2)])
                api.call.side_effect = [response, {"workflow_runs": [self.workflow_run("failure")]}]
                found, states = collect_repo(api, self.repo())
                self.assertEqual([f.key for f in found], ["workflow:o/private:2"])
                by_source = {s.source_id: s for s in states}
                self.assertEqual(by_source["o/private:workflow:1"].state, expected)
                self.assertEqual(by_source["o/private:workflow:2"].state, "ok")
                self.assertEqual(api.call.call_count, 2)

    def test_more_than_twenty_cancelled_runs_and_branch_scope(self):
        for path in (".github/workflows/check.yml", "dynamic/codeql"):
            with self.subTest(path=path):
                api = self.api()
                api.call.return_value = {"workflow_runs": [self.workflow_run("cancelled")] * 25 + [self.workflow_run("failure")]}
                finding, state = collect_workflow(api, self.repo(), self.workflow(path=path))
                self.assertEqual(finding.state, OPEN)
                self.assertEqual(state.state, "ok")
                params = parse_qs(urlsplit(api.call.call_args.args[0]).query)
                self.assertEqual(params["per_page"], ["100"])
                self.assertEqual(params["status"], ["completed"])
                self.assertEqual(params.get("branch"), None if path.startswith("dynamic/") else ["main"])

    def test_workflow_search_reaches_second_and_third_pages(self):
        for page in (2, 3):
            with self.subTest(page=page):
                api = self.api()
                api.call.side_effect = ([{"workflow_runs": [self.workflow_run("cancelled")] * 100}] * (page - 1) +
                                        [{"workflow_runs": [self.workflow_run("failure")]}])
                finding, state = collect_workflow(api, self.repo(), self.workflow())
                self.assertEqual((finding.state, state.state), (OPEN, "ok"))
                self.assertEqual(api.call.call_count, page)
                self.assertEqual([parse_qs(urlsplit(c.args[0]).query)["page"] for c in api.call.call_args_list],
                                 [[str(n)] for n in range(1, page + 1)])

    def test_history_cap_preserves_existing_finding_and_marks_unverified(self):
        api = self.api([self.workflow()])
        api.call.return_value = {"workflow_runs": [self.workflow_run("cancelled")] * 100}
        project, health, log = self.sync(api, {"workflow:o/private:1": self.item()})
        project.upsert.assert_called_once()
        self.assertEqual(api.call.call_count, 3)
        self.assertIn("history_cap_exhausted", health.body)
        self.assertIn("Unverified existing open findings: 1", health.body)
        self.assertEqual(log["unverified_findings"], 1)

    def test_inconclusive_runs_preserve_existing_findings(self):
        for conclusion in ("cancelled", "skipped", "neutral", None, "future_conclusion"):
            with self.subTest(conclusion=conclusion):
                api = self.api([self.workflow()])
                api.call.return_value = {"workflow_runs": [self.workflow_run(conclusion)]}
                project, health, _ = self.sync(api, {"workflow:o/private:1": self.item()})
                project.upsert.assert_called_once()
                self.assertIn("degraded: 1", health.body)
                self.assertIsNone(workflow_finding("o/private", self.workflow(), self.workflow_run(conclusion)))
        self.assertIsNone(workflow_finding("o/private", self.workflow(), {}))

    def test_unknown_latest_run_cannot_resolve_from_older_success(self):
        api = self.api([self.workflow()])
        api.call.return_value = {"workflow_runs": [self.workflow_run("future_conclusion"), self.workflow_run("success")]}
        project, health, _ = self.sync(api, {"workflow:o/private:1": self.item()})
        project.upsert.assert_called_once()
        self.assertIn("unknown_conclusion", health.body)

    def test_no_runs_is_degraded_and_preserves_finding(self):
        api = self.api([self.workflow()])
        api.call.return_value = {"workflow_runs": []}
        project, health, _ = self.sync(api, {"workflow:o/private:1": self.item()})
        project.upsert.assert_called_once()
        # Runs read plus the workflow file check for reusable workflows.
        self.assertEqual(api.call.call_count, 2)
        self.assertIn("no_qualifying_run", health.body)

    @staticmethod
    def contents(text):
        return {"content": base64.b64encode(text.encode()).decode()}

    def test_reusable_only_workflow_is_skipped(self):
        api = self.api([self.workflow()])
        api.call.side_effect = lambda endpoint: (
            self.contents("name: Check\n\non:\n  workflow_call:\n    inputs:\n      x:\n        type: string\n")
            if "/contents/" in endpoint else {"workflow_runs": []})
        _, health, log = self.sync(api)
        self.assertNotIn("workflow:1", health.body.split("<!--")[0])
        self.assertIn("✅ All supported sources checked", health.body)
        self.assertIn("contents/.github/workflows/check.yml?ref=main",
                      [c.args[0] for c in api.call.call_args_list][-1])

    def test_reusable_detection_requires_only_workflow_call(self):
        for text, expected in (
                ("on:\n  workflow_call:\n", True),
                ("on: workflow_call\n", True),
                ("'on': [workflow_call]  # reusable\n", True),
                ("on:\n  - workflow_call\n", True),
                ("on:\n  workflow_call:\n  push:\n    branches: [main]\n", False),
                ("on: [push, workflow_call]\n", False),
                ("on:\n  workflow_dispatch:\n", False),
                ("name: x\njobs: {}\n", False)):
            with self.subTest(text=text):
                self.assertEqual(reusable_only(text), expected)

    def test_unreadable_workflow_file_keeps_degraded(self):
        api = self.api([self.workflow()])
        api.call.side_effect = lambda endpoint: (_ for _ in ()).throw(APIError("404")) if "/contents/" in endpoint else {"workflow_runs": []}
        _, health, _ = self.sync(api)
        self.assertIn("no_qualifying_run", health.body)

    def test_owner_marked_unsupported_source(self):
        api = self.api()
        api.pages.side_effect = lambda endpoint, **params: (
            [self.repo()] if endpoint == "user/repos" else
            (_ for _ in ()).throw(APIError("403")) if "code-scanning" in endpoint else [])
        project = Mock()
        project.managed = {}
        project.upsert.return_value = "updated"
        project.archive_completed.return_value = 0
        project.update_status.return_value = True
        with patch("security_project_sync.Project", return_value=project), patch("builtins.print") as public_log:
            synchronize(api, "o", 1, True, (), ["O/Private:code-scanning-alerts"])
        health = project.upsert.call_args.args[0]
        self.assertIn("- ➖ `o/private:code-scanning-alerts`", health.body)
        self.assertIn("❌ unavailable: 0", health.body)
        self.assertIn("➖ unsupported: 1", health.body)
        self.assertIn("✅ All supported sources checked", health.body)
        self.assertEqual(json.loads(public_log.call_args.args[0])["sources"]["unsupported"], 1)

    def test_readable_unsupported_source_is_ok(self):
        api = self.api()
        project = Mock()
        project.managed = {}
        project.upsert.return_value = "updated"
        project.archive_completed.return_value = 0
        project.update_status.return_value = True
        with patch("security_project_sync.Project", return_value=project), patch("builtins.print"):
            synchronize(api, "o", 1, True, (), ["o/private:code-scanning-alerts"])
        self.assertIn("➖ unsupported: 0", project.upsert.call_args.args[0].body)

    def test_only_explicit_success_resolves_existing_workflow(self):
        api = self.api([self.workflow()])
        api.call.return_value = {"workflow_runs": [self.workflow_run("success")]}
        project, health, log = self.sync(api, {"workflow:o/private:1": self.item()})
        self.assertEqual(project.upsert.call_count, 2)
        self.assertEqual(project.upsert.call_args_list[0].args[0].state, DONE)
        self.assertEqual(log["unverified_findings"], 0)
        self.assertIn("✅ All supported sources checked", health.body)

    def test_all_known_failures_open_workflow_findings(self):
        for conclusion in ("failure", "timed_out", "action_required", "startup_failure", "stale"):
            with self.subTest(conclusion=conclusion):
                self.assertEqual(workflow_finding("o/private", self.workflow(), self.workflow_run(conclusion)).state, OPEN)

    def test_absent_workflow_disabled_or_missing_never_resolves(self):
        for response, reason in ((self.workflow(state="disabled_manually"), "workflow_disabled"),
                                 (APIError("404"), "missing_or_inaccessible"),
                                 (self.workflow(), "workflow_not_in_inventory")):
            for old_state in (OPEN, DONE):
                with self.subTest(reason=reason, old_state=old_state):
                    api = self.api()
                    api.call.side_effect = [response]
                    project, health, _ = self.sync(api, {"workflow:o/private:1": self.item(old_state)})
                    api.call.assert_called_once_with("repos/o/private/actions/workflows/1")
                    project.upsert.assert_called_once()
                    self.assertIn(reason, health.body)
                    self.assertIn("unavailable: 1" if isinstance(response, APIError) else "degraded: 1", health.body)

    def test_disabled_inventory_workflow_does_not_read_runs(self):
        api = self.api([self.workflow(state="disabled_inactivity")])
        project, health, _ = self.sync(api, {"workflow:o/private:1": self.item()})
        api.call.assert_not_called()
        project.upsert.assert_called_once()
        self.assertIn("workflow_disabled", health.body)

    def test_successfully_empty_sources_are_ok(self):
        api = self.api()
        findings, states = collect_repo(api, self.repo())
        self.assertEqual(findings, [])
        self.assertEqual(len(states), 5)
        self.assertTrue(all(s.state == "ok" and s.last_success_at for s in states))
        _, health, _ = self.sync(api)
        for line in ("- ✅ ok: 6", "- ⚠️ degraded: 0", "- ❌ unavailable: 0", "- ➖ unsupported: 0"):
            self.assertIn(line, health.body)
        self.assertIn("No open findings observed", health.body)
        self.assertIn("✅ All supported sources checked", health.body)

    def test_last_success_round_trip_and_degraded_run_keeps_old_value(self):
        api = self.api([self.workflow()])
        with patch("security_project_sync.datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2020, 1, 1, tzinfo=timezone.utc)
            _, healthy, _ = self.sync(api)
        previous = source_history(healthy.draft_body())["o/private:workflow:1"]
        self.assertEqual(previous, "2020-01-01T00:00:00Z")
        api.call.return_value = {"workflow_runs": [self.workflow_run("cancelled")]}
        _, degraded, _ = self.sync(api, {"monitor:health": self.item(ACTIVE, healthy.draft_body()),
                                       "workflow:o/private:1": self.item()})
        self.assertEqual(source_history(degraded.draft_body())["o/private:workflow:1"], previous)
        self.assertIn(f"- ⚠️ `o/private:workflow:1` — no_qualifying_run — last success: {previous}", degraded.body)
        self.assertEqual(managed_key(self.item(ACTIVE, degraded.draft_body())), "monitor:health")

    def test_source_attempt_and_success_timestamps_and_unknown_history(self):
        source = SourceState("o/private:dependabot-alerts", last_attempt_at="2026-11-23T10:00:00Z")
        self.assertEqual(source.last_success_at, source.last_attempt_at)
        failed = failed_source("o/private:workflow:1", APIError("404"))
        self.assertRegex(failed.last_attempt_at, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        health = health_finding({source.source_id: source, failed.source_id: failed}, [], {},
                               "2026-11-23T11:00:00Z", 1, (), 1)
        self.assertEqual(failed.last_success_at, "")
        self.assertIn("missing_or_inaccessible — last success: unknown", health.body)
        self.assertIn('"o/private:workflow:1": ""', health.body)
        self.assertIn("Last completed sync: 2026-11-23T11:00:00Z", health.body)

    def test_missing_or_malformed_history_starts_fresh(self):
        for block in ("", "{", "[]", '{"source": "yesterday"}', '{"source": null}',
                      '{"source": "2026-11-23T10:00:00"}'):
            with self.subTest(block=block):
                body = f"<!-- {STATE_MARKER}\n{block}\n-->" if block else "old card"
                self.assertEqual(source_history(body), {})
                api = self.api([self.workflow()])
                api.call.return_value = {"workflow_runs": []}
                _, health, _ = self.sync(api, {"monitor:health": self.item(ACTIVE, body)})
                self.assertIn("no_qualifying_run — last success: unknown", health.body)

    def test_bare_403_and_404_are_unavailable_not_unsupported(self):
        for status in ("403", "404"):
            source = failed_source("o/private:dependabot-alerts", APIError(status))
            self.assertEqual(source.state, "unavailable")
        self.assertIn("unsupported", SOURCE_STATES)

    def test_unverified_excludes_closed_and_successfully_checked_findings(self):
        api = self.api([self.workflow(1), self.workflow(2), self.workflow(3)])
        api.call.side_effect = lambda endpoint: {"workflow_runs": (
            [] if "/1/" in endpoint or "/3/" in endpoint else [self.workflow_run("failure")])}
        _, health, log = self.sync(api, {"workflow:o/private:1": self.item(),
                                         "workflow:o/private:2": self.item(),
                                         "workflow:o/private:3": self.item(DONE)})
        self.assertIn("Unverified existing open findings: 1", health.body)
        self.assertEqual(log["unverified_findings"], 1)
        self.assertNotIn("o/private", json.dumps(log))

    def test_global_repository_read_failure_is_reported(self):
        api = self.api()
        api.pages.side_effect = APIError("503")
        project, health, log = self.sync(api, {"workflow:o/private:1": self.item()})
        api.call.assert_not_called()
        project.upsert.assert_called_once()
        self.assertIn("- ❌ `repos` — http_503 — last success: unknown", health.body)
        self.assertIn("⚠️ Some sources could not be checked", health.body)
        self.assertEqual(log["unverified_findings"], 1)

    def test_no_health_write_after_failed_finding_write(self):
        api = self.api([self.workflow()])
        project = Mock()
        project.archive_completed.return_value = 0
        project.update_status.return_value = True
        project.managed = {}
        project.upsert.side_effect = APIError("503")
        with patch("security_project_sync.Project", return_value=project), patch("builtins.print") as public_log:
            with self.assertRaises(APIError):
                synchronize(api, "o", 1, True)
        project.upsert.assert_called_once()
        self.assertEqual(project.upsert.call_args.args[0].key, "workflow:o/private:1")
        public_log.assert_not_called()


class PresentationTests(unittest.TestCase):
    def test_health_sections_lists_and_hidden_history(self):
        previous = "2026-10-01T12:00:00Z"
        states = {s.source_id: s for s in (
            SourceState("repos"), SourceState("o/private:workflow:2", "degraded", "workflow_disabled"),
            failed_source("o/private:secret-scanning-alerts", APIError("403")),
            SourceState("o/private:code-scanning-alerts", "unsupported", "owner_marked"))}
        health = health_finding(states, [], {"o/private:workflow:2": previous},
                                "2026-11-23T12:00:00Z", 1, ("o/excluded",), 2)
        expected = [
            "## Summary\n\n⚠️ Some sources could not be checked",
            "- Last completed sync: 2026-11-23T12:00:00Z", "- Repositories: 1",
            "- Open findings observed: 0.", "- Unverified existing open findings: 2.",
            "- No open findings observed in successfully read sources.",
            "## Sources\n\n- ✅ ok: 1\n- ⚠️ degraded: 1\n- ❌ unavailable: 1\n- ➖ unsupported: 1",
            "## Needs attention\n\n- ❌ `o/private:secret-scanning-alerts` — http_403 — last success: unknown",
            f"- ⚠️ `o/private:workflow:2` — workflow_disabled — last success: {previous}",
            "## Unsupported\n\n- ➖ `o/private:code-scanning-alerts`",
            "## Excluded repositories\n\n- `o/excluded`", "## Notes\n\n- 403/404 means unavailable",
        ]
        for text in expected:
            self.assertIn(text, health.body)
        self.assertNotIn("|", health.body)
        self.assertEqual(source_history(health.draft_body())["o/private:workflow:2"], previous)
        self.assertEqual(managed_key(SourceStateTests.item(ACTIVE, health.draft_body())), HEALTH_KEY)

    def test_healthy_card_omits_optional_sections_and_empty_statement_when_findings_open(self):
        finding = Finding("dependabot:o/private:1", "o/private", "Dependabot", "title", "body")
        health = health_finding({"repos": SourceState("repos")}, [finding], {}, "now", 1, (), 0)
        self.assertTrue(health.body.startswith("## Summary\n\n✅ All supported sources checked\n"))
        self.assertIn("## Needs attention\n\nNone.", health.body)
        self.assertIn("- Open findings observed: 1.", health.body)
        for text in ("## Unsupported", "## Excluded repositories", "No open findings observed"):
            self.assertNotIn(text, health.body)

    def test_owner_marked_unsupported_source_is_separate_from_attention(self):
        state = SourceState("o/private:code-scanning-alerts", "unsupported", "owner_marked")
        health = health_finding({state.source_id: state}, [], {}, "now", 1, (), 0)
        self.assertIn("✅ All supported sources checked", health.body)
        self.assertIn("## Needs attention\n\nNone.", health.body)
        self.assertIn("## Unsupported\n\n- ➖ `o/private:code-scanning-alerts`", health.body)


class ProjectStatusTests(unittest.TestCase):
    @staticmethod
    def latest(status=ON_TRACK, body=STATUS_MARKER):
        return {"status": status, "body": body, "createdAt": "2026-11-23T12:00:00Z"}

    def test_status_computation_and_priority(self):
        cases = [
            ("ok", "ok", 0, 0, ON_TRACK), ("ok", "unsupported", 0, 0, ON_TRACK),
            ("ok", "degraded", 0, 0, AT_RISK), ("ok", "ok", 1, 0, AT_RISK),
            ("ok", "ok", 0, 1, AT_RISK), ("ok", "unavailable", 0, 0, OFF_TRACK),
            ("degraded", "ok", 0, 0, OFF_TRACK), ("unavailable", "ok", 0, 0, OFF_TRACK),
            ("ok", "unavailable", 1, 1, OFF_TRACK),
        ]
        for discovery, state, observed, unverified, expected in cases:
            with self.subTest(case=(discovery, state, observed, unverified)):
                states = {"repos": SourceState("repos", discovery), "source": SourceState("source", state)}
                self.assertEqual(overall_status(states, observed, unverified), expected)

    def test_post_on_status_change_manual_latest_or_no_updates(self):
        cases = [([self.latest(ON_TRACK)], AT_RISK), ([self.latest(AT_RISK)], OFF_TRACK),
                 ([self.latest(OFF_TRACK)], ON_TRACK), ([self.latest(body="Owner update")], ON_TRACK),
                 ([self.latest(body=None)], ON_TRACK), ([], ON_TRACK)]
        for updates, status in cases:
            with self.subTest(updates=updates, status=status):
                project = project_with_items()
                project.api.gql.return_value = {"node": {"statusUpdates": {"nodes": updates}}}
                self.assertTrue(project.update_status(status, {"repos": SourceState("repos")}, 2, 3))
                self.assertEqual(project.api.gql.call_count, 2)
                read, write = project.api.gql.call_args_list
                self.assertEqual(read.args[0], STATUS_UPDATES_QUERY)
                self.assertIn("first:1, orderBy:{field:CREATED_AT, direction:DESC}", read.args[0])
                self.assertEqual(read.kwargs, {"id": "project"})
                self.assertIn("createProjectV2StatusUpdate", write.args[0])
                payload = write.kwargs["input"]
                self.assertEqual(payload["projectId"], "project")
                self.assertEqual(payload["status"], status)
                self.assertIn("Open findings observed: 2; unverified: 3", payload["body"])
                self.assertIn("Security monitoring — health", payload["body"])
                lines = payload["body"].splitlines()
                self.assertEqual(lines[-1], STATUS_MARKER)
                self.assertGreaterEqual(len(lines[:-1]), 2)
                self.assertLessEqual(len(lines[:-1]), 4)

    def test_skip_unchanged_monitor_status_even_when_counts_change(self):
        for status in (ON_TRACK, AT_RISK, OFF_TRACK):
            with self.subTest(status=status):
                project = project_with_items()
                project.api.gql.return_value = {"node": {"statusUpdates": {"nodes": [self.latest(status)]}}}
                self.assertTrue(project.update_status(status, {}, 7, 8))
                project.api.gql.assert_called_once_with(STATUS_UPDATES_QUERY, id="project")

    def test_preview_never_reads_or_posts_status(self):
        project = project_with_items(apply=False)
        self.assertTrue(project.update_status(ON_TRACK, {}, 0, 0))
        project.api.gql.assert_not_called()

    def test_read_failure_skips_posting_without_raising(self):
        for response in (APIError("503"), {}, {"node": None},
                         {"node": {"statusUpdates": {"nodes": None}}},
                         {"node": {"statusUpdates": {"nodes": [{}]}}}):
            with self.subTest(response=response):
                project = project_with_items()
                if isinstance(response, Exception):
                    project.api.gql.side_effect = response
                else:
                    project.api.gql.return_value = response
                self.assertFalse(project.update_status(ON_TRACK, {}, 0, 0))
                project.api.gql.assert_called_once_with(STATUS_UPDATES_QUERY, id="project")

    def test_failed_status_mutation_is_not_swallowed_or_repeated(self):
        project = project_with_items()
        project.api.gql.side_effect = [{"node": {"statusUpdates": {"nodes": []}}}, APIError("503")]
        with self.assertRaises(APIError):
            project.update_status(ON_TRACK, {}, 0, 0)
        self.assertEqual(project.api.gql.call_count, 2)


class ArchiveTests(unittest.TestCase):
    NOW = datetime(2026, 11, 23, 12, tzinfo=timezone.utc)

    def test_only_strictly_older_than_thirty_days(self):
        boundary = self.NOW - timedelta(days=30)
        timestamps = [(boundary - timedelta(seconds=1)).isoformat(), boundary.isoformat(),
                      (boundary + timedelta(seconds=1)).isoformat(), self.NOW.isoformat(),
                      "2026-10-24T14:00:00+02:00", "invalid", "2026-10-01T12:00:00", None]
        items = [completed_item(f"dependabot:o/private:{i}", updated_at=ts) for i, ts in enumerate(timestamps)]
        missing = completed_item("dependabot:o/private:missing")
        del missing["updatedAt"]
        project = project_with_items(items + [missing])
        self.assertEqual(project.archive_completed(self.NOW), 1)
        project.api.gql.assert_called_once()
        self.assertEqual(project.api.gql.call_args.kwargs["input"],
                         {"projectId": "project", "itemId": items[0]["id"]})

    def test_all_managed_finding_kinds_and_terminal_states_are_eligible(self):
        items = [completed_item(f"{kind}:o/private:{i}", state=state)
                 for kind in ("pr", "dependabot", "code-scanning", "secret-scanning", "workflow")
                 for i, state in enumerate((DONE, CLOSED, MERGED))]
        project = project_with_items(items)
        self.assertEqual(project.archive_completed(self.NOW), 15)
        self.assertEqual(project.api.gql.call_count, 15)
        self.assertTrue(all("archiveProjectV2Item" in call.args[0] for call in project.api.gql.call_args_list))

    def test_nonterminal_health_manual_and_already_archived_items_are_skipped(self):
        items = [completed_item(state=OPEN), completed_item(state=ACTIVE),
                 completed_item(status="W trakcie"), completed_item(status="Do zrobienia"),
                 completed_item(HEALTH_KEY), completed_item(None), completed_item("review:o/private:1"),
                 completed_item("release:o/private:1"), completed_item(archived=True)]
        project = project_with_items(items)
        self.assertEqual(project.archive_completed(self.NOW), 0)
        project.api.gql.assert_not_called()

    def test_cap_fifty_and_preview_counts_without_mutations(self):
        for apply in (False, True):
            with self.subTest(apply=apply):
                items = [completed_item(f"dependabot:o/private:{i}") for i in range(60)]
                project = project_with_items(items, apply=apply)
                self.assertEqual(project.archive_completed(self.NOW), 50)
                self.assertEqual(project.api.gql.call_count, 50 if apply else 0)
                self.assertEqual(sum(i["isArchived"] for i in items), 50 if apply else 0)

    def test_changed_or_reopened_cards_are_not_archived_from_stale_snapshot(self):
        for apply in (False, True):
            for state in (OPEN, DONE):
                with self.subTest(apply=apply, state=state):
                    item = completed_item()
                    project = project_with_items([item], apply=apply)
                    finding = Finding(item["id"], "o/private", "Dependabot alert", "changed", "body", state=state)
                    self.assertEqual(project.upsert(finding), "updated")
                    project.api.gql.reset_mock()
                    self.assertEqual(project.archive_completed(self.NOW), 0)
                    project.api.gql.assert_not_called()

    def test_unchanged_old_terminal_card_can_still_be_archived(self):
        item = completed_item()
        project = project_with_items([item])
        finding = Finding(item["id"], "o/private", "Dependabot alert", "title", "body", state=DONE)
        self.assertEqual(project.upsert(finding), "updated")
        project.api.gql.assert_not_called()
        self.assertEqual(project.archive_completed(self.NOW), 1)

    def test_archived_rows_do_not_override_visible_items_or_block_reopened_native_cards(self):
        visible = completed_item()
        archived = completed_item(archived=True)
        archived["content"]["id"] = "archived-draft"
        native = completed_item("pr:o/private:2", archived=True)
        native["content"]["id"] = "archived-pr"
        project = project_with_items([visible, archived, native])
        self.assertIs(project.managed[visible["id"]], visible)
        self.assertNotIn(native["id"], project.managed)
        self.assertNotIn("archived-draft", project.content_ids)
        self.assertNotIn("archived-pr", project.content_ids)

    def test_archived_or_absent_resolved_finding_is_not_recreated_on_next_run(self):
        for items in ([], [completed_item(archived=True)]):
            for apply in (False, True):
                with self.subTest(items=bool(items), apply=apply):
                    project = project_with_items(items, apply=apply)
                    finding = Finding("dependabot:o/private:1", "o/private", "Dependabot alert", "title", "body", state=DONE)
                    self.assertEqual(project.upsert(finding), "ignored")
                    project.api.gql.assert_not_called()

    def test_reopened_alert_after_archival_can_create_new_card(self):
        project = project_with_items([completed_item(archived=True)])
        finding = Finding("dependabot:o/private:1", "o/private", "Dependabot alert", "title", "body")
        project.api.gql.side_effect = [
            {"addProjectV2DraftIssue": {"projectItem": {"id": "new-item"}}}, *([{}] * 6)]
        self.assertEqual(project.upsert(finding), "created")
        self.assertIn("addProjectV2DraftIssue", project.api.gql.call_args_list[0].args[0])
        self.assertEqual(project.managed[finding.key]["id"], "new-item")

    def test_archive_mutation_failure_is_not_repeated(self):
        project = project_with_items([completed_item()])
        project.api.gql.side_effect = APIError("503")
        with self.assertRaises(APIError):
            project.archive_completed(self.NOW)
        project.api.gql.assert_called_once()


class PresentationSyncTests(unittest.TestCase):
    def test_status_read_failure_continues_to_archives_and_counts_only_log(self):
        project = project_with_items([completed_item()])
        project.api.pages.return_value = []
        project.api.gql.side_effect = [APIError("503"), {}]
        project.upsert = Mock(return_value="updated")
        with patch("security_project_sync.Project", return_value=project), \
                patch("security_project_sync.datetime", wraps=datetime) as clock, \
                patch("builtins.print") as public_log:
            clock.now.return_value = ArchiveTests.NOW
            synchronize(project.api, "o", 1, True)
        log = json.loads(public_log.call_args.args[0])
        self.assertIs(log["status_update_read_failed"], True)
        self.assertEqual(log["archived"], 1)
        self.assertEqual(project.api.gql.call_count, 2)
        self.assertIn("archiveProjectV2Item", project.api.gql.call_args.args[0])
        for private in ("o/private", "http_503", "Security monitoring", STATUS_MARKER):
            self.assertNotIn(private, public_log.call_args.args[0])

    def test_preview_counts_archives_and_skips_status_entirely(self):
        project = project_with_items([completed_item()], apply=False)
        project.api.pages.return_value = []
        project.upsert = Mock(return_value="updated")
        project.update_status = Mock()
        with patch("security_project_sync.Project", return_value=project), \
                patch("security_project_sync.datetime", wraps=datetime) as clock, \
                patch("builtins.print") as public_log:
            clock.now.return_value = ArchiveTests.NOW
            synchronize(project.api, "o", 1)
        log = json.loads(public_log.call_args.args[0])
        self.assertEqual(log["mode"], "preview")
        self.assertEqual(log["archived"], 1)
        self.assertIs(log["status_update_read_failed"], False)
        project.update_status.assert_not_called()
        project.api.gql.assert_not_called()

    def test_status_and_archive_follow_successful_health_write_only(self):
        for failed_health in (False, True):
            with self.subTest(failed_health=failed_health):
                api = Mock()
                api.pages.return_value = []
                project = Mock()
                project.managed = {}
                project.archive_completed.return_value = 0
                project.update_status.return_value = True
                if failed_health:
                    project.upsert.side_effect = APIError("503")
                with patch("security_project_sync.Project", return_value=project), patch("builtins.print"):
                    if failed_health:
                        with self.assertRaises(APIError):
                            synchronize(api, "o", 1, True)
                        project.update_status.assert_not_called()
                        project.archive_completed.assert_not_called()
                    else:
                        synchronize(api, "o", 1, True)
                        self.assertEqual([call[0] for call in project.method_calls],
                                         ["setup", "upsert", "update_status", "archive_completed"])
                        self.assertEqual(project.upsert.call_args.args[0].key, HEALTH_KEY)
                        self.assertEqual(project.update_status.call_args.args[0], ON_TRACK)


class RetryTests(unittest.TestCase):
    @staticmethod
    def response(status=200, body="[]", headers=""):
        return subprocess.CompletedProcess([], 0 if status < 400 else 1,
                                           f"HTTP/2.0 {status} Status\r\n{headers}\r\n{body}",
                                           "" if status < 400 else f"gh: PRIVATE (HTTP {status})")

    def test_transient_rest_reads_stop_after_three_attempts(self):
        for failure in (self.response(500), self.response(503), self.response(429),
                        subprocess.TimeoutExpired(["gh"], 30)):
            with self.subTest(failure=type(failure).__name__), \
                    patch("security_project_sync.subprocess.run", side_effect=[failure] * 3) as run, \
                    patch("security_project_sync.time.sleep") as sleep, \
                    patch("security_project_sync.random.uniform", return_value=0):
                with self.assertRaises(APIError) as error:
                    GitHub().call("repos/o/private/pulls")
                self.assertEqual(run.call_count, 3)
                self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.5, 1.0])
                self.assertNotIn("PRIVATE", str(error.exception))

    def test_rest_read_recovers_and_retry_after_is_honoured(self):
        with patch("security_project_sync.subprocess.run", side_effect=[
                self.response(429, headers="Retry-After: 2\r\n"), self.response()]) as run, \
                patch("security_project_sync.time.sleep") as sleep:
            self.assertEqual(GitHub().call("repos/o/private/pulls"), [])
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_retry_after_beyond_budget_stops_without_sleeping(self):
        with patch("security_project_sync.subprocess.run", return_value=self.response(
                429, headers="Retry-After: 120\r\n")) as run, \
                patch("security_project_sync.time.sleep") as sleep:
            with self.assertRaises(APIError):
                GitHub().call("repos/o/private/pulls")
        run.assert_called_once()
        sleep.assert_not_called()

    def test_retry_after_supports_http_date(self):
        self.assertEqual(GitHub.retry_after("Retry-After: Thu, 01 Jan 1970 00:00:00 GMT"), 0)
        self.assertIsNone(GitHub.retry_after("Retry-After: invalid"))

    def test_permission_errors_and_malformed_payloads_are_never_retried(self):
        for response in (self.response(401), self.response(403), self.response(404),
                         self.response(403, body='{"message":"secondary rate limit"}'),
                         self.response(body="not JSON PRIVATE"), self.response(body="null")):
            with self.subTest(status=response.returncode, body=response.stdout), \
                    patch("security_project_sync.subprocess.run", return_value=response) as run, \
                    patch("security_project_sync.time.sleep") as sleep:
                with self.assertRaises(APIError) as error:
                    GitHub().call("repos/o/private/pulls")
                run.assert_called_once()
                sleep.assert_not_called()
                self.assertNotIn("PRIVATE", str(error.exception))

    def test_graphql_queries_retry_but_mutations_never_retry(self):
        for query, attempts in (("query { viewer { login } }", 3),
                                ("mutation { updateThing { id } }", 1)):
            for failure in (self.response(503), self.response(429), subprocess.TimeoutExpired(["gh"], 30)):
                with self.subTest(query=query, failure=type(failure).__name__), \
                        patch("security_project_sync.subprocess.run", side_effect=[failure] * attempts) as run, \
                        patch("security_project_sync.time.sleep"):
                    with self.assertRaises(APIError):
                        GitHub().gql(query)
                    self.assertEqual(run.call_count, attempts)

    def test_rest_mutations_never_retry(self):
        with patch("security_project_sync.subprocess.run", return_value=self.response(503)) as run, \
                patch("security_project_sync.time.sleep") as sleep:
            with self.assertRaises(APIError):
                GitHub().call("repos/o/private/issues", {"title": "private"})
        run.assert_called_once()
        sleep.assert_not_called()

    def test_secondary_rate_limit_query_recovers(self):
        limited = self.response(body='{"errors":[{"message":"secondary rate limit"}]}')
        for returncode in (0, 1):
            with self.subTest(returncode=returncode):
                limited.returncode = returncode
                with patch("security_project_sync.subprocess.run", side_effect=[limited, self.response(
                        body='{"data":{"viewer":{"login":"o"}}}')]) as run, \
                        patch("security_project_sync.time.sleep"):
                    self.assertEqual(GitHub().gql("query { viewer { login } }")["viewer"]["login"], "o")
                self.assertEqual(run.call_count, 2)

    def test_graphql_errors_and_invalid_shape_are_not_retried(self):
        for body in ('{"errors":[{"message":"PRIVATE"}]}', '{}', '{"data":null}'):
            with self.subTest(body=body), \
                    patch("security_project_sync.subprocess.run", return_value=self.response(body=body)) as run:
                with self.assertRaises(APIError) as error:
                    GitHub().gql("query { viewer { login } }")
                run.assert_called_once()
                self.assertNotIn("PRIVATE", str(error.exception))

    def test_pagination_decodes_headers_and_concatenated_pages(self):
        first = self.response(body='[{"number":1}]').stdout
        second = self.response(body='[{"number":2}]').stdout
        with patch("security_project_sync.subprocess.run", return_value=subprocess.CompletedProcess(
                [], 0, first + "\n" + second, "")):
            self.assertEqual(GitHub().pages("repos/o/private/pulls"), [{"number": 1}, {"number": 2}])

    def test_malformed_list_payload_is_not_retried(self):
        with patch("security_project_sync.subprocess.run", return_value=self.response(body='{"wrong": []}')) as run:
            with self.assertRaises(APIError):
                GitHub().pages("repos/o/private/actions/workflows", key="workflows")
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
