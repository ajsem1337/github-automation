import json
import subprocess
import unittest
from unittest.mock import Mock, patch

from security_project_sync import (
    ACTIVE, APIError, DONE, Finding, GitHub, OPEN, Project, alert_finding,
    desired_status, managed_key, refresh_missing, workflow_finding,
    synchronize,
)


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
        result = subprocess.CompletedProcess([], 0, '[[{"number":1}],[{"number":2}]]', '')
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
        project.managed = {"secret-scanning:o/private:8": item}
        with patch("security_project_sync.Project", return_value=project), \
             patch("security_project_sync.collect_repo", return_value=([], [("o/private", "Sekrety", "403")])), \
             patch("security_project_sync.refresh_missing", side_effect=APIError("403")), \
             patch("builtins.print") as public_log:
            synchronize(api, "o", 1, True)
        self.assertEqual(project.upsert.call_count, 1)
        health = project.upsert.call_args.args[0]
        self.assertEqual(health.key, "monitor:health")
        self.assertEqual(health.state, ACTIVE)
        self.assertIn("Brak otwartych zgłoszeń w źródłach, które udało się odczytać.", health.body)
        self.assertIn("403", health.body)
        self.assertIn("To NIE oznacza braku podatności", health.body)
        self.assertIn("osobne pozycje Do zrobienia", health.body)
        self.assertIn("o/private", health.body)
        self.assertNotIn("o/private", public_log.call_args.args[0])

    def test_draft_marker_survives_interrupted_field_updates(self):
        finding = Finding("dependabot:o/r:1", "o/r", "Dependabot", "title", "body")
        item = {"content": {"body": finding.draft_body()}, "fieldValues": {"nodes": []}}
        self.assertEqual(managed_key(item), finding.key)
        self.assertIsNone(managed_key({"content": {"body": "manual task"}, "fieldValues": {"nodes": []}}))

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


if __name__ == "__main__":
    unittest.main()


