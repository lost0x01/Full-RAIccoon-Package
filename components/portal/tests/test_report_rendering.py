import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from pypdf import PdfReader


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
SPEC = importlib.util.spec_from_file_location("portal_app", APP_PATH)
portal_app = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(portal_app)


class DummyRequest:
    def __init__(self, authenticated: bool = True):
        self.session = {}
        self.client = type("Client", (), {"host": "127.0.0.1"})()
        if authenticated:
            self.session.update({"user_id": 1, "username": "tester", "display_name": "tester", "role": "admin", "mfa_ok": True})


class ReportRenderingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data_dir = self.root / "data"
        self.documents_dir = self.data_dir / "documents"
        self.in_review_dir = self.documents_dir / "In Review"
        self.db_path = self.data_dir / "portal.db"
        self.archive_remote = self.root / "archive-remote.git"
        self.archive_repo = self.root / "archive-repo"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.documents_dir.mkdir(parents=True, exist_ok=True)
        self.in_review_dir.mkdir(parents=True, exist_ok=True)

        self.originals = {
            "DATA_DIR": portal_app.DATA_DIR,
            "DOCUMENTS_DIR": portal_app.DOCUMENTS_DIR,
            "IN_REVIEW_DIR": portal_app.IN_REVIEW_DIR,
            "DB_PATH": portal_app.DB_PATH,
            "REPORTS_REPO_DIR": portal_app.REPORTS_REPO_DIR,
            "ANALYST_KIT_DIR": portal_app.ANALYST_KIT_DIR,
            "RAICCOON_ANALYST_KIT_ROOT": os.environ.get("RAICCOON_ANALYST_KIT_ROOT"),
        }
        portal_app.DATA_DIR = self.data_dir
        portal_app.DOCUMENTS_DIR = self.documents_dir
        portal_app.IN_REVIEW_DIR = self.in_review_dir
        portal_app.DB_PATH = self.db_path
        portal_app.ANALYST_KIT_DIR = self.root / "analyst-kit"
        subprocess.run(["git", "init", "--bare", str(self.archive_remote)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "clone", str(self.archive_remote), str(self.archive_repo)], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(self.archive_repo), "config", "user.name", "Portal Test"], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(self.archive_repo), "config", "user.email", "portal-test.invalid"], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(self.archive_repo), "switch", "-c", "main"], check=True, capture_output=True, text=True)
        (self.archive_repo / "README.md").write_text("# Test archive repo\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.archive_repo), "add", "README.md"], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(self.archive_repo), "commit", "-m", "init"], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(self.archive_repo), "push", "-u", "origin", "main"], check=True, capture_output=True, text=True)
        portal_app.REPORTS_REPO_DIR = self.archive_repo
        portal_app.init_db()
        os.environ["RAICCOON_ANALYST_KIT_ROOT"] = str(Path.home() / "github" / "your-organization-analyst-kit")

    def tearDown(self):
        portal_app.DATA_DIR = self.originals["DATA_DIR"]
        portal_app.DOCUMENTS_DIR = self.originals["DOCUMENTS_DIR"]
        portal_app.IN_REVIEW_DIR = self.originals["IN_REVIEW_DIR"]
        portal_app.DB_PATH = self.originals["DB_PATH"]
        portal_app.REPORTS_REPO_DIR = self.originals["REPORTS_REPO_DIR"]
        portal_app.ANALYST_KIT_DIR = self.originals["ANALYST_KIT_DIR"]
        if self.originals["RAICCOON_ANALYST_KIT_ROOT"] is None:
            os.environ.pop("RAICCOON_ANALYST_KIT_ROOT", None)
        else:
            os.environ["RAICCOON_ANALYST_KIT_ROOT"] = self.originals["RAICCOON_ANALYST_KIT_ROOT"]
        self.tmp.cleanup()

    def test_purple_team_exercise_is_available_as_workflow_and_document_category(self):
        categories = portal_app.report_category_options()
        workflows = {workflow["key"]: workflow for workflow in portal_app.workflow_options()}

        self.assertIn("Purple Team Exercise", categories)
        self.assertIn("purple-team-exercise", workflows)
        self.assertEqual(workflows["purple-team-exercise"]["label"], "Purple team exercise")
        task = {
            "id": 128,
            "title": "Aviator Spider Purple Team exercise",
            "research_workflow": "purple-team-exercise",
            "document_category": "Purple Team Exercise",
            "created_at": "2026-06-24T10:00:00+00:00",
        }
        self.assertEqual(portal_app.report_family_for_task(task), "Purple Team Exercise")
        self.assertEqual(portal_app.opencti_report_type_for_task(task), "Request for Information")
        metadata = portal_app.report_cover_metadata(task)
        self.assertEqual(metadata["report_type"], "Purple Team Exercise")
        self.assertEqual(metadata["opencti_report_type"], "Request for Information")
        self.assertTrue(portal_app.final_report_filename_for_task(task).startswith("RPT-PTE-2026-001_"))

    def test_non_pte_research_keeps_report_opencti_type(self):
        task = {
            "id": 129,
            "title": "Example Threat Report",
            "research_workflow": "threat-intel",
            "document_category": "Threat Reports",
            "created_at": "2026-06-24T10:00:00+00:00",
        }

        self.assertEqual(portal_app.opencti_report_type_for_task(task), "Threat Intelligence Report")
        self.assertEqual(portal_app.report_cover_metadata(task)["opencti_report_type"], "Threat Intelligence Report")

    def test_stage_final_report_for_opencti_writes_published_uploader_bundle(self):
        task_id = portal_app.create_portal_task(
            title="Aviator Spider Purple Team exercise",
            description="Validate that PTE artifacts become OpenCTI RFIs.",
            task_type="research",
            priority="normal",
            requested_by="tester",
            assignee="research",
            worker_profile="default",
            due_date="",
            document_category="Purple Team Exercise",
            research_workflow="purple-team-exercise",
        )
        task = portal_app.fetch_portal_task(task_id)
        assert task is not None
        final_pdf = self.documents_dir / "Purple Team Exercise" / "RPT-PTE-2026-001_aviator-spider-purple-team-exercise.pdf"
        final_pdf.parent.mkdir(parents=True, exist_ok=True)
        final_pdf.write_bytes(b"pdf-body")

        report_dir = portal_app.stage_final_report_for_opencti(task, final_pdf)

        self.assertEqual(report_dir, portal_app.ANALYST_KIT_DIR / "reports" / "purple-team-exercise" / final_pdf.stem)
        self.assertTrue((report_dir / "report.md").exists())
        self.assertTrue((report_dir / "sources.md").exists())
        self.assertTrue((report_dir / "final" / final_pdf.name).exists())
        metadata = json.loads((report_dir / "metadata.yaml").read_text(encoding="utf-8"))
        self.assertEqual(metadata["report_id"], "RPT-PTE-2026-001")
        self.assertEqual(metadata["report_type"], "Purple Team Exercise")
        self.assertEqual(metadata["opencti_report_type"], "Request for Information")
        self.assertEqual(metadata["status"], "published")
        self.assertTrue(metadata["client_visible"])

    def test_purple_team_exercise_render_source_lets_renderer_own_numbering(self):
        task = {
            "id": 128,
            "title": "Aviator Spider Purple Team exercise",
            "research_workflow": "purple-team-exercise",
            "document_category": "Purple Team Exercise",
        }
        report_text = """## 1. Executive Summary
Body.

- 5. Threat Context
Threat context body.

### 6.1 Detection coverage matrix
Detection body.

```powershell
# Keep 1. comments inside code blocks untouched.
Write-Output "1. not a heading"
```
"""

        rendered = portal_app.renderable_report_markdown(task, report_text)

        self.assertIn("## Executive Summary", rendered)
        self.assertIn("## Threat Context", rendered)
        self.assertIn("### Detection coverage matrix", rendered)
        self.assertNotIn("## 1. Executive Summary", rendered)
        self.assertNotIn("- 5. Threat Context", rendered)
        self.assertNotIn("### 6.1 Detection coverage matrix", rendered)
        self.assertIn("# Keep 1. comments inside code blocks untouched.", rendered)
        self.assertIn('Write-Output "1. not a heading"', rendered)

    def test_renderable_report_markdown_converts_plain_numbered_sections_to_headings(self):
        task = {"id": 7, "title": "Example", "research_workflow": "threat-intel", "document_category": "Threat Reports"}
        report_text = "1. Executive Summary\nBody text\n\n2. Detection Engineering\nMore text"

        rendered = portal_app.renderable_report_markdown(task, report_text)

        self.assertIn("## 1. Executive Summary", rendered)
        self.assertIn("## 2. Detection Engineering", rendered)

    def test_renderable_report_markdown_demotes_numbered_pseudo_headings_inside_sections(self):
        task = {"id": 8, "title": "Example", "research_workflow": "threat-intel", "document_category": "Vulnerabilities"}
        report_text = """## 1. Executive Summary

## 1. This should be a bullet, not a top-level section heading.
## 2. This should also be a bullet.

## 2. Intelligence Requirement
"""

        rendered = portal_app.renderable_report_markdown(task, report_text)

        self.assertIn("## 1. Executive Summary", rendered)
        self.assertIn("## 2. Intelligence Requirement", rendered)
        self.assertIn("- 1. This should be a bullet, not a top-level section heading.", rendered)
        self.assertIn("- 2. This should also be a bullet.", rendered)
        self.assertNotIn("## 1. This should be a bullet, not a top-level section heading.", rendered)

    def test_select_report_render_source_falls_back_to_existing_bundle_when_latest_result_is_thin(self):
        task = {
            "id": 43,
            "title": "CVE-2026-77777 Bundle Fallback",
            "research_workflow": "threat-intel",
            "document_category": "Vulnerabilities",
            "kanban_task_id": "t-test",
            "last_result": "review-required: this needs human eyes before publish",
        }
        bundle_report = """## 1. Executive Summary

This is a full source-backed report body that should win over a thin handoff summary.

## 2. Vulnerability Metadata

| Field | Value |
| --- | --- |
| Vulnerability | CVE-2026-77777 |
| Severity | Critical |

## 3. Detection Engineering

```kusto
DeviceProcessEvents
| take 5
```
"""
        bundle_path = portal_app.report_bundle_markdown_path(task)
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_text(bundle_report, encoding="utf-8")

        source_name, source_text = portal_app.select_report_render_source(task, {"status": "blocked", "latest_summary": "review-required: short handoff", "result": ""})

        self.assertEqual(source_name, "existing_bundle_report_md")
        self.assertIn("full source-backed report body", source_text)

    def test_select_report_render_source_falls_back_to_canonical_analyst_kit_report_when_latest_result_is_thin(self):
        report_dir = Path(os.environ["RAICCOON_ANALYST_KIT_ROOT"]) / "reports" / "vulnerabilities" / "RPT-VTI-TEST-canonical-fallback"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.md"
        report_path.write_text(
            """## 1. Executive Summary

Canonical analyst-kit report body.

## 2. Vulnerability Metadata

| Field | Value |
| --- | --- |
| Vulnerability | CVE-2026-12121 |
| Severity | High |

## 3. Detection Engineering

```kusto
DeviceProcessEvents
| take 5
```
""",
            encoding="utf-8",
        )
        self.addCleanup(lambda: report_dir.rmdir())
        self.addCleanup(lambda: report_path.unlink(missing_ok=True))

        task = {
            "id": 44,
            "title": "Canonical Path Fallback",
            "description": "Auto-generated intake item.\n- Report path: `reports/vulnerabilities/RPT-VTI-TEST-canonical-fallback`",
            "research_workflow": "threat-intel",
            "document_category": "Vulnerabilities",
            "kanban_task_id": "t-test",
            "last_result": "review-required: short handoff only",
        }

        source_name, source_text = portal_app.select_report_render_source(task, {"status": "done", "latest_summary": "review-required: short handoff", "result": ""})

        self.assertEqual(source_name, "canonical_analyst_kit_report_md")
        self.assertIn("Canonical analyst-kit report body.", source_text)

    def test_maybe_generate_review_document_refetches_full_task_before_selecting_render_source(self):
        task_id = portal_app.create_portal_task(
            title="Canonical Refetch",
            description="Auto-generated intake item.\n- Report path: `reports/vulnerabilities/RPT-VTI-TEST-canonical-fallback-refetch`",
            priority=10,
            requested_by="tester",
            assignee="tester",
            worker_profile="default",
            task_type="research",
            source_page="threat-intel-intake",
            research_workflow="threat-intel",
            document_category="Vulnerabilities",
        )
        portal_app.execute(
            "UPDATE portal_tasks SET kanban_task_id = ?, kanban_status = ?, status = ?, updated_at = ? WHERE id = ?",
            ["t-refetch", "done", "in_progress", portal_app.now_utc().isoformat(), task_id],
        )
        full_task = portal_app.fetch_portal_task(task_id)
        partial_task = {key: full_task[key] for key in ("id", "title", "task_type", "source_page", "research_workflow", "document_category", "kanban_task_id")}

        report_dir = Path(os.environ["RAICCOON_ANALYST_KIT_ROOT"]) / "reports" / "vulnerabilities" / "RPT-VTI-TEST-canonical-fallback-refetch"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.md"
        report_path.write_text(
            """## 1. Executive Summary

Refetched canonical analyst-kit report body.

## 2. Vulnerability Metadata

| Field | Value |
| --- | --- |
| Vulnerability | CVE-2026-34343 |
| Severity | High |

## 3. Detection Engineering

```kusto
DeviceProcessEvents
| take 5
```
""",
            encoding="utf-8",
        )
        self.addCleanup(lambda: report_dir.rmdir())
        self.addCleanup(lambda: report_path.unlink(missing_ok=True))

        original_renderer = portal_app.render_review_pdf_for_task
        try:
            def fake_renderer(task, report_text):
                output = portal_app.review_document_path_for_task(task)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(report_text, encoding="utf-8")
                return output

            portal_app.render_review_pdf_for_task = fake_renderer
            review_path = portal_app.maybe_generate_review_document(partial_task, {"status": "done", "latest_summary": "review-required: short handoff", "result": ""})
        finally:
            portal_app.render_review_pdf_for_task = original_renderer

        self.assertIsNotNone(review_path)
        self.assertTrue(review_path.exists())
        self.assertIn("Refetched canonical analyst-kit report body.", review_path.read_text(encoding="utf-8"))
        updated = portal_app.fetch_portal_task(task_id)
        self.assertEqual(updated["review_document_path"], str(review_path))

    def test_sync_report_to_archive_repo_copies_pdf_into_category_repo_and_pushes(self):
        final_pdf = self.documents_dir / "Vulnerabilities" / "Example_Report.pdf"
        final_pdf.parent.mkdir(parents=True, exist_ok=True)
        final_pdf.write_text("pdf-bytes-placeholder", encoding="utf-8")

        task = {
            "id": 99,
            "title": "Example Report",
            "document_category": "Vulnerabilities",
            "research_workflow": "threat-intel",
        }

        archive_path = portal_app.sync_report_to_archive_repo(task, final_pdf)

        self.assertEqual(archive_path, self.archive_repo / "Vulnerabilities" / "Example_Report.pdf")
        self.assertTrue(archive_path.exists())
        self.assertEqual(archive_path.read_text(encoding="utf-8"), "pdf-bytes-placeholder")

        status = subprocess.run(
            ["git", "-C", str(self.archive_repo), "status", "--short"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(status.stdout.strip(), "")

        log = subprocess.run(
            ["git", "-C", str(self.archive_repo), "log", "-1", "--pretty=%s"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(log.stdout.strip(), "Add accepted report: Example Report")

        tree = subprocess.run(
            ["git", "-C", str(self.archive_repo), "ls-tree", "-r", "origin/main", "--name-only", "Vulnerabilities/Example_Report.pdf"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(tree.stdout.strip(), "Vulnerabilities/Example_Report.pdf")

    def test_final_document_path_for_task_rewrites_draft_intake_title_to_raiccoon_filename(self):
        category_dir = self.documents_dir / "Vulnerabilities"
        category_dir.mkdir(parents=True, exist_ok=True)
        (category_dir / "RPT-VTI-2026-028_existing-report.pdf").write_text("existing", encoding="utf-8")

        task = {
            "id": 101,
            "title": "Review intake draft: CVE-2026-20245 Cisco Catalyst SD-WAN Manager Improper Encoding or Escaping of Output Vulnerability",
            "document_category": "Vulnerabilities",
            "research_workflow": "threat-intel",
            "created_at": "2026-06-10T12:00:00+00:00",
            "final_document_path": "",
        }

        final_path = portal_app.final_document_path_for_task(task)

        self.assertEqual(
            final_path,
            category_dir / "RPT-VTI-2026-029_cve-2026-20245-cisco-catalyst-sd-wan-manager-improper-encoding-or-escaping-of-output-vulnerability.pdf",
        )

    def test_malware_report_filename_uses_malware_family_not_intake_title(self):
        category_dir = self.documents_dir / "Malware Analysis"
        category_dir.mkdir(parents=True, exist_ok=True)

        task = {
            "id": 102,
            "title": "Analyze and reverse engineer uploaded sample 42ed646e",
            "document_category": "Malware Analysis",
            "research_workflow": "malware-analysis",
            "created_at": "2026-06-10T12:00:00+00:00",
            "final_document_path": "",
            "last_result": "| Field | Value |\n| --- | --- |\n| Malware family / cluster | BianLian-associated Go backdoor |\n",
        }

        final_path = portal_app.final_document_path_for_task(task)

        self.assertEqual(final_path, category_dir / "RPT-MA-2026-001_bianlian-associated-go-backdoor-malware-analysis.pdf")
        self.assertEqual(portal_app.report_display_title_for_task(task), "BianLian-associated Go backdoor Malware Analysis")

    def test_malware_report_bundle_metadata_title_uses_family_from_report_body(self):
        task = {
            "id": 103,
            "title": "Sandbox queue test sample",
            "document_category": "Malware Analysis",
            "research_workflow": "malware-analysis",
        }
        report_text = """## 1. Executive Summary

Example malware-analysis body.

## 2. Sample Metadata

| Field | Value |
| --- | --- |
| Malware family | Lumma Stealer |
"""

        metadata = portal_app.report_cover_metadata(task, report_text)

        self.assertEqual(metadata["title"], "Lumma Stealer Malware Analysis")
        self.assertEqual(metadata["short_title"], "Lumma Stealer Malware Analysis")

    def test_promote_review_document_uses_clean_raiccoon_filename_and_updates_published_title(self):
        portal_app.bootstrap_admin_user()
        review_path = self.in_review_dir / "Review_intake_draft__Example.pdf"
        review_path.parent.mkdir(parents=True, exist_ok=True)
        review_path.write_text("pdf-bytes-placeholder", encoding="utf-8")

        task_id = portal_app.create_portal_task(
            title="Review intake draft: Example Portal Report",
            description="desc",
            priority=10,
            requested_by="tester",
            assignee="tester",
            worker_profile="default",
            task_type="research",
            source_page="research",
            research_workflow="threat-intel",
            document_category="Vulnerabilities",
        )
        portal_app.execute(
            "UPDATE portal_tasks SET status = 'in_review', review_document_path = ?, updated_at = ? WHERE id = ?",
            [str(review_path), portal_app.now_utc().isoformat(), task_id],
        )

        task = portal_app.fetch_portal_task(task_id)
        final_path, published_work_id = portal_app.promote_review_document(task)

        self.assertTrue(final_path.exists())
        self.assertEqual(final_path.name, "RPT-VTI-2026-001_example-portal-report.pdf")
        self.assertFalse(review_path.exists())

        updated_task = portal_app.fetch_portal_task(task_id)
        self.assertEqual(updated_task["final_document_path"], str(final_path))
        self.assertEqual(updated_task["status"], "in_review")

        published = portal_app.fetch_one("SELECT title, url FROM published_works WHERE id = ?", [published_work_id])
        self.assertEqual(published["title"], "Example Portal Report")
        self.assertEqual(published["url"], str(final_path))

        archived = self.archive_repo / "Vulnerabilities" / final_path.name
        self.assertTrue(archived.exists())
        self.assertEqual(archived.read_text(encoding="utf-8"), "pdf-bytes-placeholder")

    def test_report_document_categories_syncs_missing_final_pdfs_from_archive_repo(self):
        category_dir = self.archive_repo / "Threat Reports"
        category_dir.mkdir(parents=True, exist_ok=True)
        final_pdf = category_dir / "RPT-TR-2026-999_synced-from-archive.pdf"
        draft_pdf = category_dir / "RPT-TR-2026-999_synced-from-archive_draft.pdf"
        review_pdf = self.archive_repo / "In Review" / "RPT-TR-2026-999_review-copy.pdf"
        final_pdf.write_text("final-pdf-placeholder", encoding="utf-8")
        draft_pdf.write_text("draft-pdf-placeholder", encoding="utf-8")
        review_pdf.parent.mkdir(parents=True, exist_ok=True)
        review_pdf.write_text("review-pdf-placeholder", encoding="utf-8")

        categories = portal_app.report_document_categories()

        synced_path = self.documents_dir / "Threat Reports" / final_pdf.name
        self.assertTrue(synced_path.exists())
        self.assertFalse((self.documents_dir / "Threat Reports" / draft_pdf.name).exists())
        self.assertFalse((self.documents_dir / "In Review" / review_pdf.name).exists())
        threat_reports = next(category for category in categories if category["name"] == "Threat Reports")
        self.assertIn(final_pdf.name, [document["name"] for document in threat_reports["documents"]])

    def test_documents_page_renders_fixed_width_documents_table(self):
        category_dir = self.documents_dir / "Threat Reports"
        category_dir.mkdir(parents=True, exist_ok=True)
        (category_dir / "RPT-TR-2026-001_example.pdf").write_text("pdf-bytes-placeholder", encoding="utf-8")

        portal_app.bootstrap_admin_user()
        response = portal_app.documents_page(DummyRequest())
        html = response.body.decode("utf-8")

        self.assertIn('table class="documents-table"', html)
        self.assertIn('<col class="documents-col-kind">', html)
        self.assertIn('class="docs-size-head">Size</th>', html)
        self.assertIn('class="secondary pill-link docs-open-link"', html)
        self.assertIn('/static/style.css?v=branding-20260623-table-heads-1', html)

    def test_render_review_pdf_for_task_uses_gold_standard_renderer_and_preserves_rich_content(self):
        analyst_kit_root = Path(os.environ["RAICCOON_ANALYST_KIT_ROOT"])
        if not (analyst_kit_root / "scripts" / "render_report.py").exists():
            self.skipTest("Analyst kit renderer is not available in this environment")

        task = {
            "id": 42,
            "title": "CVE-2026-99999 Example Gold Standard",
            "research_workflow": "threat-intel",
            "document_category": "Vulnerabilities",
        }
        report_text = """## 1. Executive Summary

This report summarizes a test vulnerability scenario and the defensive actions needed to respond.

## 2. Vulnerability Metadata

| Field | Value |
| --- | --- |
| Vulnerability | CVE-2026-99999 |
| Severity | Critical |
| Exploitation Status | Proof-of-concept available |

## 3. Detection Engineering

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ \"cmd.exe\"
| take 5
```

## 4. Threat Hunting

```sigma
title: Example hunt
logsource:
  product: windows
detection:
  selection:
    Image|endswith: '\\\\cmd.exe'
  condition: selection
```

## 5. Recommendations

- Patch affected systems.
- Hunt for suspicious child-process execution.
"""

        output_path = portal_app.render_review_pdf_for_task(task, report_text)

        self.assertTrue(output_path.exists())
        reader = PdfReader(str(output_path))
        extracted = "\n".join((page.extract_text() or "") for page in reader.pages)
        self.assertIn("Table of Contents", extracted)
        self.assertIn("AI Generation", extracted)
        self.assertIn("1. Executive Summary", extracted)
        self.assertIn("DeviceProcessEvents", extracted)

        bundle_dir = portal_app.report_bundle_dir_for_task(task)
        self.assertTrue((bundle_dir / "metadata.yaml").exists())
        self.assertTrue((bundle_dir / "report.md").exists())
        self.assertTrue((bundle_dir / "final" / f"{bundle_dir.name}.docx").exists())
        self.assertTrue((bundle_dir / "final" / f"{bundle_dir.name}.pdf").exists())
        self.assertTrue((bundle_dir / "evidence" / "extracted-text" / "rendered_pdf.txt").exists())


if __name__ == "__main__":
    unittest.main()
