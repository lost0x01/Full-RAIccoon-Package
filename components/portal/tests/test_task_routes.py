import asyncio
import importlib.util
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
SPEC = importlib.util.spec_from_file_location("portal_app", APP_PATH)
portal_app = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(portal_app)


class DummyRequest:
    def __init__(self, authenticated: bool = True, username: str = "tester"):
        self.session = {}
        self.client = type("Client", (), {"host": "127.0.0.1"})()
        if authenticated:
            self.session.update(
                {
                    "user_id": 1,
                    "username": username,
                    "display_name": username,
                    "role": "admin",
                    "mfa_ok": True,
                }
            )


class TaskRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.data_dir = self.root / "data"
        self.upload_dir = self.data_dir / "uploads"
        self.documents_dir = self.data_dir / "documents"
        self.in_review_dir = self.documents_dir / "In Review"
        self.kanban_db = self.root / "kanban.db"
        self.db_path = self.data_dir / "portal.db"

        self.originals = {
            "DATA_DIR": portal_app.DATA_DIR,
            "UPLOAD_DIR": portal_app.UPLOAD_DIR,
            "DOCUMENTS_DIR": portal_app.DOCUMENTS_DIR,
            "IN_REVIEW_DIR": portal_app.IN_REVIEW_DIR,
            "DB_PATH": portal_app.DB_PATH,
            "PORTAL_KANBAN_DB": portal_app.PORTAL_KANBAN_DB,
            "sync_portal_tasks_with_kanban": portal_app.sync_portal_tasks_with_kanban,
            "move_portal_task_to_in_progress": portal_app.move_portal_task_to_in_progress,
            "queue_malware_sandbox_task": portal_app.queue_malware_sandbox_task,
            "run_sandbox": portal_app.run_sandbox,
            "task_report_quality": portal_app.task_report_quality,
            "sync_report_to_archive_repo": portal_app.sync_report_to_archive_repo,
        }

        portal_app.DATA_DIR = self.data_dir
        portal_app.UPLOAD_DIR = self.upload_dir
        portal_app.DOCUMENTS_DIR = self.documents_dir
        portal_app.IN_REVIEW_DIR = self.in_review_dir
        portal_app.DB_PATH = self.db_path
        portal_app.PORTAL_KANBAN_DB = self.kanban_db

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.documents_dir.mkdir(parents=True, exist_ok=True)
        self.in_review_dir.mkdir(parents=True, exist_ok=True)
        portal_app.init_db()
        portal_app.bootstrap_admin_user()

        portal_app.sync_portal_tasks_with_kanban = lambda: None

    def tearDown(self):
        for name, value in self.originals.items():
            setattr(portal_app, name, value)
        self.tmp.cleanup()

    def create_task(self, *, title: str, description: str = "desc", status: str = "todo", task_type: str = "general") -> int:
        task_id = portal_app.create_portal_task(
            title=title,
            description=description,
            priority=10,
            requested_by="tester",
            assignee="default",
            worker_profile="default",
            task_type=task_type,
        )
        if status != "todo":
            portal_app.execute(
                "UPDATE portal_tasks SET status = ?, updated_at = ? WHERE id = ?",
                [status, portal_app.now_utc().isoformat(), task_id],
            )
        return task_id

    def parse_json(self, response):
        return json.loads(response.body.decode("utf-8"))

    def seed_kanban_task(self, task_id: str, *, status: str = "done", result: str = "Completed successfully"):
        with sqlite3.connect(self.kanban_db) as connection:
            connection.execute(
                "CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, status TEXT, result TEXT, assignee TEXT, created_at REAL, started_at REAL, completed_at REAL, last_failure_error TEXT)"
            )
            connection.execute("CREATE TABLE task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, summary TEXT, outcome TEXT)")
            connection.execute("CREATE TABLE task_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, author TEXT, body TEXT, created_at REAL)")
            connection.execute("CREATE TABLE task_events (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, kind TEXT, payload TEXT, created_at REAL)")
            connection.execute(
                "INSERT INTO tasks (id, title, status, result, assignee, created_at, started_at, completed_at, last_failure_error) VALUES (?, ?, ?, ?, ?, 0, 0, 0, '')",
                [task_id, "Kanban task", status, result, "default"],
            )
            connection.execute("INSERT INTO task_runs (task_id, summary, outcome) VALUES (?, ?, ?)", [task_id, result, status])

    def test_move_task_requires_authentication(self):
        task_id = self.create_task(title="Unauth test")

        response = portal_app.move_task(DummyRequest(authenticated=False), task_id, "blocked")

        self.assertEqual(response.status_code, 401)
        payload = self.parse_json(response)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "Authentication required.")

    def test_rejecting_todo_task_is_no_longer_allowed(self):
        task_id = self.create_task(title="No reject gate")

        response = portal_app.move_task(DummyRequest(), task_id, "rejected")

        self.assertEqual(response.status_code, 409)
        payload = self.parse_json(response)
        self.assertFalse(payload["ok"])
        self.assertIn("Todo tasks can move to In Progress or Blocked", payload["error"])

        updated = portal_app.fetch_portal_task(task_id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "todo")

    def test_accepting_todo_task_moves_to_in_progress_and_sets_kanban_metadata(self):
        task_id = self.create_task(title="Accept me")

        def fake_move(task, username):
            portal_app.execute(
                "UPDATE portal_tasks SET status = ?, kanban_task_id = ?, kanban_status = ?, updated_at = ? WHERE id = ?",
                ["in_progress", "t_test123", "running", portal_app.now_utc().isoformat(), task["id"]],
            )
            portal_app.add_task_history(int(task["id"]), "transition", username, "Moved task to In Progress for test.")
            return {"status": "running"}

        portal_app.move_portal_task_to_in_progress = fake_move

        response = portal_app.move_task(DummyRequest(), task_id, "in_progress")

        self.assertEqual(response.status_code, 200)
        payload = self.parse_json(response)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "in_progress")
        self.assertEqual(payload["kanban_task_id"], "t_test123")
        self.assertEqual(payload["kanban_status"], "running")
        self.assertEqual(payload["message"], "Task moved to In Progress and dispatched to Hermes Kanban.")
        self.assertTrue(payload["has_active_tasks"])

        updated = portal_app.fetch_portal_task(task_id)
        self.assertEqual(updated["status"], "in_progress")
        self.assertEqual(updated["kanban_task_id"], "t_test123")
        self.assertEqual(updated["kanban_status"], "running")

    def test_create_task_route_can_mark_task_as_report_work_and_auto_dispatch(self):
        def fake_move(task, username):
            portal_app.execute(
                "UPDATE portal_tasks SET status = ?, kanban_task_id = ?, kanban_status = ?, updated_at = ? WHERE id = ?",
                ["in_progress", "t_autostart", "running", portal_app.now_utc().isoformat(), task["id"]],
            )
            return {"status": "running"}

        portal_app.move_portal_task_to_in_progress = fake_move

        response = portal_app.create_task(
            DummyRequest(),
            title="Investigate Nightmare Eclipse",
            description="Build a full report on Nightmare Eclipse as a threat actor profile",
            priority=8,
            assignee="tester",
            worker_profile="default",
            task_type="research",
            research_workflow="threat-intel",
            document_category="Threat Actor Profiles",
            due_date="2026-07-01",
            sla_hours=48,
            acceptance_criteria="Final PDF, full IOC list, and OpenCTI-ready STIX notes.",
            parent_task_id=0,
        )

        self.assertEqual(response.status_code, 303)
        location = response.headers.get("location", "")
        self.assertTrue(location.startswith("/tasks#task-"))
        task_id = int(location.rsplit("-", 1)[-1])
        created = portal_app.fetch_portal_task(task_id)
        self.assertIsNotNone(created)
        self.assertEqual(created["status"], "in_progress")
        self.assertEqual(created["kanban_task_id"], "t_autostart")
        self.assertEqual(created["task_type"], "research")
        self.assertEqual(created["source_page"], "research")
        self.assertEqual(created["research_workflow"], "threat-intel")
        self.assertEqual(created["document_category"], "Threat Actor Profiles")
        self.assertEqual(created["due_date"], "2026-07-01")
        self.assertEqual(created["sla_hours"], 48)
        self.assertIn("Final PDF", created["acceptance_criteria"])

    def test_create_research_route_dispatches_non_default_workflow_without_sandbox(self):
        def fake_move(task, username):
            portal_app.execute(
                "UPDATE portal_tasks SET status = ?, kanban_task_id = ?, kanban_status = ?, updated_at = ? WHERE id = ?",
                ["in_progress", "t_detection", "running", portal_app.now_utc().isoformat(), task["id"]],
            )
            return {"id": "t_detection", "status": "running"}

        def fail_sandbox(*args, **kwargs):
            raise AssertionError("RAIccoon Local Sandbox sandbox must not run for detection-engineering research")

        portal_app.move_portal_task_to_in_progress = fake_move
        portal_app.run_sandbox = fail_sandbox

        response = asyncio.run(
            portal_app.create_search(
                DummyRequest(),
                query="Build detections for suspicious PowerShell download cradle activity",
                workflow="detection-engineering",
                title="PowerShell detection package",
                document_category="Detection Engineering",
                priority=7,
                assignee="tester",
                worker_profile="default",
                files=[],
            )
        )

        self.assertEqual(response.status_code, 200)
        task = portal_app.fetch_all("SELECT * FROM portal_tasks ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(task["research_workflow"], "detection-engineering")
        self.assertEqual(task["status"], "in_progress")
        self.assertEqual(task["kanban_task_id"], "t_detection")

    def test_malware_research_route_queues_sandbox_without_waiting_for_vm(self):
        queued = []

        def fake_queue(task_id, sample_paths, username):
            queued.append((task_id, sample_paths, username))

        portal_app.queue_malware_sandbox_task = fake_queue
        upload = portal_app.UploadFile(filename="sample.exe", file=io.BytesIO(b"MZ test"))

        response = asyncio.run(
            portal_app.create_search(
                DummyRequest(),
                query="Analyze this uploaded sample",
                workflow="malware-analysis",
                title="Sandbox queue test",
                document_category="Malware Analysis",
                priority=9,
                assignee="tester",
                worker_profile="default",
                files=[upload],
            )
        )

        self.assertEqual(response.status_code, 200)
        task = portal_app.fetch_all("SELECT * FROM portal_tasks ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual(task["research_workflow"], "malware-analysis")
        self.assertEqual(task["status"], "todo")
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0][0], task["id"])
        self.assertEqual(len(queued[0][1]), 1)
        self.assertTrue(Path(queued[0][1][0]).exists())

    def test_malware_research_route_queues_every_uploaded_sample_for_sandbox(self):
        queued = []

        def fake_queue(task_id, sample_paths, username):
            queued.append((task_id, sample_paths, username))

        portal_app.queue_malware_sandbox_task = fake_queue
        uploads = [
            portal_app.UploadFile(filename="first.exe", file=io.BytesIO(b"MZ first")),
            portal_app.UploadFile(filename="second.dll", file=io.BytesIO(b"MZ second")),
        ]

        response = asyncio.run(
            portal_app.create_search(
                DummyRequest(),
                query="Analyze both uploaded samples",
                workflow="malware-analysis",
                title="All samples sandbox queue test",
                document_category="Malware Analysis",
                priority=9,
                assignee="tester",
                worker_profile="default",
                files=uploads,
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(queued), 1)
        self.assertEqual(len(queued[0][1]), 2)
        self.assertTrue(all(Path(path).exists() for path in queued[0][1]))

    def test_malware_sandbox_failure_blocks_existing_task_instead_of_losing_it(self):
        sample = self.upload_dir / "sample.exe"
        sample.write_bytes(b"MZ test")
        task_id = portal_app.create_portal_task(
            title="Failing sandbox task",
            description="Analyze sample",
            priority=9,
            requested_by="tester",
            assignee="tester",
            worker_profile="default",
            task_type="research",
            source_page="research",
            research_workflow="malware-analysis",
            document_category="Malware Analysis",
            uploaded_files=str(sample),
        )
        portal_app.run_sandbox = lambda path: (False, "VBoxManage guestcontrol copyto failed", 1.2, [])

        portal_app.process_malware_sandbox_task(task_id, str(sample), "tester")

        task = portal_app.fetch_portal_task(task_id)
        self.assertEqual(task["status"], "blocked")
        self.assertIn("RAIccoon Local Sandbox sandbox failed before Hermes dispatch", task["blocked_reason"])
        history_types = [entry["event_type"] for entry in portal_app.fetch_task_history(task_id)]
        self.assertIn("sandbox_failed", history_types)

    def test_task_board_payload_surfaces_efficiency_metadata_and_filters(self):
        blocked_id = self.create_task(title="Waiting on customer telemetry", status="blocked", task_type="research")
        active_id = self.create_task(title="Active stale report", status="in_progress", task_type="research")
        todo_id = self.create_task(title="OpenCTI upload gap", status="todo", task_type="general")
        old_stamp = "2026-01-01T00:00:00+00:00"
        portal_app.execute(
            """
            UPDATE portal_tasks
            SET due_date = ?, sla_hours = ?, source_page = ?, blocked_reason = ?, blocked_at = ?, updated_at = ?, started_at = ?
            WHERE id = ?
            """,
            ["2026-01-02", 1, "client-brief", "Need VPN logs", old_stamp, old_stamp, old_stamp, blocked_id],
        )
        portal_app.execute(
            """
            UPDATE portal_tasks
            SET due_date = ?, sla_hours = ?, source_page = ?, updated_at = ?, started_at = ?, kanban_status = ?
            WHERE id = ?
            """,
            ["2026-01-02", 1, "opencti-upload", old_stamp, old_stamp, "running", active_id],
        )
        portal_app.execute(
            "UPDATE portal_tasks SET source_page = ?, priority = ? WHERE id = ?",
            ["opencti-upload", 7, todo_id],
        )

        payload = portal_app.task_board_payload(filters={"status": "blocked", "assignee": "default"})

        self.assertIn("templates", payload)
        self.assertIn("analytics", payload)
        self.assertIn("filter_options", payload)
        self.assertIn("quick_views", payload)
        self.assertIn("blocked", [column["key"] for column in payload["columns"]])
        visible_ids = [task["id"] for column in payload["columns"] for task in column["items"]]
        self.assertEqual(visible_ids, [blocked_id])
        blocked = payload["tasks"][0]
        self.assertTrue(blocked["is_blocked"])
        self.assertTrue(blocked["is_overdue"])
        self.assertTrue(blocked["is_stale"])
        self.assertEqual(blocked["due_state"], "overdue")
        self.assertEqual(blocked["blocked_reason"], "Need VPN logs")
        self.assertGreaterEqual(payload["analytics"]["blocked_count"], 1)
        self.assertGreaterEqual(payload["analytics"]["stale_count"], 1)
        self.assertIn("opencti-upload", payload["filter_options"]["source_pages"])

    def test_workflow_context_surfaces_focus_queue_steps_and_action_cards(self):
        blocked_id = self.create_task(title="Blocked malware report", status="blocked", task_type="research")
        review_id = self.create_task(title="Reviewable client brief", status="in_review", task_type="research")
        portal_app.execute(
            "UPDATE portal_tasks SET source_page = ?, research_workflow = ?, document_category = ?, updated_at = ? WHERE id = ?",
            ["research", "malware-analysis", "Malware Analysis", "2026-01-01T00:00:00+00:00", blocked_id],
        )
        portal_app.execute(
            "UPDATE portal_tasks SET source_page = ?, research_workflow = ?, document_category = ? WHERE id = ?",
            ["research", "threat-intel", "Executive Summaries", review_id],
        )

        payload = portal_app.task_board_payload()
        context = portal_app.workflow_context("tasks", payload)

        self.assertEqual(context["active_page"], "tasks")
        self.assertEqual(context["focus_queue"][0]["id"], blocked_id)
        self.assertTrue(context["focus_queue"][0]["is_blocked"])
        step_keys = [step["key"] for step in context["workflow_steps"]]
        self.assertEqual(step_keys, ["intake", "execute", "review", "deliver"])
        self.assertGreaterEqual(context["workflow_steps"][1]["count"], 1)
        self.assertGreaterEqual(context["workflow_steps"][2]["count"], 1)
        self.assertEqual([card["label"] for card in context["action_cards"]], ["Unblock work", "Review queue", "SLA risk", "Quality gates"])
        self.assertIn("blocked", context["status_line"])

    def test_dashboard_nav_renders_grouped_sections(self):
        response = portal_app.dashboard_page(DummyRequest())
        html = response.body.decode("utf-8")

        self.assertEqual(response.status_code, 200)
        self.assertIn('class="tabs simple-nav grouped-nav"', html)
        self.assertIn(">Command<", html)
        self.assertIn(">Delivery<", html)
        self.assertIn(">Admin<", html)
        self.assertIn('href="/research"', html)
        self.assertIn('href="/works"', html)
        self.assertIn('href="/security"', html)
        self.assertLess(html.index(">Command<"), html.index(">Delivery<"))
        self.assertLess(html.index(">Delivery<"), html.index(">Admin<"))

    def test_workflow_data_route_requires_auth_and_returns_workflow_payload(self):
        self.create_task(title="Needs operator", status="blocked", task_type="research")

        unauth = portal_app.workflow_data(DummyRequest(authenticated=False))
        self.assertEqual(unauth.status_code, 401)

        response = portal_app.workflow_data(DummyRequest())
        self.assertEqual(response.status_code, 200)
        payload = self.parse_json(response)
        self.assertTrue(payload["ok"])
        self.assertIn("workflow", payload)
        self.assertIn("action_cards", payload["workflow"])
        self.assertIn("focus_queue", payload["workflow"])
        self.assertIn("workflow_steps", payload["workflow"])

    def test_bulk_task_actions_assign_comment_block_and_move_selected_tasks(self):
        first_id = self.create_task(title="Bulk one")
        second_id = self.create_task(title="Bulk two")

        assign_response = portal_app.bulk_update_tasks(
            DummyRequest(),
            task_ids=[first_id, second_id],
            action="assign",
            assignee="rob",
            comment="",
            status="",
            priority=0,
            due_date="",
            blocked_reason="",
        )
        self.assertEqual(assign_response.status_code, 200)
        self.assertEqual(self.parse_json(assign_response)["updated_count"], 2)
        self.assertEqual(portal_app.fetch_portal_task(first_id)["assignee"], "rob")

        comment_response = portal_app.bulk_update_tasks(
            DummyRequest(),
            task_ids=[first_id, second_id],
            action="comment",
            assignee="",
            comment="Need Rob review before launch.",
            status="",
            priority=0,
            due_date="",
            blocked_reason="",
        )
        self.assertEqual(comment_response.status_code, 200)
        self.assertEqual(len(portal_app.fetch_task_comments(first_id)), 1)

        block_response = portal_app.bulk_update_tasks(
            DummyRequest(),
            task_ids=[first_id],
            action="block",
            assignee="",
            comment="",
            status="",
            priority=0,
            due_date="",
            blocked_reason="Waiting on logs",
        )
        self.assertEqual(block_response.status_code, 200)
        blocked = portal_app.fetch_portal_task(first_id)
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["blocked_reason"], "Waiting on logs")

        move_response = portal_app.bulk_update_tasks(
            DummyRequest(),
            task_ids=[second_id],
            action="move",
            assignee="",
            comment="",
            status="blocked",
            priority=0,
            due_date="",
            blocked_reason="",
        )
        self.assertEqual(move_response.status_code, 200)
        self.assertEqual(portal_app.fetch_portal_task(second_id)["status"], "blocked")

    def test_update_task_ownership_route_can_convert_general_task_to_report_task(self):
        task_id = self.create_task(title="Convert me", description="Need a full profile")

        response = portal_app.update_task_ownership_route(
            DummyRequest(),
            task_id,
            assignee="tester",
            worker_profile="default",
            task_type="research",
            research_workflow="threat-intel",
            document_category="Threat Actor Profiles",
        )

        self.assertEqual(response.status_code, 200)
        updated = portal_app.fetch_portal_task(task_id)
        self.assertIsNotNone(updated)
        self.assertEqual(updated["task_type"], "research")
        self.assertEqual(updated["source_page"], "research")
        self.assertEqual(updated["research_workflow"], "threat-intel")
        self.assertEqual(updated["document_category"], "Threat Actor Profiles")

    def test_sync_auto_publishes_completed_general_kanban_task(self):
        task_id = self.create_task(title="Autopublish general", status="in_progress", task_type="general")
        portal_app.execute(
            "UPDATE portal_tasks SET kanban_task_id = ?, kanban_status = ?, started_at = ?, updated_at = ? WHERE id = ?",
            ["t_done_general", "running", portal_app.now_utc().isoformat(), portal_app.now_utc().isoformat(), task_id],
        )
        self.seed_kanban_task("t_done_general", status="done", result="General work completed.")
        setattr(portal_app, "sync_portal_tasks_with_kanban", self.originals["sync_portal_tasks_with_kanban"])

        portal_app.sync_portal_tasks_with_kanban()

        updated = portal_app.fetch_portal_task(task_id)
        self.assertEqual(updated["status"], "accepted")
        self.assertEqual(updated["kanban_status"], "done")
        self.assertIn("Auto-published", updated["review_notes"])
        history_types = [entry["event_type"] for entry in portal_app.fetch_task_history(task_id)]
        self.assertIn("transition", history_types)

    def test_sync_auto_publishes_completed_research_task_after_review_pdf_generation(self):
        task_id = self.create_task(title="Autopublish report", status="in_progress", task_type="research")
        review_pdf = self.in_review_dir / "autopublish-report.pdf"
        review_pdf.write_bytes(b"%PDF-1.4\n% test pdf\n")
        portal_app.execute(
            """
            UPDATE portal_tasks
            SET kanban_task_id = ?, kanban_status = ?, source_page = ?, research_workflow = ?, document_category = ?, review_document_path = ?, started_at = ?, updated_at = ?
            WHERE id = ?
            """,
            [
                "t_done_research",
                "running",
                "research",
                "threat-intel",
                "Threat Reports",
                str(review_pdf),
                portal_app.now_utc().isoformat(),
                portal_app.now_utc().isoformat(),
                task_id,
            ],
        )
        self.seed_kanban_task("t_done_research", status="done", result="Research report completed.")
        setattr(portal_app, "sync_portal_tasks_with_kanban", self.originals["sync_portal_tasks_with_kanban"])
        setattr(portal_app, "task_report_quality", lambda task: {"pass_gate": True, "score": 98, "missing_required": []})
        setattr(portal_app, "sync_report_to_archive_repo", lambda task, destination: destination)

        portal_app.sync_portal_tasks_with_kanban()

        updated = portal_app.fetch_portal_task(task_id)
        self.assertEqual(updated["status"], "accepted")
        self.assertEqual(updated["kanban_status"], "done")
        self.assertTrue(updated["final_document_path"])
        self.assertTrue(Path(updated["final_document_path"]).exists())
        self.assertFalse(review_pdf.exists())
        self.assertGreater(int(updated["published_work_id"]), 0)

    def test_approve_and_publish_accepts_in_review_task(self):
        task_id = self.create_task(title="Publish me", status="in_review", task_type="general")

        response = portal_app.approve_and_publish_task(
            DummyRequest(),
            task_id,
            review_notes="Looks good. Ship it.",
            reviewer_signoff="on",
        )

        self.assertEqual(response.status_code, 200)
        payload = self.parse_json(response)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "accepted")
        self.assertIn("Task published.", payload["message"])
        self.assertFalse(payload["has_active_tasks"])

        updated = portal_app.fetch_portal_task(task_id)
        self.assertEqual(updated["status"], "accepted")
        self.assertEqual(updated["review_notes"], "Looks good. Ship it.")
        self.assertEqual(updated["reviewer"], "")
        self.assertEqual(int(updated["review_signoff"]), 0)

    def test_manual_approve_and_publish_overrides_low_research_qa_score(self):
        task_id = self.create_task(title="Manual low QA publish", status="in_review", task_type="research")
        review_pdf = self.in_review_dir / "manual-low-qa.pdf"
        review_pdf.write_bytes(b"%PDF-1.4\n% low qa but human approved\n")
        portal_app.execute(
            """
            UPDATE portal_tasks
            SET source_page = ?, research_workflow = ?, document_category = ?, review_document_path = ?, review_notes = ?, updated_at = ?
            WHERE id = ?
            """,
            [
                "research",
                "threat-intel",
                "Threat Reports",
                str(review_pdf),
                "Human reviewed known QA gaps and approves publication.",
                portal_app.now_utc().isoformat(),
                task_id,
            ],
        )
        setattr(portal_app, "task_report_quality", lambda task: {"pass_gate": False, "score": 42, "missing_required": ["Detection or hunt query"]})
        setattr(portal_app, "sync_report_to_archive_repo", lambda task, destination: destination)

        response = portal_app.approve_and_publish_task(
            DummyRequest(username="human-reviewer"),
            task_id,
            review_notes="Human override: accepted despite QA score 42/100; publish for client deadline.",
            reviewer_signoff="on",
        )

        self.assertEqual(response.status_code, 200)
        payload = self.parse_json(response)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "accepted")
        self.assertIn("Manual QA override", payload["message"])
        updated = portal_app.fetch_portal_task(task_id)
        self.assertEqual(updated["status"], "accepted")
        self.assertTrue(updated["final_document_path"])
        self.assertTrue(Path(updated["final_document_path"]).exists())
        self.assertFalse(review_pdf.exists())
        history = "\n".join(entry["detail"] for entry in portal_app.fetch_task_history(task_id))
        self.assertIn("Manual QA override", history)


if __name__ == "__main__":
    unittest.main()
