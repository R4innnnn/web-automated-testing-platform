from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from fastapi.testclient import TestClient


BACKEND = Path(__file__).resolve().parents[1]
FIXTURE = BACKEND.parent / "fixtures" / "mini_target.py"
sys.path.insert(0, str(BACKEND))

from app import storage  # noqa: E402
from app.main import app  # noqa: E402
from app.models import JobConfig  # noqa: E402
from app.scope import requires_authorization, validate_authorization  # noqa: E402


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_job(client: TestClient, job_id: str, seconds: float = 130) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        response = client.get(f"/api/jobs/{job_id}")
        assert response.status_code == 200
        job = response.json()
        if job["status"] in {"completed", "failed"}:
            return job
        time.sleep(0.4)
    raise AssertionError("job did not finish within test timeout")


def test_authorization_boundary():
    plain = JobConfig(mode="url", url="https://example.com/")
    assert not requires_authorization(plain)
    validate_authorization(plain)
    passive = JobConfig(mode="url", url="https://example.com/", modules=["config"])
    assert not requires_authorization(passive)
    active = JobConfig(mode="url", url="https://example.com/", modules=["sqli"])
    assert requires_authorization(active)
    try:
        validate_authorization(active)
    except ValueError:
        pass
    else:
        raise AssertionError("active public probing must require a statement")
    local = JobConfig(mode="url", url="http://127.0.0.1:8777/", modules=["sqli"])
    assert not requires_authorization(local)


def test_local_blackbox_and_optional_modules(tmp_path):
    storage.DATA_DIR = tmp_path
    storage.DB_PATH = tmp_path / "jobs.sqlite3"
    storage.RUN_DIR = tmp_path / "runs"
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [sys.executable, str(FIXTURE), "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(60):
            try:
                if httpx.get(url + "/", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            raise AssertionError("fixture did not start")

        with TestClient(app) as client:
            basic = client.post("/api/jobs", json={
                "mode": "url", "url": url + "/", "max_pages": 15,
                "max_requests": 90, "request_delay_ms": 0,
            })
            assert basic.status_code == 202, basic.text
            basic_job = wait_job(client, basic.json()["id"])
            assert basic_job["status"] == "completed", basic_job["error"]
            assert basic_job["result"]["pages"]
            assert basic_job["config"]["modules"] == []
            assert any(f["module"] == "runtime" for f in basic_job["result"]["findings"])
            assert (storage.run_path(basic_job["id"]) / "index.html").is_file()

            security = client.post("/api/jobs", json={
                "mode": "url", "url": url + "/",
                "max_pages": 15, "max_requests": 300,
                "timeout_seconds": 180, "request_delay_ms": 0,
                "modules": [
                    "sqli", "xss", "upload", "file_include",
                    "auth", "info_leak", "config", "open_redirect",
                ],
                "login": {
                    "login_url": url + "/login",
                    "username": "test_user",
                    "password": "StrongPass!2026",
                    "test_username": "test_user",
                    "test_password": "StrongPass!2026",
                    "password_change_url": url + "/change-password",
                },
            })
            assert security.status_code == 202, security.text
            secured = wait_job(client, security.json()["id"], seconds=180)
            assert secured["status"] == "completed", secured["error"]
            discovered = {item["module"] for item in secured["result"]["findings"]}
            assert {
                "sqli", "xss", "upload", "file_include",
                "auth", "info_leak", "config", "open_redirect",
            }.issubset(discovered), (discovered, secured["result"]["notes"])
            assert secured["config"]["login"]["password"] is None
            assert secured["config"]["login"]["test_password"] is None
            exported = (storage.run_path(secured["id"]) / "result.json").read_text(
                encoding="utf-8"
            )
            assert "StrongPass!2026" not in exported
            chosen = secured["result"]["findings"][0]
            hidden = client.post(
                f"/api/jobs/{secured['id']}/findings/{chosen['id']}/suppress"
            )
            assert hidden.status_code == 200
            after_hide = client.get(f"/api/jobs/{secured['id']}").json()
            assert next(f for f in after_hide["result"]["findings"]
                        if f["id"] == chosen["id"])["suppressed"]
            restored = client.delete(
                f"/api/jobs/{secured['id']}/findings/{chosen['id']}/suppress"
            )
            assert restored.status_code == 200
            after_restore = client.get(f"/api/jobs/{secured['id']}").json()
            assert not next(f for f in after_restore["result"]["findings"]
                            if f["id"] == chosen["id"])["suppressed"]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def test_source_directory_starts_target_and_runs_dynamically(tmp_path):
    storage.DATA_DIR = tmp_path
    storage.DB_PATH = tmp_path / "jobs.sqlite3"
    storage.RUN_DIR = tmp_path / "runs"
    port = free_port()
    url = f"http://127.0.0.1:{port}/"
    command = f'"{sys.executable}" "{FIXTURE.name}" --port {port}'
    with TestClient(app) as client:
        response = client.post("/api/jobs", json={
            "mode": "source",
            "source_dir": str(FIXTURE.parent),
            "startup_mode": "command",
            "startup_command": command,
            "ready_url": url,
            "max_pages": 3,
            "max_requests": 30,
            "request_delay_ms": 0,
        })
        assert response.status_code == 202, response.text
        job = wait_job(client, response.json()["id"], seconds=60)
        assert job["status"] == "completed", job["error"]
        assert job["result"]["pages"]
        assert job["result"]["static_analysis"]["languages"]["Python"] >= 1
        assert (storage.run_path(job["id"]) / "target.log").is_file()
