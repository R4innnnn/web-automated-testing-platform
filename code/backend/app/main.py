from __future__ import annotations

import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .models import JobConfig, Module
from .report import write_reports
from .runner import run_job
from .scope import requires_authorization, validate_authorization
from .storage import (
    add_suppression, get_job, list_jobs, list_suppressions, new_job,
    remove_suppression, run_path, update_job,
)


app = FastAPI(title="Web 自动化测试平台", version="0.1.0")


@app.middleware("http")
async def local_origin_only(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        sent_origin = request.headers.get("origin")
        if sent_origin:
            allowed = {
                f"{request.url.scheme}://{request.headers.get('host', '')}",
                "http://127.0.0.1:8000", "http://localhost:8000",
                "http://127.0.0.1:5173", "http://localhost:5173",
            }
            if sent_origin not in allowed:
                return JSONResponse(
                    {"detail": "跨站请求被拒绝"}, status_code=403
                )
    return await call_next(request)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "name": "Web 自动化测试平台"}


@app.get("/api/modules")
def modules() -> list[dict]:
    labels = {
        Module.SQLI: "SQL 注入", Module.XSS: "XSS",
        Module.UPLOAD: "文件上传", Module.FILE_INCLUDE: "文件包含／路径遍历",
        Module.AUTH: "认证安全", Module.INFO_LEAK: "信息泄漏",
        Module.CONFIG: "配置弱项", Module.OPEN_REDIRECT: "开放重定向",
    }
    return [{"id": module.value, "label": labels[module]} for module in Module]


@app.post("/api/jobs", status_code=202)
def start_job(config: JobConfig) -> dict:
    try:
        validate_authorization(config)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    job_id = new_job(config.target_url, config.public_view())
    thread = threading.Thread(target=run_job, args=(job_id, config), daemon=True)
    thread.start()
    return {"id": job_id, "status": "queued",
            "authorization_required": requires_authorization(config)}


@app.get("/api/jobs")
def jobs() -> list[dict]:
    return list_jobs()


@app.get("/api/jobs/{job_id}")
def job(job_id: str) -> dict:
    item = get_job(job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    return item


@app.get("/api/jobs/{job_id}/report")
def report(job_id: str):
    if get_job(job_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    path = run_path(job_id) / "index.html"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="报告尚未生成")
    return FileResponse(path, media_type="text/html")


@app.get("/api/jobs/{job_id}/artifact/{file_path:path}")
def artifact(job_id: str, file_path: str):
    if get_job(job_id) is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    base = run_path(job_id).resolve()
    path = (base / file_path).resolve()
    if not path.is_relative_to(base) or not path.is_file():
        raise HTTPException(status_code=404, detail="文件不存在")
    return FileResponse(path)


@app.post("/api/jobs/{job_id}/findings/{finding_id}/suppress")
def suppress_finding(job_id: str, finding_id: str) -> dict:
    item = get_job(job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    finding = next(
        (candidate for candidate in item["result"].get("findings", [])
         if candidate.get("id") == finding_id),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="发现不存在")
    add_suppression(finding)
    finding["suppressed"] = True
    remaining = sum(
        not candidate.get("suppressed")
        for candidate in item["result"].get("findings", [])
    )
    update_job(job_id, result=item["result"],
               progress={**item["progress"], "findings": remaining})
    write_reports(run_path(job_id), item["result"])
    return {"suppressed": True, "finding_id": finding_id}


@app.get("/api/suppressions")
def suppressions() -> list[dict]:
    return list_suppressions()


@app.delete("/api/jobs/{job_id}/findings/{finding_id}/suppress")
def restore_finding(job_id: str, finding_id: str) -> dict:
    item = get_job(job_id)
    if item is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    finding = next(
        (candidate for candidate in item["result"].get("findings", [])
         if candidate.get("id") == finding_id),
        None,
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="发现不存在")
    remove_suppression(finding_id)
    finding["suppressed"] = False
    remaining = sum(
        not candidate.get("suppressed")
        for candidate in item["result"].get("findings", [])
    )
    update_job(job_id, result=item["result"],
               progress={**item["progress"], "findings": remaining})
    write_reports(run_path(job_id), item["result"])
    return {"suppressed": False, "finding_id": finding_id}


FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
