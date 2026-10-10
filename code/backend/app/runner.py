from __future__ import annotations

import hashlib
import re
import threading
import time
from urllib.parse import urlsplit

from .crawler import Budget, crawl
from .models import JobConfig, redact_url
from .probes import ProbeEngine
from .report import write_reports
from .scope import Scope, validate_authorization
from .static_analysis import read_coverage, scan_source
from .storage import is_suppressed, run_path, update_job
from .target import TargetProcess


RUN_LOCK = threading.Lock()
SECRET_IN_TEXT = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+"
)


def _deduplicate(findings: list[dict]) -> list[dict]:
    kept: list[dict] = []
    seen: set[str] = set()
    for finding in findings:
        evidence = finding.get("evidence", {})
        parsed_url = urlsplit(finding.get("url", ""))
        location = (
            f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path or '/'}"
        )
        key_text = "|".join([
            finding.get("module", ""), finding.get("title", ""),
            location, str(evidence.get("parameter", "")),
            str(evidence.get("cookie_name", "")),
        ])
        key = hashlib.sha256(key_text.encode()).hexdigest()[:12]
        if key in seen:
            continue
        seen.add(key)
        kept.append({"id": key, **finding})
    return kept


def _sanitize(value, key: str = ""):
    if isinstance(value, dict):
        return {
            name: _sanitize(item, name)
            for name, item in value.items()
            if not (key == "headers" and name.lower() in {
                "set-cookie", "cookie", "authorization", "proxy-authorization"
            })
        }
    if isinstance(value, list):
        return [_sanitize(item, key) for item in value]
    if isinstance(value, str):
        if key in {"url", "probe_url", "source_page", "target"}:
            value = redact_url(value)
        return SECRET_IN_TEXT.sub(r"\1=[REDACTED]", value)
    return value


def run_job(job_id: str, config: JobConfig) -> None:
    # One task at a time avoids accidental concurrent load on a target.
    with RUN_LOCK:
        _run_job_locked(job_id, config)


def _run_job_locked(job_id: str, config: JobConfig) -> None:
    started = time.monotonic()
    output_dir = run_path(job_id)
    process = TargetProcess(config, output_dir)
    progress = {"phase": "starting", "pages": 0, "requests": 0, "findings": 0}
    update_job(job_id, status="running", progress=progress)

    def set_progress(value: dict) -> None:
        progress.update(value)
        update_job(job_id, progress=progress)

    try:
        validate_authorization(config)
        scope = Scope(config)
        process.start()
        process.wait_ready()
        set_progress({"phase": "source_analysis"})
        source_result = (
            scan_source(config.source_dir or "")
            if config.mode == "source" else None
        )
        budget = Budget(config.max_requests)
        set_progress({"phase": "exploring"})
        crawled = crawl(config, output_dir, scope, budget, set_progress, process)
        set_progress({"phase": "probing", "pages": len(crawled["pages"])})
        engine = ProbeEngine(config, scope, budget, crawled, output_dir, set_progress)
        probe_findings, notes = engine.run()
        crashed = process.crash_evidence()
        if crashed and not any(
            item["title"] == "目标进程退出" for item in crawled["findings"]
        ):
            crawled["findings"].append({
                "module": "runtime", "title": "目标进程退出",
                "severity": "high", "confidence": "observed",
                "url": config.target_url, "evidence": crashed,
            })
        for error in process.new_log_errors():
            crawled["findings"].append({
                "module": "runtime", "title": "服务端日志出现致命异常",
                "severity": "high", "confidence": "observed",
                "url": config.target_url, "evidence": error,
            })
        process.stop()
        coverage = read_coverage(config.coverage_report)
        findings = _deduplicate(crawled["findings"] + probe_findings)
        for finding in findings:
            finding["suppressed"] = is_suppressed(finding["id"])
        result = _sanitize({
            "target": config.target_url,
            "mode": config.mode, "modules": [module.value for module in config.modules],
            "algorithm": config.algorithm, "seed": config.seed,
            "pages": crawled["pages"], "events": crawled["events"],
            "state_edges": crawled["state_edges"],
            "auth_status": crawled["auth_status"],
            "findings": findings,
            "static_analysis": source_result, "coverage": coverage,
            "notes": notes,
            "request_count": budget.count,
            "elapsed_seconds": round(time.monotonic() - started, 2),
        })
        write_reports(output_dir, result)
        update_job(job_id, status="completed", result=result,
                   progress={"phase": "completed", "pages": len(crawled["pages"]),
                             "requests": budget.count,
                             "findings": sum(not f["suppressed"] for f in findings)})
    except Exception as exc:
        update_job(job_id, status="failed", error=f"{type(exc).__name__}: {exc}",
                   progress={**progress, "phase": "failed"})
    finally:
        process.stop()
