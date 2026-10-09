from __future__ import annotations

import hashlib
import random
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from .models import JobConfig
from .scope import Scope


SKIP_LINK = re.compile(
    r"(?:logout|signout|delete|remove|destroy|reset|drop|truncate)", re.I
)


@dataclass
class Budget:
    maximum: int
    count: int = 0

    def take(self) -> bool:
        if self.count >= self.maximum:
            return False
        self.count += 1
        return True


def normalise_url(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/",
         "", query, "")
    )


def state_key(url: str, html: str) -> str:
    # Numeric run-specific text is ignored for page-state grouping.
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    structural = "|".join(
        f"{node.name}:{node.get('id','')}:{node.get('name','')}"
        for node in soup.find_all(["form", "input", "button", "a", "textarea"])
    )
    structural = re.sub(r"\d{4,}", "#", structural)
    value = urlparse(url).path + "|" + structural
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def extract_page(url: str, html: str, scope: Scope) -> tuple[list[str], list[dict]]:
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    forms: list[dict] = []
    for anchor in soup.select("a[href]"):
        href = anchor.get("href", "")
        target = normalise_url(urljoin(url, href))
        if scope.allows(target) and not SKIP_LINK.search(target):
            links.append(target)
    for form in soup.select("form"):
        method = (form.get("method") or "get").upper()
        if method not in {"GET", "POST"}:
            continue
        action = normalise_url(urljoin(url, form.get("action") or url))
        if not scope.allows(action) or SKIP_LINK.search(action):
            continue
        fields: dict[str, str] = {}
        field_types: dict[str, str] = {}
        for field in form.select("input[name],textarea[name],select[name]"):
            name = field.get("name")
            if not name:
                continue
            kind = (field.get("type") or field.name or "text").lower()
            if kind in {"submit", "button", "reset", "image"}:
                if kind == "submit":
                    fields.setdefault(name, field.get("value") or "")
                continue
            field_types[name] = kind
            fields[name] = field.get("value") or (
                field.text.strip() if field.name == "textarea" else ""
            )
        forms.append({
            "method": method, "url": action, "fields": fields,
            "field_types": field_types, "source_page": url,
        })
        if method == "GET" and fields:
            parsed = urlparse(action)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query.update(fields)
            links.append(urlunparse(parsed._replace(query=urlencode(query))))
    return list(dict.fromkeys(links)), forms


def _login(page, config: JobConfig, scope: Scope, events: list[dict]) -> str:
    login = config.login
    if not login or not login.login_url or not login.username or not login.password:
        return "未配置"
    if not scope.allows(login.login_url):
        return "登录地址不在范围内"
    try:
        page.goto(login.login_url, wait_until="domcontentloaded", timeout=12000)
        user_sel = login.username_selector or (
            'input[name="username"],input[name="user"],input[type="email"],'
            'input[type="text"]'
        )
        pass_sel = login.password_selector or 'input[type="password"]'
        page.locator(user_sel).first.fill(login.username)
        page.locator(pass_sel).first.fill(login.password)
        submit = login.submit_selector or 'button[type="submit"],input[type="submit"]'
        page.locator(submit).first.click(timeout=5000)
        page.wait_for_timeout(400)
        success = (
            login.success_text.lower() in page.content().lower()
            if login.success_text else
            page.locator('input[type="password"]').count() == 0
        )
        events.append({
            "action": "login", "url": login.login_url,
            "result": "success" if success else "unconfirmed",
            "note": "账号和口令不保存",
        })
        return "成功" if success else "未确认"
    except PlaywrightError as exc:
        events.append({"action": "login", "url": login.login_url,
                       "result": "error", "message": str(exc)[:250]})
        return "失败"


def crawl(config: JobConfig, run_dir: Path, scope: Scope, budget: Budget,
          progress, target_process=None) -> dict:
    started = time.monotonic()
    frontier = [normalise_url(config.target_url)]
    queued = set(frontier)
    seen: set[str] = set()
    pages: list[dict] = []
    forms: list[dict] = []
    events: list[dict] = []
    findings: list[dict] = []
    state_edges: list[dict] = []
    page_errors: list[str] = []
    randomizer = random.Random(config.seed)
    auth_status = "未配置"
    cookies: list[dict] = []
    screenshots = run_dir / "screenshots"
    screenshots.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()

        def route_request(route):
            request = route.request
            if request.is_navigation_request() and not scope.allows(request.url):
                route.abort()
            elif budget.take():
                route.continue_()
            else:
                route.abort()

        page.route("**/*", route_request)
        page.on("pageerror", lambda error: page_errors.append(str(error)[:500]))
        auth_status = _login(page, config, scope, events)
        while frontier and len(pages) < config.max_pages:
            if time.monotonic() - started > config.timeout_seconds:
                events.append({"action": "stop", "reason": "时间预算已耗尽"})
                break
            if budget.count >= budget.maximum:
                events.append({"action": "stop", "reason": "请求预算已耗尽"})
                break
            index = -1 if config.algorithm == "dfs" else (
                randomizer.randrange(len(frontier))
                if config.algorithm == "random" else 0
            )
            url = frontier.pop(index)
            if url in seen or not scope.allows(url):
                continue
            seen.add(url)
            before_errors = len(page_errors)
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=12000)
                page.wait_for_timeout(150)
                final_url = page.url
                if not scope.allows(final_url):
                    events.append({"action": "navigate", "url": url,
                                   "result": "范围外跳转已拦截"})
                    continue
                status = response.status if response else 0
                headers = response.all_headers() if response else {}
                html = page.content()
                screenshot_name = f"page-{len(pages)+1:03d}.png"
                screenshot_path = screenshots / screenshot_name
                page.screenshot(path=str(screenshot_path), full_page=True,
                                timeout=8000)
                key = state_key(final_url, html)
                item = {
                    "url": final_url, "status": status, "state": key,
                    "title": page.title()[:150], "headers": headers,
                    "screenshot": f"screenshots/{screenshot_name}",
                    "html_length": len(html),
                }
                pages.append(item)
                events.append({"action": "navigate", "url": url,
                               "result": status, "state": key,
                               "screenshot": item["screenshot"]})
                links, new_forms = extract_page(final_url, html, scope)
                forms.extend(new_forms)
                for link in links:
                    if link not in queued and link not in seen:
                        frontier.append(link)
                        queued.add(link)
                    state_edges.append({"from": key, "to_url": link})
                if status >= 500:
                    findings.append({
                        "module": "runtime", "title": "服务返回 5xx",
                        "severity": "medium", "confidence": "observed",
                        "url": final_url, "evidence": {"status": status},
                        "screenshot": item["screenshot"],
                    })
                if status == 404 and len(pages) > 1:
                    findings.append({
                        "module": "runtime", "title": "站内链接返回 404",
                        "severity": "low", "confidence": "observed",
                        "url": final_url, "evidence": {"status": status},
                        "screenshot": item["screenshot"],
                    })
                for error in page_errors[before_errors:]:
                    findings.append({
                        "module": "runtime", "title": "前端脚本运行异常",
                        "severity": "low", "confidence": "observed",
                        "url": final_url, "evidence": {"message": error},
                        "screenshot": item["screenshot"],
                    })
                if target_process and target_process.crash_evidence():
                    findings.append({
                        "module": "runtime", "title": "目标进程退出",
                        "severity": "high", "confidence": "observed",
                        "url": final_url,
                        "evidence": target_process.crash_evidence(),
                        "screenshot": item["screenshot"],
                    })
                    break
                progress({"phase": "exploring", "pages": len(pages),
                          "requests": budget.count, "frontier": len(frontier)})
            except PlaywrightError as exc:
                events.append({"action": "navigate", "url": url,
                               "result": "browser_error",
                               "message": str(exc)[:400]})
                if target_process and target_process.crash_evidence():
                    findings.append({
                        "module": "runtime", "title": "目标进程退出",
                        "severity": "high", "confidence": "observed",
                        "url": url, "evidence": target_process.crash_evidence(),
                    })
                    break
        cookies = context.cookies()
        browser.close()
    # Query parameters of visited links are testable even without a form.
    for seen_url in seen:
        parsed = urlparse(seen_url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if params:
            forms.append({
                "method": "GET", "url": urlunparse(parsed._replace(query="")),
                "fields": params, "field_types": {name: "text" for name in params},
                "source_page": seen_url,
            })
    unique_forms: dict[tuple, dict] = {}
    for form in forms:
        key = (form["method"], form["url"], tuple(sorted(form["fields"])))
        unique_forms.setdefault(key, form)
    return {
        "pages": pages, "forms": list(unique_forms.values()),
        "events": events, "findings": findings, "state_edges": state_edges,
        "auth_status": auth_status, "cookies": cookies,
        "elapsed_seconds": round(time.monotonic() - started, 2),
    }
