from __future__ import annotations

import difflib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from uuid import uuid4

import httpx
from bs4 import BeautifulSoup
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from .crawler import Budget
from .models import JobConfig, Module
from .scope import Scope, is_public_url


MAX_BODY = 300_000
SKIP_FIELD = re.compile(r"(?:csrf|token|nonce|submit|button|captcha|password)", re.I)
SQL_ERROR = re.compile(
    r"(?:SQL syntax|mysql_fetch|mysqli_|PDOException|sqlite3?\.|"
    r"syntax error.*SQL|SQLite|ORA-\d{5}|PostgreSQL.*ERROR|You have an error in your SQL)",
    re.I,
)
REDIRECT_FIELD = re.compile(r"(?:next|return|redirect|redir|url|dest|continue|callback)", re.I)
FILE_FIELD = re.compile(r"(?:file|path|page|include|template|document|doc)", re.I)
SESSION_COOKIE = re.compile(r"(?:session|sessid|auth|token|sid)", re.I)


@dataclass
class Response:
    status: int
    text: str
    headers: dict[str, str]
    url: str


def make_finding(module: str, title: str, severity: str, url: str,
                 evidence: dict, confidence: str = "confirmed") -> dict:
    return {
        "module": module, "title": title, "severity": severity,
        "confidence": confidence, "url": url, "evidence": evidence,
    }


class ProbeEngine:
    def __init__(self, config: JobConfig, scope: Scope, budget: Budget,
                 crawl_result: dict, run_dir: Path, progress):
        self.config = config
        self.scope = scope
        self.budget = budget
        self.crawl = crawl_result
        self.run_dir = run_dir
        self.progress = progress
        self.findings: list[dict] = []
        self.notes: list[str] = []
        self.deadline = time.monotonic() + max(
            0, config.timeout_seconds - crawl_result.get("elapsed_seconds", 0)
        )
        self.client = httpx.Client(
            timeout=8, follow_redirects=False,
            headers={"User-Agent": "WebTestPlatform/0.1 (authorised testing)"},
        )
        for cookie in crawl_result.get("cookies", []):
            try:
                self.client.cookies.set(
                    cookie["name"], cookie["value"],
                    domain=cookie.get("domain", urlparse(config.target_url).hostname),
                    path=cookie.get("path", "/"),
                )
            except (KeyError, ValueError):
                pass

    def close(self) -> None:
        self.client.close()

    def request(self, method: str, url: str, *, params: dict | None = None,
                files: dict | None = None,
                headers: dict[str, str] | None = None) -> Response | None:
        if (time.monotonic() >= self.deadline
                or not self.scope.allows(url) or not self.budget.take()):
            return None
        if self.config.request_delay_ms:
            time.sleep(self.config.request_delay_ms / 1000)
        try:
            kwargs: dict = {"follow_redirects": False}
            if headers:
                kwargs["headers"] = headers
            if method == "GET":
                kwargs["params"] = params
            else:
                kwargs["data"] = params
                if files:
                    kwargs["files"] = files
            with self.client.stream(method, url, **kwargs) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) >= MAX_BODY:
                        break
                text = body[:MAX_BODY].decode(
                    response.encoding or "utf-8", errors="replace"
                )
                return Response(
                    response.status_code, text, dict(response.headers),
                    str(response.url),
                )
        except (httpx.HTTPError, UnicodeError) as exc:
            self.notes.append(f"{method} {url}: {type(exc).__name__}")
            return None

    def endpoint_request(self, endpoint: dict, overrides: dict | None = None) -> Response | None:
        params = dict(endpoint["fields"])
        params.update(overrides or {})
        return self.request(endpoint["method"], endpoint["url"], params=params)

    def endpoints(self, *, max_count: int = 18) -> list[dict]:
        return self.crawl.get("forms", [])[:max_count]

    def run(self) -> tuple[list[dict], list[str]]:
        actions = {
            Module.SQLI: self.check_sqli,
            Module.XSS: self.check_xss,
            Module.UPLOAD: self.check_upload,
            Module.FILE_INCLUDE: self.check_file_include,
            Module.AUTH: self.check_auth,
            Module.INFO_LEAK: self.check_info_leak,
            Module.CONFIG: self.check_config,
            Module.OPEN_REDIRECT: self.check_open_redirect,
        }
        try:
            for module in self.config.modules:
                if time.monotonic() >= self.deadline:
                    self.notes.append("时间预算已耗尽，后续模块未执行")
                    break
                if self.budget.count >= self.budget.maximum:
                    self.notes.append("请求预算已耗尽，后续模块未执行")
                    break
                self.progress({
                    "phase": "probing", "module": module.value,
                    "requests": self.budget.count,
                    "findings": len(self.findings),
                })
                try:
                    actions[module]()
                except Exception as exc:
                    self.notes.append(f"{module.value} 检测器异常：{type(exc).__name__}: {exc}")
        finally:
            self.close()
        return self.findings, self.notes

    def check_sqli(self) -> None:
        for endpoint in self.endpoints(max_count=12):
            for name, value in list(endpoint["fields"].items())[:5]:
                if SKIP_FIELD.search(name) or endpoint["field_types"].get(name) in {"file", "password"}:
                    continue
                base = self.endpoint_request(endpoint)
                if base is None:
                    return
                quoted = self.endpoint_request(endpoint, {name: value + "'"})
                if quoted is None:
                    return
                base_error = bool(SQL_ERROR.search(base.text))
                quote_error = bool(SQL_ERROR.search(quoted.text))
                if quote_error and not base_error:
                    self.findings.append(make_finding(
                        "sqli", "SQL 注入：输入触发数据库错误", "high", endpoint["url"],
                        {"parameter": name, "method": endpoint["method"],
                         "baseline_status": base.status, "probe_status": quoted.status,
                         "signal": "探测请求出现数据库错误特征，基线请求没有"},
                    ))
                    continue
                if not str(value).strip().isdigit():
                    continue
                truth = self.endpoint_request(endpoint, {name: value + " AND 1=1"})
                false = self.endpoint_request(endpoint, {name: value + " AND 1=2"})
                if truth is None or false is None:
                    return
                a = _similarity(base.text, truth.text)
                b = _similarity(base.text, false.text)
                if a >= 0.88 and b <= 0.68 and truth.status == base.status:
                    self.findings.append(make_finding(
                        "sqli", "SQL 注入：布尔条件改变查询结果", "high", endpoint["url"],
                        {"parameter": name, "method": endpoint["method"],
                         "baseline_true_similarity": round(a, 2),
                         "baseline_false_similarity": round(b, 2)},
                    ))

    def check_xss(self) -> None:
        for endpoint in self.endpoints(max_count=12):
            for name, value in list(endpoint["fields"].items())[:5]:
                if SKIP_FIELD.search(name) or endpoint["field_types"].get(name) in {"file", "password"}:
                    continue
                tag = uuid4().hex[:10]
                variable = "__webtest_" + tag
                payload = f'<svg onload="window.{variable}=1">'
                if endpoint["method"] == "GET":
                    probe_url = _url_with_params(endpoint["url"], {
                        **endpoint["fields"], name: payload
                    })
                    executed = self._browser_marker(probe_url, variable)
                    if executed:
                        self.findings.append(make_finding(
                            "xss", "XSS：浏览器执行了受控标记", "high", endpoint["url"],
                            {"parameter": name, "method": "GET",
                             "marker": variable, "probe_url": probe_url},
                        ))
                elif endpoint["method"] == "POST" and (
                    endpoint["field_types"].get(name) == "textarea"
                    or re.search(r"(?:comment|message|feedback|guestbook|name)", name, re.I)
                ):
                    sent = self.endpoint_request(endpoint, {name: payload})
                    if sent is None:
                        return
                    # Stored XSS is confirmed only after revisiting a page.
                    for revisit in [endpoint["source_page"], sent.url]:
                        if self.scope.allows(revisit) and self._browser_marker(revisit, variable):
                            self.findings.append(make_finding(
                                "xss", "存储型 XSS：再次访问时执行了受控标记",
                                "high", revisit,
                                {"parameter": name, "method": "POST",
                                 "marker": variable},
                            ))
                            break

    def _browser_marker(self, url: str, variable: str) -> bool:
        if (time.monotonic() >= self.deadline
                or not self.scope.allows(url) or not self.budget.take()):
            return False
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context()
                if self.crawl.get("cookies"):
                    context.add_cookies(self.crawl["cookies"])
                page = context.new_page()
                page.route(
                    "**/*",
                    lambda route: route.continue_()
                    if (not route.request.is_navigation_request()
                        or self.scope.allows(route.request.url))
                    else route.abort(),
                )
                page.goto(url, wait_until="domcontentloaded", timeout=10000)
                page.wait_for_timeout(300)
                result = bool(page.evaluate(f"Boolean(window.{variable})"))
                context.close()
                browser.close()
                return result
        except PlaywrightError:
            return False

    def check_info_leak(self) -> None:
        paths = {
            "/.git/HEAD": re.compile(r"^ref: refs/", re.M),
            "/.svn/entries": re.compile(r"(?:^\d+\s*$|svn)", re.I | re.M),
            "/.env": re.compile(r"^[A-Z_]{3,}=.{1,}", re.M),
            "/backup.sql": re.compile(r"(?:CREATE TABLE|INSERT INTO)", re.I),
            "/robots.txt.bak": re.compile(r"User-agent:", re.I),
        }
        base = self.scope.allowed_origin
        for path, signature in paths.items():
            url = base + path
            if not self.scope.allows(url):
                continue
            response = self.request("GET", url)
            if response is None:
                return
            if response.status == 200 and signature.search(response.text):
                self.findings.append(make_finding(
                    "info_leak", "敏感或备份文件可直接访问", "medium", url,
                    {"path": path, "status": response.status,
                     "signal": "内容签名匹配；内容未写入报告"},
                ))

    def check_config(self) -> None:
        https = urlparse(self.config.target_url).scheme == "https"
        for cookie in self.crawl.get("cookies", []):
            if not SESSION_COOKIE.search(cookie.get("name", "")):
                continue
            if not cookie.get("httpOnly"):
                self.findings.append(make_finding(
                    "config", "会话 Cookie 缺少 HttpOnly", "medium",
                    self.config.target_url,
                    {"cookie_name": cookie.get("name"), "attribute": "HttpOnly"},
                ))
            if https and not cookie.get("secure"):
                self.findings.append(make_finding(
                    "config", "HTTPS 会话 Cookie 缺少 Secure", "medium",
                    self.config.target_url,
                    {"cookie_name": cookie.get("name"), "attribute": "Secure"},
                ))
        if https:
            for page in self.crawl.get("pages", [])[:5]:
                headers = {key.lower(): value for key, value in page.get("headers", {}).items()}
                if "strict-transport-security" not in headers:
                    self.notes.append(
                        f"{page['url']} 未发现 HSTS；需结合部署情况人工评估，未计为 Bug"
                    )
        # A crafted Origin probe is active; public URL mode without a statement
        # receives only the passive checks above.
        if is_public_url(self.config.target_url) and not self.config.authorization:
            self.notes.append("未提供远程授权声明，配置模块仅执行被动检查")
            return
        if self.crawl.get("auth_status") != "成功":
            return
        origin = "https://webtest-origin.invalid"
        cross = self.request(
            "GET", self.config.target_url, headers={"Origin": origin}
        )
        if cross is None:
            return
        allow = cross.headers.get("access-control-allow-origin", "")
        credentials = cross.headers.get("access-control-allow-credentials", "")
        if allow == origin and credentials.lower() == "true":
            self.findings.append(make_finding(
                "config", "跨域响应允许任意来源携带凭证读取", "high",
                self.config.target_url,
                {"reflected_origin": allow, "credentials": credentials},
            ))

    def check_open_redirect(self) -> None:
        destination = "https://example.invalid/webtest"
        for endpoint in self.endpoints(max_count=18):
            for name in endpoint["fields"]:
                if not REDIRECT_FIELD.search(name):
                    continue
                response = self.endpoint_request(endpoint, {name: destination})
                if response is None:
                    return
                location = response.headers.get("location", "")
                if 300 <= response.status < 400 and (
                    urlparse(urljoin(endpoint["url"], location)).hostname == "example.invalid"
                ):
                    self.findings.append(make_finding(
                        "open_redirect", "开放重定向：跳转至用户指定站外地址",
                        "medium", endpoint["url"],
                        {"parameter": name, "method": endpoint["method"],
                         "status": response.status, "location_host": "example.invalid",
                         "followed": False},
                    ))
                    continue
                if endpoint["method"] == "GET":
                    probe_url = _url_with_params(endpoint["url"], {
                        **endpoint["fields"], name: destination
                    })
                    if self._browser_redirect(probe_url):
                        self.findings.append(make_finding(
                            "open_redirect", "前端开放重定向", "medium", endpoint["url"],
                            {"parameter": name, "method": "GET",
                             "destination_host": "example.invalid",
                             "followed": False},
                        ))

    def _browser_redirect(self, url: str) -> bool:
        if (time.monotonic() >= self.deadline
                or not self.scope.allows(url) or not self.budget.take()):
            return False
        escaped = False
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()

                def route_request(route):
                    nonlocal escaped
                    request = route.request
                    if request.is_navigation_request() and not self.scope.allows(request.url):
                        if urlparse(request.url).hostname == "example.invalid":
                            escaped = True
                        route.abort()
                    else:
                        route.continue_()

                page.route("**/*", route_request)
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=8000)
                    page.wait_for_timeout(350)
                except PlaywrightError:
                    pass
                browser.close()
        except PlaywrightError:
            return False
        return escaped

    def check_file_include(self) -> None:
        targets = [
            (r"C:\Windows\win.ini", re.compile(r"for 16-bit app support", re.I)),
            (r"..\..\..\..\Windows\win.ini", re.compile(r"for 16-bit app support", re.I)),
            ("/etc/hosts", re.compile(r"(?:127\.0\.0\.1|::1)\s+localhost", re.I)),
            ("../../../../etc/hosts", re.compile(r"(?:127\.0\.0\.1|::1)\s+localhost", re.I)),
        ]
        for endpoint in self.endpoints(max_count=18):
            for name in endpoint["fields"]:
                if not FILE_FIELD.search(name) or SKIP_FIELD.search(name):
                    continue
                baseline = self.endpoint_request(endpoint)
                if baseline is None:
                    return
                for path, signature in targets:
                    response = self.endpoint_request(endpoint, {name: path})
                    if response is None:
                        return
                    if (response.status < 500 and signature.search(response.text)
                            and not signature.search(baseline.text)):
                        self.findings.append(make_finding(
                            "file_include", "文件包含或路径遍历读取了系统示例文件",
                            "high", endpoint["url"],
                            {"parameter": name, "method": endpoint["method"],
                             "file_type": "Windows win.ini" if "win.ini" in path else "Unix hosts",
                             "content_saved": False},
                        ))
                        break

    def check_upload(self) -> None:
        for endpoint in self.endpoints(max_count=20):
            file_fields = [
                name for name, kind in endpoint["field_types"].items()
                if kind == "file"
            ]
            if endpoint["method"] != "POST" or not file_fields:
                continue
            tag = uuid4().hex[:10]
            filename = f"webtest_{tag}.php"
            marker = f"WEBTEST_SAFE_MARKER_{tag}"
            data = {k: v for k, v in endpoint["fields"].items() if k not in file_fields}
            field = file_fields[0]
            sent = self.request(
                "POST", endpoint["url"], params=data,
                files={field: (filename, marker.encode(), "text/plain")},
            )
            if sent is None:
                return
            soup = BeautifulSoup(sent.text, "html.parser")
            candidates: list[str] = []
            for anchor in soup.select("a[href]"):
                href = anchor.get("href") or ""
                if filename in href:
                    candidates.append(urljoin(endpoint["url"], href))
            parsed = urlparse(endpoint["url"])
            candidates.extend([
                f"{self.scope.allowed_origin}/uploads/{filename}",
                f"{self.scope.allowed_origin}/hackable/uploads/{filename}",
                f"{self.scope.allowed_origin}/upload/{filename}",
                urljoin(endpoint["url"], filename),
                urljoin(endpoint["source_page"], filename),
            ])
            for candidate in dict.fromkeys(candidates):
                if not self.scope.allows(candidate):
                    continue
                fetched = self.request("GET", candidate)
                if fetched is None:
                    return
                if fetched.status == 200 and marker in fetched.text:
                    self.findings.append(make_finding(
                        "upload", "危险扩展名文件上传后可公开访问",
                        "high", endpoint["url"],
                        {"upload_field": field, "filename": filename,
                         "retrieval_url": candidate,
                         "test_content": "无害纯文本标记，未上传可执行代码",
                         "cleanup": "如目标不自动清理，请删除该测试文件"},
                    ))
                    break

    def check_auth(self) -> None:
        login = self.config.login
        if not login or not login.login_url or not login.test_username:
            self.notes.append("认证检测需要登录地址和专用测试账号，当前未配置")
            return
        if not self.scope.allows(login.login_url):
            self.notes.append("登录地址不在测试范围内")
            return
        if (login.password_change_url and login.test_password
                and login.username == login.test_username
                and login.password == login.test_password):
            self._check_password_policy()
        elif login.password_change_url:
            self.notes.append("口令策略检测要求当前登录账号与专用测试账号一致")
        wrong = "WEBTEST_WRONG_" + uuid4().hex[:8]
        baseline = self._login_attempt(login.test_username, wrong)
        if baseline is None:
            return
        for guess in ("admin", "password", "123456", "12345678"):
            result = self._login_attempt(login.test_username, guess)
            if result is None:
                return
            if _auth_succeeded(result, baseline, login.success_text):
                self.findings.append(make_finding(
                    "auth", "专用测试账号使用易猜口令", "high",
                    login.login_url,
                    {"account": login.test_username, "guess": guess,
                     "attempts": 4, "note": "仅测试用户指定的专用账号"},
                ))
                break
        # This is an explicitly bounded observation, not proof that unlimited
        # brute force would succeed.
        observations: list[tuple[int, str]] = []
        for index in range(6):
            result = self._login_attempt(login.test_username, wrong + str(index))
            if result is None:
                return
            observations.append((result.status, result.text[:2000]))
            if result.status in {403, 429} or re.search(
                r"(?:captcha|验证码|locked|锁定|too many|过于频繁|稍后再试)",
                result.text, re.I,
            ):
                return
        if len(observations) == 6:
            self.notes.append(
                "专用测试账号连续六次失败登录中未观察到锁定或限速；"
                "该次数不足以单独判定可暴力破解，未计为 Bug"
            )

    def _login_attempt(self, username: str, password: str) -> Response | None:
        login = self.config.login
        if not login or not login.login_url:
            return None
        page = self.request("GET", login.login_url)
        if page is None:
            return None
        soup = BeautifulSoup(page.text, "html.parser")
        form = next(
            (item for item in soup.select("form")
             if item.select_one('input[type="password"]')),
            None,
        )
        if form is None:
            self.notes.append("登录页没有可识别的密码表单")
            return None
        method = (form.get("method") or "POST").upper()
        action = urljoin(login.login_url, form.get("action") or login.login_url)
        if not self.scope.allows(action):
            return None
        fields: dict[str, str] = {}
        user_field = password_field = None
        for field in form.select("input[name]"):
            name = field.get("name")
            kind = (field.get("type") or "text").lower()
            if not name:
                continue
            fields[name] = field.get("value") or ""
            if kind == "password":
                password_field = name
            elif (kind in {"text", "email"} and user_field is None
                  and not SKIP_FIELD.search(name)):
                user_field = name
        if not user_field or not password_field:
            self.notes.append("登录表单字段无法识别")
            return None
        fields[user_field] = username
        fields[password_field] = password
        return self.request(method, action, params=fields)

    def _check_password_policy(self) -> None:
        login = self.config.login
        if not login or not login.password_change_url or not login.test_password:
            return
        if not self.scope.allows(login.password_change_url):
            return
        weak = "123456"
        if login.test_password == weak:
            self.notes.append("专用测试账号已使用弱口令，跳过改密策略试验")
            return
        changed = self._submit_password_change(login.test_password, weak)
        if changed is None:
            return
        # Verify against a fresh invalid-login baseline to avoid treating a
        # generic success page as accepted password change.
        baseline = self._login_attempt(login.test_username or "", "WEBTEST_WRONG_" + uuid4().hex[:6])
        actual = self._login_attempt(login.test_username or "", weak)
        if baseline is None or actual is None:
            self.notes.append("改密结果无法验证，请核对专用测试账号")
            return
        if _auth_succeeded(actual, baseline, login.success_text):
            restored = self._submit_password_change(weak, login.test_password)
            restoration_verified = False
            if restored is not None:
                verified = self._login_attempt(
                    login.test_username or "", login.test_password
                )
                fresh_wrong = self._login_attempt(
                    login.test_username or "", "WEBTEST_WRONG_" + uuid4().hex[:6]
                )
                restoration_verified = bool(
                    verified and fresh_wrong
                    and _auth_succeeded(verified, fresh_wrong, login.success_text)
                )
            self.findings.append(make_finding(
                "auth", "账号可设置常见弱口令", "medium",
                login.password_change_url,
                {"account": login.test_username, "tested_password": "123456",
                 "restoration_verified": restoration_verified,
                 "note": "仅使用专用测试账号"},
            ))
            if not restoration_verified:
                self.notes.append("弱口令试验后未能确认原口令恢复，请人工检查专用测试账号")

    def _submit_password_change(self, old: str, new: str) -> Response | None:
        login = self.config.login
        if not login or not login.password_change_url:
            return None
        page = self.request("GET", login.password_change_url)
        if page is None:
            return None
        soup = BeautifulSoup(page.text, "html.parser")
        form = next(
            (item for item in soup.select("form")
             if len(item.select('input[type="password"]')) >= 2),
            None,
        )
        if form is None:
            self.notes.append("未发现可识别的改密表单")
            return None
        fields: dict[str, str] = {}
        passwords: list[str] = []
        for field in form.select("input[name]"):
            name = field.get("name")
            if not name:
                continue
            fields[name] = field.get("value") or ""
            if (field.get("type") or "").lower() == "password":
                passwords.append(name)
        if len(passwords) < 2:
            return None
        if len(passwords) == 2:
            fields[passwords[0]] = new
            fields[passwords[1]] = new
        else:
            fields[passwords[0]] = old
            fields[passwords[1]] = new
            fields[passwords[2]] = new
        action = urljoin(login.password_change_url, form.get("action") or login.password_change_url)
        if not self.scope.allows(action):
            return None
        method = (form.get("method") or "POST").upper()
        return self.request(method, action, params=fields)


def _url_with_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    merged = dict(parse_qsl(parsed.query, keep_blank_values=True))
    merged.update(params)
    return urlunparse(parsed._replace(query=urlencode(merged)))


def _similarity(left: str, right: str) -> float:
    def clean(value: str) -> str:
        value = re.sub(r"\b\d{4,}\b", "#", value[:100_000])
        return re.sub(r"\s+", " ", value)
    return difflib.SequenceMatcher(None, clean(left), clean(right),
                                   autojunk=True).ratio()


def _auth_succeeded(candidate: Response, baseline: Response,
                    success_text: str | None) -> bool:
    if success_text:
        return (success_text.lower() in candidate.text.lower()
                and success_text.lower() not in baseline.text.lower())
    candidate_location = candidate.headers.get("location", "")
    baseline_location = baseline.headers.get("location", "")
    if (300 <= candidate.status < 400 and candidate_location
            and candidate_location != baseline_location
            and not re.search(r"(?:login|signin|error)", candidate_location, re.I)):
        return True
    return False
