from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import BaseModel, Field, field_validator, model_validator


class Module(StrEnum):
    SQLI = "sqli"
    XSS = "xss"
    UPLOAD = "upload"
    FILE_INCLUDE = "file_include"
    AUTH = "auth"
    INFO_LEAK = "info_leak"
    CONFIG = "config"
    OPEN_REDIRECT = "open_redirect"


# The configuration module only reads headers/cookies in public unauthorised mode.
ACTIVE_MODULES = {
    Module.SQLI, Module.XSS, Module.UPLOAD, Module.FILE_INCLUDE,
    Module.AUTH, Module.INFO_LEAK, Module.OPEN_REDIRECT,
}


class Authorization(BaseModel):
    basis: Literal["owner", "written_permission", "public_lab"]
    details: str = Field(min_length=8, max_length=1000)
    allowed_origin: str
    allowed_path_prefix: str = "/"
    acknowledged: bool

    @field_validator("allowed_origin")
    @classmethod
    def origin_only(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("授权范围必须是 HTTP(S) 网址")
        if parsed.username or parsed.password:
            raise ValueError("请不要把账号口令放入网址")
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    @field_validator("allowed_path_prefix")
    @classmethod
    def path_prefix(cls, value: str) -> str:
        if not value.startswith("/") or value.startswith("//"):
            raise ValueError("路径范围须以单个 / 开头")
        return value


class LoginConfig(BaseModel):
    login_url: str | None = None
    username: str | None = None
    password: str | None = None
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    success_text: str | None = None
    password_change_url: str | None = None
    test_username: str | None = None
    test_password: str | None = None


class JobConfig(BaseModel):
    mode: Literal["url", "source"]
    url: str | None = None
    source_dir: str | None = None
    startup_mode: Literal["auto", "command", "existing"] = "existing"
    startup_command: str | None = None
    ready_url: str | None = None
    algorithm: Literal["bfs", "dfs", "random"] = "bfs"
    seed: int | None = None
    max_pages: int = Field(default=20, ge=1, le=100)
    max_requests: int = Field(default=150, ge=1, le=1000)
    timeout_seconds: int = Field(default=180, ge=15, le=1800)
    request_delay_ms: int = Field(default=300, ge=0, le=10000)
    modules: list[Module] = Field(default_factory=list)
    authorization: Authorization | None = None
    login: LoginConfig | None = None
    coverage_report: str | None = None
    log_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_inputs(self) -> "JobConfig":
        if self.mode == "url":
            if not self.url:
                raise ValueError("网址模式需要目标网址")
            self.ready_url = self.url
        else:
            if not self.source_dir:
                raise ValueError("目录模式需要源码目录")
            if not Path(self.source_dir).is_dir():
                raise ValueError("源码目录不存在")
            if not self.ready_url:
                raise ValueError("目录模式需要就绪网址")
            if self.startup_mode == "command" and not self.startup_command:
                raise ValueError("手动启动模式需要启动命令")
        for field_name in ("url", "ready_url"):
            value = getattr(self, field_name)
            if value:
                parsed = urlparse(value)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise ValueError("目标必须是 HTTP(S) 网址")
                if parsed.username or parsed.password:
                    raise ValueError("请在登录配置中填写账号，不要放入网址")
        self.modules = list(dict.fromkeys(self.modules))
        return self

    @property
    def target_url(self) -> str:
        return self.ready_url or self.url or ""

    def public_view(self) -> dict:
        data = self.model_dump(mode="json")
        for name in ("url", "ready_url"):
            if data.get(name):
                data[name] = redact_url(data[name])
        if data.get("login"):
            data["login"]["password"] = None
            data["login"]["test_password"] = None
            if data["login"].get("login_url"):
                data["login"]["login_url"] = redact_url(data["login"]["login_url"])
            if data["login"].get("password_change_url"):
                data["login"]["password_change_url"] = redact_url(
                    data["login"]["password_change_url"]
                )
        return data


SENSITIVE_QUERY = {
    "password", "passwd", "pwd", "token", "csrf", "secret",
    "api_key", "apikey", "access_token", "session", "auth",
}


def redact_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value
    query = [
        (name, "[REDACTED]" if name.lower() in SENSITIVE_QUERY else item)
        for name, item in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse(parsed._replace(query=urlencode(query)))
