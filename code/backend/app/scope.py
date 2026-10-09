from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from .models import ACTIVE_MODULES, JobConfig


def origin(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    port = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return f"{parsed.scheme.lower()}://{host}{port}"


def is_public_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host.lower() == "localhost" or host.lower().endswith(".localhost"):
        return False
    if host.lower().endswith((".local", ".internal")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        # Treat domain names as public. DNS interception or split DNS must not
        # silently bypass the authorization gate.
        return True


def requires_authorization(config: JobConfig) -> bool:
    return is_public_url(config.target_url) and any(
        module in ACTIVE_MODULES for module in config.modules
    )


def validate_authorization(config: JobConfig) -> None:
    if not requires_authorization(config):
        return
    proof = config.authorization
    if proof is None or not proof.acknowledged:
        raise ValueError("公开网址的主动安全检测需要授权声明")
    if origin(proof.allowed_origin) != origin(config.target_url):
        raise ValueError("授权域名与目标网址不一致")
    if not urlparse(config.target_url).path.startswith(proof.allowed_path_prefix):
        raise ValueError("目标路径不在授权范围内")


class Scope:
    def __init__(self, config: JobConfig):
        self.allowed_origin = origin(config.target_url)
        self.path_prefix = (
            config.authorization.allowed_path_prefix
            if requires_authorization(config) and config.authorization
            else "/"
        )

    def allows(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            prefix = self.path_prefix.rstrip("/")
            path_ok = (
                self.path_prefix == "/"
                or parsed.path == prefix
                or parsed.path.startswith(prefix + "/")
            )
            return (
                parsed.scheme in {"http", "https"}
                and origin(url) == self.allowed_origin
                and path_ok
            )
        except (ValueError, TypeError):
            return False
