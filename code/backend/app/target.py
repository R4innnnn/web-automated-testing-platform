from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .models import JobConfig


def guess_command(root: Path, ready_url: str) -> str:
    if (root / "package.json").exists():
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        scripts = package.get("scripts", {})
        for name in ("start", "dev", "serve"):
            if name in scripts:
                return f"npm run {name}"
    if (root / "manage.py").exists():
        return "python manage.py runserver 127.0.0.1:" + str(urlparse(ready_url).port or 8000)
    if (root / "app.py").exists():
        return "python app.py"
    if (root / "main.py").exists():
        return "python main.py"
    if (root / "gradlew.bat").exists():
        return "gradlew.bat bootRun"
    if (root / "mvnw.cmd").exists():
        return "mvnw.cmd spring-boot:run"
    if (root / "pom.xml").exists():
        return "mvn spring-boot:run"
    if (root / "index.php").exists() and shutil.which("php"):
        parsed = urlparse(ready_url)
        return f"php -S 127.0.0.1:{parsed.port or 8000} -t ."
    raise ValueError("无法自动识别启动方式，请填写启动命令或选用现有服务")


class TargetProcess:
    def __init__(self, config: JobConfig, output_dir: Path):
        self.config = config
        self.output_dir = output_dir
        self.process: subprocess.Popen | None = None
        self.lines: deque[str] = deque(maxlen=300)
        self.command: str | None = None
        self._log_file = None
        self._log_offsets: dict[Path, int] = {}
        self._reader_thread: threading.Thread | None = None

    def start(self) -> None:
        for raw_path in self.config.log_paths:
            path = Path(raw_path)
            if path.is_file():
                self._log_offsets[path] = path.stat().st_size
        if self.config.mode != "source" or self.config.startup_mode == "existing":
            return
        root = Path(self.config.source_dir or "").resolve()
        self.command = (
            guess_command(root, self.config.target_url)
            if self.config.startup_mode == "auto"
            else self.config.startup_command
        )
        if not self.command:
            raise ValueError("没有可用的启动命令")
        self._log_file = (self.output_dir / "target.log").open("w", encoding="utf-8")
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self.process = subprocess.Popen(
            self.command, shell=True, cwd=root, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace", bufsize=1, creationflags=flags,
        )
        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()

    def _read_output(self) -> None:
        if not self.process or not self.process.stdout:
            return
        for line in self.process.stdout:
            line = line.rstrip()
            self.lines.append(line)
            if self._log_file:
                self._log_file.write(line + "\n")
                self._log_file.flush()

    def wait_ready(self, timeout: float = 25.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError(f"目标进程在就绪前退出，代码 {self.process.returncode}")
            try:
                with httpx.Client(timeout=2, follow_redirects=False) as client:
                    response = client.get(self.config.target_url)
                if response.status_code < 600:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise RuntimeError("目标在限定时间内未就绪")

    def crash_evidence(self) -> dict | None:
        if self.process and self.process.poll() is not None:
            return {
                "exit_code": self.process.returncode,
                "log_tail": list(self.lines)[-40:],
                "command": self.command,
            }
        return None

    def new_log_errors(self) -> list[dict]:
        errors: list[dict] = []
        pattern = re.compile(
            r"(?:PHP Fatal error|Uncaught (?:Exception|Error)|"
            r"Traceback \(most recent call last\)|"
            r"Exception in thread|java\.lang\.[A-Za-z]+Exception)",
            re.I,
        )
        for path, offset in self._log_offsets.items():
            try:
                with path.open("rb") as handle:
                    handle.seek(min(offset, path.stat().st_size))
                    chunk = handle.read(500_000).decode("utf-8", errors="replace")
                for line in chunk.splitlines():
                    if pattern.search(line):
                        errors.append({"log_path": str(path), "message": line[:500]})
            except OSError:
                continue
        return errors[:20]

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                    capture_output=True, timeout=8, check=False,
                )
            else:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
        if self._reader_thread:
            self._reader_thread.join(timeout=2)
        if self._log_file:
            self._log_file.close()
