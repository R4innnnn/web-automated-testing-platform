from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path


LANGUAGES = {
    ".php": "PHP", ".py": "Python", ".java": "Java",
    ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
}
IGNORED = {
    ".git", "node_modules", "vendor", ".venv", "venv",
    "dist", "build", "target", ".next", "__pycache__",
}

# These rules nominate review locations. They do not establish exploitability.
RULES: dict[str, list[tuple[str, str, str]]] = {
    "PHP": [
        ("sqli", r"\b(?:mysqli_query|mysql_query|->query|->exec)\s*\(", "检查 SQL 拼接与参数化查询"),
        ("xss", r"\b(?:echo|print)\s+.*\$_(?:GET|POST|REQUEST)", "检查用户输入的输出编码"),
        ("file_include", r"\b(?:include|require|readfile|file_get_contents)\s*\(", "检查路径参数的限制"),
        ("upload", r"\bmove_uploaded_file\s*\(", "检查上传扩展名和落地目录"),
        ("open_redirect", r"\bheader\s*\(\s*['\"]Location", "检查跳转目标的验证"),
    ],
    "Python": [
        ("sqli", r"\.execute\s*\(|\btext\s*\(", "检查 SQL 参数化"),
        ("xss", r"\brender_template_string\s*\(|\bMarkup\s*\(", "检查模板自动转义"),
        ("file_include", r"\b(?:open|send_file|send_from_directory)\s*\(", "检查文件路径来源"),
        ("open_redirect", r"\bredirect\s*\(", "检查跳转目标的验证"),
    ],
    "Java": [
        ("sqli", r"\b(?:createStatement|executeQuery|executeUpdate)\s*\(", "检查 SQL 参数化"),
        ("xss", r"\b(?:getWriter\(\)\.print|setAttribute)\s*\(", "检查输出编码"),
        ("file_include", r"\b(?:new File|Files\.read|FileInputStream)\s*\(", "检查路径参数来源"),
        ("open_redirect", r"\bsendRedirect\s*\(", "检查跳转目标的验证"),
    ],
    "JavaScript": [
        ("sqli", r"\b(?:query|execute)\s*\(", "检查 SQL 参数化"),
        ("xss", r"\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b", "检查 DOM 注入"),
        ("file_include", r"\b(?:readFile|sendFile|createReadStream)\s*\(", "检查路径参数来源"),
        ("upload", r"\b(?:multer|formidable|busboy)\b", "检查上传处理"),
        ("open_redirect", r"\b(?:redirect|location\.href|location\.assign)\s*(?:\(|=)", "检查跳转目标的验证"),
    ],
}
RULES["TypeScript"] = RULES["JavaScript"]


def scan_source(root_string: str, limit: int = 3000) -> dict:
    root = Path(root_string).resolve()
    candidates: list[dict] = []
    counts: dict[str, int] = {}
    visited = 0
    for path in root.rglob("*"):
        if visited >= limit:
            break
        if not path.is_file() or path.is_symlink() or any(part in IGNORED for part in path.parts):
            continue
        language = LANGUAGES.get(path.suffix.lower())
        if not language or path.stat().st_size > 1_000_000:
            continue
        visited += 1
        counts[language] = counts.get(language, 0) + 1
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            for kind, pattern, message in RULES[language]:
                if re.search(pattern, line):
                    candidates.append({
                        "module": kind, "language": language,
                        "file": str(path.relative_to(root)),
                        "line": number, "message": message,
                        "status": "待动态验证或人工核查",
                    })
                    break
        if len(candidates) >= 500:
            break
    return {"files_scanned": visited, "languages": counts, "candidates": candidates}


def read_coverage(path_string: str | None) -> dict | None:
    if not path_string:
        return None
    path = Path(path_string)
    if not path.is_file() or path.stat().st_size > 20_000_000:
        return {"status": "unavailable", "reason": "覆盖率文件不存在或过大"}
    try:
        if path.suffix.lower() == ".xml":
            root = ET.parse(path).getroot()
            if root.tag == "coverage" and "line-rate" in root.attrib:
                return {"status": "available", "format": "coverage.xml",
                        "line_rate": round(float(root.attrib["line-rate"]) * 100, 2)}
            if root.tag == "report":
                covered = missed = 0
                for counter in root.iter("counter"):
                    if counter.attrib.get("type") == "LINE":
                        covered += int(counter.attrib.get("covered", "0"))
                        missed += int(counter.attrib.get("missed", "0"))
                total = covered + missed
                if total:
                    return {"status": "available", "format": "JaCoCo XML",
                            "line_rate": round(covered / total * 100, 2)}
        else:
            found: set[tuple[str, int]] = set()
            hit: set[tuple[str, int]] = set()
            source = ""
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("SF:"):
                    source = line[3:]
                elif line.startswith("DA:"):
                    number, count, *_ = line[3:].split(",")
                    key = (source, int(number))
                    found.add(key)
                    if int(count) > 0:
                        hit.add(key)
            if found:
                return {"status": "available", "format": "LCOV",
                        "line_rate": round(len(hit) / len(found) * 100, 2)}
    except (ET.ParseError, OSError, ValueError, IndexError):
        pass
    return {"status": "unavailable", "reason": "无法识别覆盖率格式"}
