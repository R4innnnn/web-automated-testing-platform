"""Record a short platform demo against the local fixture.

Start the platform and mini_target first. The video captures actual browser
interaction with the platform and is saved to video/platform-demo.webm.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", default="http://127.0.0.1:8000/")
    parser.add_argument("--target", default="http://127.0.0.1:8777/")
    args = parser.parse_args()
    output = ROOT / "video"
    output.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1440, "height": 900},
            record_video_dir=str(output),
            record_video_size={"width": 1440, "height": 900},
        )
        page = context.new_page()
        page.goto(args.platform, wait_until="domcontentloaded")
        page.wait_for_timeout(700)
        page.get_by_placeholder("http://127.0.0.1:8000/").first.fill(args.target)
        for label in ("SQL 注入", "XSS", "开放重定向"):
            page.locator(".module-option").filter(has_text=label).first.click()
        page.wait_for_timeout(600)
        page.locator(".start-button").click()
        page.locator(".status-pill.completed").wait_for(timeout=120_000)
        page.wait_for_timeout(1500)
        first_finding = page.locator(".finding-heading").first
        if first_finding.count():
            first_finding.click()
            page.wait_for_timeout(900)
        report = page.locator(".report-link").get_attribute("href")
        if report:
            page.goto(args.platform.rstrip("/") + report, wait_until="domcontentloaded")
            page.wait_for_timeout(1600)
        video = page.video
        context.close()
        browser.close()
        source = Path(video.path())
    target = output / "platform-demo.webm"
    if source.resolve() != target.resolve():
        os.replace(source, target)
    print(target)


if __name__ == "__main__":
    main()
