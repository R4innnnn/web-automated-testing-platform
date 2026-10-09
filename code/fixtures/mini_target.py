"""Intentionally vulnerable local test fixture. Binds to loopback only."""

from __future__ import annotations

import argparse
import html
import sqlite3
from urllib.parse import quote

import uvicorn
from fastapi import Cookie, FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse


app = FastAPI(title="Local security test fixture")
uploaded: dict[str, bytes] = {}
comments: list[str] = []
passwords = {"test_user": "StrongPass!2026", "weak_user": "admin"}


def shell(body: str) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html><head><title>本机测试站</title></head>"
        "<body><h1>本机测试站</h1>" + body + "</body></html>"
    )


@app.get("/")
def index():
    return shell("""
      <p>此站仅用于验证自动化测试平台，请勿公开部署。</p>
      <nav>
        <a href="/sql?id=1">SQL 查询</a>
        <a href="/echo?q=hello">输出回显</a>
        <a href="/redirect?next=/">跳转</a>
        <a href="/include?file=public.txt">文件读取</a>
        <a href="/upload">文件上传</a>
        <a href="/stored">留言</a>
        <a href="/login">登录</a>
        <a href="/error">服务错误示例</a>
        <a href="/js-error">前端错误示例</a>
      </nav>
    """)


@app.get("/sql", response_class=HTMLResponse)
def sql(id: str = "1"):
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE items(id INTEGER, name TEXT)")
    db.execute("INSERT INTO items VALUES(1,'alpha'),(2,'beta')")
    try:
        # Deliberately unsafe for the local scanner fixture.
        rows = db.execute("SELECT name FROM items WHERE id = " + id).fetchall()
        return shell("<p>" + ", ".join(row[0] for row in rows) + "</p>")
    except sqlite3.DatabaseError as exc:
        return shell("<p>SQLite error: " + html.escape(str(exc)) + "</p>")
    finally:
        db.close()


@app.get("/echo", response_class=HTMLResponse)
def echo(q: str = ""):
    # Deliberately unescaped for XSS verification.
    return shell("<div>" + q + "</div>")


@app.get("/redirect")
def redirect(next: str = "/"):
    return RedirectResponse(next, status_code=302)


@app.get("/include", response_class=HTMLResponse)
def include(file: str = "public.txt"):
    if "win.ini" in file:
        return shell("<pre>; for 16-bit app support\n[fonts]</pre>")
    if "hosts" in file:
        return shell("<pre>127.0.0.1 localhost</pre>")
    return shell("<p>Public file</p>")


@app.get("/upload", response_class=HTMLResponse)
def upload_form():
    return shell("""
      <form action="/upload" method="post" enctype="multipart/form-data">
        <input name="file" type="file">
        <input name="submit" type="submit" value="Upload">
      </form>
    """)


@app.post("/upload", response_class=HTMLResponse)
async def upload(file: UploadFile = File(...), submit: str = Form("Upload")):
    filename = file.filename or "unknown"
    uploaded[filename] = await file.read()
    return shell(f'<a href="/uploads/{quote(filename)}">View upload</a>')


@app.get("/uploads/{filename}")
def get_upload(filename: str):
    if filename not in uploaded:
        return PlainTextResponse("missing", status_code=404)
    return PlainTextResponse(uploaded[filename].decode("utf-8", errors="replace"))


@app.get("/stored", response_class=HTMLResponse)
def stored_form():
    content = "".join("<div>" + item + "</div>" for item in comments)
    return shell("""
      <form action="/stored" method="post">
        <textarea name="message"></textarea>
        <input name="submit" type="submit" value="Send">
      </form>
    """ + content)


@app.post("/stored")
def stored_submit(message: str = Form(""), submit: str = Form("Send")):
    comments.append(message)
    return RedirectResponse("/stored", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return shell("""
      <form action="/login" method="post">
        <input name="username" type="text">
        <input name="password" type="password">
        <input name="submit" type="submit" value="Login">
      </form>
    """)


@app.post("/login")
def login(username: str = Form(""), password: str = Form("")):
    if passwords.get(username) == password:
        response = RedirectResponse("/home", status_code=302)
        response.set_cookie("session_id", username, httponly=False)
        return response
    return shell("<p>Invalid credentials</p>" + """
      <form action="/login" method="post">
        <input name="username" type="text">
        <input name="password" type="password">
        <input name="submit" type="submit" value="Login">
      </form>
    """)


@app.get("/home", response_class=HTMLResponse)
def home(session_id: str | None = Cookie(default=None)):
    if not session_id:
        return shell("<p>Please login</p>")
    return shell(f"<p>Welcome {html.escape(session_id)}</p>"
                 '<a href="/change-password">Change password</a>')


@app.get("/change-password", response_class=HTMLResponse)
def password_form(session_id: str | None = Cookie(default=None)):
    if not session_id:
        return shell("<p>Please login</p>")
    return shell("""
      <form action="/change-password" method="post">
        <input name="old_password" type="password">
        <input name="new_password" type="password">
        <input name="confirm_password" type="password">
        <input name="submit" type="submit" value="Change">
      </form>
    """)


@app.post("/change-password", response_class=HTMLResponse)
def change_password(
    old_password: str = Form(""), new_password: str = Form(""),
    confirm_password: str = Form(""), session_id: str | None = Cookie(default=None)
):
    if not session_id or passwords.get(session_id) != old_password:
        return shell("<p>Invalid current password</p>")
    if new_password != confirm_password:
        return shell("<p>Mismatch</p>")
    passwords[session_id] = new_password
    return shell("<p>Password changed</p>")


@app.get("/.git/HEAD")
def exposed_git():
    return PlainTextResponse("ref: refs/heads/main\n")


@app.get("/error")
def error():
    return PlainTextResponse("Example server error", status_code=500)


@app.get("/js-error", response_class=HTMLResponse)
def js_error():
    return shell("<script>throw new Error('fixture browser error')</script>")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8777)
    args = parser.parse_args()
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
