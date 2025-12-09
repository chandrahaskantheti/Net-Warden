#!/usr/bin/env python3
"""
Minimal web UI for the Net-Warden SQLite database.

Run:
    python app.py
Then open http://127.0.0.1:8000

No external dependencies required.
"""
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import html
import http.cookies
import io
import os
from pathlib import Path
import secrets
import csv
import sys
import time
import urllib.parse

from db_helpers import (
    DB_PATH,
    dashboard_data,
    get_connection,
    delete_submission,
    insert_submission,
    search_urls,
    status_counts,
    user_counts,
    url_details,
    verify_user_credentials,
)

BASE_DIR = Path(__file__).parent
SESSION_COOKIE_NAME = "netwarden_session"
SESSION_DURATION = 60 * 60 * 8  # 8 hours
SESSIONS = {}


def escape(value):
    if value is None:
        return ""
    return html.escape(str(value))


def format_datetime(value):
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(value)


def render_page(title, body, admin_view=False, user=None):
    def nav_link(href, label, active=False):
        cls = ' class="active"' if active else ""
        return f'<a href="{href}"{cls}>{label}</a>'

    nav_links = [nav_link("/", "User View", not admin_view)]
    if user and user.get("role") == "admin":
        nav_links.append(nav_link("/?view=admin", "Admin View", admin_view))
    session_block = (
        f"<div class='session-chip'><div class='muted'>Signed in as</div><strong>{escape(user['name'])}</strong><span class='role-pill'>{escape(user['role'].title())}</span><a class='pill' href='/logout'>Logout</a></div>"
        if user
        else "<div class='session-chip'><a class='pill' href='/login'>Login</a></div>"
    )
    nav = f"""
    <header class=\"topbar\">
      <div class=\"brand\"><a class=\"brand-link\" href=\"/\">Net-Warden</a></div>
      <nav>
        {' '.join(nav_links)}
      </nav>
      {session_block}
    </header>
    """
    script = """
    <script>
      document.addEventListener("DOMContentLoaded", () => {
        const filterCells = Array.from(document.querySelectorAll("th.mini-filter"));
        const closeAll = () => filterCells.forEach(cell => cell.classList.remove("open"));

        filterCells.forEach(cell => {
          const toggle = cell.querySelector(".filter-toggle");
          toggle?.addEventListener("click", (event) => {
            event.preventDefault();
            const isOpen = cell.classList.contains("open");
            closeAll();
            if (!isOpen) {
              cell.classList.add("open");
            }
          });
        });

        document.addEventListener("click", (event) => {
          if (!filterCells.some(cell => cell.contains(event.target))) {
            closeAll();
          }
        });

        window.addEventListener("keydown", (event) => {
          if (event.key === "Escape") {
            closeAll();
          }
        });
      });
    </script>
    """
    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>{html.escape(title)}</title>
      <link rel="stylesheet" href="/static/style.css" />
    </head>
    <body>
      {nav}
      <main class="shell">
        {body}
      </main>
      {script}
    </body>
    </html>
    """


class NetWardenHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.current_user = self.get_current_user()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path.startswith("/static/"):
            self.serve_static(path)
            return
        if path == "/":
            self.render_dashboard(query)
        elif path == "/login":
            self.render_login(query)
        elif path == "/logout":
            self.handle_logout()
        elif path == "/urls":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        elif path.startswith("/url/"):
            url_id = path.split("/")[-1]
            self.render_url_detail(url_id)
        else:
            self.send_error(404, "Not Found")

    def serve_static(self, path):
        safe_path = path.lstrip("/")
        full_path = (BASE_DIR / safe_path).resolve()
        try:
            if not full_path.is_file() or not full_path.is_relative_to(BASE_DIR):
                raise FileNotFoundError
        except (FileNotFoundError, ValueError):
            self.send_error(404, "Not Found")
            return
        content_type = "text/css" if full_path.suffix == ".css" else "application/octet-stream"
        data = full_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.current_user = self.get_current_user()
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/submit":
            if not self.require_login(next_url=self.headers.get("Referer", "/")):
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            form = urllib.parse.parse_qs(body)
            ok, result = insert_submission(form, self.current_user["user_id"])
            if ok:
                self.send_response(303)
                self.send_header("Location", f"/url/{result}")
                self.end_headers()
            else:
                query = urllib.parse.urlencode({"error": result})
                referer = self.headers.get("Referer", "")
                target = "/"
                try:
                    ref_path = urllib.parse.urlparse(referer).path
                    if ref_path and ref_path.startswith("/urls"):
                        target = "/urls"
                except ValueError:
                    pass
                self.send_response(303)
                self.send_header("Location", f"{target}?{query}#submit")
                self.end_headers()
        elif parsed.path == "/delete":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            form = urllib.parse.parse_qs(body)
            if not self.require_admin(next_url=self.headers.get("Referer", "/")):
                return
            try:
                url_id = int(form.get("url_id", [0])[0])
            except ValueError:
                self.send_error(400, "Invalid id")
                return
            ok, msg = delete_submission(url_id)
            referer = self.headers.get("Referer", "/")
            target = "/"
            try:
                ref = urllib.parse.urlparse(referer)
                target = ref.path + (f"?{ref.query}" if ref.query else "")
            except ValueError:
                pass
            if ok:
                self.send_response(303)
                self.send_header("Location", target)
                self.end_headers()
            else:
                query = urllib.parse.urlencode({"error": msg})
                self.send_response(303)
                self.send_header("Location", f"{target}&{query}" if "?" in target else f"{target}?{query}")
                self.end_headers()
        elif parsed.path == "/login":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            form = urllib.parse.parse_qs(body)
            self.process_login(form)
        else:
            self.send_error(404, "Not Found")

    def filter_link(self, action_path, q, status, user_id, extra_params=None):
        query = {}
        if q:
            query["q"] = q
        if status:
            query["result_code"] = status
        if user_id:
            query["user_id"] = user_id
        if extra_params:
            query.update(extra_params)
        qs = urllib.parse.urlencode(query)
        return f"{action_path}?{qs}" if qs else action_path

    def render_url_tools(self, q, result_code, user_id, error, action_path, admin_view=False):
        rows, users = search_urls(q, result_code, user_id)
        status_totals = status_counts(q, user_id)
        user_totals = user_counts(q, result_code)
        table_rows = ""
        for row in rows:
            action_cell = ""
            if admin_view:
                action_cell = (
                    f'<td class="col-actions"><form method="POST" action="/delete" '
                    f'onsubmit="return confirm(\'Delete this URL?\');">'
                    f'<input type="hidden" name="view" value="admin" />'
                    f'<input type="hidden" name="url_id" value="{row["url_id"]}" />'
                    f'<button class="btn-danger btn-icon" type="submit" title="Delete">&#128465;</button>'
                    f"</form></td>"
                )
            table_rows += f"""
            <tr>
              <td><a href="/url/{row['url_id']}">{escape(row['url'])}</a>
                <div class="muted">{escape(row['url_domain'])}</div>
              </td>
              <td>{self.render_status_badge(row['result_code'])}</td>
              <td>{escape(row['submitter'])}</td>
              <td>{format_datetime(row['created_at'])}</td>
              <td class="muted">+{row['phishing_votes']} / -{row['legitimate_votes']}</td>
              {action_cell}
            </tr>
            """
        view_params = {"view": "admin"} if admin_view else None
        current_link = self.filter_link(action_path, q, result_code, user_id, view_params)
        login_href = "/login"
        safe_next = self.clean_next_target(current_link)
        if safe_next and safe_next != "/":
            login_href = f"/login?next={urllib.parse.quote(safe_next, safe='/?:=&%')}"
        if self.current_user:
            submitter_name = escape(self.current_user["name"])
            submitter_role = escape(self.current_user["role"])
            submit_block = f"""
            <div class="card" id="submit">
              <h2>Submit URL</h2>
              <form method="POST" action="/submit" class="form-grid">
                <input type="hidden" name="user_id" value="{escape(self.current_user['user_id'])}" />
                <div>
                  <label for="url">URL</label>
                  <input type="text" id="url" name="url" required placeholder="https://example.com/login" />
                </div>
                <div>
                  <label>Submitter</label>
                  <div class="submitter-pill">{submitter_name} <span class="muted">({submitter_role})</span></div>
                </div>
                <div>
                  <label for="result_code">Classification</label>
                  <select id="result_code" name="result_code">
                    <option value="">Unknown</option>
                    <option value="PHISHING">Phishing</option>
                    <option value="SUSPICIOUS">Suspicious</option>
                    <option value="LEGITIMATE">Legitimate</option>
                  </select>
                </div>
                <button type="submit" class="action-button">Submit</button>
              </form>
              {f'<p class="error" style="margin-top:10px;">{escape(error)}</p>' if error else ''}
            </div>
            """
        else:
            submit_block = f"""
            <div class="card" id="submit">
              <h2>Submit URL</h2>
              <p class="muted">Please <a href="{login_href}">log in</a> to submit URLs for review.</p>
            </div>
            """
        has_filters = bool(q or result_code or user_id)
        active_attr = 'class="active"'
        reset_href = self.filter_link(action_path, "", "", "", view_params)
        extra = {"export": "1"}
        if admin_view:
            extra["view"] = "admin"
        export_href = self.filter_link(action_path, q, result_code, user_id, extra)
        status_class = "mini-filter col-status" + (" active" if result_code else "")
        submitter_class = "mini-filter col-submitter" + (" active" if user_id else "")
        return f"""
        {submit_block}
        <div class="card" style="margin-top:18px;">
          <div class="status-line">
            <h2>Results</h2>
            <div class="flex" style="gap:10px; align-items:center;">
              <div class="muted">{len(rows)} rows</div>
              <a class="reset-link { 'enabled' if has_filters else 'disabled'}" href="{reset_href if has_filters else '#'}">Reset</a>
              <a class="reset-link export enabled" href="{export_href}">Export</a>
            </div>
          </div>
          <table>
            <thead>
              <tr>
                <th class="mini-filter col-url">
                  <button type="button" class="filter-toggle">URL ▾</button>
                  <div class="mini-filters">
                    <form method="GET" action="{action_path}" style="display:grid; gap:8px;">
                      <input type="text" name="q" value="{escape(q)}" placeholder="Search domain or URL" />
                      {f'<input type="hidden" name="result_code" value="{escape(result_code)}" />' if result_code else ''}
                      {f'<input type="hidden" name="user_id" value="{escape(user_id)}" />' if user_id else ''}
                      { '<input type="hidden" name="view" value="admin" />' if admin_view else '' }
                      <div class="flex" style="justify-content: flex-end; gap:8px;">
                        <a class="reset-link export enabled" href="{self.filter_link(action_path, '', result_code, user_id, view_params)}">Clear</a>
                        <button type="submit" class="reset-link enabled" style="border:none;">Apply</button>
                      </div>
                    </form>
                  </div>
                </th>
                <th class="{status_class}">
                  <button type="button" class="filter-toggle">Status ▾</button>
                  <div class="mini-filters">
                    <a href="{self.filter_link(action_path, q, '', user_id, view_params)}" {active_attr if not result_code else ""}>All statuses ({sum(status_totals.values()) or len(rows)})</a>
                    <a href="{self.filter_link(action_path, q, 'PHISHING', user_id, view_params)}" {active_attr if result_code == "PHISHING" else ""}>Phishing ({status_totals.get('PHISHING', 0)})</a>
                    <a href="{self.filter_link(action_path, q, 'SUSPICIOUS', user_id, view_params)}" {active_attr if result_code == "SUSPICIOUS" else ""}>Suspicious ({status_totals.get('SUSPICIOUS', 0)})</a>
                    <a href="{self.filter_link(action_path, q, 'LEGITIMATE', user_id, view_params)}" {active_attr if result_code == "LEGITIMATE" else ""}>Legitimate ({status_totals.get('LEGITIMATE', 0)})</a>
                  </div>
                </th>
                <th class="{submitter_class}">
                  <button type="button" class="filter-toggle">Submitter ▾</button>
                  <div class="mini-filters" style="max-height: 320px; overflow-y: auto;">
                    <a href="{self.filter_link(action_path, q, result_code, '', view_params)}" {active_attr if not user_id else ""}>All submitters ({sum(user_totals.values()) or len(rows)})</a>
                    {''.join(
                        f'<a href="{self.filter_link(action_path, q, result_code, str(user["user_id"]), view_params)}" {active_attr if str(user_id) == str(user["user_id"]) else ""}>{escape(user["name"])} — {escape(user["role"])} ({user_totals.get(user["user_id"], 0)})</a>'
                        for user in users
                    )}
                  </div>
                </th>
                <th class="col-date">Submitted</th>
                <th class="col-votes">Votes</th>
                { '<th class="col-actions">Actions</th>' if admin_view else '' }
              </tr>
            </thead>
            <tbody>{table_rows or '<tr><td colspan="5" class="muted">No URLs found.</td></tr>'}</tbody>
          </table>
        </div>
        """

    def render_dashboard(self, query):
        q = query.get("q", [""])[0]
        result_code = query.get("result_code", [""])[0]
        user_id = query.get("user_id", [""])[0]
        admin_view = query.get("view", [""])[0] == "admin"
        if admin_view and not self.is_admin():
            if not self.current_user:
                self.redirect_to_login(self.path or "/?view=admin")
            else:
                self.send_error(403, "Admin privileges required")
            return
        export = query.get("export", [""])[0]
        error = query.get("error", [""])[0]
        if export:
            rows, _users = search_urls(q, result_code, user_id)
            self.export_csv(rows)
            return
        data = dashboard_data()
        count_map = {row["result_code"] or "UNKNOWN": row["count"] for row in data["result_counts"]}
        stat_cards = f"""
          <div class="belt stat-row">
            <div class="stat stat-primary">
              <div class="muted">Total URLs</div>
              <div class="stat-number">{data['total_urls']}</div>
            </div>
            <div class="stat stat-primary">
              <div class="muted">Phishing</div>
              <div class="stat-number">{count_map.get('PHISHING', 0)}</div>
            </div>
            <div class="stat stat-primary">
              <div class="muted">Legitimate</div>
              <div class="stat-number">{count_map.get('LEGITIMATE', 0)}</div>
            </div>
            <div class="stat stat-primary">
              <div class="muted">Suspicious</div>
              <div class="stat-number">{count_map.get('SUSPICIOUS', 0)}</div>
            </div>
            <div class="stat stat-warm">
              <div class="muted">Users</div>
              <div class="stat-number">{data['total_users']}</div>
            </div>
            <div class="stat stat-warm">
              <div class="muted">Rules</div>
              <div class="stat-number">{data['total_rules']}</div>
            </div>
          </div>
        """
        tools = self.render_url_tools(q, result_code, user_id, error, "/", admin_view=admin_view)
        body = f"""
        <h1 style="margin-bottom:4px;">Security Pulse</h1>
        <p class="muted">Snapshot of submissions, statuses, and votes.</p>
        <div class="belt" style="margin:14px 0 18px;">{stat_cards}</div>
        {tools}
        """
        self.respond_html(
            render_page(
                "Net-Warden Dashboard",
                body,
                admin_view=admin_view,
                user=self.current_user,
            )
        )

    def render_urls(self, query):
        q = query.get("q", [""])[0]
        result_code = query.get("result_code", [""])[0]
        user_id = query.get("user_id", [""])[0]
        error = query.get("error", [""])[0]
        admin_view = query.get("view", [""])[0] == "admin"
        body = self.render_url_tools(q, result_code, user_id, error, "/urls", admin_view=admin_view)
        self.respond_html(
            render_page("URLs", body, admin_view=admin_view, user=self.current_user)
        )

    def render_url_detail(self, url_id):
        try:
            url_id_int = int(url_id)
        except ValueError:
            self.send_error(400, "Invalid id")
            return
        data = url_details(url_id_int)
        if not data:
            self.send_error(404, "Not found")
            return
        url_row = data["url"]
        rules_rows = "".join(
            f"<li><strong>{escape(r['rule_name'])}</strong> · {escape(r['rule_type'])} · {escape(r['risk_level'])}"
            f"<div class='muted'>{escape(r['match_details'])}</div></li>"
            for r in data["rules"]
        ) or "<li class='muted'>No rules recorded.</li>"
        status_rows = "".join(
            f"<li><div class='status-line'>{self.render_status_badge(s['result_code'])}<span class='muted'>{format_datetime(s['created_at'])}</span></div>"
            f"<div><strong>{escape(s['label'])}</strong> — {escape(s['reviewer_name'] or 'Unassigned')}</div>"
            f"<div class='muted'>{escape(s['description'] or '')}</div></li>"
            for s in data["statuses"]
        ) or "<li class='muted'>No review statuses.</li>"
        vote_rows = "".join(
            f"<li><strong>{escape(v['name'])}</strong> ({escape(v['role'])}) — {'Phishing' if v['vote_value'] == 1 else 'Legitimate'}"
            f"<div class='muted'>{format_datetime(v['created_at'])}</div></li>"
            for v in data["votes"]
        ) or "<li class='muted'>No votes yet.</li>"
        score_rows = "".join(
            f"<li><strong>{escape(s['external_source'])}</strong> · {escape(s['risk_level'] or 'n/a')} · avg: {escape(s['avg_score'])} · live: {escape(s['online_score'])}"
            f"<div class='muted'>{format_datetime(s['created_at'])}</div></li>"
            for s in data["scores"]
        ) or "<li class='muted'>No score comparisons.</li>"
        body = f"""
        <div class="card">
          <div class="status-line">
            <div>
              <h1 style="margin:0;">URL #{url_row['url_id']}</h1>
              <div class="muted">{escape(url_row['url'])}</div>
              <div class="muted">Domain: {escape(url_row['url_domain'])} · TLD: {escape(url_row['tld'] or '—')}</div>
            </div>
            {self.render_status_badge(url_row['result_code'])}
          </div>
          <div class="flex" style="margin-top:12px;">
            <span class="muted">Submitted by {escape(url_row['submitter_name'])} ({escape(url_row['submitter_role'])})</span>
            <span class="muted">Created: {format_datetime(url_row['created_at'])}</span>
            <span class="muted">Updated: {format_datetime(url_row['updated_at'])}</span>
          </div>
        </div>
        <div class="grid" style="margin-top:16px;">
          <div class="card">
            <h3>Rule Matches</h3>
            <ul class="stack" style="padding-left:18px; list-style: disc;">{rules_rows}</ul>
          </div>
          <div class="card">
            <h3>Votes</h3>
            <ul class="stack" style="padding-left:18px; list-style: disc;">{vote_rows}</ul>
          </div>
        </div>
        <div class="grid" style="margin-top:16px;">
          <div class="card">
            <h3>Statuses</h3>
            <ul class="stack" style="padding-left:18px; list-style: disc;">{status_rows}</ul>
          </div>
          <div class="card">
            <h3>External Scores</h3>
            <ul class="stack" style="padding-left:18px; list-style: disc;">{score_rows}</ul>
          </div>
        </div>
        """
        self.respond_html(render_page("URL Detail", body, user=self.current_user))

    def render_login(self, query, error_message=None, email_value=""):
        next_target = query.get("next", [""])[0]
        error_text = error_message if error_message is not None else query.get("error", [""])[0]
        info = (
            f"<p class='muted'>You are currently signed in as {escape(self.current_user['name'])}. You can continue or <a href='/logout'>log out</a> to switch accounts.</p>"
            if self.current_user
            else ""
        )
        body = f"""
        <div class=\"auth-container\">
          <div class=\"card auth-card\">
            <h1>Account Login</h1>
            <p class=\"muted\">Sign in with your Net-Warden credentials.</p>
            {f'<p class="error">{escape(error_text)}</p>' if error_text else ''}
            <form method=\"POST\" action=\"/login\" class=\"stack\">
              <input type=\"hidden\" name=\"next\" value=\"{escape(next_target)}\" />
              <div>
                <label for=\"email\">Email</label>
                <input type=\"email\" id=\"email\" name=\"email\" required value=\"{escape(email_value or query.get('email', [''])[0])}\" />
              </div>
              <div>
                <label for=\"password\">Password</label>
                <input type=\"password\" id=\"password\" name=\"password\" required />
              </div>
              <button type=\"submit\" class=\"action-button\">Login</button>
            </form>
            {info}
          </div>
        </div>
        """
        self.respond_html(render_page("Sign In", body, user=self.current_user))

    def process_login(self, form):
        email = form.get("email", [""])[0].strip()
        password = form.get("password", [""])[0]
        next_target = form.get("next", [""])[0]
        if not password or len(password) > 256 or any(ord(ch) < 32 for ch in password):
            self.render_login({"next": [next_target]}, error_message="Password cannot be empty or contain control characters.", email_value=email)
            return
        user = verify_user_credentials(email, password)
        if not user:
            self.render_login({"next": [next_target]}, error_message="Invalid email or password.", email_value=email)
            return
        session_id, cookie_header = self.start_session(user)
        target = self.clean_next_target(next_target)
        self.send_response(303)
        self.send_header("Location", target)
        self.send_header("Set-Cookie", cookie_header)
        self.end_headers()

    def handle_logout(self):
        cookie_header = self.expire_session()
        self.send_response(303)
        self.send_header("Location", "/")
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()

    def render_status_badge(self, code):
        label = code or "UNKNOWN"
        css = "pill-badge tag-warn"
        if label.upper() == "PHISHING":
            css = "pill-badge tag-danger"
        elif label.upper() == "LEGITIMATE":
            css = "pill-badge tag-success"
        return f'<span class="{css}">{escape(label)}</span>'

    def redirect(self, target, cookies=None):
        self.send_response(303)
        self.send_header("Location", target)
        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def redirect_to_login(self, next_url="/"):
        safe_next = self.clean_next_target(next_url)
        target = "/login"
        if safe_next and safe_next != "/":
            target += f"?next={urllib.parse.quote(safe_next, safe='/?:=&%')}"
        self.redirect(target)

    def clean_next_target(self, target):
        if not target:
            return "/"
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme or parsed.netloc:
            return "/"
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    def is_admin(self):
        return bool(self.current_user and self.current_user.get("role") == "admin")

    def require_admin(self, next_url="/"):
        if self.is_admin():
            return True
        if not self.current_user:
            safe_next = next_url or "/"
            try:
                parsed = urllib.parse.urlparse(safe_next)
                safe_path = parsed.path or "/"
                if parsed.query:
                    safe_path = f"{safe_path}?{parsed.query}"
            except ValueError:
                safe_path = "/"
            self.redirect_to_login(safe_path)
        else:
            self.send_error(403, "Admin privileges required")
        return False

    def require_login(self, next_url="/"):
        if self.current_user:
            return True
        self.redirect_to_login(next_url)
        return False

    def get_current_user(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(cookie_header)
        except http.cookies.CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE_NAME)
        if not morsel:
            return None
        session_id = morsel.value
        session = SESSIONS.get(session_id)
        now = time.time()
        if not session or session.get("expires_at", 0) < now:
            if session_id in SESSIONS:
                SESSIONS.pop(session_id, None)
            return None
        session["expires_at"] = now + SESSION_DURATION
        self.active_session_id = session_id
        return session

    def start_session(self, user_row):
        session_id = secrets.token_hex(32)
        session_data = {
            "user_id": user_row["user_id"],
            "name": user_row["name"],
            "email": user_row["email"],
            "role": user_row["role"],
            "expires_at": time.time() + SESSION_DURATION,
        }
        SESSIONS[session_id] = session_data
        self.current_user = session_data
        self.active_session_id = session_id
        return session_id, self.build_session_cookie(session_id)

    def build_session_cookie(self, session_id, max_age=SESSION_DURATION):
        cookie = http.cookies.SimpleCookie()
        cookie[SESSION_COOKIE_NAME] = session_id
        cookie[SESSION_COOKIE_NAME]["path"] = "/"
        cookie[SESSION_COOKIE_NAME]["httponly"] = True
        cookie[SESSION_COOKIE_NAME]["samesite"] = "Lax"
        if max_age is not None:
            cookie[SESSION_COOKIE_NAME]["max-age"] = str(int(max_age))
        return cookie.output(header="", sep="")

    def expire_session(self):
        session_id = getattr(self, "active_session_id", None)
        if not session_id:
            cookie_header = self.headers.get("Cookie")
            if cookie_header:
                cookie = http.cookies.SimpleCookie()
                try:
                    cookie.load(cookie_header)
                except http.cookies.CookieError:
                    cookie = None
                if cookie and cookie.get(SESSION_COOKIE_NAME):
                    session_id = cookie[SESSION_COOKIE_NAME].value
        if session_id:
            SESSIONS.pop(session_id, None)
        cookie = http.cookies.SimpleCookie()
        cookie[SESSION_COOKIE_NAME] = ""
        cookie[SESSION_COOKIE_NAME]["path"] = "/"
        cookie[SESSION_COOKIE_NAME]["httponly"] = True
        cookie[SESSION_COOKIE_NAME]["samesite"] = "Lax"
        cookie[SESSION_COOKIE_NAME]["max-age"] = "0"
        cookie[SESSION_COOKIE_NAME]["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
        return cookie.output(header="", sep="")

    def respond_html(self, content):
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def export_csv(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["URL", "Domain", "TLD", "Status", "Submitter", "Submitted", "Phishing votes", "Legitimate votes"])
        for row in rows:
            writer.writerow([
                row["url"],
                row["url_domain"],
                row["tld"],
                row["result_code"],
                row["submitter"],
                row["created_at"],
                row["phishing_votes"],
                row["legitimate_votes"],
            ])
        data = output.getvalue().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", "attachment; filename=\"net-warden-urls.csv\"")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    if not DB_PATH.exists():
        sys.stderr.write(f"Database not found at {DB_PATH}\n")
        sys.exit(1)
    if len(sys.argv) > 1 and sys.argv[1] == "--check":
        with get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM url_submissions").fetchone()
            print(f"Database reachable. url_submissions rows: {row[0]}")
        return

    port = int(os.environ.get("PORT", "8000"))
    server = HTTPServer(("0.0.0.0", port), NetWardenHandler)
    print(f"Net-Warden UI running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
