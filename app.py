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
    cast_vote,
    dashboard_data,
    delete_submission,
    get_admin_actions,
    get_contributor_stats,
    get_connection,
    get_rule_effectiveness,
    get_rule_usage,
    get_risk_rankings,
    get_user_vote,
    get_vote_conflicts,
    insert_submission,
    run_admin_action,
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


def render_page(title, body, admin_view=False, user=None, current_path="/"):
    def nav_link(href, label, active=False):
        cls = ' class="active"' if active else ""
        return f'<a href="{href}"{cls}>{label}</a>'

    try:
        parsed = urllib.parse.urlparse(current_path)
        active_path = parsed.path or "/"
    except ValueError:
        active_path = "/"
    nav_links = [nav_link("/", "User View", not admin_view and active_path == "/")]
    if user and user.get("role") == "admin":
        nav_links.append(nav_link("/?view=admin", "Admin View", admin_view))
        nav_links.append(nav_link("/analytics", "Analytics", active_path.startswith("/analytics")))
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
        elif path == "/analytics":
            self.render_analytics(query)
        elif path.startswith("/url/"):
            url_id = path.split("/")[-1]
            self.render_url_detail(url_id, query)
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
        elif parsed.path == "/vote":
            if not self.require_login(next_url=self.headers.get("Referer", "/")):
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            form = urllib.parse.parse_qs(body)
            try:
                url_id = int(form.get("url_id", [0])[0])
                vote_value = int(form.get("vote_value", [0])[0])
            except ValueError:
                self.send_error(400, "Invalid vote")
                return
            ok, msg = cast_vote(url_id, self.current_user["user_id"], vote_value)
            referer = self.headers.get("Referer", f"/url/{url_id}")
            target = self.clean_next_target(referer) or f"/url/{url_id}"
            qs = urllib.parse.urlencode({("status" if ok else "error"): msg})
            sep = "&" if "?" in target else "?"
            self.send_response(303)
            self.send_header("Location", f"{target}{sep}{qs}")
            self.end_headers()
        elif parsed.path == "/admin-action":
            if not self.require_admin(next_url=self.headers.get("Referer", "/analytics")):
                return
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            form = urllib.parse.parse_qs(body)
            action_id = form.get("action", [""])[0]
            ok, msg = run_admin_action(action_id)
            qs = urllib.parse.urlencode({("status" if ok else "error"): msg})
            self.send_response(303)
            self.send_header("Location", f"/analytics?{qs}")
            self.end_headers()
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

    def render_url_tools(self, q, result_code, user_id, error, action_path, admin_view=False, status_message=""):
        viewer_user_id = self.current_user["user_id"] if self.current_user else None
        rows, users = search_urls(q, result_code, user_id, viewer_user_id=viewer_user_id)
        status_totals = status_counts(q, user_id)
        user_totals = user_counts(q, result_code)
        table_rows = ""
        column_count = 5 + (1 if self.current_user else 0) + (1 if admin_view else 0)
        for row in rows:
            vote_cell = ""
            if self.current_user:
                vote_cell = f'<td class="col-user-vote">{self.render_vote_form(row["url_id"], row["current_user_vote"], compact=True)}</td>'
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
              {vote_cell}
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
        vote_header = '<th class="col-user-vote">Your Vote</th>' if self.current_user else ''
        empty_row = table_rows or f'<tr><td colspan="{column_count}" class="muted">No URLs found.</td></tr>'
        flash_block = ""
        if status_message:
            flash_block = f'<div class="alert success">{escape(status_message)}</div>'
        return f"""
        {submit_block}
        {flash_block}
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
                {vote_header}
                { '<th class="col-actions">Actions</th>' if admin_view else '' }
              </tr>
            </thead>
            <tbody>{empty_row}</tbody>
          </table>
        </div>
        """

    def render_dashboard(self, query):
        q = query.get("q", [""])[0]
        result_code = query.get("result_code", [""])[0]
        user_id = query.get("user_id", [""])[0]
        admin_view = query.get("view", [""])[0] == "admin"
        viewer_user_id = self.current_user["user_id"] if self.current_user else None
        if admin_view and not self.is_admin():
            if not self.current_user:
                self.redirect_to_login(self.path or "/?view=admin")
            else:
                self.send_error(403, "Admin privileges required")
                return
        export = query.get("export", [""])[0]
        error = query.get("error", [""])[0]
        status_msg = query.get("status", [""])[0]
        if export:
            rows, _users = search_urls(q, result_code, user_id, viewer_user_id=viewer_user_id)
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
        tools = self.render_url_tools(q, result_code, user_id, error, "/", admin_view=admin_view, status_message=status_msg)
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
                current_path=self.path,
            )
        )

    def render_urls(self, query):
        q = query.get("q", [""])[0]
        result_code = query.get("result_code", [""])[0]
        user_id = query.get("user_id", [""])[0]
        error = query.get("error", [""])[0]
        admin_view = query.get("view", [""])[0] == "admin"
        status_msg = query.get("status", [""])[0]
        body = self.render_url_tools(q, result_code, user_id, error, "/urls", admin_view=admin_view, status_message=status_msg)
        self.respond_html(
            render_page("URLs", body, admin_view=admin_view, user=self.current_user, current_path=self.path)
        )

    def render_analytics(self, query):
        if not self.require_admin(next_url=self.path or "/analytics"):
            return
        status_msg = query.get("status", [""])[0]
        error_msg = query.get("error", [""])[0]
        contributors = get_contributor_stats()
        rule_usage = get_rule_usage()
        vote_conflicts = get_vote_conflicts()
        risk_rankings = get_risk_rankings()
        rule_effectiveness = get_rule_effectiveness()
        admin_actions = get_admin_actions()

        def fmt_pct(value):
            return f"{(value if value is not None else 0):.2f}%"

        contrib_rows = "".join(
            f"<tr><td>{escape(row['name'])}</td>"
            f"<td>{row['total_submissions'] or 0}</td>"
            f"<td>+{row['phishing_count'] or 0}</td>"
            f"<td>-{row['legitimate_count'] or 0}</td>"
            f"<td>{row['suspicious_count'] or 0}</td></tr>"
            for row in contributors
        ) or "<tr><td colspan='5' class='muted'>No submissions yet.</td></tr>"

        rule_rows = "".join(
            f"<tr><td>{escape(row['rule_name'])}</td>"
            f"<td>{escape(row['rule_type'] or '')}</td>"
            f"<td>{escape(row['risk_level'] or '')}</td>"
            f"<td>{row['urls_matched'] or 0}</td></tr>"
            for row in rule_usage
        ) or "<tr><td colspan='4' class='muted'>No rules found.</td></tr>"

        conflict_cards = "".join(
            f"""
            <li>
              <strong><a href="/url/{row['url_id']}">{escape(row['url'])}</a></strong>
              <div class="muted">Result: {escape(row['result_code'] or 'UNKNOWN')} · Votes: +{row['phishing_votes']} / -{row['legitimate_votes']}</div>
              <div class="muted">Review: {escape(row['review_status'] or '')} — {escape(row['review_description'] or '')}</div>
            </li>
            """
            for row in vote_conflicts
        ) or "<li class='muted'>No conflicting votes detected.</li>"

        risk_rows = "".join(
            f"<tr><td><a href='/url/{row['url_id']}'>{escape(row['url_domain'])}</a></td>"
            f"<td>{row['risk_score']:.2f}</td>"
            f"<td>{escape(row['risk_level'] or 'n/a')}</td>"
            f"<td>{row['vote_count']}</td>"
            f"<td>{escape(row['agreement_status'])}</td></tr>"
            for row in risk_rankings
        ) or "<tr><td colspan='5' class='muted'>No rankings available.</td></tr>"

        effectiveness_rows = "".join(
            f"<tr><td>{escape(row['rule_name'])}</td>"
            f"<td>{row['urls_matched']}</td>"
            f"<td>{row['phishing_matches']}</td>"
            f"<td>{row['legitimate_matches']}</td>"
            f"<td>{fmt_pct(row['phishing_accuracy_percent'])}</td></tr>"
            for row in rule_effectiveness
        ) or "<tr><td colspan='5' class='muted'>No effectiveness data.</td></tr>"

        action_cards = "".join(
            f"""
            <form method="POST" action="/admin-action" class="card action-card">
              <input type="hidden" name="action" value="{escape(action['id'])}" />
              <h3>{escape(action['label'])}</h3>
              <p class="muted">{escape(action['description'])}</p>
              <button type="submit" class="action-button secondary">Run Task</button>
            </form>
            """
            for action in admin_actions
        )

        alerts = ""
        if status_msg:
            alerts += f'<div class="alert success">{escape(status_msg)}</div>'
        if error_msg:
            alerts += f'<div class="alert error">{escape(error_msg)}</div>'

        body = f"""
        <h1 style="margin-bottom:6px;">Analytics & Maintenance</h1>
        <p class="muted">Deep dive into submission trends and run integration tasks.</p>
        {alerts}
        <div class="grid" style="margin-top:18px;">
          <div class="card">
            <h2>Top Contributors</h2>
            <table>
              <thead><tr><th>User</th><th>Total</th><th>Phishing</th><th>Legitimate</th><th>Suspicious</th></tr></thead>
              <tbody>{contrib_rows}</tbody>
            </table>
          </div>
          <div class="card">
            <h2>Rule Coverage</h2>
            <table>
              <thead><tr><th>Rule</th><th>Type</th><th>Risk</th><th>Matches</th></tr></thead>
              <tbody>{rule_rows}</tbody>
            </table>
          </div>
        </div>
        <div class="grid" style="margin-top:16px;">
          <div class="card">
            <h2>Vote Conflicts</h2>
            <ul class="stack" style="list-style: disc; padding-left: 22px;">{conflict_cards}</ul>
          </div>
          <div class="card">
            <h2>Risk Rankings</h2>
            <table>
              <thead><tr><th>URL</th><th>Score</th><th>Risk</th><th>Votes</th><th>Agreement</th></tr></thead>
              <tbody>{risk_rows}</tbody>
            </table>
          </div>
        </div>
        <div class="card" style="margin-top:16px;">
          <h2>Rule Effectiveness</h2>
          <table>
            <thead><tr><th>Rule</th><th>Matches</th><th>Phishing</th><th>Legitimate</th><th>Accuracy %</th></tr></thead>
            <tbody>{effectiveness_rows}</tbody>
          </table>
        </div>
        <div class="card" style="margin-top:16px;">
          <h2>Data Maintenance</h2>
          <p class="muted">Execute integration scripts directly from the UI.</p>
          <div class="grid action-grid">{action_cards}</div>
        </div>
        """
        self.respond_html(
            render_page(
                "Analytics",
                body,
                user=self.current_user,
                current_path=self.path,
            )
        )

    def render_url_detail(self, url_id, query=None):
        try:
            url_id_int = int(url_id)
        except ValueError:
            self.send_error(400, "Invalid id")
            return
        data = url_details(url_id_int)
        if not data:
            self.send_error(404, "Not found")
            return
        status_msg = ""
        error_msg = ""
        if query:
            status_msg = query.get("status", [""])[0]
            error_msg = query.get("error", [""])[0]
        url_row = data["url"]
        user_vote = None
        if self.current_user:
            user_vote = get_user_vote(url_id_int, self.current_user["user_id"])
        phishing_votes = sum(1 for v in data["votes"] if v["vote_value"] == 1)
        legitimate_votes = sum(1 for v in data["votes"] if v["vote_value"] == -1)
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
        vote_panel = (
            self.render_vote_form(url_row["url_id"], user_vote)
            if self.current_user
            else "<p class='muted'>Log in to participate in voting.</p>"
        )
        alerts = ""
        if status_msg:
            alerts += f'<div class="alert success">{escape(status_msg)}</div>'
        if error_msg:
            alerts += f'<div class="alert error">{escape(error_msg)}</div>'
        body = f"""
        {alerts}
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
        <div class="card" style="margin-top:16px;">
          <div class="status-line">
            <h3 style="margin:0;">Community Voting</h3>
            <div class="muted">+{phishing_votes} / -{legitimate_votes}</div>
          </div>
          {vote_panel}
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
        self.respond_html(render_page("URL Detail", body, user=self.current_user, current_path=self.path))

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
        self.respond_html(render_page("Sign In", body, user=self.current_user, current_path=self.path))

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

    def render_vote_form(self, url_id, current_vote, compact=False):
        if not self.current_user:
            return ""
        size_class = "vote-form"
        if compact:
            size_class += " compact"
        phish_cls = "vote-btn vote-phish" + (" active" if current_vote == 1 else "")
        legit_cls = "vote-btn vote-legit" + (" active" if current_vote == -1 else "")
        phish_label = "Flag Phishing" if not compact else "+"
        legit_label = "Mark Legit" if not compact else "-"
        return f"""
        <form method="POST" action="/vote" class="{size_class}">
          <input type="hidden" name="url_id" value="{url_id}" />
          <button type="submit" name="vote_value" value="1" class="{phish_cls}" title="Mark as phishing">{phish_label}</button>
          <button type="submit" name="vote_value" value="-1" class="{legit_cls}" title="Mark as legitimate">{legit_label}</button>
        </form>
        """

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
