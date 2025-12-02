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
import os
from pathlib import Path
import sqlite3
import sys
import urllib.parse

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "database" / "net_warden.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def escape(value):
    if value is None:
        return ""
    return html.escape(str(value))


def parse_url_parts(raw_url):
    """Extract domain and TLD from a URL string."""
    parsed = urllib.parse.urlparse(raw_url)
    domain = parsed.hostname or raw_url
    tld = None
    if domain and "." in domain:
        tld = "." + domain.split(".")[-1]
    return domain, tld


def dashboard_data():
    with get_connection() as conn:
        total_urls = conn.execute("SELECT COUNT(*) FROM url_submissions").fetchone()[0]
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_rules = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        result_counts = conn.execute(
            "SELECT result_code, COUNT(*) as count FROM url_submissions GROUP BY result_code"
        ).fetchall()
        recent_urls = conn.execute(
            """
            SELECT u.url_id, u.url, u.url_domain, u.result_code, u.created_at,
                   usr.name AS submitter,
                   COALESCE(SUM(CASE WHEN v.vote_value = 1 THEN 1 ELSE 0 END), 0) AS phishing_votes,
                   COALESCE(SUM(CASE WHEN v.vote_value = -1 THEN 1 ELSE 0 END), 0) AS legitimate_votes
            FROM url_submissions u
            JOIN users usr ON u.user_id = usr.user_id
            LEFT JOIN votes v ON u.url_id = v.url_id
            GROUP BY u.url_id, u.url, u.url_domain, u.result_code, u.created_at, usr.name
            ORDER BY u.created_at DESC
            LIMIT 5
            """
        ).fetchall()
    return {
        "total_urls": total_urls,
        "total_users": total_users,
        "total_rules": total_rules,
        "result_counts": result_counts,
        "recent_urls": recent_urls,
    }


def search_urls(query_text="", result_code=""):
    query_text = f"%{query_text.lower()}%" if query_text else "%"
    where_clause = """
        WHERE (LOWER(u.url) LIKE ? OR LOWER(u.url_domain) LIKE ?)
    """
    params = [query_text, query_text]
    if result_code:
        where_clause += " AND u.result_code = ?"
        params.append(result_code)

    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT u.url_id, u.url, u.url_domain, u.tld, u.result_code, u.created_at,
                   usr.name AS submitter,
                   COALESCE(SUM(CASE WHEN v.vote_value = 1 THEN 1 ELSE 0 END), 0) AS phishing_votes,
                   COALESCE(SUM(CASE WHEN v.vote_value = -1 THEN 1 ELSE 0 END), 0) AS legitimate_votes
            FROM url_submissions u
            JOIN users usr ON u.user_id = usr.user_id
            LEFT JOIN votes v ON u.url_id = v.url_id
            {where_clause}
            GROUP BY u.url_id, u.url, u.url_domain, u.tld, u.result_code, u.created_at, usr.name
            ORDER BY u.created_at DESC
            LIMIT 100
            """
            ,
            params,
        ).fetchall()
        users = conn.execute(
            "SELECT user_id, name, email, role FROM users ORDER BY role, name"
        ).fetchall()
    return rows, users


def url_details(url_id):
    with get_connection() as conn:
        url_row = conn.execute(
            """
            SELECT u.*, usr.name AS submitter_name, usr.email AS submitter_email, usr.role AS submitter_role
            FROM url_submissions u
            JOIN users usr ON u.user_id = usr.user_id
            WHERE u.url_id = ?
            """,
            (url_id,),
        ).fetchone()
        if not url_row:
            return None
        rules = conn.execute(
            """
            SELECT r.rule_name, r.risk_level, r.rule_type, urm.match_details, urm.matched_at
            FROM url_rule_matches urm
            JOIN rules r ON urm.rule_id = r.rule_id
            WHERE urm.url_id = ?
            ORDER BY r.risk_level DESC, r.rule_name
            """,
            (url_id,),
        ).fetchall()
        statuses = conn.execute(
            """
            SELECT s.label, s.result_code, s.description, s.created_at, reviewer.name AS reviewer_name
            FROM statuses s
            LEFT JOIN users reviewer ON s.reviewer_id = reviewer.user_id
            WHERE s.url_id = ?
            ORDER BY s.created_at DESC
            """,
            (url_id,),
        ).fetchall()
        votes = conn.execute(
            """
            SELECT usr.name, usr.role, v.vote_value, v.created_at
            FROM votes v
            JOIN users usr ON v.user_id = usr.user_id
            WHERE v.url_id = ?
            ORDER BY v.created_at DESC
            """,
            (url_id,),
        ).fetchall()
        scores = conn.execute(
            """
            SELECT external_source, avg_score, online_score, risk_level, created_at
            FROM url_score_comparisons
            WHERE url_id = ?
            ORDER BY created_at DESC
            """,
            (url_id,),
        ).fetchall()
    return {
        "url": url_row,
        "rules": rules,
        "statuses": statuses,
        "votes": votes,
        "scores": scores,
    }


def insert_submission(form):
    raw_url = form.get("url", [""])[0].strip()
    if not raw_url:
        return False, "URL is required."
    try:
        user_id = int(form.get("user_id", [0])[0])
    except ValueError:
        return False, "Invalid user."
    result_code = form.get("result_code", ["SUSPICIOUS"])[0] or None
    domain, tld = parse_url_parts(raw_url)

    with get_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO url_submissions (user_id, url, url_domain, tld, result_code)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, raw_url, domain, tld, result_code),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            return False, f"Could not save URL: {exc}"
        new_id = conn.execute(
            "SELECT url_id FROM url_submissions WHERE url = ?", (raw_url,)
        ).fetchone()[0]
    return True, new_id


def format_datetime(value):
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return str(value)


def render_page(title, body):
    nav = """
    <header class="topbar">
      <div class="brand">Net-Warden</div>
      <nav>
        <a href="/">Dashboard</a>
        <a href="/urls">URLs</a>
        <a class="pill" href="/urls#submit">Submit URL</a>
      </nav>
    </header>
    """
    styles = """
    <style>
      :root {
        --bg: #0d1b2a;
        --panel: #13263a;
        --accent: #4fd1c5;
        --text: #e8f1f2;
        --muted: #94a6b8;
        --danger: #f56565;
        --success: #5ac8a1;
        --border: #1f3a52;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: "Gill Sans", "Segoe UI", "Trebuchet MS", sans-serif;
        background: radial-gradient(circle at 10% 20%, rgba(79,209,197,0.15), transparent 25%),
                    radial-gradient(circle at 90% 20%, rgba(245,101,101,0.12), transparent 25%),
                    var(--bg);
        color: var(--text);
        min-height: 100vh;
      }
      .topbar {
        position: sticky;
        top: 0;
        z-index: 10;
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 14px 24px;
        background: rgba(13,27,42,0.9);
        backdrop-filter: blur(6px);
        border-bottom: 1px solid var(--border);
      }
      .brand { font-weight: 700; letter-spacing: 0.8px; }
      nav a {
        color: var(--text);
        margin-left: 12px;
        text-decoration: none;
        padding: 8px 12px;
        border-radius: 10px;
        border: 1px solid transparent;
        transition: all 0.15s ease;
      }
      nav a:hover { border-color: var(--accent); color: var(--accent); }
      nav a.pill { background: var(--accent); color: #0d1b2a; font-weight: 600; }
      .shell {
        max-width: 1100px;
        margin: 24px auto 64px;
        padding: 0 20px;
      }
      h1, h2, h3 { margin: 6px 0 12px; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
      .card {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 16px;
        box-shadow: 0 8px 20px rgba(0,0,0,0.2);
      }
      .muted { color: var(--muted); font-size: 0.9rem; }
      table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
      }
      th, td {
        padding: 10px 8px;
        border-bottom: 1px solid var(--border);
        text-align: left;
      }
      th { color: var(--muted); font-size: 0.9rem; }
      .pill-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 999px;
        font-size: 0.85rem;
        font-weight: 600;
        border: 1px solid var(--border);
      }
      .tag-success { background: rgba(90,200,161,0.15); color: var(--success); }
      .tag-danger { background: rgba(245,101,101,0.15); color: var(--danger); }
      .tag-warn { background: rgba(255,184,0,0.16); color: #ffd166; }
      form { display: grid; gap: 12px; }
      label { display: block; font-weight: 600; margin-bottom: 6px; }
      input[type="text"], select, textarea {
        width: 100%;
        background: #0f1f33;
        border: 1px solid var(--border);
        border-radius: 10px;
        color: var(--text);
        padding: 10px 12px;
      }
      button {
        background: var(--accent);
        color: #0d1b2a;
        border: none;
        border-radius: 10px;
        padding: 10px 14px;
        font-weight: 700;
        cursor: pointer;
        box-shadow: 0 8px 16px rgba(79,209,197,0.25);
        transition: transform 0.1s ease;
      }
      button:hover { transform: translateY(-1px); }
      .stack { display: grid; gap: 12px; }
      .flex { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
      .status-line { display: flex; justify-content: space-between; align-items: center; }
      .error { color: var(--danger); font-weight: 600; }
      @media (max-width: 640px) {
        nav a { margin-left: 6px; padding: 6px 10px; }
        .topbar { flex-direction: column; align-items: flex-start; gap: 8px; }
      }
    </style>
    """
    return f"""<!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>{html.escape(title)}</title>
      {styles}
    </head>
    <body>
      {nav}
      <main class="shell">
        {body}
      </main>
    </body>
    </html>
    """


class NetWardenHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/":
            self.render_dashboard()
        elif path == "/urls":
            self.render_urls(query)
        elif path.startswith("/url/"):
            url_id = path.split("/")[-1]
            self.render_url_detail(url_id)
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/submit":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            form = urllib.parse.parse_qs(body)
            ok, result = insert_submission(form)
            if ok:
                self.send_response(303)
                self.send_header("Location", f"/url/{result}")
                self.end_headers()
            else:
                query = urllib.parse.urlencode({"error": result})
                self.send_response(303)
                self.send_header("Location", f"/urls?{query}#submit")
                self.end_headers()
        else:
            self.send_error(404, "Not Found")

    def render_dashboard(self):
        data = dashboard_data()
        counts_html = "".join(
            f'<div class="card"><div class="muted">{escape(row["result_code"] or "UNKNOWN")}</div><div style="font-size:2rem;font-weight:700;">{row["count"]}</div></div>'
            for row in data["result_counts"]
        )
        recent_rows = "".join(
            f"""
            <tr>
              <td><a href="/url/{row['url_id']}">{escape(row['url'])}</a>
                <div class="muted">{escape(row['url_domain'])}</div>
              </td>
              <td>{self.render_status_badge(row['result_code'])}</td>
              <td>{escape(row['submitter'])}</td>
              <td>{format_datetime(row['created_at'])}</td>
              <td class="muted">+{row['phishing_votes']} / -{row['legitimate_votes']}</td>
            </tr>
            """
            for row in data["recent_urls"]
        )
        body = f"""
        <h1>Security Pulse</h1>
        <p class="muted">Live view of the phishing URL dataset.</p>
        <div class="grid" style="margin-top:10px;">
          <div class="card">
            <div class="muted">Total URLs</div>
            <div style="font-size:2.4rem;font-weight:700;">{data['total_urls']}</div>
          </div>
          <div class="card">
            <div class="muted">Users</div>
            <div style="font-size:2.4rem;font-weight:700;">{data['total_users']}</div>
          </div>
          <div class="card">
            <div class="muted">Rules</div>
            <div style="font-size:2.4rem;font-weight:700;">{data['total_rules']}</div>
          </div>
          {counts_html}
        </div>
        <div class="card" style="margin-top:18px;">
          <div class="status-line">
            <h2>Recent URLs</h2>
            <a href="/urls" style="color:var(--accent);text-decoration:none;">View all</a>
          </div>
          <table>
            <thead><tr><th>URL</th><th>Status</th><th>Submitter</th><th>Submitted</th><th>Votes</th></tr></thead>
            <tbody>{recent_rows or '<tr><td colspan="5" class="muted">No data yet.</td></tr>'}</tbody>
          </table>
        </div>
        """
        self.respond_html(render_page("Net-Warden Dashboard", body))

    def render_urls(self, query):
        q = query.get("q", [""])[0]
        result_code = query.get("result_code", [""])[0]
        error = query.get("error", [""])[0]
        rows, users = search_urls(q, result_code)
        options = "".join(
            f'<option value="{escape(user["user_id"])}">{escape(user["name"])} — {escape(user["role"])}</option>'
            for user in users
        )
        table_rows = "".join(
            f"""
            <tr>
              <td><a href="/url/{row['url_id']}">{escape(row['url'])}</a>
                <div class="muted">{escape(row['url_domain'])}</div>
              </td>
              <td>{self.render_status_badge(row['result_code'])}</td>
              <td>{escape(row['submitter'])}</td>
              <td>{format_datetime(row['created_at'])}</td>
              <td class="muted">+{row['phishing_votes']} / -{row['legitimate_votes']}</td>
            </tr>
            """
            for row in rows
        )
        body = f"""
        <div class="grid">
          <div class="card">
            <h2>Filter URLs</h2>
            <form method="GET">
              <div>
                <label for="q">Search domain or URL</label>
                <input type="text" id="q" name="q" value="{escape(q)}" placeholder="paypal, .tk, bit.ly" />
              </div>
              <div>
                <label for="result_code">Status</label>
                <select id="result_code" name="result_code">
                  <option value="">Any</option>
                  <option value="PHISHING" {"selected" if result_code == "PHISHING" else ""}>Phishing</option>
                  <option value="LEGITIMATE" {"selected" if result_code == "LEGITIMATE" else ""}>Legitimate</option>
                  <option value="SUSPICIOUS" {"selected" if result_code == "SUSPICIOUS" else ""}>Suspicious</option>
                </select>
              </div>
              <button type="submit">Apply</button>
            </form>
          </div>
          <div class="card" id="submit">
            <h2>Submit URL</h2>
            <form method="POST" action="/submit">
              <div>
                <label for="url">URL</label>
                <input type="text" id="url" name="url" required placeholder="https://example.com/login" />
              </div>
              <div>
                <label for="user_id">Submitter</label>
                <select id="user_id" name="user_id" required>
                  <option value="">Pick a user</option>
                  {options}
                </select>
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
              <button type="submit">Save</button>
            </form>
            {f'<p class="error" style="margin-top:10px;">{escape(error)}</p>' if error else ''}
          </div>
        </div>
        <div class="card" style="margin-top:18px;">
          <div class="status-line">
            <h2>Results</h2>
            <div class="muted">{len(rows)} rows</div>
          </div>
          <table>
            <thead><tr><th>URL</th><th>Status</th><th>Submitter</th><th>Submitted</th><th>Votes</th></tr></thead>
            <tbody>{table_rows or '<tr><td colspan="5" class="muted">No URLs found.</td></tr>'}</tbody>
          </table>
        </div>
        """
        self.respond_html(render_page("URLs", body))

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
        self.respond_html(render_page("URL Detail", body))

    def render_status_badge(self, code):
        label = code or "UNKNOWN"
        css = "pill-badge tag-warn"
        if label.upper() == "PHISHING":
            css = "pill-badge tag-danger"
        elif label.upper() == "LEGITIMATE":
            css = "pill-badge tag-success"
        return f'<span class="{css}">{escape(label)}</span>'

    def respond_html(self, content):
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


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
