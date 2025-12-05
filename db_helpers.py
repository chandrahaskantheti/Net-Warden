from datetime import datetime
import hashlib
import hmac
import secrets
import sqlite3
from pathlib import Path
from typing import Optional, Tuple

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "database" / "net_warden.db"
PASSWORD_SCHEME = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 390000


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password: str) -> str:
    """Return a salted PBKDF2 hash for storage."""

    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"{PASSWORD_SCHEME}${PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    if not encoded:
        return False
    try:
        scheme, iter_str, salt_hex, hash_hex = encoded.split("$")
    except ValueError:
        return False
    if scheme != PASSWORD_SCHEME:
        return False
    try:
        iterations = int(iter_str)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, TypeError):
        return False
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived.hex(), hash_hex)


def get_user_by_email(email: str):
    with get_connection() as conn:
        return conn.execute(
            "SELECT user_id, name, email, role, password_hash FROM users WHERE LOWER(email) = LOWER(?)",
            (email,),
        ).fetchone()


def verify_user_credentials(email: str, password: str):
    row = get_user_by_email(email)
    if not row:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return row


def set_user_password(user_id: int, password: str):
    encoded = hash_password(password)
    with get_connection() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE user_id = ?", (encoded, user_id))
        conn.commit()
    return encoded


def parse_url_parts(raw_url: str) -> Tuple[str, Optional[str]]:
    import urllib.parse

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


def search_urls(query_text: str = "", result_code: str = "", user_id: Optional[str] = None):
    query_text = f"%{query_text.lower()}%" if query_text else "%"
    where_clause = """
        WHERE (LOWER(u.url) LIKE ? OR LOWER(u.url_domain) LIKE ?)
    """
    params = [query_text, query_text]
    if result_code:
        where_clause += " AND u.result_code = ?"
        params.append(result_code)
    if user_id:
        where_clause += " AND u.user_id = ?"
        params.append(user_id)

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


def status_counts(query_text: str = "", user_id: Optional[str] = None):
    query_text = f"%{query_text.lower()}%" if query_text else "%"
    where_clause = """
        WHERE (LOWER(u.url) LIKE ? OR LOWER(u.url_domain) LIKE ?)
    """
    params = [query_text, query_text]
    if user_id:
        where_clause += " AND u.user_id = ?"
        params.append(user_id)
    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT u.result_code, COUNT(*) as count
            FROM url_submissions u
            {where_clause}
            GROUP BY u.result_code
            """
            ,
            params,
        ).fetchall()
    return {row["result_code"] or "": row["count"] for row in rows}


def user_counts(query_text: str = "", result_code: str = ""):
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
            SELECT u.user_id, COUNT(*) as count
            FROM url_submissions u
            {where_clause}
            GROUP BY u.user_id
            """
            ,
            params,
        ).fetchall()
    return {row["user_id"]: row["count"] for row in rows}


def url_details(url_id: int):
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
    import urllib.parse

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
                """
                ,
                (user_id, raw_url, domain, tld, result_code),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            return False, f"Could not save URL: {exc}"
        new_id = conn.execute(
            "SELECT url_id FROM url_submissions WHERE url = ?", (raw_url,)
        ).fetchone()[0]
    return True, new_id


def delete_submission(url_id: int):
    with get_connection() as conn:
        try:
            conn.execute("DELETE FROM votes WHERE url_id = ?", (url_id,))
            conn.execute("DELETE FROM statuses WHERE url_id = ?", (url_id,))
            conn.execute("DELETE FROM url_rule_matches WHERE url_id = ?", (url_id,))
            conn.execute("DELETE FROM url_score_comparisons WHERE url_id = ?", (url_id,))
            conn.execute("DELETE FROM url_submissions WHERE url_id = ?", (url_id,))
            conn.commit()
        except sqlite3.Error as exc:
            return False, f"Could not delete URL: {exc}"
    return True, None
