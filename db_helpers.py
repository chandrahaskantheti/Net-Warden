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


def search_urls(
    query_text: str = "",
    result_code: str = "",
    user_id: Optional[str] = None,
    viewer_user_id: Optional[int] = None,
):
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

    viewer_select = "NULL AS current_user_vote"
    viewer_params: list = []
    if viewer_user_id is not None:
        viewer_select = """
            (
                SELECT vote_value
                FROM votes vv
                WHERE vv.url_id = u.url_id AND vv.user_id = ?
                LIMIT 1
            ) AS current_user_vote
        """
        viewer_params.append(viewer_user_id)

    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT u.url_id, u.url, u.url_domain, u.tld, u.result_code, u.created_at,
                   usr.name AS submitter,
                   COALESCE(SUM(CASE WHEN v.vote_value = 1 THEN 1 ELSE 0 END), 0) AS phishing_votes,
                   COALESCE(SUM(CASE WHEN v.vote_value = -1 THEN 1 ELSE 0 END), 0) AS legitimate_votes,
                   {viewer_select}
            FROM url_submissions u
            JOIN users usr ON u.user_id = usr.user_id
            LEFT JOIN votes v ON u.url_id = v.url_id
            {where_clause}
            GROUP BY u.url_id, u.url, u.url_domain, u.tld, u.result_code, u.created_at, usr.name
            ORDER BY u.created_at DESC
            LIMIT 100
            """
            ,
            params + viewer_params,
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


def insert_submission(form, submitter_id: int):
    import urllib.parse

    raw_url = form.get("url", [""])[0].strip()
    if not raw_url:
        return False, "URL is required."
    if len(raw_url) > 2048 or any(ch in raw_url for ch in ("\n", "\r", ";")):
        return False, "URL contains invalid characters."
    if not submitter_id:
        return False, "Authentication required."
    result_code = form.get("result_code", ["SUSPICIOUS"])[0] or None
    domain, tld = parse_url_parts(raw_url)
    if not domain:
        return False, "Could not determine domain for URL."

    with get_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO url_submissions (user_id, url, url_domain, tld, result_code)
                VALUES (?, ?, ?, ?, ?)
                """
                ,
                (submitter_id, raw_url, domain, tld, result_code),
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


def get_contributor_stats(limit: int = 10):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT users.user_id,
                   users.name,
                   users.email,
                   users.role,
                   COUNT(url_submissions.url_id) AS total_submissions,
                   SUM(CASE WHEN url_submissions.result_code = 'PHISHING' THEN 1 ELSE 0 END) AS phishing_count,
                   SUM(CASE WHEN url_submissions.result_code = 'LEGITIMATE' THEN 1 ELSE 0 END) AS legitimate_count,
                   SUM(CASE WHEN url_submissions.result_code = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious_count
            FROM users
            LEFT JOIN url_submissions ON users.user_id = url_submissions.user_id
            WHERE users.role = 'user'
            GROUP BY users.user_id, users.name, users.email, users.role
            ORDER BY total_submissions DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_rule_usage():
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT rules.rule_id,
                   rules.rule_name,
                   rules.rule_type,
                   rules.risk_level,
                   COUNT(url_rule_matches.url_id) AS urls_matched
            FROM rules
            LEFT JOIN url_rule_matches ON rules.rule_id = url_rule_matches.rule_id
            GROUP BY rules.rule_id, rules.rule_name, rules.rule_type, rules.risk_level
            ORDER BY urls_matched DESC, rules.rule_name
            """
        ).fetchall()


def get_vote_conflicts(limit: int = 10):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT u.url_id,
                   u.url,
                   u.result_code,
                   s.label AS review_status,
                   s.description AS review_description,
                   COUNT(CASE WHEN v.vote_value = 1 THEN 1 END) AS phishing_votes,
                   COUNT(CASE WHEN v.vote_value = -1 THEN 1 END) AS legitimate_votes,
                   COUNT(v.vote_id) AS total_votes
            FROM url_submissions u
            INNER JOIN statuses s ON u.url_id = s.url_id
            LEFT JOIN votes v ON u.url_id = v.url_id
            WHERE EXISTS (
                SELECT 1
                FROM votes v2
                WHERE v2.url_id = u.url_id
                  AND v2.vote_value != (
                      SELECT CASE
                          WHEN u.result_code = 'PHISHING' THEN 1
                          WHEN u.result_code = 'LEGITIMATE' THEN -1
                          ELSE 0
                      END
                  )
            )
            GROUP BY u.url_id, u.url, u.result_code, s.label, s.description
            HAVING COUNT(v.vote_id) > 0
            ORDER BY total_votes DESC, u.url_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_risk_rankings(limit: int = 20):
    with get_connection() as conn:
        return conn.execute(
            """
            WITH url_risk_scores AS (
                SELECT u.url_id,
                       u.url,
                       u.url_domain,
                       u.result_code,
                       COALESCE(usc.avg_score, 0.5) AS risk_score,
                       usc.risk_level,
                       COUNT(v.vote_id) AS vote_count,
                       AVG(v.vote_value) AS avg_vote_value
                FROM url_submissions u
                LEFT JOIN url_score_comparisons usc ON u.url_id = usc.url_id
                LEFT JOIN votes v ON u.url_id = v.url_id
                GROUP BY u.url_id, u.url, u.url_domain, u.result_code, usc.avg_score, usc.risk_level
            )
            SELECT url_id,
                   url,
                   url_domain,
                   result_code,
                   risk_score,
                   risk_level,
                   vote_count,
                   avg_vote_value,
                   RANK() OVER (ORDER BY risk_score DESC) AS risk_rank,
                   CASE
                       WHEN avg_vote_value > 0.5 THEN 'Phishing Agreement'
                       WHEN avg_vote_value < -0.5 THEN 'Legitimate Agreement'
                       ELSE 'Uncertain'
                   END AS agreement_status
            FROM url_risk_scores
            ORDER BY risk_score DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_rule_effectiveness(limit: int = 25):
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT r.rule_id,
                   r.rule_name,
                   r.rule_type,
                   r.risk_level,
                   COUNT(DISTINCT urm.url_id) AS urls_matched,
                   COUNT(
                       DISTINCT CASE WHEN u.result_code = 'PHISHING' THEN urm.url_id END
                   ) AS phishing_matches,
                   COUNT(
                       DISTINCT CASE WHEN u.result_code = 'LEGITIMATE' THEN urm.url_id END
                   ) AS legitimate_matches,
                   ROUND(
                       CAST(
                           COUNT(
                               DISTINCT CASE WHEN u.result_code = 'PHISHING' THEN urm.url_id END
                           ) AS REAL
                       )
                       / NULLIF(COUNT(DISTINCT urm.url_id), 0) * 100,
                       2
                   ) AS phishing_accuracy_percent
            FROM rules r
            LEFT JOIN url_rule_matches urm ON r.rule_id = urm.rule_id
            LEFT JOIN url_submissions u ON urm.url_id = u.url_id
            GROUP BY r.rule_id, r.rule_name, r.rule_type, r.risk_level
            HAVING COUNT(DISTINCT urm.url_id) > 0
            ORDER BY urls_matched DESC, phishing_accuracy_percent DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()


def get_user_vote(url_id: int, user_id: int):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT vote_value FROM votes WHERE url_id = ? AND user_id = ?",
            (url_id, user_id),
        ).fetchone()
    return row["vote_value"] if row else None


def cast_vote(url_id: int, user_id: int, vote_value: int):
    if vote_value not in (-1, 1):
        return False, "Invalid vote."
    with get_connection() as conn:
        current = conn.execute(
            "SELECT vote_value FROM votes WHERE url_id = ? AND user_id = ?",
            (url_id, user_id),
        ).fetchone()
        try:
            if current and current["vote_value"] == vote_value:
                conn.execute("DELETE FROM votes WHERE url_id = ? AND user_id = ?", (url_id, user_id))
                conn.commit()
                return True, "Vote removed."
            conn.execute(
                """
                INSERT INTO votes (user_id, url_id, vote_value)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id, url_id) DO UPDATE
                SET vote_value = excluded.vote_value,
                    created_at = CURRENT_TIMESTAMP
                """,
                (user_id, url_id, vote_value),
            )
            conn.commit()
            return True, "Vote recorded."
        except sqlite3.Error as exc:
            return False, f"Could not record vote: {exc}"


def _update_results_from_votes():
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE url_submissions
            SET result_code = (
                    SELECT CASE
                        WHEN AVG(v.vote_value) > 0.3 THEN 'PHISHING'
                        WHEN AVG(v.vote_value) < -0.3 THEN 'LEGITIMATE'
                        ELSE 'SUSPICIOUS'
                    END
                    FROM votes v
                    WHERE v.url_id = url_submissions.url_id
                    GROUP BY v.url_id
                    HAVING COUNT(v.vote_id) >= 3
                ),
                updated_at = CURRENT_TIMESTAMP
            WHERE url_id IN (
                SELECT url_id
                FROM votes
                GROUP BY url_id
                HAVING COUNT(vote_id) >= 3
                   AND ABS(AVG(vote_value)) > 0.3
            )
            """
        )
        conn.commit()
        return cursor.rowcount


def _recalculate_risk_scores():
    with get_connection() as conn:
        cursor = conn.execute(
            """
            WITH url_metrics AS (
                SELECT u.url_id,
                       COUNT(DISTINCT urm.rule_id) AS rule_count,
                       AVG(
                           CASE WHEN r.risk_level = 'critical' THEN 1.0
                                WHEN r.risk_level = 'high' THEN 0.75
                                WHEN r.risk_level = 'medium' THEN 0.5
                                WHEN r.risk_level = 'low' THEN 0.25
                                ELSE 0.0
                           END
                       ) AS avg_rule_risk,
                       COUNT(DISTINCT v.vote_id) AS vote_count,
                       AVG(v.vote_value) AS avg_vote
                FROM url_submissions u
                LEFT JOIN url_rule_matches urm ON u.url_id = urm.url_id
                LEFT JOIN rules r ON urm.rule_id = r.rule_id
                LEFT JOIN votes v ON u.url_id = v.url_id
                GROUP BY u.url_id
            )
            UPDATE url_score_comparisons
            SET avg_score = (
                    SELECT (um.avg_rule_risk * 0.6 + (um.avg_vote + 1) / 2 * 0.4)
                    FROM url_metrics um
                    WHERE um.url_id = url_score_comparisons.url_id
                ),
                risk_level = (
                    SELECT CASE
                        WHEN (um.avg_rule_risk * 0.6 + (um.avg_vote + 1) / 2 * 0.4) >= 0.75 THEN 'critical'
                        WHEN (um.avg_rule_risk * 0.6 + (um.avg_vote + 1) / 2 * 0.4) >= 0.5 THEN 'high'
                        WHEN (um.avg_rule_risk * 0.6 + (um.avg_vote + 1) / 2 * 0.4) >= 0.25 THEN 'medium'
                        ELSE 'low'
                    END
                    FROM url_metrics um
                    WHERE um.url_id = url_score_comparisons.url_id
                )
            WHERE url_id IN (SELECT url_id FROM url_metrics)
            """
        )
        conn.commit()
        return cursor.rowcount


def _cleanup_inactive_urls():
    with get_connection() as conn:
        cursor = conn.execute(
            """
            DELETE FROM url_submissions
            WHERE url_id IN (
                SELECT u.url_id
                FROM url_submissions u
                WHERE u.created_at < datetime('now', '-90 days')
                  AND NOT EXISTS (SELECT 1 FROM votes v WHERE v.url_id = u.url_id)
                  AND NOT EXISTS (SELECT 1 FROM statuses s WHERE s.url_id = u.url_id)
                  AND NOT EXISTS (SELECT 1 FROM url_rule_matches urm WHERE urm.url_id = u.url_id)
            )
            """
        )
        conn.commit()
        return cursor.rowcount


def _cleanup_rule_matches():
    with get_connection() as conn:
        cursor = conn.execute(
            """
            DELETE FROM url_rule_matches
            WHERE match_id IN (
                SELECT urm.match_id
                FROM url_rule_matches urm
                LEFT JOIN url_submissions u ON urm.url_id = u.url_id
                LEFT JOIN rules r ON urm.rule_id = r.rule_id
                WHERE u.url_id IS NULL
                   OR r.rule_id IS NULL
                   OR (u.result_code = 'LEGITIMATE' AND r.risk_level IN ('high', 'critical'))
            )
            """
        )
        conn.commit()
        return cursor.rowcount


def _promote_active_users():
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET role = CASE
                WHEN (
                    SELECT COUNT(DISTINCT u.url_id)
                    FROM url_submissions u
                    WHERE u.user_id = users.user_id
                      AND u.result_code = 'PHISHING'
                ) >= 5
                AND users.role = 'user'
                THEN 'analyst'
                ELSE users.role
            END
            WHERE user_id IN (
                SELECT user_id
                FROM url_submissions
                GROUP BY user_id
                HAVING COUNT(DISTINCT url_id) >= 10
            )
            """
        )
        conn.commit()
        return cursor.rowcount


def _auto_classify_pending():
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE url_submissions
            SET result_code = COALESCE((
                    SELECT CASE
                        WHEN COUNT(urm.rule_id) >= 3 THEN 'PHISHING'
                        WHEN COUNT(urm.rule_id) >= 1 THEN 'SUSPICIOUS'
                        ELSE 'LEGITIMATE'
                    END
                    FROM url_rule_matches urm
                    WHERE urm.url_id = url_submissions.url_id
                ), 'LEGITIMATE'),
            updated_at = CURRENT_TIMESTAMP
            WHERE result_code IS NULL
        """
        )
        conn.commit()
        return cursor.rowcount


ADMIN_ACTIONS = {
    "reclassify_votes": {
        "label": "Apply vote-driven classification",
        "description": "Update URL result codes when the community vote average is decisive (Statement 12).",
        "runner": _update_results_from_votes,
    },
    "recompute_scores": {
        "label": "Recalculate blended risk scores",
        "description": "Refresh url_score_comparisons using the rule/vote weighting (Statement 16).",
        "runner": _recalculate_risk_scores,
    },
    "cleanup_urls": {
        "label": "Remove inactive submissions",
        "description": "Delete URLs older than 90 days with no votes, statuses, or rule matches (Statement 14).",
        "runner": _cleanup_inactive_urls,
    },
    "cleanup_rule_matches": {
        "label": "Clean orphaned rule matches",
        "description": "Drop rule matches referencing missing URLs/rules or benign results (Statement 18).",
        "runner": _cleanup_rule_matches,
    },
    "promote_users": {
        "label": "Promote active reporters",
        "description": "Elevate prolific phishing reporters to analyst role (Statement 19).",
        "runner": _promote_active_users,
    },
    "auto_classify_pending": {
        "label": "Auto-classify pending URLs",
        "description": "Set statuses for submissions lacking result codes based on rule matches (Statement 20).",
        "runner": _auto_classify_pending,
    },
}


def get_admin_actions():
    return [
        {"id": action_id, "label": meta["label"], "description": meta["description"]}
        for action_id, meta in ADMIN_ACTIONS.items()
    ]


def run_admin_action(action_id: str):
    action = ADMIN_ACTIONS.get(action_id)
    if not action:
        return False, "Unknown maintenance task."
    runner = action["runner"]
    try:
        affected = runner()
    except sqlite3.Error as exc:
        return False, f"Could not execute action: {exc}"
    return True, f"{action['label']} complete. Rows affected: {affected}."
