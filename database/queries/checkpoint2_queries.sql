-- Project Checkpoint 2: SQL Queries and Data Modification Statements
-- Net-Warden Phishing Detection System
-- Total: 20 SQL statements showing different query formats and structure

-- Breakdown:
-- - Queries 1-10: SELECT statements that retrieve and analyze data CRUD ops
-- - Statements 11-20: Statements that add, update, or delete data CRUD

-- These statements support the following features:
-- - Submit URL, View URL Details, Filter/Search URLs, Export Data
-- - Report Suspicious URL (Voting), Manage Records (Admin operations)
-- - View URL History, Update URL Status, Delete URL Records

PRAGMA foreign_keys = ON;

-- see user by role
SELECT name, role
FROM users
ORDER BY role, name;

-- see which URLs are marked as PHISHING
SELECT url, result_code 
FROM url_submissions
WHERE result_code = 'PHISHING';

-- see the count of URLs by result code (how many are legit, phishing, suspicious)
SELECT result_code, COUNT(*) AS count
FROM url_submissions
GROUP BY result_code;



-- see which user roles have the most submissions and their distributions

-- initial
-- SELECT users.name, users.email, COUNT(*) AS submissions
-- FROM users
-- JOIN url_submissions u ON users.user_id = u.user_id
-- GROUP BY users.user_id, users.name, users.email
-- ORDER BY submissions DESC;

-- after revision
SELECT users.user_id, users.role, users.name, users.email, COUNT(url_submissions.url_id) AS total_submissions,
SUM(CASE WHEN url_submissions.result_code = 'PHISHING' THEN 1 ELSE 0 END) AS phishing_count,
SUM(CASE WHEN url_submissions.result_code = 'LEGITIMATE' THEN 1 ELSE 0 END) AS legitimate_count,
SUM(CASE WHEN url_submissions.result_code = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious_count

FROM users
LEFT JOIN url_submissions ON users.user_id = url_submissions.user_id
where users.role='user'
GROUP BY users.user_id, users.name, users.email
ORDER BY total_submissions DESC;


-- see how many url matches thre are for each rule (good for analysis and supplying chart data)
SELECT rules.rule_name, COUNT(url_rule_matches.url_id) AS urls_matched
FROM rules
LEFT JOIN url_rule_matches ON rules.rule_id = url_rule_matches.rule_id
GROUP BY rules.rule_id ORDER BY urls_matched DESC;


-- see the votes distribution by the submitted urls (see how many having phishing vs legitimate votes)
SELECT 
url_submissions.url,
SUM(CASE WHEN votes.vote_value = 1 THEN 1 ELSE 0 END) AS phishing_votes,
SUM(CASE WHEN votes.vote_value = -1 THEN 1 ELSE 0 END) AS legitimate_votes
FROM url_submissions
LEFT JOIN votes ON url_submissions.url_id = votes.url_id
GROUP BY url_submissions.url_id;





-- Use Case: View URL Details
-- this lets us verify that were collecting the data correctly (ie url_domain is getting the correct domain, tld is taking the correct tld, result code is right)
SELECT 
    u.url_id,
    u.url,
    u.url_domain,
    u.tld,
    u.result_code,
    usr.name AS submitter_name,
    usr.email AS submitter_email,
    COUNT(urm.rule_id) AS matched_rules_count,
    GROUP_CONCAT(r.rule_name, ', ') AS matched_rule_names,
    u.created_at,
    u.updated_at
FROM url_submissions u
INNER JOIN users usr ON u.user_id = usr.user_id
LEFT JOIN url_rule_matches urm ON u.url_id = urm.url_id
LEFT JOIN rules r ON urm.rule_id = r.rule_id
GROUP BY u.url_id, u.url, u.url_domain, u.tld, u.result_code, usr.name, usr.email, u.created_at, u.updated_at
ORDER BY u.created_at DESC;

-- Query 2: Find URLs that have been reviewed but have conflicting votes
-- Use Case: View URL Details, Filter URLs
SELECT 
    u.url_id,
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
HAVING COUNT(v.vote_id) > 0;

-- Query 3: Rank URLs by risk score and show voting agreement
-- Use Case: Filter and Search URLs, Export Data
WITH url_risk_scores AS (
    SELECT 
        u.url_id,
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
SELECT 
    url_id,
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
ORDER BY risk_score DESC;

-- Query 4: Detailed URL analysis report
-- Use Case: View URL Details, Export Data
SELECT 
    u.url_id,
    u.url,
    u.url_domain,
    u.tld,
    u.result_code,
    COUNT(DISTINCT urm.rule_id) AS rules_triggered,
    COUNT(DISTINCT v.user_id) AS voters_count,
    COUNT(DISTINCT s.status_id) AS review_count,
    MAX(s.created_at) AS last_review_date,
    CASE 
        WHEN COUNT(DISTINCT urm.rule_id) >= 3 THEN 'High Risk'
        WHEN COUNT(DISTINCT urm.rule_id) >= 2 THEN 'Medium Risk'
        WHEN COUNT(DISTINCT urm.rule_id) = 1 THEN 'Low Risk'
        ELSE 'No Rules Matched'
    END AS risk_assessment,
    COALESCE(usc.avg_score, 0.0) AS external_score
FROM url_submissions u
LEFT JOIN url_rule_matches urm ON u.url_id = urm.url_id
LEFT JOIN votes v ON u.url_id = v.url_id
LEFT JOIN statuses s ON u.url_id = s.url_id
LEFT JOIN url_score_comparisons usc ON u.url_id = usc.url_id
GROUP BY u.url_id, u.url, u.url_domain, u.tld, u.result_code, usc.avg_score
HAVING COUNT(DISTINCT urm.rule_id) > 0 OR COUNT(DISTINCT v.user_id) > 0;

-- Query 5: Find users who submitted URLs with highest rule match counts
-- Use Case: Filter and Search URLs
SELECT 
    usr.user_id,
    usr.name,
    usr.email,
    usr.role,
    COUNT(DISTINCT u.url_id) AS urls_submitted,
    SUM(rule_counts.matched_rules) AS total_rule_matches,
    AVG(rule_counts.matched_rules) AS avg_rules_per_url
FROM users usr
INNER JOIN url_submissions u ON usr.user_id = u.user_id
INNER JOIN (
    SELECT 
        url_id,
        COUNT(rule_id) AS matched_rules
    FROM url_rule_matches
    GROUP BY url_id
) rule_counts ON u.url_id = rule_counts.url_id
WHERE usr.role = 'user'
GROUP BY usr.user_id, usr.name, usr.email, usr.role
HAVING COUNT(DISTINCT u.url_id) > 0
ORDER BY total_rule_matches DESC;

-- Query 6: Combine phishing and suspicious URLs with different search criteria
-- Use Case: Filter and Search URLs
SELECT 
    'High_Risk_Phishing' AS category,
    u.url_id,
    u.url,
    u.url_domain,
    u.result_code,
    COUNT(urm.rule_id) AS rule_count
FROM url_submissions u
INNER JOIN url_rule_matches urm ON u.url_id = urm.url_id
INNER JOIN rules r ON urm.rule_id = r.rule_id
WHERE u.result_code = 'PHISHING' AND r.risk_level IN ('high', 'critical')
GROUP BY u.url_id, u.url, u.url_domain, u.result_code
HAVING COUNT(urm.rule_id) >= 2

UNION

SELECT 
    'Suspicious_TLD' AS category,
    u.url_id,
    u.url,
    u.url_domain,
    u.result_code,
    COUNT(urm.rule_id) AS rule_count
FROM url_submissions u
INNER JOIN url_rule_matches urm ON u.url_id = urm.url_id
INNER JOIN rules r ON urm.rule_id = r.rule_id
WHERE u.tld IN ('.tk', '.ml', '.ga') OR r.rule_type = 'tld'
GROUP BY u.url_id, u.url, u.url_domain, u.result_code
ORDER BY category, rule_count DESC;

-- Query 7: URL history with review timeline
-- Use Case: View URL History
SELECT 
    u.url_id,
    u.url,
    u.result_code,
    u.created_at AS submission_date,
    s.status_id,
    s.label AS status_label,
    s.result_code AS review_result,
    reviewer.name AS reviewer_name,
    reviewer.role AS reviewer_role,
    s.created_at AS review_date,
    JULIANDAY(s.created_at) - JULIANDAY(u.created_at) AS days_between_submission_and_review
FROM url_submissions u
LEFT JOIN statuses s ON u.url_id = s.url_id
LEFT JOIN users reviewer ON s.reviewer_id = reviewer.user_id
WHERE u.created_at >= datetime('now', '-30 days')
    AND (s.reviewer_id IS NOT NULL OR u.result_code IS NOT NULL)
ORDER BY u.created_at DESC, s.created_at DESC;

-- Query 9: Rule effectiveness analysis - see how well each rule detects phishing
-- Use Case: Export Data (Analytics)
SELECT 
    r.rule_id,
    r.rule_name,
    r.rule_type,
    r.risk_level,
    COUNT(DISTINCT urm.url_id) AS urls_matched,
    COUNT(DISTINCT CASE WHEN u.result_code = 'PHISHING' THEN urm.url_id END) AS phishing_matches,
    COUNT(DISTINCT CASE WHEN u.result_code = 'LEGITIMATE' THEN urm.url_id END) AS legitimate_matches,
    ROUND(
        CAST(COUNT(DISTINCT CASE WHEN u.result_code = 'PHISHING' THEN urm.url_id END) AS REAL) / 
        NULLIF(COUNT(DISTINCT urm.url_id), 0) * 100, 
        2
    ) AS phishing_accuracy_percent
FROM rules r
LEFT JOIN url_rule_matches urm ON r.rule_id = urm.rule_id
LEFT JOIN url_submissions u ON urm.url_id = u.url_id
GROUP BY r.rule_id, r.rule_name, r.rule_type, r.risk_level
HAVING COUNT(DISTINCT urm.url_id) > 0
ORDER BY urls_matched DESC, phishing_accuracy_percent DESC;

-- Query 10: Rank URLs by submission date within each TLD
-- Use Case: Filter and Search URLs
SELECT 
    url_id,
    url,
    url_domain,
    tld,
    result_code,
    created_at,
    ROW_NUMBER() OVER (PARTITION BY tld ORDER BY created_at DESC) AS submission_rank_in_tld,
    COUNT(*) OVER (PARTITION BY tld) AS total_submissions_in_tld
FROM url_submissions
WHERE tld IS NOT NULL
ORDER BY tld, created_at DESC;

-- Statement 11: Submit new URL and automatically link matching rules
-- Use Case: Submit URL for Analysis
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code)
VALUES (
    3, 
    'https://secure-verify-account-update.tk/login',
    'secure-verify-account-update.tk',
    '.tk',
    'PHISHING'
);

-- Insert matching rules for the newly submitted URL
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details)
SELECT 
    (SELECT MAX(url_id) FROM url_submissions WHERE url = 'https://secure-verify-account-update.tk/login'),
    rule_id,
    'Auto-matched based on URL pattern analysis'
FROM rules
WHERE rule_id IN (
    SELECT rule_id FROM rules 
    WHERE rule_name = 'Suspicious Keywords' 
       OR rule_name = 'Suspicious TLD'
       OR (rule_type = 'keyword' AND pattern LIKE '%verify%')
);

-- Verification: Show the inserted URL and its matched rules
SELECT 'Statement 11 Result: New URL submitted with matched rules' AS status;
SELECT u.url_id, u.url, u.result_code, COUNT(urm.rule_id) AS rules_matched
FROM url_submissions u
LEFT JOIN url_rule_matches urm ON u.url_id = urm.url_id
WHERE u.url = 'https://secure-verify-account-update.tk/login'
GROUP BY u.url_id, u.url, u.result_code;

-- Statement 12: Update URL status based on voting agreement
-- Use Case: Update URL Status, Manage Records
UPDATE url_submissions
SET result_code = (
    SELECT 
        CASE 
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
);

-- Verification: Show updated URLs
SELECT 'Statement 12 Result: URLs updated based on voting' AS status;
SELECT url_id, url, result_code, updated_at 
FROM url_submissions 
WHERE updated_at >= datetime('now', '-1 minute')
ORDER BY updated_at DESC
LIMIT 5;

-- Statement 13: Update reviewer information for statuses reviewed by specific admin
-- Use Case: Manage Records, Update URL Status
UPDATE statuses
SET description = description || ' | Updated by system based on agreement threshold',
    result_code = (
        SELECT result_code 
        FROM url_submissions 
        WHERE url_submissions.url_id = statuses.url_id
    )
WHERE reviewer_id IN (
    SELECT user_id 
    FROM users 
    WHERE role = 'admin'
)
AND status_id IN (
    SELECT s.status_id
    FROM statuses s
    INNER JOIN url_submissions u ON s.url_id = u.url_id
    INNER JOIN votes v ON u.url_id = v.url_id
    GROUP BY s.status_id
    HAVING COUNT(v.vote_id) >= 2
);

-- Verification: Show updated statuses
SELECT 'Statement 13 Result: Statuses updated by admin review' AS status;
SELECT s.status_id, s.url_id, s.label, s.result_code, s.description
FROM statuses s
WHERE s.description LIKE '%Updated by system%'
ORDER BY s.created_at DESC
LIMIT 5;

-- Statement 14: Remove old URL submissions that have no activity
-- Use Case: Delete URL Record, Manage Records
DELETE FROM url_submissions
WHERE url_id IN (
    SELECT u.url_id
    FROM url_submissions u
    WHERE u.created_at < datetime('now', '-90 days')
    AND NOT EXISTS (
        SELECT 1 FROM votes v WHERE v.url_id = u.url_id
    )
    AND NOT EXISTS (
        SELECT 1 FROM statuses s WHERE s.url_id = u.url_id
    )
    AND NOT EXISTS (
        SELECT 1 FROM url_rule_matches urm WHERE urm.url_id = u.url_id
    )
);

-- Verification: Show count of remaining URLs
SELECT 'Statement 14 Result: Old inactive URLs removed' AS status;
SELECT COUNT(*) AS remaining_urls FROM url_submissions;
SELECT COUNT(*) AS urls_with_votes FROM url_submissions u WHERE EXISTS (SELECT 1 FROM votes v WHERE v.url_id = u.url_id);

-- Statement 15: Add new rule and create test matches
-- Use Case: Manage Records (Admin)
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld)
VALUES ('Suspicious Subdomain Count', 'Detects URLs with excessive subdomain levels', '^https?://([^/]+\.){4,}', 'regex', 'medium', NULL);

-- Insert rule matches for existing URLs that match the new rule
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details)
SELECT 
    u.url_id,
    (SELECT rule_id FROM rules WHERE rule_name = 'Suspicious Subdomain Count'),
    'Matched: Multiple subdomain levels detected'
FROM url_submissions u
WHERE LENGTH(u.url) - LENGTH(REPLACE(u.url_domain, '.', '')) >= 4;

-- Verification: Show the new rule and its matches
SELECT 'Statement 15 Result: New rule added and matched to URLs' AS status;
SELECT r.rule_id, r.rule_name, COUNT(urm.url_id) AS urls_matched
FROM rules r
LEFT JOIN url_rule_matches urm ON r.rule_id = urm.rule_id
WHERE r.rule_name = 'Suspicious Subdomain Count'
GROUP BY r.rule_id, r.rule_name;

-- Statement 16: Recalculate and update risk scores based on current data
-- Use Case: Update URL Status
WITH url_metrics AS (
    SELECT 
        u.url_id,
        COUNT(DISTINCT urm.rule_id) AS rule_count,
        AVG(CASE WHEN r.risk_level = 'critical' THEN 1.0
                 WHEN r.risk_level = 'high' THEN 0.75
                 WHEN r.risk_level = 'medium' THEN 0.5
                 WHEN r.risk_level = 'low' THEN 0.25
                 ELSE 0.0 END) AS avg_rule_risk,
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
WHERE url_id IN (SELECT url_id FROM url_metrics);

-- Verification: Show updated risk scores
SELECT 'Statement 16 Result: Risk scores recalculated' AS status;
SELECT url_id, avg_score, risk_level, external_source
FROM url_score_comparisons
ORDER BY avg_score DESC
LIMIT 5;

-- Statement 17: Create status review based on voting agreement
-- Use Case: Report Suspicious URL, Update URL Status
INSERT OR IGNORE INTO statuses (url_id, reviewer_id, result_code, label, description)
SELECT 
    v.url_id,
    (SELECT user_id FROM users WHERE role = 'admin' LIMIT 1) AS reviewer_id,
    CASE 
        WHEN AVG(v.vote_value) > 0.5 THEN 'PHISHING'
        WHEN AVG(v.vote_value) < -0.5 THEN 'LEGITIMATE'
        ELSE 'SUSPICIOUS'
    END AS result_code,
    CASE 
        WHEN AVG(v.vote_value) > 0.5 THEN 'Community Confirmed Phishing'
        WHEN AVG(v.vote_value) < -0.5 THEN 'Community Confirmed Legitimate'
        ELSE 'Under Community Review'
    END AS label,
    'Automated status update based on ' || COUNT(v.vote_id) || ' community votes. Average vote: ' || ROUND(AVG(v.vote_value), 2) AS description
FROM votes v
WHERE v.url_id NOT IN (
    SELECT url_id FROM statuses WHERE created_at > datetime('now', '-1 day')
)
GROUP BY v.url_id
HAVING COUNT(v.vote_id) >= 2;

-- Verification: Show newly created statuses
SELECT 'Statement 17 Result: Statuses created from voting agreement' AS status;
SELECT s.status_id, s.url_id, s.label, s.result_code, s.description
FROM statuses s
WHERE s.label LIKE '%Community%'
ORDER BY s.created_at DESC
LIMIT 5;

-- Statement 18: Clean up unlinked rule matches
-- Use Case: Manage Records, Delete URL Record
DELETE FROM url_rule_matches
WHERE match_id IN (
    SELECT urm.match_id
    FROM url_rule_matches urm
    LEFT JOIN url_submissions u ON urm.url_id = u.url_id
    LEFT JOIN rules r ON urm.rule_id = r.rule_id
    WHERE u.url_id IS NULL OR r.rule_id IS NULL
    OR (u.result_code = 'LEGITIMATE' AND r.risk_level IN ('high', 'critical'))
);

-- Verification: Show remaining rule matches
SELECT 'Statement 18 Result: Unlinked rule matches cleaned up' AS status;
SELECT COUNT(*) AS total_rule_matches FROM url_rule_matches;
SELECT COUNT(*) AS valid_matches FROM url_rule_matches urm
WHERE EXISTS (SELECT 1 FROM url_submissions u WHERE u.url_id = urm.url_id)
AND EXISTS (SELECT 1 FROM rules r WHERE r.rule_id = urm.rule_id);

-- Statement 19: Update user role based on submission activity
-- Use Case: Manage Records
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
);

-- Verification: Show updated user roles
SELECT 'Statement 19 Result: User roles updated based on activity' AS status;
SELECT user_id, name, email, role 
FROM users 
ORDER BY user_id;

-- Statement 20: Submit URL with full analysis pipeline
-- Use Case: Submit URL for Analysis
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code)
VALUES (
    (SELECT user_id FROM users WHERE email = 'john.doe@example.com' LIMIT 1),
    'https://suspicious-payment-gateway.tk/checkout',
    'suspicious-payment-gateway.tk',
    '.tk',
    NULL
);

-- Auto-classify based on rules
UPDATE url_submissions
SET result_code = (
    SELECT CASE 
        WHEN COUNT(urm.rule_id) >= 3 THEN 'PHISHING'
        WHEN COUNT(urm.rule_id) >= 2 THEN 'SUSPICIOUS'
        WHEN COUNT(urm.rule_id) = 1 THEN 'SUSPICIOUS'
        ELSE 'LEGITIMATE'
    END
    FROM url_rule_matches urm
    WHERE urm.url_id = url_submissions.url_id
    GROUP BY urm.url_id
)
WHERE url = 'https://suspicious-payment-gateway.tk/checkout'
AND result_code IS NULL;

-- Verification: Show the submitted URL and its classification
SELECT 'Statement 20 Result: URL submitted and auto-classified' AS status;
SELECT u.url_id, u.url, u.url_domain, u.result_code, u.created_at,
       COUNT(urm.rule_id) AS rules_matched
FROM url_submissions u
LEFT JOIN url_rule_matches urm ON u.url_id = urm.url_id
WHERE u.url = 'https://suspicious-payment-gateway.tk/checkout'
GROUP BY u.url_id, u.url, u.url_domain, u.result_code, u.created_at;
