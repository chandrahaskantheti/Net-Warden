-- this file is the full relational schema

PRAGMA foreign_keys = ON;

-- Users of the system (admins, analysts, reporters)
-- we autoincremend user id as a simple id, rather than random generate
-- to capture time of account creation, we use current timestamp
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'user')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- URL submissions awaiting phishing evaluation
-- remember that users submit urls to check if the link is a phishing link
CREATE TABLE IF NOT EXISTS url_submissions (
    url_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL, -- every url is submitted by a user, we need to know who that is
    url TEXT NOT NULL, --- every url submission has the full url
    url_domain TEXT NOT NULL, -- for example, from "http://example.com/path", we extract "example.com"
    tld TEXT, -- for example, from "example.com", we extract ".com"
    result_code TEXT, -- e.g., 'PHISHING', 'LEGITIMATE', 'SUSPICIOUS'
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    CONSTRAINT fk_submission_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE,
    CONSTRAINT uq_url UNIQUE (url)
);

-- Rule definitions used by the filtering logic
CREATE TABLE IF NOT EXISTS rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL UNIQUE,
    description TEXT,
    pattern TEXT,
    rule_type TEXT CHECK (rule_type IN ('keyword', 'regex', 'domain', 'length', 'tld', 'other')),
    risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    tld TEXT
);

-- Junction table capturing which rules triggered for a submission
CREATE TABLE IF NOT EXISTS url_rule_matches (
    match_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    rule_id INTEGER NOT NULL,
    match_details TEXT,
    matched_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_match_url
        FOREIGN KEY (url_id) REFERENCES url_submissions(url_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_match_rule
        FOREIGN KEY (rule_id) REFERENCES rules(rule_id)
        ON DELETE CASCADE,
    CONSTRAINT uq_match UNIQUE (url_id, rule_id)
);

-- Status reviews tied to URL submissions and reviewer accounts
CREATE TABLE IF NOT EXISTS statuses (
    status_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    reviewer_id INTEGER,
    result_code TEXT NOT NULL,
    label TEXT NOT NULL,
    description TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_status_url
        FOREIGN KEY (url_id) REFERENCES url_submissions(url_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_status_reviewer
        FOREIGN KEY (reviewer_id) REFERENCES users(user_id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_status_url ON statuses (url_id);
CREATE INDEX IF NOT EXISTS idx_status_reviewer ON statuses (reviewer_id);

-- Voting table (many-to-many between users and URL submissions)
CREATE TABLE IF NOT EXISTS votes (
    vote_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url_id INTEGER NOT NULL,
    vote_value INTEGER NOT NULL CHECK (vote_value IN (-1, 1)),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_vote_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_vote_url
        FOREIGN KEY (url_id) REFERENCES url_submissions(url_id)
        ON DELETE CASCADE,
    CONSTRAINT uq_vote UNIQUE (user_id, url_id)
);

CREATE INDEX IF NOT EXISTS idx_votes_url ON votes (url_id);

-- External or computed risk comparisons for each URL submission
CREATE TABLE IF NOT EXISTS url_score_comparisons (
    rep_id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER NOT NULL,
    external_source TEXT,
    avg_score REAL,
    online_score REAL,
    risk_level TEXT CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_score_url
        FOREIGN KEY (url_id) REFERENCES url_submissions(url_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scores_url ON url_score_comparisons (url_id);

