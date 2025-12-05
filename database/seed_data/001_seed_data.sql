-- This is the sample data needed for the database, mentioned in Project2

PRAGMA foreign_keys = ON;


-- Default passwords: adminpass, analystpass, johnpass, janepass, bobpass
INSERT OR IGNORE INTO users (name, email, role, password_hash) VALUES (
    'Admin User',
    'admin@netwarden.local',
    'admin',
    'pbkdf2_sha256$390000$9e0a3fdb6854519d01fdea09fe569846$438b99ac85b49e9ea12fc46dc15f6980b5db3866cf3501e0feadfa80e0bd0afd'
);
INSERT OR IGNORE INTO users (name, email, role, password_hash) VALUES (
    'Security Analyst',
    'analyst@netwarden.local',
    'analyst',
    'pbkdf2_sha256$390000$c8cba634c4ddd23123f3fe901b556872$1e02e8a28cea85bcf6a37720e2c22275dbb11fefd8bcfd4041171e846dfec570'
);
INSERT OR IGNORE INTO users (name, email, role, password_hash) VALUES (
    'John Doe',
    'john.doe@example.com',
    'user',
    'pbkdf2_sha256$390000$b4c1ad6a91b90c50d08fa3885c82258c$1a4a3d487671f1007afffd250d5c0e8df32df6ce0c8e2531e82de3b2397dd0e3'
);
INSERT OR IGNORE INTO users (name, email, role, password_hash) VALUES (
    'Jane Smith',
    'jane.smith@example.com',
    'user',
    'pbkdf2_sha256$390000$8517b2e78e6a643ffcf42b06d18be6d6$d9c373eb70b2377385dc8c598b91d1a98ebd9dcdf1031c1ca02e88ad276d2b7b'
);
INSERT OR IGNORE INTO users (name, email, role, password_hash) VALUES (
    'Bob Johnson',
    'bob.johnson@example.com',
    'user',
    'pbkdf2_sha256$390000$1df1b9a851a5635e01df4cd49b3d1439$fb9779eb9415785feed9d7837c8943393eeed71e2ef84979ba3cfc566aa89a9d'
);


-- 2. INSERT RULES (8 statements)
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('Suspicious Keywords', 'Detects common phishing keywords in URL', 'verify|secure|update|account|login', 'keyword', 'high', NULL);
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('IP Address in URL', 'URL contains IP address instead of domain', '^\d+\.\d+\.\d+\.\d+', 'regex', 'critical', NULL);
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('Suspicious TLD', 'URL uses suspicious top-level domain', NULL, 'tld', 'medium', '.tk');
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('Long URL Length', 'URL exceeds suspicious length threshold', NULL, 'length', 'medium', NULL);
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('Multiple Dashes', 'URL contains excessive dashes', '-{3,}', 'regex', 'low', NULL);
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('Percent Encoding', 'High percentage of encoded characters', '%[0-9A-F]{2}', 'regex', 'high', NULL);
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('Suspicious Domain Pattern', 'Domain matches known phishing patterns', 'paypal|amazon|microsoft', 'keyword', 'high', NULL);
INSERT OR IGNORE INTO rules (rule_name, description, pattern, rule_type, risk_level, tld) VALUES ('Short URL Service', 'URL uses URL shortening service', 'bit\.ly|tinyurl|goo\.gl', 'regex', 'medium', NULL);


-- 3. INSERT URL SUBMISSIONS (10 statements)
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (3, 'https://verify-paypal-account-secure.tk/login', 'verify-paypal-account-secure.tk', '.tk', 'PHISHING');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (4, 'https://www.amazon.com/products/item123', 'amazon.com', '.com', 'LEGITIMATE');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (3, 'http://192.168.1.100/secure-update-account', '192.168.1.100', NULL, 'PHISHING');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (5, 'https://www.microsoft.com/account/signin', 'microsoft.com', '.com', 'LEGITIMATE');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (4, 'https://bit.ly/suspicious-link-xyz', 'bit.ly', '.ly', 'SUSPICIOUS');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (3, 'https://update-bank-account-now.tk/verify', 'update-bank-account-now.tk', '.tk', 'PHISHING');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (5, 'https://www.github.com/user/repo', 'github.com', '.com', 'LEGITIMATE');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (4, 'http://suspicious-domain-with-many-dashes---here.com/path', 'suspicious-domain-with-many-dashes---here.com', '.com', 'SUSPICIOUS');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (3, 'https://login-apple-verify-id.tk/account', 'login-apple-verify-id.tk', '.tk', 'PHISHING');
INSERT OR IGNORE INTO url_submissions (user_id, url, url_domain, tld, result_code) VALUES (5, 'https://www.google.com/search?q=test', 'google.com', '.com', 'LEGITIMATE');


-- 4. INSERT URL RULE MATCHES (11 statements)
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (1, 1, 'Matched keywords: verify, secure, login');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (1, 3, 'Suspicious TLD detected: .tk');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (1, 7, 'Matched domain pattern: paypal');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (3, 2, 'IP address detected in URL: 192.168.1.100');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (3, 1, 'Matched keywords: secure, update, account');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (5, 8, 'URL shortening service detected: bit.ly');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (6, 1, 'Matched keywords: update, account, verify');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (6, 3, 'Suspicious TLD detected: .tk');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (8, 5, 'Multiple dashes detected in domain');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (9, 1, 'Matched keywords: login, verify, account');
INSERT OR IGNORE INTO url_rule_matches (url_id, rule_id, match_details) VALUES (9, 3, 'Suspicious TLD detected: .tk');


-- 5. INSERT STATUSES (5 statements)
INSERT OR IGNORE INTO statuses (url_id, reviewer_id, result_code, label, description) VALUES (1, 2, 'PHISHING', 'Confirmed Phishing', 'Multiple suspicious indicators detected including suspicious TLD and phishing keywords');
INSERT OR IGNORE INTO statuses (url_id, reviewer_id, result_code, label, description) VALUES (2, 1, 'LEGITIMATE', 'Verified Legitimate', 'Domain verified as official Amazon domain');
INSERT OR IGNORE INTO statuses (url_id, reviewer_id, result_code, label, description) VALUES (3, 2, 'PHISHING', 'Confirmed Phishing', 'IP address in URL is a strong phishing indicator');
INSERT OR IGNORE INTO statuses (url_id, reviewer_id, result_code, label, description) VALUES (4, 1, 'LEGITIMATE', 'Verified Legitimate', 'Official Microsoft domain confirmed');
INSERT OR IGNORE INTO statuses (url_id, reviewer_id, result_code, label, description) VALUES (5, 2, 'SUSPICIOUS', 'Under Review', 'URL shortening service detected, requires further investigation');


-- 6. INSERT VOTES (6 statements)
INSERT OR IGNORE INTO votes (user_id, url_id, vote_value) VALUES (3, 1, 1);  -- User 3 votes phishing (1) for URL 1
INSERT OR IGNORE INTO votes (user_id, url_id, vote_value) VALUES (4, 1, 1);  -- User 4 votes phishing (1) for URL 1
INSERT OR IGNORE INTO votes (user_id, url_id, vote_value) VALUES (5, 2, -1); -- User 5 votes legitimate (-1) for URL 2
INSERT OR IGNORE INTO votes (user_id, url_id, vote_value) VALUES (3, 3, 1);  -- User 3 votes phishing (1) for URL 3
INSERT OR IGNORE INTO votes (user_id, url_id, vote_value) VALUES (4, 4, -1); -- User 4 votes legitimate (-1) for URL 4
INSERT OR IGNORE INTO votes (user_id, url_id, vote_value) VALUES (5, 5, 1);  -- User 5 votes phishing (1) for URL 5


-- 7. INSERT URL SCORE COMPARISONS (5 statements)
INSERT OR IGNORE INTO url_score_comparisons (url_id, external_source, avg_score, online_score, risk_level) VALUES (1, 'VirusTotal', 0.85, 0.90, 'high');
INSERT OR IGNORE INTO url_score_comparisons (url_id, external_source, avg_score, online_score, risk_level) VALUES (2, 'Google Safe Browsing', 0.05, 0.02, 'low');
INSERT OR IGNORE INTO url_score_comparisons (url_id, external_source, avg_score, online_score, risk_level) VALUES (3, 'VirusTotal', 0.92, 0.95, 'critical');
INSERT OR IGNORE INTO url_score_comparisons (url_id, external_source, avg_score, online_score, risk_level) VALUES (4, 'Google Safe Browsing', 0.03, 0.01, 'low');
INSERT OR IGNORE INTO url_score_comparisons (url_id, external_source, avg_score, online_score, risk_level) VALUES (5, 'URLVoid', 0.65, 0.70, 'medium');

-- Summary: 5 users + 8 rules + 10 URLs + 11 rule matches + 5 statuses + 6 votes + 5 score comparisons
-- Total: 50 INSERT statements for table population
