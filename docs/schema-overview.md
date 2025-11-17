# Database Schema Overview

This system uses a rule-based phishing URL detection workflow as outlined in the project requirements. The SQLite schema captured in `database/migrations/001_init.sql` implements the six core entities from the ER diagram:

1. `users` – actors (admins, analysts, end-users) who submit URLs, vote on classifications, or review statuses.
2. `url_submissions` – incoming URLs plus derived metadata (domain, TLD) and the latest result code.
3. `rules` – filter logic definitions (regex patterns, keyword checks, domain lists) and associated risk levels.
4. `url_rule_matches` – junction table recording which rules fired for each submission.
5. `statuses` – review events tying a submission to an optional reviewer, result code, and descriptive status label.
6. `votes` – crowd feedback representing a many-to-many relationship between users and url_submissions, restricted to one vote per user–URL pair.
7. `url_score_comparisons` – external/computed reputation metrics linked back to `url_submissions`.

## Using the schema

1. Enable foreign keys (already included) and apply the migration:
   ```bash
   sqlite3 database/net_warden.db < database/migrations/001_init.sql
   sqlite3 database/net_warden.db < database/seed_data/001_seed_data.sql
   sqlite3 -header -column database/net_warden.db < database/queries/checkpoint2_queries.sql
   ```
2. Seed reference data (rules, sample users, test URLs) in follow-up scripts inside `database/seed_data/`.
3. For Project Checkpoint 2 deliverables, commit the resulting `net_warden.db` and the SQL script above to your repository and demonstrate the DDL/DML statements during the lab presentation.

