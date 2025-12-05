# Net-Warden
# Project Requirements & Use Cases

The **Phishing URL Detection System** allows users to submit and analyze website URLs for phishing indicators.  
The system applies **rule-based classification**, enables **user feedback/voting**,  
and provides **administrators** with tools to manage data integrity and reports.

---

## Authentication

- Visit `http://127.0.0.1:8000/login` to authenticate. Sessions are stored server-side and expire after 8 hours of inactivity.
- Only administrator accounts can open the admin dashboard or perform destructive actions; regular users stay in the standard view.
- Seed accounts and their default passwords:
  - Admin — `admin@netwarden.local` / `adminpass`
  - Analyst — `analyst@netwarden.local` / `analystpass`
  - John Doe — `john.doe@example.com` / `johnpass`
  - Jane Smith — `jane.smith@example.com` / `janepass`
  - Bob Johnson — `bob.johnson@example.com` / `bobpass`

---

## 1. Submit URL
- Users can submit website URLs to be analyzed.  
- The system validates each submission and stores it in the database for further classification.

---

## 2. Parse and Classify URL
- The system automatically extracts URL components *(domain, scheme, TLD, and length)*.  
- Detection rules are applied to classify URLs as **phishing** or **legitimate**.

---

## 3. View URL Details
- Users can view stored URLs along with their extracted attributes, matched rules, classification results, and timestamps.

---

## 4. Filter and Search URLs
- Users can search and filter URLs by attributes such as **domain**, **TLD**, or **classification status**  
  to locate specific records efficiently.

---

## 5. Report Suspicious URL
- Users can flag URLs they believe are phishing or confirm legitimate ones.  
- Feedback is stored and may influence future classifications after reaching a consensus threshold.

---

## 6. Export Data
- Users can export filtered URL datasets and related analysis results for external review, reporting, or documentation.

---

## 7. Manage Records *(Admin only)*
- Administrators can review, update, or delete URL entries.  
- Admins also oversee user reports to maintain data accuracy and ensure system integrity.
