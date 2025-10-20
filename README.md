# Net-Warden
# Project Requirements & Use Cases

The **Phishing URL Detection System** allows users to submit and analyze website URLs for phishing indicators.  
The system applies **rule-based classification**, enables **user feedback/voting**,  
and provides **administrators** with tools to manage data integrity and reports.

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
