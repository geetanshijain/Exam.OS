# Product Requirement Document (PRD) — Project: ExamOS

## 1. Executive Summary
ExamOS is a secure, institutional question paper lifecycle management platform designed to prevent leaks before exams start. The product secures papers from the moment of creation, subjects them to strict multi-role approval loops, locks them down using cryptographically enforced countdown timers, tracks access via immutable logging, and protects printed assets via dynamic watermarks.

## 2. Core Problem Space
* **The Leak Window:** Traditional software protects exams *during* execution. Leaks occur *before* the exam via corrupt insiders, unencrypted storage, or early printing access.
* **Lack of Attribution:** If a paper leaks, institutions cannot prove *who* leaked it.
* **Complex Audits:** Reviewing technical system logs during a crisis takes hours; security teams need instant plain-language threat indicators.

## 3. Targeted Personas
* **Paper Setter (Instructor):** Uploads raw files; loses access immediately post-submission to prevent insider compromise.
* **Exam Controller (Admin):** Oversees security parameters, approves releases, views live threat dashboards, and acts on security alerts.
* **Printing Officer:** Accesses papers strictly during a narrow printing window directly prior to the exam.

## 4. Minimum Viable Product (MVP) Scope
### Functional Requirements
* **Role-Based Access Control (RBAC):** Distinct interfaces and strict endpoint permissions for Paper Setters, Controllers, and Printing Officers.
* **Time-Locked Sandbox:** A strict system clock verification mechanism preventing file access or decryption before `ExamTime - 30 Minutes`.
* **Dynamic Watermarked PDF Generator:** Automated stamping of the viewing/printing user's ID, current timestamp, and IP address across all document pages upon generation.
* **Natural Language Log Analysis:** A clean module leveraging the Gemini API to analyze raw system event text strings and return concise, actionable security risk summaries to the controller.
* **The Honeytoken Trap:** If an unauthorized user attempts to breach the time-lock, the system yields a fake, trackable placeholder document ("Honeytoken") while flashing a high-priority alert to the dashboard.

### Out of Scope (Explicitly Excluded)
* Real SMS/Email infrastructure (mocked via UI input fields).
* Machine Learning models trained from scratch (replaced by deterministic, rule-based point tracking).
* Physical device/Hardware ID fingerprinting.

## 5. Success Metrics for the Pitch
* Fully demonstrable end-to-end flow: Upload → Multi-stage approval → Time-locked security blockade → Safe time-elapsed decryption → Labeled PDF download.
* The "Wow Effect": A simulated security breach triggering an automated text-summary alert and capturing a rogue user using the Honeytoken Trap.