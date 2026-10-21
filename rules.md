# Development Rules & Security Constraints

## 1. Technical Implementation Constraints
* **Zero Client-Side Security Logic:** All authorization checks, time-lock calculations, and file processing tasks must occur behind backend API layers. The frontend only displays state; it never controls validation.
* **Strict JWT Management:** Sessions are monitored via short-lived JWT authorization payloads passed via standard headers. No credentials or keys reside within local browser persistence layers unhashed.
* **Fail-Closed Defaulting:** If an API endpoint encounters a processing exception or database timeout during access verification, the system must immediately issue a `403 Forbidden` response and drop the connection.

## 2. Codebase Organization & Styling
* **TypeScript Typing:** Explicitly define all interface definitions and operational payloads. The use of generic `any` structures is strictly forbidden.
* **Component Modularity:** Isolate complex presentation sections into dedicated sub-directories under `src/components/`. Keep layout compositions flat and highly readable.
* **Deterministic Risk Scoring:** Do not attempt complex model execution. Implement static weight parameters for calculation tasks:
  * Unauthorized system access attempt = +50 points
  * Out of schedule resource query = +30 points
  * Shift from standard operational time = +20 points

## 3. Hackathon Engineering Safeguards
* Do not spend more than 30 minutes debugging real file system uploads. If multi-part form payloads fail, fall back to string representations of files immediately.
* Mock configurations explicitly using standard variables so parameters can be quickly adjusted on stage during judging panels.