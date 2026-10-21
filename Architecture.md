Markdown
# System Architecture Document — ExamOS

## 1. High-Level Technology Stack
* **Frontend:** React.js, Tailwind CSS, TypeScript, Shadcn UI components.
* **Backend:** FastAPI (Python), PyJWT for secure state representation, PyCryptodome (for light crypto processing handles).
* **Database:** PostgreSQL (Supabase managed instance) for relational persistence.
* **External Integration:** Gemini API (via standard python SDK) for parsing system log strings.

## 2. System Component Topology
[Client Browser: React/Shadcn]
│
▼ (HTTPS / Signed JSON Web Tokens)
[API Gateway: FastAPI]
│
├─► [Database Storage: PostgreSQL] (User tables, Encrypted blobs, Audit trails)
├─► [Security Core: Cryptography Engine] (AES-256 transformations)
└─► [AI Processor: Gemini API] (Log stream analysis & summaries)


## 3. Database Schema Blueprint

### Table: `users`
* `id`: UUID (Primary Key)
* `email`: VARCHAR (Unique)
* `password_hash`: VARCHAR
* `role`: VARCHAR (ENUM: 'setter', 'controller', 'printer')
* `created_at`: TIMESTAMP

### Table: `question_papers`
* `id`: UUID (Primary Key)
* `title`: VARCHAR
* `encrypted_payload`: TEXT (Base64 encoded string representing data asset)
* `encryption_key_salt`: VARCHAR
* `release_time`: TIMESTAMP
* `status`: VARCHAR (ENUM: 'draft', 'pending_approval', 'approved', 'locked', 'released')

### Table: `approvals`
* `id`: UUID (Primary Key)
* `paper_id`: UUID (Foreign Key -> `question_papers.id`)
* `approver_id`: UUID (Foreign Key -> `users.id`)
* `status`: VARCHAR (ENUM: 'approved', 'rejected')
* `updated_at`: TIMESTAMP

### Table: `audit_logs`
* `id`: UUID (Primary Key)
* `user_id`: UUID (Nullable - for unauthenticated access tracking)
* `action_taken`: VARCHAR
* `ip_address`: VARCHAR
* `severity_level`: VARCHAR (ENUM: 'low', 'medium', 'high', 'critical')
* `timestamp`: TIMESTAMP

## 4. Primary Security Implementations
* **Data Security:** Files undergo standard symmetrical encryption before permanent block commitments are stored. 
* **Time Enforcement:** Decryption utilities read directly against isolated server-side system times, never utilizing client-side device parameters to prevent front-end tampering.