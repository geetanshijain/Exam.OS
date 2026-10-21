# UI/UX Layout Specification & Design System

## 1. Visual Strategy & Architecture
* **Theme:** Deep charcoal bases (`#0F172A`), structural steel elements, high contrast text indicators, bright red/amber alert states.
* **Aesthetic Goal:** Professional, enterprise security portal styling. Clean layouts, zero distraction elements, high information density.

## 2. Interface View Master Map

### View A: Document Upload Portal (Target User: Paper Setter)
* **Hero Element:** Central drop-zone area accommodating drag-and-drop file operations.
* **Status Manifest:** Clear tabular representations detailing pending uploads, historical file validation status, and immediate post-upload confirmation elements.

### View B: Administrative Command Center (Target User: Exam Controller)
* **Top Metric Panel:** Visual metric cards detailing platform access levels: Active Sessions, Vault Locks, System Severity Levels, Completed Safe Cycles.
* **Threat Activity Grid:** Multi-colored logs prioritizing real-time alerts. High threat levels pulse cleanly in red layout areas.
* **AI Analysis Box:** Floating layout block displaying plain language operational assessments produced via structural processing utilities.

### View C: Secure Extraction Portal (Target User: Printing Officer)
* **Countdown Element:** Prominent numerical layout tracking seconds remaining before operational vaults permit safe document extraction.
* **Asset Interface:** Clean interaction controls allowing authenticated secure downloads only after all structural criteria are satisfied.

## 3. Verified UI Component Targets
* Leverage `shadcn/ui` framework baselines for core interactions: Data Tables for logging grids, Dialog primitives for system confirmation modals, Card wrappers for metrics, and Progress indicators for encryption operations.