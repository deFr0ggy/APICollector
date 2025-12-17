# APICollector v0.0.2
### Proactive API Security Assessment for Burp Suite

**APICollector** is a comprehensive Burp Suite extension designed to streamline the entire API security testing lifecycle. It bridges the gap between development artifacts (like OpenAPI specs or Postman collections) and professional security auditing.

Whether you are performing a quick manual assessment or a full-scale API compliance audit, APICollector provides the central dashboard you need to import, test, document, and report.

---

## 🔄 Core Workflow

APICollector is built around a logical flow from discovery to delivery:

1.  **Import**: Load your attack surface from **OpenAPI (YAML/JSON)**, **Postman**, **Insomnia**, or even **cURL** commands.
2.  **Interact**: Use the live **Endpoints** table to modify requests on the fly, send them to Repeater, or execute them internally with live status tracking.
3.  **Audit**: Run automated **Compliance Assessments** to check for missing security headers, information leakage, and best practices across grouped API paths.
4.  **Track**: Document findings **inline** as you discover them. Capture evidence (Req/Res) automatically and assign OWASP API Top 10 categories.
5.  **Report**: Generate professional **Markdown reports**, **CSVs**, or **JSON** exports that include verified safe endpoints and detailed vulnerability write-ups.

---

## 🌟 Key Features

### 📡 Unified API Discovery & Import
*   **Universal Support**: Seamlessly parse OpenAPI 2.0/3.0 (YAML & JSON), Postman v2.1, Insomnia, and cURL.
*   **Zero Dependencies**: Features a custom-built, lightweight YAML parser—no manual library installations required.
*   **Port & Domain Preservation**: Automatically extracts host, scheme, and non-standard ports (e.g., `:5000`) for local dev testing.

### 🧪 Advanced Endpoint Testing
*   **Live Status Tracking**: Monitor HTTP response codes in real-time within the main utility grid.
*   **Response Caching**: Every endpoint "remembers" its last request and response, even after you switch tabs.
*   **Editor Experience**: Native **Undo/Redo** (Ctrl+Z/Ctrl+Y) support and **Word Wrap** for managing complex JSON payloads.

### 🛡 Integrated Findings Management (NEW)
*   **Inline Workflow**: Tag vulnerabilities directly in the main table with interactive dropdowns (Vulnerable, Safe, Pending).
*   **Smart Remediation**: Automatically pre-fills fix recommendations based on the **OWASP API Security Top 10 (2023)**.
*   **Evidence Automation**: One-click "Add Finding" captures the current request/response traffic as proof-of-concept evidence.

### 📊 Professional Compliance Auditing
*   **Path Grouping**: Automatically organizes endpoints by API segments for cleaner assessment views.
*   **Rule-Based Scanning**: Scans for mandatory headers (CSP, HSTS, etc.) and forbidden headers (Server, X-Powered-By) to detect leaks in bulk.
*   **Traffic Logging**: View the exact response that triggered a compliance violation directly in the audit tab.

---

## 🚀 Getting Started

1.  Download the `APICollector.py` file.
2.  In Burp Suite, go to the **Extensions** tab -> **Installed** -> **Add**.
3.  Select **Python** as the extension type and point to the `APICollector.py` file.
4.  (Prerequisite: Ensure **Jython** is configured in your Burp Suite options).
5.  Open the **APICollector** tab and click **Import API** to get started!

---

## 📖 Usage Tips

*   **Documenting Safe Endpoints**: Mark verified secure APIs as "Not Vulnerable." They will be included in your final report in a dedicated "Verified Safe" section to show a complete audit trail.
*   **Path Grouping**: Use the Compliance tab to see how your security posture looks across different microservices or API versions using the "Group" column.
*   **Data Persistence**: Use the **Export JSON** feature to backup your current assessment findings for later use or integration with other tools.

---

## 📝 Release Notes v0.0.2
*   ✨ **Full Vulnerability Tracker**: Integrated inline findings management.
*   ✨ **Remediation Engine**: Smart recommendations for OWASP API risks.
*   ✨ **Reporting+**: Comprehensive Markdown/CSV exports including safe endpoints and evidence.
*   ✨ **UX Overhaul**: Added undo/redo, word wrap, and thread-safe UI updates.
*   ✨ **Improved Parsing**: Enhanced OpenAPI YAML support and variable resolution for Postman.

---
*Developed for professional security researchers and API developers.*
