# APICollector v0.0.2

**APICollector** is a powerful Burp Suite extension designed to verify and audit REST APIs. It bridges the gap between API development exports (Insomnia, Postman, OpenAPI) and security testing, providing a centralized dashboard for static analysis, traffic collection, compliance auditing, and **integrated vulnerability management**.

## 🚀 Key Features

### NEW: Integrated Findings Management
*   **Inline Vulnerability Status**: Directly tag endpoints as **Vulnerable**, **Not Vulnerable**, or **Pending** using a dropdown in the main Endpoints table.
*   **Per-Endpoint Findings**: Dedicated "Findings" tab at the bottom of the Endpoints view to manage all security bugs for a specific API.
*   **OWASP API Top 10 (2023)**: Categorize findings using the industry-standard OWASP API Security risk categories.
*   **Smart Remediation**: Automatically pre-fills architectural fix recommendations based on the selected OWASP category.
*   **Assessment Logging**: Includes **verified safe endpoints** (Not Vulnerable) in reports with full traffic evidence for a complete audit trail.
*   **Evidence Capture**: One-click "Add Finding" auto-populates the vulnerable Request and Response evidence from your current test session.
*   **Multiple Findings**: Document multiple distinct vulnerabilities for a single endpoint (e.g., BOLA and SSRF on the same URL).
*   **Unified Reporting**: Local findings are automatically synchronized to the global "Vulnerabilities" tab for professional export and assessment overview.

### Interactive Endpoints Table
*   **Live Status**: Real-time HTTP status codes as you test.
*   **Editable Requests**: Modify headers/bodies on the fly with **Undo/Redo support**.
*   **Word Wrap**: Improved readability for long requests and responses.
*   **Execute Internal**: Send requests directly from the extension.
*   **Response Caching**: Each endpoint remembers its previous request and response.

### Import & Parsing
*   **Universal Import**: Insomnia, Postman (v2.1), OpenAPI/Swagger (v2.0 & v3.0, JSON & YAML), and cURL.
*   **Zero Dependencies**: Embedded YAML parser - no external libraries required.
*   **Port Detection**: Automatically extracts and preserves custom ports (e.g., `localhost:5000`).

---

## 📖 Using the Integrated Findings Manager

### 1. Identify a Bug
*   Execute a request and observe the results in the **Request / Response** tab.

### 2. Tag the Endpoint
*   In the **Endpoints** table, find the **Vulnerability** column.
*   Click the cell to open the dropdown and select **Vulnerable** (turns red) or **Not Vulnerable** (turns green).

### 3. Document Detailed Findings
*   Switch the bottom pane to the **Findings** tab.
*   Click **Add Finding**.
*   Select the **Severity** and **OWASP Category**.
*   Add your PoC notes. The current request and response are automatically captured as evidence.

### 4. Professional Export
*   Head to the global **Vulnerabilities** tab to see the aggregated list of all findings.
*   Export as a **Markdown Report**, **CSV**, or **JSON**.

---

## 📝 Release Notes v0.0.2

### Features
*   ✨ **Integrated Findings Workflow**: Direct management from the Endpoints table.
*   ✨ **OWASP API Top 10 (2023) Integration**: Standardized risk reporting.
*   ✨ **Inline Table Editors**: Dropdown status selection in the main grid.
*   ✨ **Evidence-to-Finding Linking**: Smooth data flow from traffic to documentation.
*   ✨ **Multi-finding Support**: Track complex vulnerabilities per single endpoint.

### Recent Fixes
*   ✅ Added thread-safe UI updates for better stability.
*   ✅ Improved port handling for local development environments.
*   ✅ Refined Auth detection for OpenAPI contracts.
