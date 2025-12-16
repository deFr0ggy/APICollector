# APICollector

**APICollector** is a powerful Burp Suite extension designed to verify and audit REST APIs. It bridges the gap between API development exports (Insomnia, Postman, OpenAPI) and security testing, providing a centralized dashboard for static analysis, traffic collection, and compliance auditing.

## 🚀 Key Features

*   **Universal Import**: Seamlessly import API definitions from:
    *   **Insomnia** (JSON Export)
    *   **Postman Collections** (v2.1 JSON)
    *   **OpenAPI / Swagger** (JSON & YAML)
    *   **cURL Commands** (Paste directly from clipboard)
*   **Security Dashboard**: Instant static analysis of imported endpoints against **OWASP API Security Top 10 (2023)**.
    *   Identifies authentication gaps, BOLA risks, sensitive keywords, and unsafe methods.
    *   Clickable links navigate directly to the risky endpoint.
*   **Interactive Endpoints Table**:
    *   **Live Status**: See real-time HTTP status codes (200 OK, 403 Forbidden) as you test.
    *   **Risk Highlighting**: Risky HTTP verbs (DELETE, PUT) and missing auth are highlighted.
    *   **Multi-Select**: Shift+Click / Ctrl+Click to manage multiple endpoints.
    *   **Editable Requests**: Modify headers/bodies on the fly before sending.
*   **Compliance Manager**:
    *   Automated checking of **Security Headers** (e.g., `HSTS`, `Content-Security-Policy`).
    *   **Custom Rules**: Save/Load JSON rules to define **Mandatory** and **Forbidden** headers for your organization.
    *   **Visual Reporting**: Clear Red/Orange/Green indicators for compliance status.
*   **Environment Manager**:
    *   Global search/replace for variables (Host, Port, Scheme).
    *   Bulk update endpoints to point to a new internal/staging server.
*   **Parameter Analysis**:
    *   Auto-extraction of parameters from Request/Response schemas.
    *   Helps identify hidden parameters for fuzzing.

---

## 🛠 Installation

1.  **Requirements**: Burp Suite (Community or Professional), Jython Standalone JAR (`jython-standalone-2.7.x.jar`).
2.  **Setup Jython**:
    *   Go to **Extensions** -> **Extensions Settings**.
    *   Under **Python Environment**, select your `jython-standalone.jar`.
3.  **Load Extension**:
    *   Go to **Extensions** -> **Installed**.
    *   Click **Add**.
    *   Select **Extension type**: `Python`.
    *   Select the `APICollector.py` file.

---

## 📖 Step-by-Step Usage

### 1. Importing APIs
*   **File Import**: Click **Import API** and select your Insomnia/Postman/OpenAPI file.
*   **Clipboard**: Copy a cURL command and click **Paste cURL** to add it instantly.
*   *Note: If "Environment" variables are used in the file (e.g., `{{base_url}}`), use the **Environment Tab** to resolve them.*

### 2. Static Analysis (Dashboard)
*   Immediately after import, switch to the **Dashboard** tab.
*   Review potential risks (e.g., "Broken Object Level Authorization").
*   Click any link (e.g., `GET /users/{id}`) to jump to that endpoint in the main table.

### 3. Executing Requests (Endpoints Tab)
*   **Select**: Click an endpoint in the table. Use **Shift+Click** for multiple.
*   **Edit**: View the **Request** pane at the bottom. You can edit the path, headers, or body.
    *   *Tip: Click **Reset Request** if you make a mistake.*
*   **Send**:
    *   **Execute (Internal)**: Sends the request from the extension. The response status updates in the table (Green for 2xx, Red for 4xx/5xx).
    *   **Send to Repeater**: Pushes the selected request(s) to Burp's Repeater tool for manual testing.
*   **Filter**: Use the "Verb Filter" dropdown to show only `POST` or `DELETE` requests.

### 4. Auditing Compliance (Compliance Tab)
Replace manual header checks with the auto-assessor.
1.  **Switch to Compliance Tab**.
2.  **Configure Rules**:
    *   Click **Save Sample Rules** to get a template.
    *   Edit the JSON to define your `mandatory` (must have) and `forbidden` (must not have) headers.
    *   Click **Load Rules** to apply them. (Defaults are provided if you skip this).
3.  **Run Assessment**:
    *   Select endpoints in the **Endoints** tab (or all).
    *   Click **Assess Compliance**.
    *   The tool sends live requests and analyzes the response headers.
4.  **Review Results**:
    *   **Red**: Missing Mandatory Header (e.g., No `Strict-Transport-Security`).
    *   **Orange**: Forbidden Header Found (e.g., `Server: nginx` leaking info).
    *   **Green**: Fully compliant.

### 5. Managing Environment
*   Switch to the **Environment** tab.
*   **Bulk Edit**: Enter a new Host/Port (e.g., `localhost:8080`) and click **Apply Changes**.
*   This updates all imported endpoints to target the new server.

---

## 🧹 Data Management
*   **Clear Data**: Resets all tables and analysis.
    *   *Includes a safety confirmation dialog to prevent accidental loss.*
