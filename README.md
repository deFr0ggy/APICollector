# APICollector v0.0.1

**APICollector** is a powerful Burp Suite extension designed to verify and audit REST APIs. It bridges the gap between API development exports (Insomnia, Postman, OpenAPI) and security testing, providing a centralized dashboard for static analysis, traffic collection, and compliance auditing.

## 🚀 Key Features

### Import & Parsing
*   **Universal Import**: Seamlessly import API definitions from:
    *   **Insomnia** (JSON Export)
    *   **Postman Collections** (v2.1 JSON)
    *   **OpenAPI / Swagger** (v2.0 & v3.0 - JSON & YAML)
    *   **cURL Commands** (Paste directly from clipboard)
*   **Zero Dependencies**: Embedded YAML parser - no external libraries required
*   **Variable Resolution**: Automatic resolution of Postman/Insomnia variables (`{{baseUrl}}`, `{{_.variable}}`)
*   **Order Preservation**: APIs display in the same order as your source file
*   **Port Detection**: Automatically extracts and preserves custom ports (e.g., `localhost:5000`)

### Security Dashboard
*   Instant static analysis against **OWASP API Security Top 10 (2023)**
*   Identifies authentication gaps, BOLA risks, sensitive keywords, and unsafe methods
*   Clickable links navigate directly to risky endpoints

### Interactive Endpoints Table
*   **Live Status**: Real-time HTTP status codes (200 OK, 403 Forbidden) as you test
*   **Risk Highlighting**: Risky HTTP verbs (DELETE, PUT) and missing auth highlighted
*   **Multi-Select**: Shift+Click / Ctrl+Click to manage multiple endpoints
*   **Editable Requests**: Modify headers/bodies on the fly with **Undo/Redo support (Ctrl+Z / Ctrl+Y)**
*   **Word Wrap**: Request and Response text areas support line wrapping for better readability
*   **Execute Internal**: Send requests directly from the extension without leaving Burp
*   **Response Caching**: Switch between endpoints and see your previous results - nothing gets lost!

### Compliance Manager
*   **Automated Checking**: Test security headers (`HSTS`, `Content-Security-Policy`, etc.)
*   **Custom Rules**: Save/Load JSON rules for **Mandatory** and **Forbidden** headers
*   **Visual Reporting**: Clear Red/Orange/Green indicators
*   **Path Grouping**: Endpoints organized by functional area (e.g., `users`, `auth`, `products`)
*   **Response Display**: View the actual server response that triggered each violation
*   **CSV Export**: Export compliance results including full Request/Response data for offline analysis

### Environment Manager
*   Global search/replace for variables (Host, Port, Scheme)
*   Bulk update endpoints to point to new servers (internal/staging/production)

### Parameter Analysis
*   Auto-extraction of parameters from Request/Response schemas
*   Helps identify hidden parameters for fuzzing

---

## 🛠 Installation

1.  **Requirements**: 
    *   Burp Suite (Community or Professional)
    *   Jython Standalone JAR (`jython-standalone-2.7.x.jar`)
2.  **Setup Jython**:
    *   Go to **Extensions** → **Extensions Settings**
    *   Under **Python Environment**, select your `jython-standalone.jar`
3.  **Load Extension**:
    *   Go to **Extensions** → **Installed**
    *   Click **Add**
    *   Select **Extension type**: `Python`
    *   Select the `APICollector.py` file

---

## 📖 Step-by-Step Usage

### 1. Importing APIs
*   **File Import**: Click **Import API** and select your Insomnia/Postman/OpenAPI file (JSON or YAML)
*   **Clipboard**: Copy a cURL command and click **Paste cURL** to add it instantly
*   *Note: Collection variables are automatically loaded and resolved (e.g., `{{baseUrl}}`).*
*   *Tip: Custom ports (like `localhost:5000`) are automatically detected and preserved.*

### 2. Static Analysis (Dashboard)
*   Immediately after import, switch to the **Dashboard** tab
*   Review potential risks (e.g., "Broken Object Level Authorization")
*   Click any link (e.g., `GET /users/{id}`) to jump to that endpoint in the main table

### 3. Executing Requests (Endpoints Tab)
*   **Select**: Click an endpoint in the table. Use **Shift+Click** for multiple
*   **Edit**: View the **Request** pane at the bottom. You can edit the path, headers, or body
    *   **Undo/Redo**: Press **Ctrl+Z** to undo changes, **Ctrl+Y** to redo
    *   *Tip: Click **Reset Request** if you want to restore the original.*
*   **Send**:
    *   **Execute (Internal)**: Sends the request from the extension. The response status updates in the table (Green for 2xx, Red for 4xx/5xx)
    *   **Send to Repeater**: Pushes the selected request(s) to Burp's Repeater tool for manual testing
*   **Response Caching**: Switch to another endpoint and come back - your previous request/response is preserved!
*   **Filter**: Use the "Verb Filter" dropdown to show only `POST` or `DELETE` requests

### 4. Auditing Compliance (Compliance Tab)
Replace manual header checks with the auto-assessor.

1.  **Configure Rules**:
    *   Click **Save Sample Rules** to get a template
    *   Edit the JSON to define your `mandatory` (must have) and `forbidden` (must not have) headers
    *   Click **Load Rules** to apply them (Defaults are provided if you skip this)

2.  **Run Assessment**:
    *   Select endpoints in the **Endpoints** tab (or all)
    *   Click **Assess Compliance**
    *   The tool sends live requests and analyzes the response headers

3.  **Review Results**:
    *   **Group Column**: Endpoints are grouped by functional area for easy navigation
    *   **Red**: Missing Mandatory Header (e.g., No `Strict-Transport-Security`)
    *   **Orange**: Forbidden Header Found (e.g., `Server: nginx` leaking info)
    *   **Green**: Fully compliant
    *   **Click any row**: View the full Request and Response in the bottom pane

4.  **Export Results**:
    *   Click **Export CSV** to save all compliance findings
    *   CSV includes: ID, Group, Method, Path, Violation, Detail, full Request, and full Response

### 5. Managing Environment
*   Switch to the **Environment** tab
*   **Bulk Edit**: Enter a new Host/Port (e.g., `localhost:8080`) and click **Apply Changes**
*   This updates all imported endpoints to target the new server

---

## 🧹 Data Management
*   **Clear Data**: Resets all tables and analysis
    *   *Includes a safety confirmation dialog to prevent accidental loss*

---

## 🎯 Tips & Tricks

*   **Word Wrap**: Long request/response lines automatically wrap for better readability
*   **Undo/Redo**: Edit requests freely - you can always undo with Ctrl+Z
*   **Response Caching**: Switch between endpoints without losing your test results
*   **Grouping**: Use the Group column in Compliance tab to quickly find all violations for a specific API area
*   **CSV Export**: Share compliance reports with your team or import into Excel for further analysis
*   **Thread Safety**: All UI operations are thread-safe - the extension won't freeze during bulk operations
*   **Port Handling**: Custom ports are automatically detected (e.g., `localhost:5000` for development APIs)

---

## 📝 Version 0.0.1 Release Notes

### Features
*   ✅ Unified OpenAPI/Swagger support (v2.0 & v3.0)
*   ✅ Postman Collections (v2.1) import with variable resolution
*   ✅ Embedded YAML parser (zero external dependencies)
*   ✅ Preserved API definition order
*   ✅ Fixed "Execute Internal" UI freeze with thread-safe updates
*   ✅ Word wrap for Request/Response text areas
*   ✅ Undo/Redo support (Ctrl+Z / Ctrl+Y) for request editing
*   ✅ Response caching - switch between endpoints without losing results
*   ✅ Enhanced Compliance features:
    *   Response display for violations
    *   Path grouping for better organization
    *   CSV export with full Request/Response data
*   ✅ Clear Data confirmation dialog
*   ✅ Proper port detection and handling (e.g., `localhost:5000`)
*   ✅ Fixed POST request Content-Length calculation

### Bug Fixes
*   🐛 Fixed POST requests hanging due to Content-Length mismatch
*   🐛 Fixed domain/port extraction for non-standard ports
*   🐛 Fixed Postman variable resolution (`{{variable}}` syntax)
*   🐛 Fixed Auth column accuracy for OpenAPI security schemes
*   🐛 Fixed YAML import dependency issues

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## 📄 License

This project is released under the MIT License.

---

## 🔗 Links

*   **OWASP API Security Top 10**: https://owasp.org/API-Security/
*   **Burp Suite**: https://portswigger.net/burp
*   **GitHub**: https://github.com/deFr0ggy/APICollector
