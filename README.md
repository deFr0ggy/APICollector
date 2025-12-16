# APICollector

![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Python](https://img.shields.io/badge/Language-Python%20(Jython)-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**APICollector** is a comprehensive, open-source Burp Suite extension designed to supercharge your API security testing workflow. It bridges the gap between API development tools (Insomnia, Postman, OpenAPI) and Burp Suite's powerful security auditing capabilities.

## 🚀 Features

### 1. Unified API Import 📥
Import API specifications from multiple sources into a single, standardized dashboard:
*   **Insomnia**: Full support for Export JSON format.
*   **Postman**: Supports Collection v2.0/v2.1 JSON.
*   **OpenAPI/Swagger**: Supports version 2.0 and 3.0 (JSON & YAML).

### 2. Live Security Dashboard 🛡️
Automatically analyzes imported APIs against the **OWASP API Security Top 10 (2023)**.
*   **Static Analysis**: flags potential vulnerabilities like *Broken Object Level Authorization (BOLA)*, *Mass Assignment*, and *Lack of Authentication* based on heuristics.
*   **Interactive**: Click any finding to verify the specific endpoint immediately.

### 3. Interactive Endpoints Table ⚡
*   **Split View**: View Request and Response side-by-side.
*   **Editable Requests**: Tweak headers, bodies, or parameters on the fly without sending to Repeater first.
*   **Live Status**: Real-time color-coded feedback (e.g., `200 OK` in Green, `500 Error` in Red).
*   **Visual Highlighting**: Risky methods (`DELETE`, `PUT`, `PATCH`) are highlighted in **BLUE** for quick identification.

### 4. Advanced Test Manager 🧪
Generate and manage security tests without cluttering your Repeater tab.
*   **Auto-Generation**: create SQLi, XSS, and LFI payloads for selected endpoints.
*   **Fuzzing**: Recursive JSON fuzzing to test deep object properties.
*   **Review & Execute**: Review generated tests in a dedicated tab before executing them.
*   **Reset Capability**: One-click "Reset Request" to undo manual changes and revert to the original payload.

### 5. Schema Analysis 🔍
*   **Parameters Tab**: Instantly view all expected **Request** and **Response** parameters for every endpoint, extracted recursively from the API schema.

### 6. Environment Management 🌍
*   **Context Switching**: Easily switch all endpoints from `localhost` to `staging.api.com` in seconds.
*   **Bulk Edit**: Apply scheme (HTTP/HTTPS), Host, and Port changes to hundreds of endpoints with one click.

---

## 🛠️ Installation

1.  **Prerequisites**:
    *   **Burp Suite Professional/Community**.
    *   **Jython Standalone JAR**: Download the latest version from [Jython.org](https://www.jython.org/download).

2.  **Setup**:
    1.  Open Burp Suite.
    2.  Go to **Extensions** -> **Extensions Settings**.
    3.  Under **Python Environment**, select your `jython-standalone-*.jar`.
    4.  Go to **Extensions** -> **Installed**.
    5.  Click **Add**.
    6.  Select **Extension Type**: `Python`.
    7.  Select the `APICollector.py` file.
    8.  Click **Next**. The extension should load with no errors.

---

## 📖 Usage Guide

### Importing Data
1.  Navigate to the **APICollector** tab.
2.  Click **Import API**.
3.  Select your JSON or YAML file (Insomnia Export, Postman Collection, or OpenAPI Spec).
4.  The **Endpoints** table will populate with all found requests.

### Testing Endpoints
1.  Select an endpoint in the table.
2.  The request appears in the **Bottom Left** pane. You can edit it if needed.
3.  Click **Execute (Internal)** to send it.
4.  View the response in the **Bottom Right** pane.

### Generating Security Tests
1.  Select one or more interesting endpoints in the main table.
2.  Click **Generate Security Tests**.
3.  Switch to the **Test Manager** tab.
4.  Review the generated attack vectors (SQLi, XSS, etc.).
5.  Select a test and click **Send Request** to verify.

### Environment Switching
1.  Go to the **Environment** tab.
2.  Enter your new **Host** (e.g., `api.staging.com`), **Port** (e.g., `443`), and **Scheme** (`HTTPS`).
3.  Click **Select All** (or choose specific endpoints).
4.  Click **Apply Changes**. All endpoints are now updated!

---

## ⚠️ Disclaimer
This tool is for educational and authorized security testing purposes only. misuse of this tool to attack targets without prior mutual consent is illegal. 

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.
