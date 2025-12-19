# APICollector v0.0.3
### Proactive API Security Assessment for Burp Suite

**APICollector** is a comprehensive Burp Suite extension designed to streamline the entire API security testing lifecycle. It bridges the gap between development artifacts (like OpenAPI specs or Postman collections) and professional security auditing.

By centralizing discovery, documentation, and vulnerability tracking, APICollector allows auditors to maintain a clear, evidence-based view of the API attack surface.

---

## 🚀 What's New in v0.0.3

### 📂 Advanced Project Management
- **Total Project Isolation**: Save and load your entire workspace into standalone `.apic` files.
- **Full Persistence**: All endpoints, findings, parameters, and evidence snapshots are persistent across Burp restarts.
- **Client-Centric Workflow**: Easily switch between different assessments (e.g., `Client_A.apic` vs `Client_B.apic`) without data overlap.

### 🛡️ Vulnerability Revalidation Lifecycle
- **Stateful Finding Tracking**: Track the resolution status of findings from **Open** ➔ **Remediated** ➔ **Verified (Fixed)**.
- **Dual-Evidence snapshots**: Automatically capture and compare **Original PoC Evidence** vs. **Verification Retest Evidence**.
- **Interactive Verification**: Instantly push any historical finding back to the internal executor to verify developer fixes in real-time.

### 📊 Audit-Ready Reporting
- **Remediation Progress**: Automated executive summaries showing remediation health and statistics.
- **Evidence Documentation**: Professional Markdown reports now include side-by-side traffic snapshots for every verified finding, creating an incontrovertible audit trail.

### 🔓 Universal Parameter Decoding
- Deep integration with Burp's decoding engine ensures that all parameters (URL, Form, JSON) are displayed in a clean, human-readable format.

---

## 🏗️ Core Workflow

1.  **Ingestion**: Import your attack surface from **OpenAPI (YAML/JSON)**, **Postman**, **Insomnia**, or **cURL**.
2.  **Context**: Right-click any traffic in Burp Proxy/Repeater and select **"Send to APICollector"** for instant indexing.
3.  **Analysis**: Use the **Endpoints** and **Parameters** tabs to build a comprehensive data dictionary and risk map.
4.  **Testing**: Use the **Internal Executor** for rapid iteration using native Burp editors, or push to **Burp Repeater**.
5.  **Audit**: Document findings in the **Endpoints** tab to automatically populate the **Vulnerabilities** dashboard.
6.  **Verify**: Re-test findings using the **Revalidation Panel** and capture proof-of-fix snapshots.
7.  **Report**: Generate professional **Markdown**, **CSV**, or **JSON** reports for stakeholders.

---

## 🛠️ Key Features

- **Multi-Source Support**: Seamless parsing of modern API documentation standards.
- **Native Burp Integration**: Full use of `IMessageEditor` for professional syntax highlighting and context menus.
- **Automated Compliance**: Built-in OWASP API Top 10 (2023) mapping and security configuration scanning.
- **Extensible Rules**: Load custom compliance rules via JSON to match your specific audit requirements.
- **Zero Dependencies**: Includes an embedded, lightweight YAML parser for portability.

---

## 🚀 Getting Started

1.  Download the `APICollector.py` file.
2.  In Burp Suite, go to the **Extensions** tab -> **Installed** -> **Add**.
3.  Select **Python** as the extension type and point to the `APICollector.py` file.
4.  *(Prerequisite: Ensure **Jython 2.7.x** is configured in your Burp Suite options).*

---

## 📖 Release History

### v0.0.3 (Current)
- Implemented **File-Based Project Management** (.apic system).
- Implemented **Vulnerability Revalidation** with state tracking and dual-evidence capture.
- Automated **Universal URL Decoding** for all parameter types.
- Optimized performance for large JSON handling (EDT thread offloading).
- Added **Global Status Bar** for persistent operational feedback.
- Simplified Vulnerability Dashboard for a cleaner result-driven UI.

### v0.0.2
- **Context Menu Integration**: Added "Send to APICollector" for live traffic ingestion.
- **Native Editors**: Integrated Burp's native message editors for professional traffic analysis.
- **YAML Support**: Added embedded support for OpenAPI YAML specifications.
- **Internal Executor**: Fixed thread-locking issues for a more responsive UI.

### v0.0.1
- Initial release with Support for OpenAPI, Postman, and Insomnia.
- Automated parameter extraction and basic reporting engine.

---
*Developed by **Kamran Saifullah** for professional security researchers and API developers.*
