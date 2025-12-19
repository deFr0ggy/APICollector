# APICollector v0.0.4
### Proactive API Security Assessment for Burp Suite

**APICollector** is a comprehensive Burp Suite extension designed to streamline the entire API security testing lifecycle. It bridges the gap between development artifacts (like OpenAPI specs or Postman collections) and professional security auditing.

---

## 🚀 What's New in v0.0.4

### 📊 Assessment Analytics Dashboard
- **Executive Mission Control**: A new visual dashboard featuring high-level metrics for your assessment.
- **Risk Distribution**: Color-coded cards showing the count of **Critical, High, Medium, Low, and Info** findings.
- **Remediation Health**: Real-time tracking of finding statuses (**Open, Remediated, Verified, Re-Open**).
- **Visual Progress**: A dynamic progress bar showing the percentage of findings successfully verified as fixed.
- **Inventory Statistics**: Summary of total endpoints vs. vulnerable endpoints to assess the overall risk surface.

---

## 🏗️ Core Workflow

1.  **Ingestion**: Import from **OpenAPI (YAML/JSON)**, **Postman**, **Insomnia**, or **cURL**.
2.  **Context**: Right-click any traffic in Burp Proxy/Repeater and select **"Send to APICollector"**.
3.  **Analysis**: Use the **Endpoints** and **Parameters** tabs to map the attack surface and data dictionary.
4.  **Testing**: Use the **Internal Executor** for rapid iteration or push to **Burp Repeater**.
5.  **Audit**: Document findings in the **Endpoints** tab to automatically populate the **Vulnerabilities** dashboard.
6.  **Verify**: Re-test findings using the **Revalidation Panel** and capture proof-of-fix snapshots.
7.  **Dashboard**: Monitor high-level assessment health and risk distribution in the **Dashboard** tab.
8.  **Report**: Generate professional **Markdown**, **CSV**, or **JSON** reports.

---

## 🛠️ Key Features (v0.0.3 Recap)

- **File-Based Project Management**: Save/Load entire workspaces into `.apic` files for assessment isolation.
- **Vulnerability Revalidation**: Stateful tracking with side-by-side PoC vs. Retest evidence.
- **Universal Parameter Decoding**: Automatic URL-decoding for human-readable parameter documentation.
- **Native Burp Integration**: Full use of `IMessageEditor` for syntax highlighting and context menus.

---

## 🚀 Getting Started

1.  Download `APICollector.py`.
2.  In Burp Suite, go to the **Extensions** tab -> **Installed** -> **Add**.
3.  Select **Python** as the extension type and point to `APICollector.py`.
4.  *(Prerequisite: Ensure **Jython 2.7.x** is configured in Burp Suite settings).*

---

## 📖 Release History

### v0.0.4 (Current)
- Added **Assessment Analytics Dashboard** with risk distribution & remediation metrics.
- Added **Visual Progress Tracking** for verified fixes.
- Enhanced dashboard UI with professional CSS metric cards.

### v0.0.3
- Added **Project Management** (.apic file system).
- Added **Vulnerability Revalidation** with dual-evidence tracking.
- Implemented **Universal URL Decoding** for parameters.
- Added **Global Status Bar** for operational feedback.

### v0.0.2
- Added context menu integration ("Send to APICollector").
- Integrated Burp native message editors.
- Added YAML support for OpenAPI.

### v0.0.1
- Initial release with Support for OpenAPI, Postman, and Insomnia.

---
*Developed by **Kamran Saifullah** for professional security researchers.*
