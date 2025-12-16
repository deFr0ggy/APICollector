# -*- coding: utf-8 -*-

from burp import IBurpExtender, ITab
from javax.swing import (
    JPanel, JButton, JTable, JScrollPane, JFileChooser,
    JCheckBox, JComboBox, JLabel, ListSelectionModel
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout
from javax.swing import (
    JPanel, JButton, JTable, JScrollPane, JFileChooser,
    JCheckBox, JComboBox, JLabel, ListSelectionModel,
    JTabbedPane, JTextArea, JSplitPane, JEditorPane,
    JTextField, JOptionPane
)
from javax.swing.event import HyperlinkListener, HyperlinkEvent
from javax.swing.event import HyperlinkListener, HyperlinkEvent
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, GridLayout, Color, Font
from java.awt import Rectangle
from java.net import URL
from java.lang import Boolean
import json
import re
import threading
import traceback


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("APICollector")

        self.env = {}
        self.bodies = {}
        self.api_spec = {} 
        self.vulns = [] 
        
        self.generated_tests_data = [] 
        self._build_ui()
        callbacks.addSuiteTab(self)

        self.log("Loaded")


    def _build_ui(self):
        self.main_panel = JPanel(BorderLayout())
        self.tabs = JTabbedPane()

        self.endpoints_panel = JPanel(BorderLayout())
        
        self.model = DefaultTableModel(
            ["Domain", "Scheme", "Method", "Path", "Auth", "Risk", "Type", "Status"], 0
        )

        self.table = JTable(self.model)
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(self.auto_push_selected)
        
        self.table.getColumnModel().getColumn(1).setCellRenderer(SchemeRenderer())
        self.table.getColumnModel().getColumn(2).setCellRenderer(MethodRenderer())
        self.table.getColumnModel().getColumn(7).setCellRenderer(StatusRenderer())

        self.stats = JLabel("Ready")
        self.endpoints_panel.add(self.stats, BorderLayout.NORTH)

        self.endpoint_tabs = JTabbedPane()
        self.ep_req_area = JTextArea()
        self.ep_req_area.setEditable(True) 
        self.ep_req_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.ep_res_area = JTextArea()
        self.ep_res_area.setEditable(False)
        
        self.endpoint_req_scroll = JScrollPane(self.ep_req_area)
        self.endpoint_res_scroll = JScrollPane(self.ep_res_area)
        
        self.ep_detail_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self.endpoint_req_scroll, self.endpoint_res_scroll)
        self.ep_detail_split.setResizeWeight(0.5)

        self.ep_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.ep_split.setTopComponent(JScrollPane(self.table))
        self.ep_split.setBottomComponent(self.ep_detail_split)
        self.ep_split.setDividerLocation(300)

        controls = JPanel()

        self.autoScan = JCheckBox("Auto send to Repeater")

        self.verbFilter = JComboBox(
            ["ALL", "GET", "POST", "PUT", "DELETE", "PATCH"]
        )

        controls.add(JButton("Import API", actionPerformed=self.import_api))
        controls.add(JButton("Clear Data", actionPerformed=self.clear_data))
        controls.add(JButton("Execute (Internal)", actionPerformed=self.send_endpoint_request))
        controls.add(JButton("Reset Request", actionPerformed=self.reset_endpoint_request))
        controls.add(JButton("Send to Repeater", actionPerformed=self.push_selected))
        controls.add(JButton("Send All to Repeater", actionPerformed=self.push_all))
        controls.add(JButton("Generate Security Tests", actionPerformed=self.generate_tests))

        controls.add(self.autoScan)
        controls.add(self.verbFilter)

        self.endpoints_panel.add(self.ep_split, BorderLayout.CENTER)
        self.endpoints_panel.add(controls, BorderLayout.SOUTH)

        self.dashboard_panel = JPanel(BorderLayout())
        self.dash_content = JEditorPane()
        self.dash_content.setContentType("text/html")
        self.dash_content.setEditable(False)
        self.dash_content.addHyperlinkListener(self.dashboard_link_clicked)
        self.dash_content.setText("<html><body><h1>Security Dashboard</h1><p>No API loaded.</p></body></html>")
        
        self.dashboard_panel.add(JScrollPane(self.dash_content), BorderLayout.CENTER)
        
        refresh_btn = JButton("Refresh Dashboard", actionPerformed=self.update_dashboard)
        self.dashboard_panel.add(refresh_btn, BorderLayout.SOUTH)

        refresh_btn = JButton("Refresh Dashboard", actionPerformed=self.update_dashboard)
        self.dashboard_panel.add(refresh_btn, BorderLayout.SOUTH)

        self.env_panel = JPanel(BorderLayout())
        
        env_form = JPanel(GridLayout(2, 4, 5, 5))
        self.env_host = JTextField("")
        self.env_port = JTextField("")
        self.env_scheme = JComboBox(["No Change", "HTTP", "HTTPS"])
        
        env_form.add(JLabel("New Host:"))
        env_form.add(self.env_host)
        env_form.add(JLabel("New Port:"))
        env_form.add(self.env_port)
        env_form.add(JLabel("New Scheme:"))
        env_form.add(self.env_scheme)
        env_form.add(JButton("Select All", actionPerformed=lambda x: self.toggle_env_selection(True)))
        env_form.add(JButton("Deselect All", actionPerformed=lambda x: self.toggle_env_selection(False)))

        self.env_panel.add(env_form, BorderLayout.NORTH)

        self.env_model = BooleanTableModel(["Select", "Method", "Domain", "Path"], 0)
        self.env_table = JTable(self.env_model)
        
        self.env_panel.add(JScrollPane(self.env_table), BorderLayout.CENTER)

        env_actions = JPanel()
        env_actions.add(JButton("Refresh List", actionPerformed=self.sync_env_table))
        env_actions.add(JButton("Apply Changes", actionPerformed=self.apply_env_changes))
        
        self.env_panel.add(env_actions, BorderLayout.SOUTH)

        self.test_manager_panel = JPanel(BorderLayout())
        
        self.test_model = DefaultTableModel(["ID", "Method", "Path", "Type"], 0)
        self.test_table = JTable(self.test_model)
        self.test_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.test_table.getSelectionModel().addListSelectionListener(self.test_selected)
        
        self.preview_panel = JPanel(BorderLayout())
        
        self.tm_tabs = JTabbedPane()
        self.tm_req_text = JTextArea()
        self.tm_req_text.setEditable(True) 
        self.tm_req_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        
        self.tm_res_text = JTextArea()
        self.tm_res_text.setEditable(False)
        self.tm_res_text.setFont(Font("Monospaced", Font.PLAIN, 12))
        
        self.tm_req_scroll = JScrollPane(self.tm_req_text)
        self.tm_res_scroll = JScrollPane(self.tm_res_text)
        
        self.tm_detail_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.tm_req_scroll, self.tm_res_scroll)
        self.tm_detail_split.setResizeWeight(0.5)
        
        preview_controls = JPanel()
        self.tm_send_btn = JButton("Send Request", actionPerformed=self.send_test_request)
        self.tm_reset_btn = JButton("Reset Request", actionPerformed=self.reset_test_request)
        self.preview_btn = JButton("Send to Repeater", actionPerformed=self.send_preview_to_repeater)
        self.preview_btn.setEnabled(False)
        self.tm_send_btn.setEnabled(False)
        self.tm_reset_btn.setEnabled(False)
        self.clear_tests_btn = JButton("Clear List", actionPerformed=self.clear_tests)
        
        preview_controls.add(self.tm_send_btn)
        preview_controls.add(self.tm_reset_btn)
        preview_controls.add(self.preview_btn)
        preview_controls.add(self.clear_tests_btn)
        
        self.preview_panel.add(self.tm_detail_split, BorderLayout.CENTER)
        self.preview_panel.add(preview_controls, BorderLayout.SOUTH)
        
        self.split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(self.test_table), self.preview_panel)
        self.split.setDividerLocation(400)
        
        self.test_manager_panel.add(self.split, BorderLayout.CENTER)
        
        self.param_panel = JPanel(BorderLayout())
        self.param_model = DefaultTableModel(["Method", "Path", "Request Params", "Response Params"], 0)
        self.param_table = JTable(self.param_model)
        self.param_panel.add(JScrollPane(self.param_table), BorderLayout.CENTER)

        self.tabs.addTab("Endpoints", self.endpoints_panel)
        self.tabs.addTab("Dashboard", self.dashboard_panel)
        self.tabs.addTab("Environment", self.env_panel)
        self.tabs.addTab("Test Manager", self.test_manager_panel)
        self.tabs.addTab("Parameters", self.param_panel)

        self.main_panel.add(self.tabs, BorderLayout.CENTER)


    def import_api(self, event):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) != JFileChooser.APPROVE_OPTION:
            return

        try:
            raw = open(chooser.getSelectedFile().getAbsolutePath()).read()
            is_yaml = False
            root = None
            try:
                root = json.loads(raw)
            except:
                try:
                    from org.yaml.snakeyaml import Yaml
                    root = Yaml().load(raw)
                    is_yaml = True
                    self.log("Parsed as YAML")
                except Exception as ye:
                    self.log("JSON and YAML parsing failed. Error: %s" % ye)
                    return

            
            is_postman = False
            if "info" in root:
                info = root.get("info", {})
                if "_postman_id" in info or "postman" in info.get("schema", ""):
                     is_postman = True
            
            if root.get("_type") == "export":
                self.log("Detected Insomnia export")
                self.load_environment(root)
                self.parse_insomnia(root)
            elif "swagger" in root or "openapi" in root:
                if is_yaml: self.log("Detected Swagger/OpenAPI (YAML)")
                else: self.log("Detected Swagger/OpenAPI (JSON)")
                self.parse_openapi(root)
            elif is_postman:
                self.log("Detected Postman Collection")
                self.parse_postman(root)
            else:
                self.log("Unknown format. structure: %s" % root.keys())
                self.parse_openapi(root) 

            self.update_dashboard(None)

        except Exception as e:
            self.log("Import failed: %s" % e)

    def clear_data(self, event):
        resp = JOptionPane.showConfirmDialog(
            self.main_panel,
            "Are you sure you want to clear all data? This cannot be undone.",
            "Confirm Clear Data",
            JOptionPane.YES_NO_OPTION
        )
        
        if resp != JOptionPane.YES_OPTION:
            return

        self.model.setRowCount(0)
        self.test_model.setRowCount(0)
        self.generated_tests_data = []
        self.env = {}
        self.bodies = {}
        self.api_spec = {}
        self.stats.setText("Data cleared")
        self.update_dashboard(None)
        self.tm_req_text.setText("")
        self.tm_res_text.setText("")
        self.preview_btn.setEnabled(False)
        self.tm_send_btn.setEnabled(False)
        self.tm_reset_btn.setEnabled(False)
        
        self.ep_req_area.setText("")
        self.ep_res_area.setText("")
        
        self.env_model.setRowCount(0)
        self.env_host.setText("")
        self.env_port.setText("")
        self.env_scheme.setSelectedIndex(0)
        
        self.param_model.setRowCount(0)


    def sync_env_table(self, event):
        self.env_model.setRowCount(0)
        rows = self.model.getRowCount()
        for i in range(rows):
            method = self.model.getValueAt(i, 2)
            domain = self.model.getValueAt(i, 0)
            path = self.model.getValueAt(i, 3)
            self.env_model.addRow([False, method, domain, path])

    def toggle_env_selection(self, state):
        for i in range(self.env_model.getRowCount()):
            self.env_model.setValueAt(state, i, 0)

    def apply_env_changes(self, event):
        new_host = self.env_host.getText().strip()
        new_port = self.env_port.getText().strip()
        new_scheme = self.env_scheme.getSelectedItem()
        
        count = 0
        for i in range(self.env_model.getRowCount()):
            if self.env_model.getValueAt(i, 0):
                if new_scheme != "No Change":
                    self.model.setValueAt(new_scheme, i, 1)
                
                if new_host:
                    domain_val = new_host
                    if new_port:
                        domain_val += ":" + new_port
                    self.model.setValueAt(domain_val, i, 0)
                elif new_port:
                    current_domain = self.model.getValueAt(i, 0).split(":")[0]
                    self.model.setValueAt(current_domain + ":" + new_port, i, 0)
                
                self.env_model.setValueAt(self.model.getValueAt(i, 0), i, 2)
                
                count += 1
        
        self.stats.setText("Updated %d endpoints." % count)
        self.update_dashboard(None)


    def load_environment(self, root):
        for r in root.get("resources", []):
            if r.get("_type") == "environment":
                for k, v in r.get("data", {}).items():
                    if isinstance(v, basestring):
                        self.env[k] = v

    def resolve_vars(self, text):
        if not text:
            return text

        def repl(m):
            return self.env.get(m.group(1), m.group(0))

        return re.sub(r"\{\{\s*_\.(.*?)\s*\}\}", repl, text)

    
    def _extract_json_keys(self, data):
        keys = set()
        if isinstance(data, dict):
             for k, v in data.items():
                 keys.add(k)
                 keys.update(self._extract_json_keys(v))
        elif isinstance(data, list):
             for item in data:
                 keys.update(self._extract_json_keys(item))
        return keys

    def parse_insomnia(self, root):
        count = 0

        for r in root.get("resources", []):
            if r.get("_type") != "request":
                continue

            try:
                raw_url = self.resolve_vars(r.get("url", ""))
                if not raw_url.startswith("http"):
                    raw_url = "https://example.com" + raw_url

                u = URL(raw_url)

                domain = u.getHost()
                scheme = u.getProtocol().upper()
                verb = r.get("method", "GET")
                path = u.getPath() or "/"

                auth = self.insomnia_auth(r)
                risk = self.risk(verb, auth)

                self.model.addRow([domain, scheme, verb, path, auth, risk, "REST", ""])

                body = None
                if r.get("body") and isinstance(r.get("body"), dict):
                    body = r["body"].get("text")
                
                req_params = []
                if body:
                    try:
                        j_body = json.loads(body)
                        req_params = list(self._extract_json_keys(j_body))
                    except:
                        pass
                
                self.param_model.addRow([verb, path, ", ".join(sorted(req_params)), ""])

                self.bodies[self.model.getRowCount() - 1] = body
                count += 1

            except Exception as e:
                self.log("Parse error: %s" % e)

        self.stats.setText("Imported %d endpoints" % count)


    def parse_postman(self, root):
        self.postman_item_count = 0
        items = root.get("item", [])
        self._traverse_postman_items(items)
        self.stats.setText("Imported %d Postman endpoints" % self.postman_item_count)

    def _traverse_postman_items(self, items):
        for item in items:
            if "item" in item:
                self._traverse_postman_items(item["item"])
            elif "request" in item:
                self._parse_postman_request(item)

    def _parse_postman_request(self, item):
        try:
            req = item["request"]
            
            url_obj = req.get("url")
            raw_url = ""
            if isinstance(url_obj, dict):
                 raw_url = url_obj.get("raw", "")
            elif isinstance(url_obj, basestring):
                 raw_url = url_obj
            
            raw_url = self.resolve_vars(raw_url)
            
            if not raw_url.startswith("http"):
                raw_url = "https://" + raw_url

            u = URL(raw_url)
            domain = u.getHost()
            scheme = u.getProtocol().upper()
            path = u.getPath() or "/"
            
            verb = req.get("method", "GET")

            auth = "None"
            if req.get("auth"):
                 auth = req["auth"].get("type", "Custom")
            
            risk = self.risk(verb, auth)

            self.model.addRow([domain, scheme, verb, path, auth, risk, "Postman", ""])

            body = None
            if req.get("body"):
                body_mode = req["body"].get("mode")
                if body_mode == "raw":
                    body = req["body"].get("raw")
                elif body_mode == "graphql":
                     body = req["body"].get("graphql", {}).get("query")
            
            self.bodies[self.model.getRowCount() - 1] = body
            
            req_params = []
            if body:
                try:
                    j_body = json.loads(body)
                    req_params = list(self._extract_json_keys(j_body))
                except:
                    pass
            self.param_model.addRow([verb, path, ", ".join(sorted(req_params)), ""])

            self.postman_item_count += 1
            
        except Exception as e:
            self.log("Postman item error: %s" % e)


    def parse_openapi(self, root):
        count = 0
        paths = root.get("paths", {})
        
        base_url = "https://example.com"
        if "servers" in root and len(root["servers"]) > 0:
            base_url = root["servers"][0].get("url", base_url)
        elif "host" in root:
             scheme = "https" if "https" in root.get("schemes", []) else "http"
             base_url = "%s://%s%s" % (scheme, root.get("host"), root.get("basePath", ""))

        for path, methods in paths.items():
            for method, spec in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    continue
                
                try:
                    full_url = base_url + path
                    u = URL(full_url)
                    
                    domain = u.getHost()
                    scheme = u.getProtocol().upper()
                    verb = method.upper()
                    r_path = u.getPath()
                    
                    auth = "None"
                    if "security" in spec or "security" in root:
                        auth = "API Key/Bearer" 
                    
                    risk = self.risk(verb, auth)
                    
                    self.model.addRow([domain, scheme, verb, r_path, auth, risk, "OpenAPI", ""])
                    
                    body = None
                    req_params = []
                    res_params = []

                    if "requestBody" in spec:
                        content = spec["requestBody"].get("content", {})
                        if "application/json" in content:
                            schema = content["application/json"].get("schema")
                            if schema:
                                body = json.dumps(self.generate_example(schema, root), indent=2)
                                req_params = list(self._extract_openapi_keys(schema, root))

                    for code in ["200", "201", "default"]:
                         if code in spec["responses"]:
                             resp_obj = spec["responses"][code]
                             if "content" in resp_obj and "application/json" in resp_obj["content"]:
                                 schema = resp_obj["content"]["application/json"].get("schema")
                                 if schema:
                                     res_params = list(self._extract_openapi_keys(schema, root))
                             break 

                    self.bodies[self.model.getRowCount() - 1] = body
                    self.param_model.addRow([verb, r_path, ", ".join(sorted(req_params)), ", ".join(sorted(res_params))])
                    
                    count += 1
                except Exception as e:
                    self.log("OpenAPI parse error: %s" % e)

        self.stats.setText("Imported %d OpenAPI endpoints" % count)

    def generate_example(self, schema, root):
        if "$ref" in schema:
            ref = schema["$ref"].split("/")[-1]
            if "components" in root and "schemas" in root["components"]:
                return self.generate_example(root["components"]["schemas"].get(ref, {}), root)
            if "definitions" in root:
                return self.generate_example(root["definitions"].get(ref, {}), root)
            return {}
        
        t = schema.get("type")
        if t == "object":
            obj = {}
            for k, v in schema.get("properties", {}).items():
                obj[k] = self.generate_example(v, root)
            return obj
        if t == "array":
            return [self.generate_example(schema.get("items", {}), root)]
        if t == "string": return "string"
        if t == "integer": return 123
        if t == "boolean": return True
        return "value"

    def _extract_openapi_keys(self, schema, root, visited=None):
        if visited is None:
            visited = set()
        
        keys = set()
        
        if "$ref" in schema:
            ref = schema["$ref"].split("/")[-1]
            if ref in visited:
                return keys 
            visited.add(ref)
            
            target = {}
            if "components" in root and "schemas" in root["components"]:
                target = root["components"]["schemas"].get(ref, {})
            elif "definitions" in root:
                target = root["definitions"].get(ref, {})
            
            return self._extract_openapi_keys(target, root, visited)

        if schema.get("type") == "object" or "properties" in schema:
            for k, v in schema.get("properties", {}).items():
                keys.add(k)
                keys.update(self._extract_openapi_keys(v, root, visited))
        
        if schema.get("type") == "array":
            keys.update(self._extract_openapi_keys(schema.get("items", {}), root, visited))
            
        return keys

    
    def update_dashboard(self, event):
        total = self.model.getRowCount()
        if total == 0:
             self.dash_content.setText("<html><body><h2>No API Loaded</h2></body></html>")
             return

        owasp_hits = {
            "API1:2023 Broken Object Level Authorization": [],
            "API2:2023 Broken Authentication": [],
            "API3:2023 Broken Object Property Level Authorization": [],
            "API4:2023 Unrestricted Resource Consumption": [],
            "API5:2023 Broken Function Level Authorization": [],
            "API6:2023 Unrestricted Access to Sensitive Business Flows": [],
            "API7:2023 Server Side Request Forgery": [],
            "API8:2023 Security Misconfiguration": [],
            "API9:2023 Improper Inventory Management": [],
            "API10:2023 Unsafe Consumption of APIs": []
        }

        for i in range(total):
            row_data = self._get_row_data(i)
            hits = self.check_owasp_rules(row_data)
            for h in hits:
                link = "<a href='goto:%d'>%s %s</a>" % (i, row_data['method'], row_data['path'])
                owasp_hits[h].append(link)

        html = """
        <html>
        <head><style>
            body{font-family: sans-serif; padding: 20px; color: #333;} 
            h1{color: #2c3e50;}
            h2{color: #e67e22; margin-top: 20px; border-bottom: 2px solid #eee;} 
            .stat{margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 4px solid #ddd;}
            .bad{border-left-color: #e74c3c;}
            .warn{border-left-color: #f1c40f;}
            ul{margin-top: 5px; font-size: 12px; color: #555;}
            li{font-family: monospace; list-style-type: none; margin-bottom: 2px;}
            a{text-decoration: none; color: #3498db;}
        </style></head>
        <body>
            <h1>API Security Dashboard</h1>
            <p>Static Analysis of <b>%d</b> endpoints against OWASP API Security Top 10 (2023).</p>
            
            %s
        </body>
        </html>
        """ 
        
        sections = ""
        for rule_name in sorted(owasp_hits.keys()):
            hits = owasp_hits[rule_name]
            count = len(hits)
            css_class = "bad" if count > 0 else "stat"
            
            hits_html = ""
            if count > 0:
                hits_html = "<ul>" + "".join(["<li>%s</li>" % h for h in hits])
                hits_html += "</ul>"
            else:
                hits_html = "<span style='color:green; font-size:12px; margin-left:10px;'>No obvious issues detected</span>"

            sections += """
            <div class="stat %s">
                <b>%s</b>: %d potential issues
                %s
            </div>
            """ % (css_class if count > 0 else "", rule_name, count, hits_html)

        self.dash_content.setText(html % (total, sections))

    def dashboard_link_clicked(self, event):
        if event.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
            desc = event.getDescription()
            if desc.startswith("goto:"):
                try:
                    row_index = int(desc.split(":")[1])
                    self.tabs.setSelectedIndex(0) 
                    self.table.setRowSelectionInterval(row_index, row_index)
                    rect = self.table.getCellRect(row_index, 0, True)
                    self.table.scrollRectToVisible(rect)
                except Exception as e:
                    self.log("Link error: %s" % e)

    def _get_row_data(self, row):
        return {
            "domain": self.model.getValueAt(row, 0),
            "scheme": self.model.getValueAt(row, 1),
            "method": self.model.getValueAt(row, 2),
            "path": self.model.getValueAt(row, 3),
            "auth": self.model.getValueAt(row, 4),
            "risk": self.model.getValueAt(row, 5),
            "body": self.bodies.get(row)
        }

    def check_owasp_rules(self, data):
        hits = []
        path = data['path'].lower()
        method = data['method']
        
        if re.search(r"\{.*?\}|/users?/\d+|/accounts?/\d+", path):
            hits.append("API1:2023 Broken Object Level Authorization")

        if data['auth'] == "None":
            hits.append("API2:2023 Broken Authentication")

        if method in ["POST", "PUT", "PATCH"]:
            hits.append("API3:2023 Broken Object Property Level Authorization")

        if method == "GET" and ("list" in path or method == "GET") and not "?" in path:
             if path.endswith("s"): 
                 hits.append("API4:2023 Unrestricted Resource Consumption")

        if any(x in path for x in ["admin", "internal", "private", "dashboard"]):
            hits.append("API5:2023 Broken Function Level Authorization")

        if any(x in path for x in ["buy", "order", "checkout", "transfer", "send", "reset"]):
            hits.append("API6:2023 Unrestricted Access to Sensitive Business Flows")

        if data['body'] and any(x in data['body'].lower() for x in ["url", "uri", "webhook", "callback", "dest"]):
             hits.append("API7:2023 Server Side Request Forgery")
        
        if data['scheme'].lower() != "https":
            hits.append("API8:2023 Security Misconfiguration")

        if not re.search(r"/v\d+/", path):
             hits.append("API9:2023 Improper Inventory Management")
        
        if "webhook" in path or "callback" in path:
            hits.append("API10:2023 Unsafe Consumption of APIs")

        return hits


    def generate_tests(self, event):
        rows = self.table.getSelectedRows()
        if len(rows) == 0:
            self.stats.setText("Status: Select an endpoint first to generate tests.")
            return
        
        count = 0
        for i in rows:
             self.create_test_cases(i)
             count += 1
             
        self.stats.setText("Generated tests for %d endpoints. Check Test Manager tab." % count)
        self.tabs.setSelectedIndex(2) 

    def create_test_cases(self, row):
        base_req_info = self.build_request_info(row)
        if not base_req_info:
            return

        payloads = [
            ("' OR '1'='1", "SQLi_Basic"),
            ("admin' --", "SQLi_Admin"),
            ("<script>alert(1)</script>", "XSS_Reflected"),
            ("../../../../../etc/passwd", "LFI"),
            ("%2e%2e%2fetc%2fpasswd", "LFI_Encoded"),
            ("NaN", "Error_Inducing")
        ]

        self.store_test(base_req_info, base_req_info['body'], "Baseline")


        
        if base_req_info['body']:
            try:
                json_body = json.loads(base_req_info['body'])
                self.fuzz_json(json_body, payloads, base_req_info)
            except:
                pass

    def fuzz_json(self, root_data, payloads, base_req_info):
        self._fuzz_recursive(root_data, [], payloads, base_req_info, root_data)

    def _fuzz_recursive(self, current, path, payloads, base_req_info, root):
        if isinstance(current, dict):
            for k, v in current.items():
                new_path = path + [k]
                self._check_and_fuzz(v, new_path, payloads, base_req_info, root)
                self._fuzz_recursive(v, new_path, payloads, base_req_info, root)
        elif isinstance(current, list):
            for i, v in enumerate(current):
                new_path = path + [i]
                self._check_and_fuzz(v, new_path, payloads, base_req_info, root)
                self._fuzz_recursive(v, new_path, payloads, base_req_info, root)

    def _check_and_fuzz(self, value, path, payloads, base_req_info, root):
        if isinstance(value, (basestring, int, float)):
            for p, name in payloads:
                mutated_root = json.loads(json.dumps(root))
                
                target = mutated_root
                for step in path[:-1]:
                    target = target[step]
                target[path[-1]] = str(value) + p
                
                self.store_test(base_req_info, json.dumps(mutated_root), "Fuzz_%s_%s" % (name, path[-1]))

    def store_test(self, info, body_str, description):
        req_headers = info['headers']
        body_bytes = body_str.encode("utf-8") if body_str else b""
        final_req = self.helpers.buildHttpMessage(req_headers, body_bytes)
        
        test_id = len(self.generated_tests_data)
        self.generated_tests_data.append({
            "id": test_id,
            "info": info,
            "request_bytes": final_req,
            "description": description,
            "body_str": body_str
        })
        
        self.test_model.addRow([test_id, info['headers'][0].split(" ")[0], info['url'].getPath(), description])


    def test_selected(self, event):
        if event.getValueIsAdjusting():
            return
        
        row = self.test_table.getSelectedRow()
        if row >= 0:
            test_id = self.test_model.getValueAt(row, 0)
            data = self.generated_tests_data[test_id]
            self.tm_req_text.setText(self.helpers.bytesToString(data['request_bytes']))
            self.tm_res_text.setText("") 
            self.preview_btn.setEnabled(True)
            self.tm_send_btn.setEnabled(True)
            self.tm_reset_btn.setEnabled(True)
        else:
            self.tm_req_text.setText("")
            self.tm_res_text.setText("")
            self.preview_btn.setEnabled(False)
            self.tm_send_btn.setEnabled(False)
            self.tm_reset_btn.setEnabled(False)

    def send_preview_to_repeater(self, event):
        rows = self.test_table.getSelectedRows()
        if len(rows) == 0:
             return

        for row in rows:
            test_id = self.test_model.getValueAt(row, 0)
            data = self.generated_tests_data[test_id]
            info = data['info']
            
            self.callbacks.sendToRepeater(
                info['host'],
                info['port'],
                info['use_https'],
                data['request_bytes'],
                info['title'] + " " + data['description']
            )

    def clear_tests(self, event):
        self.test_model.setRowCount(0)
        self.generated_tests_data = []
        self.tm_req_text.setText("")
        self.tm_res_text.setText("")
        self.preview_btn.setEnabled(False)
        self.tm_send_btn.setEnabled(False)
        self.tm_reset_btn.setEnabled(False)

    def reset_test_request(self, event):
        row = self.test_table.getSelectedRow()
        if row >= 0:
            test_id = self.test_model.getValueAt(row, 0)
            data = self.generated_tests_data[test_id]
            self.tm_req_text.setText(self.helpers.bytesToString(data['request_bytes']))
            self.tm_res_text.setText("Reset to original test case.")

    def send_test_request(self, event):
        req_str = self.tm_req_text.getText()
        if not req_str:
            self.tm_res_text.setText("Request empty")
            return
            
        row = self.test_table.getSelectedRow()
        if row < 0: 
            return 

        test_id = self.test_model.getValueAt(row, 0)
        data = self.generated_tests_data[test_id]
        info = data['info']

        try:
             req_bytes = self.helpers.stringToBytes(req_str)
             
             self.tm_res_text.setText("Sending...")
             resp = self.callbacks.makeHttpRequest(
                 info['host'],
                 info['port'],
                 info['use_https'],
                 req_bytes
             )
             
             if resp:
                 self.tm_res_text.setText(self.helpers.bytesToString(resp))
        except Exception as e:
            traceback.print_exc()
            self.tm_res_text.setText("Error: %s" % e)

    def build_request_info(self, row):
        try:
            domain = self.model.getValueAt(row, 0)
            scheme = self.model.getValueAt(row, 1).lower()
            method = self.model.getValueAt(row, 2)
            path = self.model.getValueAt(row, 3)
            body = self.bodies.get(row)

            url = URL("%s://%s%s" % (scheme, domain, path))
            port = url.getPort()
            if port == -1:
                port = 443 if scheme == "https" else 80

            req = self.helpers.buildHttpRequest(url)
            req_info = self.helpers.analyzeRequest(req)
            headers = list(req_info.getHeaders())
            headers[0] = "%s %s HTTP/1.1" % (method, path)
            
            if body and "Content-Type" not in str(headers):
                headers.append("Content-Type: application/json")

            return {
                'host': url.getHost(),
                'port': port,
                'use_https': (scheme == "https"),
                'headers': headers,
                'body': body,
                'url': url,
                'title': "%s %s" % (method, path)
            }
        except Exception as e:
            self.log("Build req error: %s" % e)
            return None

    def send_to_repeater(self, row):
        info = self.build_request_info(row)
        if info:
            req_headers = info['headers']
            body_str = info['body']
            body_bytes = body_str.encode("utf-8") if body_str else b""
            final_req = self.helpers.buildHttpMessage(req_headers, body_bytes)
            
            self.callbacks.sendToRepeater(
                info['host'],
                info['port'],
                info['use_https'],
                final_req,
                info['title']
            )
            self.log("Sent request to Repeater: %s" % info['title'])
        else:
            self.log("Failed to build request for row %d" % row)

    def push_selected(self, event):
        row = self.table.getSelectedRow()
        if row >= 0:
            self.send_to_repeater(row)
        else:
            self.log("No row selected for Push to Repeater")

    def push_all(self, event):
        count = 0
        for i in range(self.model.getRowCount()):
            try:
                if (
                    self.verbFilter.getSelectedItem() == "ALL"
                    or self.model.getValueAt(i, 2) == self.verbFilter.getSelectedItem()
                ):
                    self.send_to_repeater(i)
                    count += 1
            except Exception as e:
                self.log("Error processing row %d: %s" % (i, e))
        self.stats.setText("Sent %d requests to Repeater" % count)

    def auto_push_selected(self, event):
        if event.getValueIsAdjusting():
            return
            
        row = self.table.getSelectedRow()
        if row >= 0:
            info = self.build_request_info(row)
            if info:
                req_bytes = self.helpers.buildHttpMessage(info['headers'], info['body'].encode('utf-8') if info['body'] else b"")
                self.ep_req_area.setText(self.helpers.bytesToString(req_bytes))
                self.ep_res_area.setText("") 
            
            if self.autoScan.isSelected():
                self.send_to_repeater(row)

    def send_endpoint_request(self, event):
        row = self.table.getSelectedRow()
        if row < 0:
            self.stats.setText("Select an endpoint first.")
            return

        info = self.build_request_info(row)
        if not info:
             return
             
        req_str = self.ep_req_area.getText()
        t = threading.Thread(target=self._do_request, args=(row, info, req_str))
        t.start()

    def _do_request(self, row, info, req_str=None):
        try:
            self.model.setValueAt("Sending...", row, 7)
            self.stats.setText("Sending request...")
            
            if req_str:
                req_bytes = self.helpers.stringToBytes(req_str)
            else:
                req_bytes = self.helpers.buildHttpMessage(info['headers'], info['body'].encode('utf-8') if info['body'] else b"")
            
            resp = self.callbacks.makeHttpRequest(
                info['host'],
                info['port'],
                info['use_https'],
                req_bytes
            )
            
            if resp:
                status_code = self.helpers.analyzeResponse(resp).getStatusCode()
                self.model.setValueAt("%d %s" % (status_code, "OK" if status_code == 200 else ""), row, 7)
                
                self.ep_res_area.setText(self.helpers.bytesToString(resp))
                self.stats.setText("Response received: %d bytes (Status: %d)" % (len(resp), status_code))
        except Exception as e:
            traceback.print_exc()
            self.model.setValueAt("Error", row, 7)
            self.ep_res_area.setText("Error: %s" % e)
            self.stats.setText("Error sending request")

    def reset_endpoint_request(self, event):
        row = self.table.getSelectedRow()
        if row >= 0:
            info = self.build_request_info(row)
            if info:
                req_bytes = self.helpers.buildHttpMessage(info['headers'], info['body'].encode('utf-8') if info['body'] else b"")
                self.ep_req_area.setText(self.helpers.bytesToString(req_bytes))
                self.stats.setText("Request reset to original.")


    def insomnia_auth(self, r):
        a = r.get("authentication")
        if not a or not a.get("type"):
            return "None"
        t = a.get("type").lower()
        if "oauth" in t:
            return "OAuth2"
        if "bearer" in t:
            return "Bearer"
        return "API Key"

    def risk(self, verb, auth):
        if auth == "None" and verb != "GET":
            return "HIGH"
        if auth == "None":
            return "MEDIUM"
        return "LOW"

    def log(self, msg):
        self.callbacks.printOutput("[APICollector] " + msg)

    def getTabCaption(self):
        return "APICollector"

    def getUiComponent(self):
        return self.main_panel


class SchemeRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = super(SchemeRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
        
        s = str(value).upper()
        if s == "HTTP":
            c.setForeground(Color.ORANGE.darker())
        elif s == "HTTPS":
             c.setForeground(Color.decode("#00aa00")) 
        else:
            c.setForeground(Color.BLACK)
            
        return c

class MethodRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = super(MethodRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
        
        s = str(value).upper()
        if s in ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"]:
            c.setForeground(Color.BLUE)
        else:
             c.setForeground(Color.BLACK)
             
        return c

class StatusRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = super(StatusRenderer, self).getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col)
        s = str(value)
        
        if s.startswith("2"):
            c.setForeground(Color.decode("#00aa00")) 
        elif s.startswith("3"):
            c.setForeground(Color.ORANGE.darker())
        elif s.startswith("4") or s.startswith("5") or "Error" in s:
            c.setForeground(Color.RED)
        elif "Sending" in s:
            c.setForeground(Color.BLUE)
        else:
             c.setForeground(Color.BLACK)
             
        return c

class BooleanTableModel(DefaultTableModel):
    def getColumnClass(self, columnIndex):
        if columnIndex == 0:
            return Boolean
        return super(BooleanTableModel, self).getColumnClass(columnIndex)