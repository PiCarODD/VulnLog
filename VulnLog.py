from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IExtensionStateListener
from javax.swing import (JPanel, JButton, JTable, JScrollPane, JSplitPane, 
                        JTabbedPane, JLabel, JComboBox, BoxLayout, Box, 
                        JOptionPane, BorderFactory, JCheckBox, JTextField)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, FlowLayout, Color, Dimension
from java.util import ArrayList
from java.lang import Runnable
from javax.swing import JFileChooser, Box, BoxLayout
from java.io import File
import json
import time
import base64
import hashlib
import sys
import os

def log(msg):
    print >> sys.stderr, "[VulnLog] " + str(msg)

class VulnRunnable(Runnable):
    def __init__(self, target):
        self.target = target
    def run(self): 
        self.target()

class MessageController:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.listeners = []
        self.data = []
        self.project_id = self._get_project_id()
        log("Initializing for project: " + str(self.project_id))
        self._load_data()

    def _delayed_load(self):
        """Load data after short delay to ensure project is loaded"""
        try:
            self._load_data()
            self.notify_listeners()
            log("Delayed load completed")
        except Exception as e:
            log("Delayed load failed: " + str(e))    

    def add_listener(self, listener):
        self.listeners.append(listener)

    def notify_listeners(self):
        for listener in self.listeners:
            SwingUtilities.invokeLater(VulnRunnable(listener.update))

    def add_vulnerability(self, entry):
        self.data.append(entry)
        self._save_data()
        self.notify_listeners()

    def get_data(self):
        return self.data

    def delete_finding(self, index):
        """Delete finding at specified index"""
        if 0 <= index < len(self.data):
            del self.data[index]
            self._save_data()
            self.notify_listeners()

    def update_status(self, index, new_status):
        """Update status of finding at specified index"""
        if 0 <= index < len(self.data):
            self.data[index]['status'] = new_status
            self._save_data()
            self.notify_listeners()

    

    def clear_data(self):
        self.data = []
        self._save_data()
        self.notify_listeners()

    def _get_project_key(self):
        """Get current project's unique key"""
        try:
            # Use a simple timestamp-based key for the current session
            return "vulnlog_findings"
        except Exception as e:
            log("Error getting project key: " + str(e))
        return None


    def _get_project_id(self):
        """Get unique identifier for current project"""
        try:
            # Try to get from proxy history
            http_listeners = self.callbacks.getProxyHistory()
            if http_listeners and len(http_listeners) > 0:
                first_req = http_listeners[0]
                if first_req:
                    host = first_req.getHttpService().getHost()
                    # Load or create timestamp for this host
                    timestamp_key = "project_timestamp_" + host
                    timestamp = self.callbacks.loadExtensionSetting(timestamp_key)
                    if not timestamp:
                        timestamp = str(int(time.time()))
                        self.callbacks.saveExtensionSetting(timestamp_key, timestamp)
                    
                    # Combine host and timestamp for unique project ID
                    project_id = hashlib.md5((host + "_" + timestamp).encode()).hexdigest()
                    log("Using host and timestamp as project ID: {} ({})".format(host, timestamp))
                    return project_id

            # If no proxy history, try to get from sitemap with same logic
            sitemap = self.callbacks.getSiteMap(None)
            if sitemap and len(sitemap) > 0:
                first_entry = sitemap[0]
                if first_entry:
                    host = first_entry.getHttpService().getHost()
                    timestamp_key = "project_timestamp_" + host
                    timestamp = self.callbacks.loadExtensionSetting(timestamp_key)
                    if not timestamp:
                        timestamp = str(int(time.time()))
                        self.callbacks.saveExtensionSetting(timestamp_key, timestamp)
                    
                    project_id = hashlib.md5((host + "_" + timestamp).encode()).hexdigest()
                    log("Using sitemap host and timestamp as project ID: {} ({})".format(host, timestamp))
                    return project_id

            log("No project identifier found, using session ID")
            session_id = "session_" + str(int(time.time()))
            return session_id
        except Exception as e:
            log("Error getting project ID: " + str(e))
            session_id = "session_" + str(int(time.time()))
            return session_id

    def _save_data(self):
        """Save findings to current project"""
        try:
            serialized = []
            for entry in self.data:
                serialized_entry = {
                    'id': entry['id'],
                    'url': entry['url'],
                    'name': entry['name'],
                    'host': entry['host'],
                    'port': entry['port'],
                    'protocol': entry['protocol'],
                    'status': entry['status'],
                    'timestamp': entry['timestamp'],
                    'request': base64.b64encode(entry['request']).decode('utf-8'),
                    'response': base64.b64encode(entry['response']).decode('utf-8') if entry['response'] else None
                }
                serialized.append(serialized_entry)
            
            project_data = json.dumps(serialized)
            # Save using project-specific key
            setting_key = "vulnlog_findings_" + self.project_id
            self.callbacks.saveExtensionSetting(setting_key, project_data)
            log("Saved {} findings for project {}".format(len(self.data), self.project_id))
        except Exception as e:
            log("Save failed: " + str(e))

    def _load_data(self):
        """Load findings for current project"""
        try:
            # Load using project-specific key
            setting_key = "vulnlog_findings_" + self.project_id
            project_data = self.callbacks.loadExtensionSetting(setting_key)
            log("Loading data for project: " + self.project_id)
            
            if project_data:
                loaded = json.loads(project_data)
                self.data = []
                for entry in loaded:
                    decoded_entry = {
                        'id': entry['id'],
                        'url': entry['url'],
                        'name': entry['name'],
                        'host': entry['host'],
                        'port': entry['port'],
                        'protocol': entry['protocol'],
                        'status': entry['status'],
                        'timestamp': entry['timestamp'],
                        'request': base64.b64decode(entry['request'].encode('utf-8')),
                        'response': base64.b64decode(entry['response'].encode('utf-8')) if entry['response'] else None
                    }
                    self.data.append(decoded_entry)
                log("Loaded {} findings for project {}".format(len(self.data), self.project_id))
            else:
                log("No existing findings for project " + self.project_id)
                self.data = []
        except Exception as e:
            log("Load failed: " + str(e))
            self.data = []

    

    
    def add_vulnerability(self, entry):
        """Add new vulnerability and notify listeners"""
        log("Adding new vulnerability")
        self.data.append(entry)
        self._save_data()
        self.notify_listeners()
        log("Vulnerability added and saved")

    def clear_data(self):
        """Clear all findings"""
        self.data = []
        self._save_data()
        self.notify_listeners()


    # Remove get_storage_file() and other file-related methods
    # Keep other existing methods (get_data, add_listener, notify_listeners)

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("VulnLog")
        
        # Initial setup
        self.controller = MessageController(callbacks)
        self.ui = VulnLogTab(self.controller, callbacks)
        
        # Register listeners
        self.controller.add_listener(self.ui)
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        
        log("Extension registered")

    def projectSwitched(self):
        """Handle project changes"""
        log("Project switch detected")
        # Create new controller and reload data
        self.controller = MessageController(self.callbacks)
        self.ui.controller = self.controller
        self.controller.add_listener(self.ui)
        
        # Update UI
        SwingUtilities.invokeLater(VulnRunnable(self.ui._init_ui))
        log("Project switch completed")

    def extensionUnloaded(self):
        """Handle extension unloading"""
        log("Extension unloading - saving data")
        if self.controller:
            self.controller._save_data()

    def createMenuItems(self, context_menu):
        menu = ArrayList()
        menu_item = JMenuItem("Add to VulnLog", actionPerformed=lambda x: self.add_vuln(context_menu))
        menu.add(menu_item)
        return menu

    def getTabCaption(self):
        return "VulnLog"
    
    def getUiComponent(self):
        return self.ui.panel

    def add_vuln(self, context):
        selected = context.getSelectedMessages()
        if not selected:
            return
        
        message = selected[0]
        http_service = message.getHttpService()
        req_info = self.helpers.analyzeRequest(message)
        url = str(req_info.getUrl())
        
        vuln_name = JOptionPane.showInputDialog(
            None,
            "Enter Vulnerability Name:",
            "VulnLog - Add Finding",
            JOptionPane.PLAIN_MESSAGE
        )
        
        if vuln_name and vuln_name.strip():
            entry = {
                'id': str(time.time()),
                'url': url,
                'name': vuln_name,
                'host': http_service.getHost(),
                'port': http_service.getPort(),
                'protocol': http_service.getProtocol(),
                'status': 'Confirm',
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'request': message.getRequest(),
                'response': message.getResponse()
            }
            self.controller.add_vulnerability(entry)
            self.flash_tab()

    def flash_tab(self):
        tab = self.ui.panel.parent.parent.parent
        original = tab.background
        flashes = [0]
        
        def animate(event):
            if flashes[0] % 2 == 0:
                tab.background = Color.RED
            else:
                tab.background = original
            flashes[0] += 1
            if flashes[0] >= 6:
                timer.stop()
                tab.background = original
                
        timer = Timer(100, animate)
        timer.start()

class VulnLogTab(IMessageEditorController):
    def __init__(self, controller, callbacks):
        """Initialize UI components"""
        self.controller = controller
        self.callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Create UI components
        self.panel = JPanel(BorderLayout())
        self._current_message = None
        self._current_request = None
        self._current_response = None
        self._current_row = None
        
        # Create message editors
        self._request_viewer = callbacks.createMessageEditor(self, False)
        self._response_viewer = callbacks.createMessageEditor(self, False)
        
        # Initialize UI
        self._init_ui()
        
        # Register as listener
        self.controller.add_listener(self)

    def _init_ui(self):
        """Initialize all UI components"""
        self.panel.removeAll()
        
        # Create top panel with controls
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.X_AXIS))
        
        # Add export button
        self.export_button = JButton("Export Findings")
        self.export_button.addActionListener(self._export_findings)
        top_panel.add(self.export_button)
        top_panel.add(Box.createHorizontalStrut(10))
        
        # Add clear all button
        self.clear_button = JButton("Clear All")
        self.clear_button.addActionListener(self._clear_all_findings)
        top_panel.add(self.clear_button)
        top_panel.add(Box.createHorizontalStrut(10))
        
        # Add delete button
        self.delete_button = JButton("Delete Selected")
        self.delete_button.addActionListener(self._delete_selected)
        self.delete_button.setEnabled(False)
        top_panel.add(self.delete_button)
        top_panel.add(Box.createHorizontalStrut(10))
        
        # Add status combo box
        # status_label = JLabel("Status: ")
        # top_panel.add(status_label)
        # self.status_combo = JComboBox(["Confirm", "False Positive", "Fixed"])
        # self.status_combo.setEnabled(False)
        # self.status_combo.addActionListener(lambda event: self._status_changed(event))
        # top_panel.add(self.status_combo)
        # top_panel.add(Box.createHorizontalStrut(10))
        
        # Add count label
        self.count_label = JLabel("Findings: 0")
        top_panel.add(self.count_label)
        top_panel.add(Box.createHorizontalGlue())  # Add flexible space
        
        # Add AI settings section
        ai_panel = JPanel()
        ai_panel.setLayout(BoxLayout(ai_panel, BoxLayout.X_AXIS))
        ai_panel.setBorder(BorderFactory.createTitledBorder("AI Settings"))
        
        # Add enable AI checkbox
        self.enable_ai = JCheckBox("Enable AI")
        self.enable_ai.setEnabled(False)  # Disabled for now
        ai_panel.add(self.enable_ai)
        ai_panel.add(Box.createHorizontalStrut(10))
        
        # Add API key input
        api_key_label = JLabel("API Key: ")
        ai_panel.add(api_key_label)
        self.api_key_field = JTextField("Coming Soon!", 20)
        self.api_key_field.setEnabled(False)  # Disabled for now
        ai_panel.add(self.api_key_field)
        
        top_panel.add(ai_panel)
        
        # Create table model and table
        self.table_model = VulnTableModel(self.controller)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.getSelectionModel().addListSelectionListener(self._selection_changed)
        
        # Create split panes
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        upper_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Add table to scroll pane
        scroll_pane = JScrollPane(self.table)
        upper_split_pane.setLeftComponent(scroll_pane)
        
        # Create request/response tabs
        tabs = JTabbedPane()
        tabs.addTab("Request", self._request_viewer.getComponent())
        tabs.addTab("Response", self._response_viewer.getComponent())
        upper_split_pane.setRightComponent(tabs)
        
        # Add components to split panes
        split_pane.setLeftComponent(upper_split_pane)
        
        # Add components to main panel
        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(split_pane, BorderLayout.CENTER)
        
        # Update the count label
        self.count_label.setText("Findings: {}".format(len(self.controller.get_data())))

    def _selection_changed(self, event):
        """Handle table selection changes"""
        if not event.getValueIsAdjusting():
            row = self.table.getSelectedRow()
            if row != -1:
                model_row = self.table.convertRowIndexToModel(row)
                data = self.controller.get_data()
                if model_row < len(data):
                    finding = data[model_row]
                    self._current_request = finding['request']
                    self._current_response = finding['response']
                    self._request_viewer.setMessage(self._current_request, True)
                    self._response_viewer.setMessage(self._current_response, False)
                    self._current_row = model_row
                    
                    # Enable controls and update status
                    self.delete_button.setEnabled(True)
                    self.status_combo.setEnabled(True)
                    self.status_combo.setSelectedItem(finding['status'])
            else:
                self._current_request = None
                self._current_response = None
                self._current_row = None
                self.delete_button.setEnabled(False)
                self.status_combo.setEnabled(False)

    def _delete_selected(self, event):
        """Delete selected finding"""
        if self._current_row is not None:
            result = JOptionPane.showConfirmDialog(
                self.panel,
                "Are you sure you want to delete this finding?",
                "Delete Finding",
                JOptionPane.YES_NO_OPTION
            )
            if result == JOptionPane.YES_OPTION:
                self.controller.delete_finding(self._current_row)
                self._current_request = None
                self._current_response = None
                self._current_row = None
                self._request_viewer.setMessage(None, True)
                self._response_viewer.setMessage(None, False)
                self.delete_button.setEnabled(False)
                self.status_combo.setEnabled(False)

    def update(self):
        """Update UI when data changes"""
        self.table_model.fireTableDataChanged()
        self.count_label.setText("Findings: {}".format(len(self.controller.get_data())))

    def _clear_all_findings(self, event):
        """Clear all findings after confirmation"""
        result = JOptionPane.showConfirmDialog(
            self.panel,
            "Are you sure you want to clear all findings?",
            "Clear All Findings",
            JOptionPane.YES_NO_OPTION
        )
        if result == JOptionPane.YES_OPTION:
            self.controller.clear_data()
            self._current_request = None
            self._current_response = None
            self._request_viewer.setMessage(None, True)
            self._response_viewer.setMessage(None, False)
            self.delete_button.setEnabled(False)
            self.status_combo.setEnabled(False)

    

    def getHttpService(self):
        return self.current_message.getHttpService() if self.current_message else None

    def getRequest(self):
        return self.current_message['request'] if self.current_message else None

    def getResponse(self):
        return self.current_message['response'] if self.current_message else None

    def update(self):
        log("UI update triggered")
        SwingUtilities.invokeLater(VulnRunnable(self._refresh_ui))

    def _refresh_ui(self):
        log("Refreshing UI")
        self.table_model.fireTableDataChanged()
        self.count_label.setText("Findings: {}".format(len(self.controller.data)))
        self.table.revalidate()
        self.table.repaint()


    def _export_findings(self, event):
        """Export findings to JSON file"""
        try:
            if not self.controller.get_data():
                JOptionPane.showMessageDialog(self.panel,
                    "No findings to export.",
                    "Export Findings",
                    JOptionPane.INFORMATION_MESSAGE)
                return

            # Create file chooser
            file_chooser = JFileChooser()
            file_chooser.setSelectedFile(File("vulnlog_findings.json"))
            
            # Show save dialog
            if file_chooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Add .json extension if not present
                if not file_path.lower().endswith('.json'):
                    file_path += '.json'
                
                # Convert findings to Burp-like format
                export_data = {
                    "target": {
                        "host": self.controller.get_data()[0]["host"] if self.controller.get_data() else "",
                        "port": self.controller.get_data()[0]["port"] if self.controller.get_data() else 0
                    },
                    "findings": []
                }

                for finding in self.controller.get_data():
                    formatted_finding = {
                        "name": finding["name"],
                        "severity": "Information",  # You might want to add severity to your findings
                        "host": finding["host"],
                        "port": finding["port"],
                        "protocol": finding["protocol"],
                        "url": finding["url"],
                        "status": finding["status"],
                        "timestamp": finding["timestamp"],
                        "request": base64.b64encode(finding["request"]).decode('utf-8'),
                        "response": base64.b64encode(finding["response"]).decode('utf-8') if finding["response"] else None,
                        "evidence": {
                            "request": self._helpers.bytesToString(finding["request"]),
                            "response": self._helpers.bytesToString(finding["response"]) if finding["response"] else None
                        }
                    }
                    export_data["findings"].append(formatted_finding)

                # Write to file
                with open(file_path, 'w') as f:
                    json.dump(export_data, f, indent=2)

                JOptionPane.showMessageDialog(self.panel,
                    "Findings exported successfully to:\n" + file_path,
                    "Export Complete",
                    JOptionPane.INFORMATION_MESSAGE)
                
                log("Exported {} findings to {}".format(len(self.controller.get_data()), file_path))

        except Exception as e:
            log("Export failed: " + str(e))
            JOptionPane.showMessageDialog(self.panel,
                "Error exporting findings:\n" + str(e),
                "Export Error",
                JOptionPane.ERROR_MESSAGE)

    def _clear_data(self, event):
        self.controller.clear_data()
        self.update()

class VulnTableModel(AbstractTableModel):
    def __init__(self, controller):
        self.controller = controller
        self.headers = ["URL", "Vulnerability", "Status", "Host", "Port", "Last Seen"]

    def getRowCount(self):
        return len(self.controller.get_data())

    def getColumnCount(self):
        return len(self.headers)

    def getColumnName(self, column):
        return self.headers[column]

    def getValueAt(self, row, column):
        try:
            entry = self.controller.get_data()[row]
            return [
                entry['url'],
                entry['name'],
                entry['status'],
                entry['host'],
                entry['port'],
                entry['timestamp']
            ][column]
        except Exception as e:
            log("Error getting value at: " + str(e))
            return ""
