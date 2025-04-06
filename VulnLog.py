from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController, IExtensionStateListener
from javax.swing import (JDialog, JTextField, JTextArea, JComboBox, JScrollPane,JTabbedPane,
                        JButton, JPanel, BoxLayout, JLabel, BorderFactory,ButtonGroup,JRadioButton,JTable,JSplitPane, JMenuItem, JOptionPane)
from java.awt import Dimension, GridBagLayout, GridBagConstraints, Insets, BorderLayout, FlowLayout, Color
from javax.swing.table import AbstractTableModel
from java.util import ArrayList
from java.lang import Runnable
from javax.swing import JFileChooser, Box, BoxLayout
from java.io import File
import json
import time
import base64
import hashlib
import random
import sys
import os
from java.awt.event import MouseAdapter
from javax.swing import SwingUtilities

class DoubleClickListener(MouseAdapter):
    def __init__(self, callback):
        self.callback = callback
        
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self.callback(event)

class FindingEditDialog(JDialog):
    def __init__(self, parent, finding, controller, row_index):
        super(FindingEditDialog, self).__init__(parent, True)
        self.finding = finding
        self.controller = controller
        self.row_index = row_index
        self.setTitle("Edit Finding")
        self.initUI()
        self.setSize(600, 500)
        self.setLocationRelativeTo(None)

    def initUI(self):
        panel = JPanel()
        panel.setLayout(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(5, 5, 5, 5)

        # Name field
        constraints.gridx = 0
        constraints.gridy = 0
        panel.add(JLabel("Name:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 1.0
        self.name_field = JTextField(self.finding['name'], 40)
        panel.add(self.name_field, constraints)

        # URL field (read-only)
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0
        panel.add(JLabel("URL:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 1.0
        url_field = JTextField(self.finding['url'], 40)
        url_field.setEditable(False)
        panel.add(url_field, constraints)

        # Severity combo box
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.weightx = 0
        panel.add(JLabel("Severity:"), constraints)
        
        constraints.gridx = 1
        self.severity_combo = JComboBox(["Critical", "High", "Medium", "Low", "Info"])
        self.severity_combo.setSelectedItem(self.finding.get('severity', 'TODO'))
        panel.add(self.severity_combo, constraints)

        # Description area
        constraints.gridx = 0
        constraints.gridy = 3
        panel.add(JLabel("Description:"), constraints)
        
        constraints.gridx = 1
        self.description_area = JTextArea(self.finding.get('description', 'TODO'), 5, 40)
        self.description_area.setLineWrap(True)
        self.description_area.setWrapStyleWord(True)
        scroll_desc = JScrollPane(self.description_area)
        panel.add(scroll_desc, constraints)

        # Impact area
        constraints.gridx = 0
        constraints.gridy = 4
        panel.add(JLabel("Impact:"), constraints)
        
        constraints.gridx = 1
        self.impact_area = JTextArea(self.finding.get('impact', 'TODO'), 5, 40)
        self.impact_area.setLineWrap(True)
        self.impact_area.setWrapStyleWord(True)
        scroll_impact = JScrollPane(self.impact_area)
        panel.add(scroll_impact, constraints)

        # Recommendation area
        constraints.gridx = 0
        constraints.gridy = 5
        panel.add(JLabel("Recommendation:"), constraints)
        
        constraints.gridx = 1
        self.recommendation_area = JTextArea(self.finding.get('recommendation', 'TODO'), 5, 40)
        self.recommendation_area.setLineWrap(True)
        self.recommendation_area.setWrapStyleWord(True)
        scroll_rec = JScrollPane(self.recommendation_area)
        panel.add(scroll_rec, constraints)

        # Buttons panel
        button_panel = JPanel()
        save_button = JButton("Save", actionPerformed=self.save_finding)
        cancel_button = JButton("Cancel", actionPerformed=lambda x: self.dispose())
        button_panel.add(save_button)
        button_panel.add(cancel_button)

        constraints.gridx = 0
        constraints.gridy = 6
        constraints.gridwidth = 2
        constraints.anchor = GridBagConstraints.CENTER
        panel.add(button_panel, constraints)

        self.add(panel)

    def save_finding(self, event):
        # Update finding with new values
        self.finding.update({
            'name': self.name_field.getText(),
            'severity': self.severity_combo.getSelectedItem(),
            'description': self.description_area.getText(),
            'impact': self.impact_area.getText(),
            'recommendation': self.recommendation_area.getText()
        })
        
        # Update in controller
        self.controller.update_finding(self.row_index, self.finding)
        self.dispose()

class AddFindingDialog(JDialog):
    def __init__(self, parent, message, controller):
        super(AddFindingDialog, self).__init__(parent, True)
        self.message = message
        self.controller = controller
        self.result = None
        self.setTitle("Add Finding")
        self.initUI()
        self.setSize(600, 500)
        self.setLocationRelativeTo(None)

    def initUI(self):
        panel = JPanel()
        panel.setLayout(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(5, 5, 5, 5)

        # Name field
        constraints.gridx = 0
        constraints.gridy = 0
        panel.add(JLabel("Name:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 1.0
        self.name_field = JTextField(40)
        panel.add(self.name_field, constraints)

        # URL field (read-only)
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0
        panel.add(JLabel("URL:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 1.0
        url_field = JTextField(str(self.message.getUrl()), 40)
        url_field.setEditable(False)
        panel.add(url_field, constraints)

        # Severity combo box
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.weightx = 0
        panel.add(JLabel("Severity:"), constraints)
        
        constraints.gridx = 1
        self.severity_combo = JComboBox(["Critical", "High", "Medium", "Low", "Info"])
        panel.add(self.severity_combo, constraints)

        # Description area
        constraints.gridx = 0
        constraints.gridy = 3
        panel.add(JLabel("Description:"), constraints)
        
        constraints.gridx = 1
        self.description_area = JTextArea(5, 40)
        self.description_area.setLineWrap(True)
        self.description_area.setWrapStyleWord(True)
        scroll_desc = JScrollPane(self.description_area)
        panel.add(scroll_desc, constraints)

        # Impact area
        constraints.gridx = 0
        constraints.gridy = 4
        panel.add(JLabel("Impact:"), constraints)
        
        constraints.gridx = 1
        self.impact_area = JTextArea(5, 40)
        self.impact_area.setLineWrap(True)
        self.impact_area.setWrapStyleWord(True)
        scroll_impact = JScrollPane(self.impact_area)
        panel.add(scroll_impact, constraints)

        # Recommendation area
        constraints.gridx = 0
        constraints.gridy = 5
        panel.add(JLabel("Recommendation:"), constraints)
        
        constraints.gridx = 1
        self.recommendation_area = JTextArea(5, 40)
        self.recommendation_area.setLineWrap(True)
        self.recommendation_area.setWrapStyleWord(True)
        scroll_rec = JScrollPane(self.recommendation_area)
        panel.add(scroll_rec, constraints)

        # Buttons panel
        button_panel = JPanel()
        save_button = JButton("Add", actionPerformed=self.save_finding)
        cancel_button = JButton("Cancel", actionPerformed=lambda x: self.dispose())
        button_panel.add(save_button)
        button_panel.add(cancel_button)

        constraints.gridx = 0
        constraints.gridy = 6
        constraints.gridwidth = 2
        constraints.anchor = GridBagConstraints.CENTER
        panel.add(button_panel, constraints)

        self.add(panel)

    def save_finding(self, event):
        if not self.name_field.getText().strip():
            JOptionPane.showMessageDialog(self,
                "Finding name is required",
                "Validation Error",
                JOptionPane.ERROR_MESSAGE)
            return

        self.result = {
            'name': self.name_field.getText().strip(),
            'severity': self.severity_combo.getSelectedItem(),
            'description': self.description_area.getText(),
            'impact': self.impact_area.getText(),
            'recommendation': self.recommendation_area.getText(),
            'handled': True
        }
        self.dispose()

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

    def notify_listeners(self):
        """Notify all listeners of data change"""
        for listener in self.listeners:
            try:
                listener.update()
            except Exception as e:
                log("Error notifying listener: " + str(e))

    def add_listener(self, listener):
        """Add a listener for data changes"""
        if listener not in self.listeners:
            self.listeners.append(listener)

    def get_data(self):
        """Get current findings data"""
        return self.data

    def add_vulnerability(self, entry):
        """Add new vulnerability and notify listeners"""
        try:
            # Ensure all required fields are present
            entry.update({
                'description': entry.get('description', 'TODO'),
                'severity': entry.get('severity', 'TODO'),
                'impact': entry.get('impact', 'TODO'),
                'recommendation': entry.get('recommendation', 'TODO')
            })
            
            self.data.append(entry)
            self._save_data()
            self.notify_listeners()
            log("Vulnerability added and saved")
        except Exception as e:
            log("Error adding vulnerability: " + str(e))

    def delete_finding(self, index):
        """Delete finding at specified index"""
        if 0 <= index < len(self.data):
            del self.data[index]
            self._save_data()
            self.notify_listeners()

    def update_finding(self, index, updated_finding):
        """Update an existing finding"""
        try:
            if 0 <= index < len(self.data):
                self.data[index] = updated_finding
                self._save_data()
                self.notify_listeners()
                log("Finding updated successfully")
        except Exception as e:
            log("Error updating finding: " + str(e))
    

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
                    timestamp_key = "project_timestamp_" + host
                    timestamp = self.callbacks.loadExtensionSetting(timestamp_key)
                    if not timestamp:
                        timestamp = str(int(time.time()))
                        self.callbacks.saveExtensionSetting(timestamp_key, timestamp)
                    
                    project_id = hashlib.md5((host + "_" + timestamp).encode()).hexdigest()
                    log("Using host and timestamp as project ID: {} ({})".format(host, timestamp))
                    return project_id

            # If no proxy history, use session-based ID
            log("No project identifier found, using session ID")
            session_id = "session_" + str(int(time.time()))
            return session_id
        except Exception as e:
            log("Error getting project ID: " + str(e))
            session_id = "session_" + str(int(time.time()))
            return session_id

    def _save_data(self):
        """Save findings to Burp's extension settings"""
        try:
            # Convert findings to serializable format
            serializable_data = []
            for entry in self.data:
                serialized_entry = {
                    'id': entry['id'],
                    'url': entry['url'],
                    'name': entry['name'],
                    'description': entry.get('description', 'TODO'),
                    'severity': entry.get('severity', 'TODO'),
                    'impact': entry.get('impact', 'TODO'),
                    'recommendation': entry.get('recommendation', 'TODO'),
                    'request': base64.b64encode(entry['request']).decode('utf-8'),
                    'response': base64.b64encode(entry['response']).decode('utf-8') if entry['response'] else None
                }
                serializable_data.append(serialized_entry)
            
            # Save to Burp's storage
            json_data = json.dumps(serializable_data)
            self.callbacks.saveExtensionSetting("data_{}".format(self.project_id), json_data)
            log("Saved {} findings for project {}".format(len(self.data), self.project_id))
        except Exception as e:
            log("Save failed: " + str(e))

    def _load_data(self):
        """Load findings from Burp's extension settings"""
        try:
            json_data = self.callbacks.loadExtensionSetting("data_{}".format(self.project_id))
            if json_data:
                loaded = json.loads(json_data)
                self.data = []

                for entry in loaded:
                    decoded_entry = {
                        'id': entry['id'],
                        'url': entry['url'],
                        'name': entry['name'],
                        'description': entry.get('description', 'TODO'),
                        'severity': entry.get('severity', 'TODO'),
                        'impact': entry.get('impact', 'TODO'),
                        'recommendation': entry.get('recommendation', 'TODO'),
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

    def clear_data(self):
        """Clear all findings"""
        self.data = []
        self._save_data()
        self.notify_listeners()


    # Remove get_storage_file() and other file-related methods
    # Keep other existing methods (get_data, add_listener, notify_listeners)

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
    def __init__(self):
        self.is_processing = False
        self._last_invocation_time = 0
        self._menu_lock = False
    
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


    def getTabCaption(self):
        return "VulnLog"
    
    def getUiComponent(self):
        return self.ui.panel

    def createMenuItems(self, invocation):
        if invocation.getToolFlag() in (self.callbacks.TOOL_PROXY, self.callbacks.TOOL_REPEATER, self.callbacks.TOOL_SCANNER):
            menu_list = ArrayList()
            menu_item = JMenuItem("Send to VulnLog")
            
            def menu_action(event):
                if not self._menu_lock:  # Check the lock
                    try:
                        self._menu_lock = True  # Set the lock
                        current_time = int(time.time() * 1000)
                        if current_time - self._last_invocation_time > 1000:
                            log("Menu action triggered at {}".format(current_time))
                            self._last_invocation_time = current_time
                            self._add_vulnerability(invocation)
                    finally:
                        # Use SwingUtilities.invokeLater to release the lock after a delay
                        def release_lock():
                            self._menu_lock = False
                        SwingUtilities.invokeLater(VulnRunnable(release_lock))
            
            menu_item.addActionListener(menu_action)
            menu_list.add(menu_item)
            return menu_list
        return None

    def _generate_id(self):
        timestamp = str(int(time.time()*1000))
        random_num = random.randint(10000, 99999)
        return "vuln_" + timestamp + "_" + str(random_num)

    def _add_vulnerability(self, invocation):
        if self._menu_lock:  # Only proceed if we have the lock
            try:
                log("_add_vulnerability called")
                # Get all selected messages first
                http_messages = invocation.getSelectedMessages()
                if not http_messages:
                    return

                # Get the main Burp frame as parent
                parent_component = SwingUtilities.getWindowAncestor(self.ui.panel)

                # Process all selected messages
                for message in http_messages:
                    log("Processing message")
                    analyzed_request = self.helpers.analyzeRequest(message)
                    url = analyzed_request.getUrl()
                    
                    class MessageWrapper:
                        def __init__(self, url):
                            self.url = url
                        def getUrl(self):
                            return self.url

                    message_wrapper = MessageWrapper(url)
                    
                    # Show the add finding dialog with proper parent
                    dialog = AddFindingDialog(parent_component, message_wrapper, self.controller)
                    dialog.setVisible(True)
                    
                    # If dialog was cancelled
                    if dialog.result is None:
                        continue
                        
                    entry = {
                        'id': self._generate_id(),
                        'url': str(url),
                        'name': dialog.result['name'],
                        'request': message.getRequest(),
                        'response': message.getResponse(),
                        'description': dialog.result['description'],
                        'severity': dialog.result['severity'],
                        'impact': dialog.result['impact'],
                        'recommendation': dialog.result['recommendation']
                    }
                    
                    self.controller.add_vulnerability(entry)
                    
                    # Show confirmation
                    SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                        parent_component,
                        "Finding added successfully!",
                        "Success",
                        JOptionPane.INFORMATION_MESSAGE
                    ))
                    break  # Only process one message at a time
                    
            except Exception as e:
                log("Error adding vulnerability: " + str(e))
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    SwingUtilities.getWindowAncestor(self.ui.panel),
                    "Error adding finding: " + str(e),
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                ))

    def flash_tab(self):
        def animate():
            tab = self.ui.panel.parent.parent.parent
            original = tab.background
            for _ in range(3):
                tab.background = Color.RED
                time.sleep(0.1)
                tab.background = original
                time.sleep(0.1)
            
        SwingUtilities.invokeLater(VulnRunnable(animate))

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
        self.delete_button.addActionListener(lambda event: self._delete_selected())
        top_panel.add(self.delete_button)
        top_panel.add(Box.createHorizontalStrut(10))
        
        # Add count label
        self.count_label = JLabel("Findings: 0")
        top_panel.add(self.count_label)
        top_panel.add(Box.createHorizontalGlue())
        
        # Add AI settings section
        ai_panel = JPanel()
        ai_panel.setLayout(BoxLayout(ai_panel, BoxLayout.X_AXIS))
        ai_panel.setBorder(BorderFactory.createTitledBorder("AI Settings"))
        
        # Create button group for radio buttons
        button_group = ButtonGroup()
        
        # Add GPT radio button
        self.gpt_radio = JRadioButton("GPT")
        button_group.add(self.gpt_radio)
        ai_panel.add(self.gpt_radio)
        ai_panel.add(Box.createHorizontalStrut(5))
        
        # Add Deepseek radio button
        self.deepseek_radio = JRadioButton("Deepseek")
        button_group.add(self.deepseek_radio)
        ai_panel.add(self.deepseek_radio)
        ai_panel.add(Box.createHorizontalStrut(10))
        
        # Add API key input
        api_key_label = JLabel("API Key: ")
        ai_panel.add(api_key_label)
        self.api_key_field = JTextField("Coming Soon!", 20)
        ai_panel.add(self.api_key_field)
        
        top_panel.add(ai_panel)
        
        # Add "View Details" button to top panel
        self.details_button = JButton("View Details")
        self.details_button.addActionListener(lambda event: self._show_details_dialog())
        self.details_button.setEnabled(False)  # Initially disabled until selection
        top_panel.add(self.details_button)
        top_panel.add(Box.createHorizontalStrut(10))
        
        # Create table model and table
        self.table_model = VulnTableModel(self.controller)
        self.table = JTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.getSelectionModel().addListSelectionListener(self._selection_changed)
        
        # Add tooltip support
        class TooltipTable(JTable):
            def getToolTipText(self, event):
                tip = None
                point = event.getPoint()
                row = self.rowAtPoint(point)
                col = self.columnAtPoint(point)
                
                if row >= 0 and col >= 2:  # Only for description, impact, and recommendation columns
                    try:
                        row = self.convertRowIndexToModel(row)
                        value = self.getModel().getValueAt(row, col)
                        if value and len(value) > 50:  # Only show tooltip for long text
                            tip = "<html><body style='width: 300px'>" + value + "</body></html>"
                    except:
                        pass
                return tip
        
        # Replace standard table with tooltip-enabled table
        self.table = TooltipTable(self.table_model)
        self.table.setAutoCreateRowSorter(True)
        self.table.getSelectionModel().addListSelectionListener(self._selection_changed)
        
        # Add mouse listener for double click
        self.table.addMouseListener(self._create_mouse_listener())
        
        # Create main vertical split pane
        main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # Add table to scroll pane
        table_scroll_pane = JScrollPane(self.table)
        main_split_pane.setTopComponent(table_scroll_pane)
        
        # Create request/response tabs
        tabs = JTabbedPane()
        tabs.addTab("Request", self._request_viewer.getComponent())
        tabs.addTab("Response", self._response_viewer.getComponent())
        
        # Add tabs to bottom of split pane
        main_split_pane.setBottomComponent(tabs)
        
        # Set the divider location to give more space to the table
        main_split_pane.setDividerLocation(0.5)  # 50% split
        
        # Add components to main panel
        self.panel.add(top_panel, BorderLayout.NORTH)
        self.panel.add(main_split_pane, BorderLayout.CENTER)
        
        # Update the count label
        self.count_label.setText("Findings: {}".format(len(self.controller.get_data())))

    def _create_mouse_listener(self):
        class MouseListener(MouseAdapter):
            def __init__(self, parent):
                self.parent = parent
                
            def mouseClicked(self, event):
                if event.getClickCount() == 2:
                    self.parent._edit_finding()
                    
        return MouseListener(self)

    def _ai_option_changed(self, ai_type):
        """Handle AI option selection"""
        JOptionPane.showMessageDialog(
            self.panel,
            "{} integration coming soon!".format(ai_type),
            "AI Settings",
            JOptionPane.INFORMATION_MESSAGE
        )

    def _selection_changed(self, event):
        """Handle table selection changes"""
        if not event.getValueIsAdjusting():
            row = self.table.getSelectedRow()
            self.details_button.setEnabled(row != -1)  # Enable details button when row is selected
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
            else:
                self._current_request = None
                self._current_response = None
                self._current_row = None

    def _delete_selected(self):
        """Delete selected finding"""
        row = self.table.getSelectedRow()
        if row != -1:
            model_row = self.table.convertRowIndexToModel(row)
            result = JOptionPane.showConfirmDialog(
                self.panel,
                "Are you sure you want to delete this finding?",
                "Delete Finding",
                JOptionPane.YES_NO_OPTION
            )
            if result == JOptionPane.YES_OPTION:
                self.controller.delete_finding(model_row)
                self._current_request = None
                self._current_response = None
                self._current_row = None
                self._request_viewer.setMessage(None, True)
                self._response_viewer.setMessage(None, False)

    def _ai_enabled_changed(self):
        """Handle AI enable/disable"""
        is_enabled = self.enable_ai.isSelected()
        self.api_key_field.setEnabled(is_enabled)
        if is_enabled:
            JOptionPane.showMessageDialog(
                self.panel,
                "AI feature coming soon!",
                "AI Settings",
                JOptionPane.INFORMATION_MESSAGE
            )

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

    def _edit_finding(self):
        """Handle double click on finding"""
        row = self.table.getSelectedRow()
        if row != -1:
            model_row = self.table.convertRowIndexToModel(row)
            finding = self.controller.get_data()[model_row]
            dialog = FindingEditDialog(self.panel, finding, self.controller, model_row)
            dialog.setVisible(True)
    

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
                
                # Get the first URL to extract host information
                first_finding = self.controller.get_data()[0]
                url = first_finding['url']
                
                # Parse the URL to get host and port
                try:
                    from java.net import URL
                    url_obj = URL(url)
                    host = url_obj.getHost()
                    port = url_obj.getPort()
                    if port == -1:  # Default port
                        port = 443 if url_obj.getProtocol() == "https" else 80
                except:
                    host = "unknown"
                    port = 0
                
                # Convert findings to Burp-like format
                export_data = {
                    "target": {
                        "host": host,
                        "port": port
                    },
                    "findings": []
                }

                for finding in self.controller.get_data():
                    formatted_finding = {
                        "name": finding["name"],
                        "severity": finding.get("severity", "Information"),
                        "url": finding["url"],
                        "description": finding.get("description", ""),
                        "impact": finding.get("impact", ""),
                        "recommendation": finding.get("recommendation", ""),
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

    def _show_details_dialog(self):
        row = self.table.getSelectedRow()
        if row != -1:
            model_row = self.table.convertRowIndexToModel(row)
            finding = self.controller.get_data()[model_row]
            
            dialog = JDialog(self.panel.getTopLevelAncestor(), "Finding Details", True)
            dialog.setSize(800, 600)
            dialog.setLocationRelativeTo(self.panel)
            
            panel = JPanel()
            panel.setLayout(GridBagLayout())
            constraints = GridBagConstraints()
            constraints.fill = GridBagConstraints.BOTH
            constraints.insets = Insets(5, 5, 5, 5)
            constraints.weightx = 1.0
            constraints.weighty = 1.0
            
            # Create text areas for each field
            name_label = JLabel("Name:")
            name_field = JTextArea(finding['name'])
            name_field.setEditable(False)
            name_field.setLineWrap(True)
            name_field.setWrapStyleWord(True)
            
            desc_label = JLabel("Description:")
            desc_area = JTextArea(finding.get('description', ''))
            desc_area.setEditable(False)
            desc_area.setLineWrap(True)
            desc_area.setWrapStyleWord(True)
            
            impact_label = JLabel("Impact:")
            impact_area = JTextArea(finding.get('impact', ''))
            impact_area.setEditable(False)
            impact_area.setLineWrap(True)
            impact_area.setWrapStyleWord(True)
            
            rec_label = JLabel("Recommendation:")
            rec_area = JTextArea(finding.get('recommendation', ''))
            rec_area.setEditable(False)
            rec_area.setLineWrap(True)
            rec_area.setWrapStyleWord(True)
            
            # Add components to panel
            constraints.gridx = 0
            constraints.gridy = 0
            constraints.weighty = 0
            panel.add(name_label, constraints)
            
            constraints.gridy = 1
            constraints.weighty = 0.1
            panel.add(JScrollPane(name_field), constraints)
            
            constraints.gridy = 2
            constraints.weighty = 0
            panel.add(desc_label, constraints)
            
            constraints.gridy = 3
            constraints.weighty = 0.3
            panel.add(JScrollPane(desc_area), constraints)
            
            constraints.gridy = 4
            constraints.weighty = 0
            panel.add(impact_label, constraints)
            
            constraints.gridy = 5
            constraints.weighty = 0.3
            panel.add(JScrollPane(impact_area), constraints)
            
            constraints.gridy = 6
            constraints.weighty = 0
            panel.add(rec_label, constraints)
            
            constraints.gridy = 7
            constraints.weighty = 0.3
            panel.add(JScrollPane(rec_area), constraints)
            
            # Add close button
            close_button = JButton("Close", actionPerformed=lambda x: dialog.dispose())
            button_panel = JPanel()
            button_panel.add(close_button)
            
            constraints.gridy = 8
            constraints.weighty = 0
            constraints.anchor = GridBagConstraints.CENTER
            panel.add(button_panel, constraints)
            
            dialog.add(panel)
            dialog.setVisible(True)

class VulnTableModel(AbstractTableModel):
    def __init__(self, controller):
        self.controller = controller
        self.columns = [
            "Finding Name",
            "URL",
            "Description",
            "Severity",
            "Impact",
            "Recommendation"
        ]

    def getColumnCount(self):
        return len(self.columns)

    def getRowCount(self):
        return len(self.controller.get_data())

    def getColumnName(self, column):
        return self.columns[column]

    def getValueAt(self, row, col):
        data = self.controller.get_data()
        if row < len(data):
            finding = data[row]
            if col == 0:
                return finding['name']
            elif col == 1:
                return finding['url']
            elif col == 2:
                return finding.get('description', 'TODO')
            elif col == 3:
                return finding.get('severity', 'TODO')
            elif col == 4:
                return finding.get('impact', 'TODO')
            elif col == 5:
                return finding.get('recommendation', 'TODO')
        return ""

    def update(self):
        """Refresh the table data"""
        self.fireTableDataChanged()
