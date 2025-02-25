from burp import IBurpExtender, ITab, IContextMenuFactory, IMessageEditorController
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JComboBox,
    JOptionPane, JMenuItem, SwingUtilities, JLabel, Timer,
    JSplitPane, JTabbedPane
)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, FlowLayout, Color, Dimension
from java.util import ArrayList
from java.lang import Runnable
import json
import time
import base64

class VulnRunnable(Runnable):
    def __init__(self, target):
        self.target = target
    def run(self): 
        self.target()

class MessageController:
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.listeners = []
        self.data = []
        self.load_data()

    def add_listener(self, listener):
        self.listeners.append(listener)

    def notify_listeners(self):
        for listener in self.listeners:
            SwingUtilities.invokeLater(VulnRunnable(listener.update))

    def add_vulnerability(self, entry):
        self.data.append(entry)
        self.save_data()
        self.notify_listeners()

    def get_data(self):
        return self.data

    def clear_data(self):
        self.data = []
        self.save_data()
        self.notify_listeners()

    def save_data(self):
        serialized = []
        for entry in self.data:
            serialized_entry = entry.copy()
            serialized_entry['request'] = base64.b64encode(entry['request'])
            serialized_entry['response'] = base64.b64encode(entry['response']) if entry['response'] else None
            serialized.append(serialized_entry)
        self.callbacks.saveExtensionSetting("vuln_data", json.dumps(serialized))

    def load_data(self):
        try:
            saved = self.callbacks.loadExtensionSetting("vuln_data")
            if saved:
                loaded = json.loads(saved)
                for entry in loaded:
                    entry['request'] = base64.b64decode(entry['request'])
                    entry['response'] = base64.b64decode(entry['response']) if entry['response'] else None
                self.data = loaded
        except Exception as e:
            print "Error loading data:", e
            self.data = []

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.controller = MessageController(callbacks)
        self.ui = VulnLogTab(self.controller, callbacks)
        
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        self.controller.add_listener(self.ui)

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
        self.controller = controller
        self.callbacks = callbacks
        self.current_message = None
        self.panel = JPanel(BorderLayout())
        self._init_ui()
        self.update()

    def _init_ui(self):
        # Main split pane
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setResizeWeight(0.5)
        
        # Table panel
        table_panel = JPanel(BorderLayout())
        self.table_model = VulnTableModel(self.controller)
        self.table = JTable(self.table_model)
        self.table.selectionModel.addListSelectionListener(self._selection_changed)
        self.table.autoCreateRowSorter = True
        
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        self.status_combo = JComboBox(["Confirm"])
        self.count_label = JLabel("Findings: 0")
        
        toolbar.add(self.count_label)
        toolbar.add(JLabel("Status:"))
        toolbar.add(self.status_combo)
        toolbar.add(JButton("Delete", actionPerformed=self._delete_selected))
        toolbar.add(JButton("Clear All", actionPerformed=self._clear_data))
        
        table_panel.add(toolbar, BorderLayout.NORTH)
        table_panel.add(JScrollPane(self.table), BorderLayout.CENTER)
        
        # Details panel
        details_panel = JTabbedPane()
        self.request_editor = self.callbacks.createMessageEditor(self, False)
        self.response_editor = self.callbacks.createMessageEditor(self, False)
        
        details_panel.addTab("Request", self.request_editor.getComponent())
        details_panel.addTab("Response", self.response_editor.getComponent())
        
        split_pane.setTopComponent(table_panel)
        split_pane.setBottomComponent(details_panel)
        self.panel.add(split_pane)

    def _selection_changed(self, event):
        if not event.getValueIsAdjusting():
            row = self.table.getSelectedRow()
            if row != -1:
                self.current_message = self.controller.get_data()[row]
                self.request_editor.setMessage(self.current_message['request'], True)
                self.response_editor.setMessage(self.current_message['response'], False)
                self.request_editor.setEditable(False)
                self.response_editor.setEditable(False)

    # IMessageEditorController implementation
    def getHttpService(self):
        return self.current_message.getHttpService() if self.current_message else None

    def getRequest(self):
        return self.current_message['request'] if self.current_message else None

    def getResponse(self):
        return self.current_message['response'] if self.current_message else None

    def update(self):
        SwingUtilities.invokeLater(VulnRunnable(self._refresh_ui))

    def _refresh_ui(self):
        self.table_model.fireTableDataChanged()
        self.count_label.setText("Findings: {}".format(len(self.controller.get_data())))
        self.table.repaint()

    def _delete_selected(self, event):
        row = self.table.getSelectedRow()
        if row != -1:
            del self.controller.get_data()[row]
            self.controller.save_data()
            self.update()

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
        entry = self.controller.get_data()[row]
        return [
            entry['url'],
            entry['name'],
            entry['status'],
            entry['host'],
            entry['port'],
            entry['timestamp']
        ][column]