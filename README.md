# VulnLog - Burp Suite Extension

![Burp Suite Extension](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Python](https://img.shields.io/badge/Python-Jython%202.7-yellow)

VulnLog is a powerful Burp Suite extension designed to help security researchers track and manage vulnerabilities during penetration tests and security assessments. It provides a comprehensive interface for logging, managing, and documenting security findings.
![VulnLog](https://github.com/PiCarODD/VulnLog/blob/main/8ab214cd352727.gif)
## Features

### Core Functionality
- **Vulnerability Logging**: Capture and document findings directly from Proxy history and Repeater
- **Detailed Finding Management**:
  - Name, URL, and Severity tracking
  - Comprehensive description fields
  - Impact assessment documentation
  - Recommendation documentation
  - Full HTTP request/response storage

### User Interface
- **Rich Dashboard**:
  - Sortable findings table
  - Tooltips for long text entries
  - Detailed view dialog for better readability
  - Request/Response viewer with syntax highlighting
- **Context Menu Integration**: Right-click any request to add findings
- **Multiple View Options**:
  - Table view for quick overview
  - Detailed view for comprehensive information
  - Split-pane layout for request/response inspection

### Data Management
- **Finding Operations**:
  - Add new findings
  - Edit existing findings
  - Delete individual entries
  - Clear all findings
  - Export findings to JSON
- **Persistent Storage**: Maintains data between Burp sessions
- **Project-Based Organization**: Automatically organizes findings by target host

### Severity Levels
- Critical
- High
- Medium
- Low
- Info

## Installation

1. Download the latest [Jython Standalone JAR](https://www.jython.org/download)
2. In Burp Suite:
   - Go to **Extender** > **Options**
   - Under **Python Environment**, select the Jython JAR file
3. Download `VulnLog.py` from this repository
4. Go to **Extensions** > **Installed** > **Add**
5. Select **Python** as the extension type
6. Choose the `VulnLog.py` file
7. Click Next

## Usage

### Adding Findings
1. Right-click any request in Proxy/Repeater/Scanner
2. Select "Send to VulnLog"
3. Fill in the finding details:
   - Name (required)
   - Severity level
   - Description
   - Impact
   - Recommendation

### Managing Findings
1. Navigate to the VulnLog tab
2. Use the table to view all findings
3. Available actions:
   - Double-click to edit a finding
   - Click "View Details" for full information
   - Use "Delete Selected" to remove findings
   - Use "Clear All" to remove all findings
   - Export findings using "Export Findings"
![VulnLog](https://github.com/PiCarODD/VulnLog/blob/main/a19bc1ff.png)

### Viewing Details
- Select any finding to view its request/response
- Use tooltips for quick preview of long text
- Click "View Details" for a comprehensive view
- Double-click entries to edit them

### Exporting Data
- Click "Export Findings" to save as JSON
- Exports include:
  - Target information (host, port)
  - Finding details
  - Full request/response data
  - Evidence in both raw and encoded formats
![VulnLog](https://github.com/PiCarODD/VulnLog/blob/main/d0d761a.png)
## Upcoming Features
- AI integration with GPT and Deepseek support
- Additional export formats (PDF, Word, XML, HTML)
- Enhanced finding templates
- Custom severity levels

## Contributing
Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -am 'Add some feature'`)
4. Push to branch (`git push origin feature/your-feature`)
5. Open a Pull Request

**Disclaimer**: This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before testing systems.
