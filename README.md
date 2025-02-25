# VulnLog - Burp Suite Extension

![Burp Suite Extension](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Python](https://img.shields.io/badge/Python-Jython%202.7-yellow)

VulnLog is a powerful Burp Suite extension designed to help security researchers track and manage vulnerabilities during penetration tests and security assessments.

![VulnLog](https://github.com/PiCarODD/VulnLog/blob/main/8ab214cd352727.gif)

## Features

- **Vulnerability Logging**: Capture findings directly from Proxy history and Repeater
- **Context Menu Integration**: Right-click any request to log vulnerabilities
- **Rich UI Dashboard**:
  - Delete individual entries or clear entire logs
- **Request/Response Storage**: Store full HTTP traffic for each finding
- **Persistent Storage**: Maintains data between Burp sessions
- **Visual Feedback**: Tab flashing on new entries
- **Export/Import**: Save findings in JSON format
- **Message Viewer**: Built-in request/response viewer with syntax highlighting

## Installation

1. Download the latest [Jython Standalone JAR](https://www.jython.org/download)
2. In Burp Suite:
   - Go to **Extender** > **Options**
   - Under **Python Environment**, select the Jython JAR file
3. Download `VulnLog.py` from this repository
4. Go to **Extensions** > **Installed** >  **Add**
5. Select **Python** as the extension type
6. Choose the `VulnLog.py` file
7. Click Next

## Usage

### Logging Vulnerabilities
1. Right-click any request in Proxy/Repeater
2. Select **Extensions** > **Add to VulnLog**
3. Enter vulnerability name when prompted

### Reviewing Vulnerabilities
1. Go to the VulnLog tab
2. Review the findings
3. Click on each findings to view the request and response

## Contributing
Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (git checkout -b feature/your-feature)
3. Commit changes (git commit -am 'Add some feature')
4. Push to branch (git push origin feature/your-feature)
5. Open a Pull Request

**Disclaimer**: This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before testing systems.
