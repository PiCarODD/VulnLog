# VulnLog - Burp Suite Extension

![Burp Suite Extension](https://img.shields.io/badge/Burp%20Suite-Extension-orange)
![Python](https://img.shields.io/badge/Python-Jython%202.7-yellow)

VulnLog is a powerful Burp Suite extension designed to help security researchers track and manage vulnerabilities during penetration tests and security assessments.

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
4. Go to **Extender** > **Extensions** > **Add**
5. Select **Python** as the extension type
6. Choose the `VulnLog.py` file

## Usage

### Logging Vulnerabilities
1. Right-click any request in Proxy/Repeater
2. Select **Extensions** > **Add to VulnLog**
3. Enter vulnerability name when prompted
