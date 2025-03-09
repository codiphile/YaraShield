# YaraShield - Advanced Malware Detection Tool

YaraShield is a powerful malware detection tool that leverages YARA rules to identify various threats in files. It provides a user-friendly GUI interface for scanning files and managing YARA rules.

![YaraShield Screenshot 1](./Images/Screenshot%201.png)
![YaraShield Screenshot 2](./Images/Screenshot%202.png)

## Features

- **Advanced Malware Detection**: Detect a wide variety of malware types using YARA pattern matching
- **User-Friendly Interface**: Intuitive GUI with file selection, scan results, and rule management
- **Comprehensive Rule Collection**: Built-in rules for detecting:
  - Ransomware
  - Backdoors
  - Cryptominers
  - Data exfiltration tools
  - Rootkits
  - Fileless malware
  - Memory injection techniques
  - Supply chain attacks
  - PowerShell attacks
  - Obfuscated JavaScript
- **Rule Management**: View and manage YARA rules through the application
- **Real-time Rule Monitoring**: Automatic detection of rule file changes
- **Detailed Scan Results**: View comprehensive information about detected threats

## Installation

### Prerequisites

- Python 3.7 or higher
- Required Python packages:
  - yara-python
  - tkinter (usually comes with Python)

### Setup

1. Clone the repository:

   ```
   git clone https://github.com/username/YaraShield.git
   cd YaraShield
   ```

2. Create a virtual environment (recommended):

   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install required packages:

   ```
   pip install yara-python
   ```

4. Run the application:
   ```
   python malware_scanner.py
   ```

## Usage

1. **File Scanning**:

   - Select a file to scan using the "Browse" button
   - Click "Scan File" to analyze the file
   - View the results in the text area

2. **Rule Management**:
   - Switch to the "YARA Rules" tab
   - View available rule files in the list
   - Select a rule file to view its contents
   - Click "Reload Rules" to refresh if you've modified rule files externally

## YARA Rules

YaraShield comes with several pre-defined rule files in the `rules` directory:

- `basic_rules.yar`: Simple malware detection rules
- `advanced_malware.yar`: Rules for ransomware, PowerShell attacks, and obfuscated JavaScript
- `advanced_threats.yar`: Rules for backdoors, cryptominers, data exfiltration, and rootkits
- `specialized_threats.yar`: Rules for supply chain attacks, memory injection, fileless malware, and persistence mechanisms

### Creating Custom Rules

You can create your own YARA rules by adding `.yar` files to the `rules` directory. The application will automatically load them at startup or when you click "Reload Rules".

Example of a simple YARA rule:

```yara
rule My_Custom_Rule {
    meta:
        name = "Custom Malware Detector"
        description = "Detects custom malware patterns"
        author = "Your Name"
        date = "2023-03-09"
        severity = "Medium"

    strings:
        $suspicious_string1 = "malicious_function"
        $suspicious_string2 = "evil_code"

    condition:
        any of them
}
```

## License

[MIT License](LICENSE)

## Author

Mudit Sharma
