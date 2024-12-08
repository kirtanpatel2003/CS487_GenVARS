# CS487_GenVARS

## Automated Vulnerability Exploitation Framework

This project is designed to automate the process of vulnerability discovery, analysis, and exploitation in a controlled and secure environment. The framework leverages SSH, Telnet, and AI (OpenAI's GPT-3.5 Turbo) to interact with systems, generate reports, and provide actionable exploitation steps.

---

## Features

1. **Vulnerability Report Generation**:
   - Connects to a target machine via SSH to run predefined commands.
   - Collects data on open ports, SUID binaries, writable files, outdated packages, and cron jobs.
   - Saves the results in a report file (`vulnerability_report.txt`).

2. **Critical Data Extraction**:
   - Extracts specific information (e.g., SUID binaries) from the vulnerability report.
   - Saves the extracted data in a smaller, focused report file (`small_report.txt`).

3. **AI-Powered Vulnerability Analysis**:
   - Uses OpenAI GPT-3.5 Turbo to analyze the extracted data.
   - Provides detailed exploitation steps for SUID binaries, grouped into three sections:
     - Exploitable without payloads.
     - Exploitable with payloads.
     - Recommendations for mitigation.
   - Outputs analysis to `ai_output.txt`.

4. **Telnet-Based Exploitation**:
   - Automates the Telnet connection to Metasploitable.
   - Logs in with default credentials.
   - Opens an interactive Nmap shell and spawns a root shell using `!sh`.

---

## Requirements

- **Python Libraries**:
  - `paramiko`: For SSH interaction.
  - `pexpect`: For Telnet automation.
  - `openai`: For AI-powered analysis.
  - `transformers` (optional): For Hugging Face GPT-based analysis.
- **System Utilities**:
  - `telnet`: Installed and available on your system.
- **Target System**:
  - A vulnerable Metasploitable instance running on the same network.

---

## Setup

1. **Clone the Repository**:
     
   git clone https://github.com/kirtanpatel2003/CS487_GenVARS.git
    

2. **Install Dependencies**:
     
   pip install paramiko pexpect openai transformers
    

3. **Set OpenAI API Key**:
   - Add your OpenAI API key as an environment variable:
       
     openai.api_key = "your-api-key"
      

---

## Usage

1. **Run the Framework**:
     
   python GenVARS.py
    

2. **Features**:
   - **Generate a Vulnerability Report**:
     Automatically connects to the target machine via SSH and generates a detailed vulnerability report.
   - **Analyze the Report**:
     Uses AI to analyze the report and provide actionable insights.
   - **Exploit the Target**:
     Automatically connects via Telnet, opens an Nmap shell, and spawns a root shell.

3. **Outputs**:
   - `vulnerability_report.txt`: Full vulnerability report.
   - `small_report.txt`: Focused report on critical data.
   - `ai_output.txt`: AI-generated analysis and exploitation steps.

---

## File Structure

 
project/
├── main.py           # Main framework script
├── README.md         # Documentation
├── vulnerability_report.txt  # Full report (generated)
├── small_report.txt  # Extracted critical data (generated)
|__ ai_output.txt     # AI analysis (generated)
 

---

## Limitations

- Ensure the target machine (e.g., Metasploitable) is reachable over the network.
- AI analysis depends on accurate data extraction and OpenAI API response.

---

## Disclaimer

This tool is intended for educational purposes only. Use it in controlled environments and with explicit permission. Unauthorized use may violate laws and ethical standards.

--- 

**Author**: Kirtan Patel, Dev Shah
**License**: MIT