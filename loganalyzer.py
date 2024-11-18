import re
from collections import Counter
import datetime

# Path to web server log file
LOG_FILE = "web_server.log"
REPORT_FILE = "investigation_report.txt"

# Common attack patterns
ATTACK_PATTERNS = {
    "SQL Injection": r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bDROP\b|\bDELETE\b|\bWHERE\b|--|;|%27|%22)",
    "XSS": r"(<script.*?>|<img.*?onerror=.*?>|javascript:|%3Cscript|alert\()",
    "Directory Traversal": r"(\.\./|\.\.\\|%2E%2E%2F|%2E%2E\\)",
    "Command Injection": r"(\bwget\b|\bcurl\b|;|&&|\|\||`|%60|cmd|powershell)",
}

# Function to parse log entries
def parse_log_line(line):
    """
    Extract IP, timestamp, and request from a log entry.
    Assumes Apache/Nginx combined log format.
    """
    log_pattern = r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)"'
    match = re.match(log_pattern, line)
    if match:
        return match.group("ip"), match.group("timestamp"), match.group("request")
    return None, None, None


# Function to analyze logs for attacks
def analyze_logs():
    print(f"Analyzing logs from {LOG_FILE}...\n")
    attack_details = {attack_type: [] for attack_type in ATTACK_PATTERNS.keys()}

    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                ip, timestamp, request = parse_log_line(line)
                if ip and request:
                    for attack_type, pattern in ATTACK_PATTERNS.items():
                        if re.search(pattern, request, re.IGNORECASE):
                            attack_details[attack_type].append({
                                "ip": ip,
                                "timestamp": timestamp,
                                "request": request.strip(),
                            })
    except FileNotFoundError:
        print(f"Error: Log file {LOG_FILE} not found.")
        return {}

    return attack_details


# Function to display attacks and save the report
def display_and_generate_report(attack_details):
    if not any(attack_details.values()):
        print("No attacks detected.")
        return

    print("Detected Attacks:\n")
    with open(REPORT_FILE, "w") as report:
        report.write("Web Attack Investigation Report\n")
        report.write(f"Generated on: {datetime.datetime.now()}\n\n")

        # Summarize and display attack types
        total_attacks = sum(len(attacks) for attacks in attack_details.values())
        print(f"Total Attacks Detected: {total_attacks}")
        report.write(f"Total Attacks Detected: {total_attacks}\n\n")

        for attack_type, attacks in attack_details.items():
            if attacks:
                print(f"\n{attack_type}: {len(attacks)} occurrence(s)")
                report.write(f"{attack_type}: {len(attacks)} occurrence(s)\n")
                for attack in attacks:
                    log_entry = f"[{attack['timestamp']}] {attack['ip']} -> {attack['request']}"
                    print(f"  {log_entry}")
                    report.write(f"  {log_entry}\n")
                report.write("\n")

    print(f"\nReport saved to {REPORT_FILE}")


if __name__ == "__main__":
    # Analyze logs and generate a report
    print("Babarsari43 Log Analyzer")
    attacks = analyze_logs()
    display_and_generate_report(attacks)

