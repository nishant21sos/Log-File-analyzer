# FINAL PROJECT: Log File Analyzer for Intrusion Detection
# Internship Project 11 - Submission Version

import re
import pandas as pd
import matplotlib.pyplot as plt

# ------------------ FILE PATHS ------------------
SSH_LOG = "logs/ssh.log"
APACHE_LOG = "logs/apache.log"
BLACKLIST_FILE = "blacklist/blacklist.txt"
REPORT_FILE = "reports/incident_report.csv"

IP_REGEX = r"\b\d{1,3}(?:\.\d{1,3}){3}\b"

# ------------------ HELPER FUNCTION ------------------
def extract_ips(log_file):
    with open(log_file, "r") as file:
        logs = file.readlines()
    ips = []
    for line in logs:
        match = re.search(IP_REGEX, line)
        if match:
            ips.append(match.group())
    return ips

# ------------------ LOAD BLACKLIST ------------------
with open(BLACKLIST_FILE, "r") as file:
    blacklist_ips = [line.strip() for line in file.readlines()]

# ------------------ SSH ANALYSIS ------------------
ssh_ips = extract_ips(SSH_LOG)
ssh_df = pd.DataFrame(ssh_ips, columns=["IP_Address"])
ssh_summary = ssh_df.value_counts().reset_index(name="Attempts")
ssh_summary["Attack_Type"] = "SSH Brute Force"

# ------------------ APACHE ANALYSIS ------------------
apache_ips = extract_ips(APACHE_LOG)
apache_df = pd.DataFrame(apache_ips, columns=["IP_Address"])
apache_summary = apache_df.value_counts().reset_index(name="Attempts")
apache_summary["Attack_Type"] = "Possible DoS / Scanning"

# ------------------ MERGE RESULTS ------------------
final_report = pd.concat([ssh_summary, apache_summary], ignore_index=True)

# ------------------ BLACKLIST CHECK ------------------
final_report["Blacklisted"] = final_report["IP_Address"].apply(
    lambda ip: "YES" if ip in blacklist_ips else "NO"
)

# ------------------ EXPORT REPORT ------------------
final_report.to_csv(REPORT_FILE, index=False)

print("Incident report generated successfully!")
print(final_report)

# ------------------ VISUALIZATION ------------------
plt.figure()
plt.bar(final_report["IP_Address"], final_report["Attempts"])
plt.xlabel("IP Address")
plt.ylabel("Number of Requests / Attempts")
plt.title("Detected Suspicious Activity by IP")
plt.show()
