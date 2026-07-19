import os
import re
import csv
import json
import sys
from datetime import datetime

print("=" * 50)
print("SOC LOG ANALYZER")
print("=" * 50)

if len(sys.argv) > 1:
    log_file_path = sys.argv[1]
else:
    log_file_path = "sample_logs/sample.log"

info_count = 0
warning_count = 0
error_count = 0
failed_login_count = 0
brute_force = False

detected_ips = []
detected_users = []
failed_login_times = []

time_based_brute_force = False
risk_score = 0
import os

if not os.path.exists(log_file_path):
    print("=" * 50)
    print("ERROR")
    print("=" * 50)
    print(f"Log file not found: {log_file_path}")
    print("Please check the file path and try again.")
    exit()
with open(log_file_path, "r") as log_file:
    for line in log_file:

        # Log Level Counting
        if "INFO" in line:
            info_count += 1
        elif "WARNING" in line:
            warning_count += 1
        elif "ERROR" in line:
            error_count += 1

        print(line.strip())

        # Failed Login Detection
        if "Failed login" in line:
            failed_login_count += 1
            print("ALERT: Failed Login Detected")

            time_match = re.search(r"\d{2}:\d{2}:\d{2}", line)

            if time_match:
                login_time = datetime.strptime(
                    time_match.group(),
                    "%H:%M:%S"
                )
                failed_login_times.append(login_time)

        # Brute Force Threshold
        if failed_login_count >= 3:
            brute_force = True

        # IP Address Detection
        ip_addresses = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            line
        )

        for ip_address in ip_addresses:
            if ip_address not in detected_ips:
                detected_ips.append(ip_address)
                print(f"IP DETECTED: {ip_address}")

        # Normal User Detection
        user_match = re.search(r"User (\w+)", line)

        if user_match:
            username = user_match.group(1)

            if username not in detected_users:
                detected_users.append(username)
                print(f"USER DETECTED: {username}")

        # Failed Login User Detection
        failed_user = re.search(r"Failed login for (\w+)", line)

        if failed_user:
            username = failed_user.group(1)

            if username not in detected_users:
                detected_users.append(username)
                print(f"USER DETECTED: {username}")
                print()
        # Time-Based Brute Force Detection
if len(failed_login_times) >= 3:

    first_time = failed_login_times[0]
    third_time = failed_login_times[2]

    time_difference = (third_time - first_time).total_seconds()

    if time_difference <= 60:
        time_based_brute_force = True
print("=" * 50)
print("SOC REPORT")
print("=" * 50)
print()

print("=" * 50)
print("TIME-BASED DETECTION")
print("=" * 50)

if time_based_brute_force:
    print("TIME-BASED BRUTE FORCE DETECTED")
else:
    print("No Time-Based Brute Force Attack")
print(f"INFO: {info_count}")
print(f"WARNING: {warning_count}")
print(f"ERROR: {error_count}")
print(f"FAILED LOGINS: {failed_login_count}")


print()

print("FAILED LOGIN TIMES:")
if failed_login_times:
    for login_time in failed_login_times:
        print(f"- {login_time.strftime('%H:%M:%S')}")
else:
    print("None")

print()

print("DETECTED USERS:")
if detected_users:
    for username in detected_users:
        print(f"- {username}")
else:
    print("None")

print()

print("DETECTED IP ADDRESSES:")
if detected_ips:
    for ip_address in detected_ips:
        print(f"- {ip_address}")
else:
    print("None")
    print("FAILED LOGIN COUNT:", failed_login_count)

# Risk Score Calculation

risk_score = (
    failed_login_count * 10
    + error_count * 20
)

if brute_force:
    risk_score += 40

if time_based_brute_force:
    risk_score += 50


print(f"RISK SCORE: {risk_score}")

print()
print("=" * 50)
print("ALERT LEVEL")
print("=" * 50)

if failed_login_count >= 3:
    print("HIGH ALERT : Possible Brute Force Attack")
elif failed_login_count >= 1:
    print("MEDIUM ALERT : Failed Login Detected")
else:
    print("LOW ALERT : Normal Activity")

print()
print("=" * 50)
print("THREAT STATUS")
print("=" * 50)

if brute_force:
    print("BRUTE FORCE ATTACK DETECTED")
else:
    print("No Brute Force Attack")

print()
print("=" * 50)
print("ATTACK SUMMARY")
print("=" * 50)

total_events = info_count + warning_count + error_count

if risk_score >= 70:
    threat_level = "HIGH"
elif risk_score >= 30:
    threat_level = "MEDIUM"
else:
    threat_level = "LOW"

print(f"TOTAL EVENTS   : {total_events}")
print(f"FAILED LOGINS  : {failed_login_count}")
print(f"DETECTED USERS : {len(detected_users)}")
print(f"DETECTED IPS   : {len(detected_ips)}")
print(f"RISK SCORE     : {risk_score}")
print(f"THREAT LEVEL   : {threat_level}")

print()
print("=" * 50)
print("SAVING TXT REPORT...")
print("=" * 50)

report_path = "reports/soc_report.txt"

with open(report_path, "w") as report_file:

    report_file.write("SOC LOG ANALYZER REPORT\n")
    report_file.write("=" * 50 + "\n")

    report_file.write(f"INFO: {info_count}\n")
    report_file.write(f"WARNING: {warning_count}\n")
    report_file.write(f"ERROR: {error_count}\n")
    report_file.write(f"FAILED LOGINS: {failed_login_count}\n")
    report_file.write(f"RISK SCORE: {risk_score}\n\n")

    report_file.write("FAILED LOGIN TIMES:\n")
    if failed_login_times:
        for login_time in failed_login_times:
            report_file.write(f"- {login_time.strftime('%H:%M:%S')}\n")
    else:
        report_file.write("None\n")

    report_file.write("\nDETECTED USERS:\n")
    if detected_users:
        for user in detected_users:
            report_file.write(f"- {user}\n")
    else:
        report_file.write("None\n")

    report_file.write("\nDETECTED IP ADDRESSES:\n")
    if detected_ips:
        for ip in detected_ips:
            report_file.write(f"- {ip}\n")
    else:
        report_file.write("None\n")

    report_file.write("\nTHREAT STATUS:\n")
    if brute_force:
        report_file.write("BRUTE FORCE ATTACK DETECTED\n")
    else:
        report_file.write("No Brute Force Attack\n")

    report_file.write("\nTIME-BASED DETECTION:\n")
    if time_based_brute_force:
        report_file.write("TIME-BASED BRUTE FORCE DETECTED\n")
    else:
        report_file.write("No Time-Based Brute Force Attack\n")

print(f"TXT Report saved successfully: {report_path}")

print()
print("=" * 50)
print("SAVING CSV REPORT...")
print("=" * 50)

csv_report_path = "reports/soc_report.csv"

with open(csv_report_path, "w", newline="") as csv_file:

    writer = csv.writer(csv_file)

    writer.writerow(["Category", "Value"])
    writer.writerow(["INFO", info_count])
    writer.writerow(["WARNING", warning_count])
    writer.writerow(["ERROR", error_count])
    writer.writerow(["FAILED LOGINS", failed_login_count])
    writer.writerow(["RISK SCORE", risk_score])

    writer.writerow([
        "FAILED LOGIN TIMES",
        ", ".join(
            [t.strftime("%H:%M:%S") for t in failed_login_times]
        )
    ])

    writer.writerow(["DETECTED USERS", ", ".join(detected_users)])
    writer.writerow(["DETECTED IPS", ", ".join(detected_ips)])

    if brute_force:
        writer.writerow(["THREAT STATUS", "BRUTE FORCE ATTACK DETECTED"])
    else:
        writer.writerow(["THREAT STATUS", "No Brute Force Attack"])
        writer.writerow(["TIME BASED BRUTE FORCE", time_based_brute_force])

print(f"CSV Report saved successfully: {csv_report_path}")

print()
print("=" * 50)
print("SAVING JSON REPORT...")
print("=" * 50)

json_report_path = "reports/soc_report.json"

report_data = {
    "INFO": info_count,
    "WARNING": warning_count,
    "ERROR": error_count,
    "FAILED_LOGINS": failed_login_count,
    "RISK_SCORE": risk_score,
    "TIME_BASED_BRUTE_FORCE": time_based_brute_force,
    "FAILED_LOGIN_TIMES": [
        t.strftime("%H:%M:%S") for t in failed_login_times
    ],
    "DETECTED_USERS": detected_users,
    "DETECTED_IPS": detected_ips,
    "THREAT_STATUS": (
        "BRUTE FORCE ATTACK DETECTED"
        if brute_force
        else "No Brute Force Attack"
    )
}

with open(json_report_path, "w") as json_file:
    json.dump(report_data, json_file, indent=4)

print(f"JSON Report saved successfully: {json_report_path}")