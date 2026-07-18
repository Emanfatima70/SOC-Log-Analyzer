import re
import csv
import json

print("=" * 50)
print("SOC LOG ANALYZER")
print("=" * 50)

log_file_path = "sample_logs/sample.log"

info_count = 0
warning_count = 0
error_count = 0
failed_login_count = 0
brute_force = False

detected_ips = []
detected_users = []

with open(log_file_path, "r") as log_file:
    for line in log_file:

        # Log level counting
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
        failed_login_times.append(time_match.group())

        # Brute Force Detection
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
print("=" * 50)
print("SOC REPORT")
print("=" * 50)

print(f"INFO: {info_count}")
print(f"WARNING: {warning_count}")
print(f"ERROR: {error_count}")
print(f"FAILED LOGINS: {failed_login_count}")

print()
print("DETECTED USERS:")
if detected_users:
    for user in detected_users:
        print(f"- {user}")
else:
    print("None")

print()
print("DETECTED IP ADDRESSES:")
if detected_ips:
    for ip_address in detected_ips:
        print(f"- {ip_address}")
else:
    print("None")

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
print("SAVING REPORT...")
print("=" * 50)

report_path = "reports/soc_report.txt"

with open(report_path, "w") as report_file:

    report_file.write("SOC LOG ANALYZER REPORT\n")
    report_file.write("=" * 50 + "\n")

    report_file.write(f"INFO: {info_count}\n")
    report_file.write(f"WARNING: {warning_count}\n")
    report_file.write(f"ERROR: {error_count}\n")
    report_file.write(f"FAILED LOGINS: {failed_login_count}\n\n")

    report_file.write("DETECTED USERS:\n")
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

print(f"Report saved successfully: {report_path}")
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

    writer.writerow(["DETECTED USERS", ", ".join(detected_users)])
    writer.writerow(["DETECTED IPS", ", ".join(detected_ips)])

    if brute_force:
        writer.writerow(["THREAT STATUS", "BRUTE FORCE ATTACK DETECTED"])
    else:
        writer.writerow(["THREAT STATUS", "No Brute Force Attack"])

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