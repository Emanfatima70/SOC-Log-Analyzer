import re

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

        # Failed login detection
        if "Failed login" in line:
            failed_login_count += 1
            print("ALERT: Failed Login Detected")

        # Brute force threshold check
        if failed_login_count >= 3:
            brute_force = True

        # IP address detection
        ip_addresses = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            line
        )

        for ip_address in ip_addresses:
            if ip_address not in detected_ips:
                detected_ips.append(ip_address)
                print(f"IP DETECTED: {ip_address}")
        # Username detection
        user_match = re.search(r"User (\w+)", line)

        if user_match:
            username = user_match.group(1)

            if username not in detected_users:
                detected_users.append(username)
                print(f"USER_DETECTED: {username}")
        failed_user = re.search(r"Failed login for (\w+)", line)

        if failed_user:
            username = failed_user.group(1)

           if username not in detected_users:
            detected_users.append(username)
            print(f"USER_DETECTED: {username}")

print()
print("=" * 50)
print("SOC REPORT")
print("=" * 50)

print(f"INFO: {info_count}")
print(f"WARNING: {warning_count}")
print(f"ERROR: {error_count}")
print(f"FAILED LOGINS: {failed_login_count}")

if detected_ips:
    print("DETECTED IP ADDRESSES:")
    for ip_address in detected_ips:
        print(f"- {ip_address}")
else:
    print("DETECTED IP ADDRESSES: None")

print()
print("=" * 50)
print("ALERT LEVEL")
print("=" * 50)

if failed_login_count >= 3:
    print("HIGH ALERT: Possible Brute Force Attack")
elif failed_login_count >= 1:
    print("MEDIUM ALERT: Failed Login Detected")
else:
    print("LOW ALERT: Normal Activity")

print()
print("=" * 50)
print("THREAT STATUS")
print("=" * 50)

if brute_force:
    print("BRUTE FORCE ATTACK DETECTED")
else:
    print("No Brute Force Attack")