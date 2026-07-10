print("=" * 50)
print("SOC LOG ANALYZER")
print("=" * 50)

log_file_path = "sample_logs/sample.log"

info_count = 0
warning_count = 0
error_count = 0

with open(log_file_path, "r") as log_file:
    for line in log_file:

        if "INFO" in line:
            info_count += 1

        elif "WARNING" in line:
            warning_count += 1

        elif "ERROR" in line:
            error_count += 1

        print(line.strip())

print("\n")
print("=" * 50)
print("SOC REPORT")
print("=" * 50)

print(f"INFO: {info_count}")
print(f"WARNING: {warning_count}")
print(f"ERROR: {error_count}")

git status
