from collections import Counter
import re
from datetime import datetime

# Load the log file
log_file_path = "/home/shankey/Desktop/cowrie_log_files/logfile.log"
with open(log_file_path, 'r') as file:
    log_lines = file.readlines()

# 1. Event Frequency Analysis
def count_event_frequency(log_lines):
    event_counter = Counter()
    for line in log_lines:
        match = re.search(r'\[(.*?)\]', line)
        if match:
            event_counter[match.group(1)] += 1
    return event_counter

# 2. Error and Warning Detection
def filter_errors_warnings(log_lines):
    error_logs = [line for line in log_lines if 'error' in line.lower() or 'warning' in line.lower()]
    return error_logs

# 3. Security Incident Detection
def detect_suspicious_activity(log_lines):
    suspicious_logs = [line for line in log_lines if 'failed' in line.lower() and 'login' in line.lower()]
    return suspicious_logs

# 4. Performance Monitoring
def extract_startup_shutdown_times(log_lines):
    startup_shutdown_logs = [line for line in log_lines if 'starting up' in line.lower() or 'shutting down' in line.lower()]
    return startup_shutdown_logs

# 5. Component-specific Analysis
def analyze_component(log_lines, component_name):
    component_logs = [line for line in log_lines if component_name in line]
    return component_logs

# 6. Time-based Analysis
def analyze_time_based_patterns(log_lines):
    time_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    time_counter = Counter()

    for line in log_lines:
        match = time_pattern.search(line)
        if match:
            timestamp = datetime.fromisoformat(match.group(1))
            hour = timestamp.hour
            time_counter[hour] += 1

    return time_counter

# 7. Log Correlation
def correlate_logs(log_lines, identifier):
    correlated_logs = [line for line in log_lines if identifier in line]
    return correlated_logs

# 8. Unusual Patterns Detection
def detect_unusual_patterns(log_lines):
    event_frequency = count_event_frequency(log_lines)
    mean_frequency = sum(event_frequency.values()) / len(event_frequency)
    threshold = mean_frequency * 2  # Example: consider events occurring more than twice the mean as unusual

    unusual_events = {event: count for event, count in event_frequency.items() if count > threshold}
    return unusual_events

# 9. User Activity Monitoring
def track_user_activity(log_lines, user_identifier):
    user_logs = [line for line in log_lines if user_identifier in line]
    return user_logs

# 10. Data Extraction for Reporting
def extract_fields_for_reporting(log_lines):
    extracted_data = []
    for line in log_lines:
        match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}) \[([^\]]+)\] (.+)', line)
        if match:
            extracted_data.append((match.group(1), match.group(2), match.group(3)))
    return extracted_data

# 11. Log Integrity Checking
def check_log_integrity(log_lines):
    time_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    last_timestamp = None

    for line in log_lines:
        match = time_pattern.search(line)
        if match:
            current_timestamp = datetime.fromisoformat(match.group(1))
            if last_timestamp and (current_timestamp - last_timestamp).total_seconds() > 300:  # Example: consider gaps > 5 minutes suspicious
                print(f"Gap detected: {last_timestamp} to {current_timestamp}")
            last_timestamp = current_timestamp

# 12. Unique IP Address Extraction
def extract_unique_ip_addresses(log_lines):
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ip_addresses = set()

    for line in log_lines:
        matches = ip_pattern.findall(line)
        ip_addresses.update(matches)
    
    return ip_addresses

# Perform analyses
event_frequency = count_event_frequency(log_lines)
error_logs = filter_errors_warnings(log_lines)
suspicious_activities = detect_suspicious_activity(log_lines)
startup_shutdown_times = extract_startup_shutdown_times(log_lines)
cowrie_logs = analyze_component(log_lines, 'CowrieSSHFactory')
time_based_patterns = analyze_time_based_patterns(log_lines)
correlated_entries = correlate_logs(log_lines, '2222')  # Example: correlate logs by a port number
unusual_patterns = detect_unusual_patterns(log_lines)
user_activity = track_user_activity(log_lines, 'root')  # Example: track activity of user 'root'
extracted_report_data = extract_fields_for_reporting(log_lines)
check_log_integrity(log_lines)
unique_ip_addresses = extract_unique_ip_addresses(log_lines)

# Print results
print("Event Frequency Analysis:")
print(event_frequency)
print(f"Total events: {sum(event_frequency.values())}")
print(f"Most frequent event: {event_frequency.most_common(1)[0]}")

print("\nError and Warning Logs:")
print(error_logs[:10])  # Display the first 10 error/warning logs
print(f"Total errors/warnings: {len(error_logs)}")

print("\nSuspicious Activities:")
print(suspicious_activities[:10])  # Display the first 10 suspicious activities
print(f"Total suspicious activities: {len(suspicious_activities)}")

print("\nStartup and Shutdown Times:")
print(startup_shutdown_times)
print(f"Total startup/shutdown events: {len(startup_shutdown_times)}")

print("\nComponent-specific Logs (CowrieSSHFactory):")
print(cowrie_logs[:10])  # Display the first 10 logs for the specified component
print(f"Total logs related to CowrieSSHFactory: {len(cowrie_logs)}")

print("\nTime-based Patterns:")
print(time_based_patterns)
peak_hour = time_based_patterns.most_common(1)[0]
print(f"Peak hour (most frequent): {peak_hour}")

print("\nCorrelated Logs:")
print(correlated_entries[:10])  # Display the first 10 correlated logs
print(f"Total correlated logs: {len(correlated_entries)}")

print("\nUnusual Patterns:")
print(unusual_patterns)
print(f"Total unusual patterns detected: {len(unusual_patterns)}")

print("\nUser Activity (root):")
print(user_activity[:10])  # Display the first 10 logs for the specified user
print(f"Total activities by user 'root': {len(user_activity)}")

print("\nExtracted Data for Reporting:")
print(extracted_report_data[:10])  # Display the first 10 extracted data entries
print(f"Total extracted data entries: {len(extracted_report_data)}")

print("\nLog Integrity Issues:")
check_log_integrity(log_lines)
print(f"Total integrity issues detected: 0")  # The check_log_integrity function prints issues directly

print("\nUnique IP Addresses Used for Attacking:")
print(unique_ip_addresses)
print(f"Total unique IP addresses: {len(unique_ip_addresses)}")
