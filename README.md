Cowrie Honeypot Setup and Log Analysis
This repository provides a comprehensive guide and tools for setting up a Cowrie honeypot using Docker, simulating SSH attacks for testing purposes, collecting logs, and performing detailed log analysis with a Python script. The project is intended for educational and security research purposes.

Table of Contents
Introduction
Disclaimer
Prerequisites
Project Structure
Setup Instructions
1. Setting Up Cowrie Honeypot
2. Simulating SSH Activity
3. Collecting Cowrie Logs
4. Analyzing Logs with the Python Script
Python Script Functions
Understanding the Output
Contributors
License
Introduction
Cowrie is a medium-interaction SSH and Telnet honeypot designed to log brute-force attacks and shell interaction performed by attackers. This project aims to:

Deploy a Cowrie honeypot in a Docker container.
Simulate SSH login attempts to generate log data.
Collect and analyze the logs to understand attack patterns and behaviors.
Provide insights into potential security incidents.
Disclaimer
Warning: This project is intended for educational and research purposes only. Unauthorized access to computer systems is illegal. Ensure you have proper authorization before conducting any security testing. The authors are not responsible for any misuse of the provided tools or instructions.

Prerequisites
Operating System: Linux-based system (e.g., Ubuntu)
Docker: Installed and running
Python 3: Installed with the following modules:
collections
re
datetime
Optional: Knowledge of SSH and network security concepts
Project Structure
log_analysis.py: Python script for analyzing Cowrie logs.
README.md: This readme file.
LICENSE: License information for the project.
Setup Instructions
1. Setting Up Cowrie Honeypot
a. Create a Docker Volume for Cowrie Logs
To persist logs outside the Docker container:


docker volume create cowrie_logs
b. Run Cowrie Docker Container
Deploy the Cowrie honeypot using Docker:


docker run -d -p 2222:2222/tcp --name cowrie -v cowrie_logs:/cowrie/log/ cowrie/cowrie
-d: Runs the container in detached mode.
-p 2222:2222/tcp: Maps port 2222 on the host to port 2222 on the container.
--name cowrie: Names the container "cowrie".
-v cowrie_logs:/cowrie/log/: Mounts the Docker volume to persist logs.
cowrie/cowrie: Specifies the Cowrie Docker image.
2. Simulating SSH Activity
To generate log data, simulate SSH login attempts to the honeypot. You can use an SSH client or a script to attempt logins to localhost on port 2222.

Note: Ensure that any simulated activity is performed ethically and within the legal boundaries. Do not attempt unauthorized access to systems that you do not own or have permission to test.

3. Collecting Cowrie Logs
After generating activity:


docker logs cowrie > /path/to/your/cowrie_log_files/logfile.log
Replace /path/to/your/cowrie_log_files/ with the directory where you want to save the log file.

4. Analyzing Logs with the Python Script
a. Prepare the Python Script
Ensure that the log_analysis.py script is updated with the correct path to your log file:


log_file_path = "/path/to/your/cowrie_log_files/logfile.log"
b. Install Required Python Modules
The script uses standard Python libraries. If needed, install any missing modules:


pip install collections re datetime
c. Run the Python Script
Execute the script:


python3 log_analysis.py
Python Script Functions
The log_analysis.py script includes the following functions:

Event Frequency Analysis

Counts how often each type of event occurs in the logs.
Error and Warning Detection

Identifies log entries that contain errors or warnings.
Security Incident Detection

Detects suspicious activities, such as failed login attempts.
Performance Monitoring

Extracts times when the Cowrie honeypot started up or shut down.
Component-specific Analysis

Analyzes logs related to a specific component.
Time-based Analysis

Analyzes patterns based on the time of log entries.
Log Correlation

Correlates log entries based on an identifier, such as a port number.
Unusual Patterns Detection

Detects events that occur more frequently than a defined threshold.
User Activity Monitoring

Tracks activities related to a specific user.
Data Extraction for Reporting

Extracts key fields from log entries for reporting purposes.
Log Integrity Checking

Checks for gaps in log timestamps that may indicate missing logs or issues.
Unique IP Address Extraction

Extracts unique IP addresses involved in the logs.
Understanding the Output
The script will print analysis results to the console, including:

Event frequencies and the most common events.
Lists of errors, warnings, and suspicious activities.
Startup and shutdown events.
Component-specific logs and time-based patterns.
Correlated logs and unusual patterns.
User activities and extracted data for reporting.
Unique IP addresses identified in the logs.
Use this information to gain insights into potential security incidents and understand the behavior of interactions with your honeypot.

Contributors
This project is a collaborative effort between:

Zishan Ahmad

Student ID: 21BCE1083
Contributions:
Setting up the Cowrie honeypot.
Developing Python script functions for event frequency analysis, error detection, security incident detection, and more.
Documentation and manual preparation.
Shashank Prasad

Student ID: 21BCE5859
Contributions:
Simulating SSH activity.
Enhancing the Python script with functions for component-specific analysis, time-based analysis, and unique IP extraction.
Documentation and reporting.

ScreenShots:
![img9](https://github.com/user-attachments/assets/8464c722-d97e-4f51-9301-590962b7ffe4)
![img4](https://github.com/user-attachments/assets/e8e9dce5-b320-4e70-9e49-3b07e2183435)
![img7](https://github.com/user-attachments/assets/5e29a431-0dda-4f56-9d0d-ea49f9742986)
![img8](https://github.com/user-attachments/assets/615a6317-f535-4616-b044-9a15feedd4f1)
![img9](https://github.com/user-attachments/assets/1acc72c2-766f-4d1f-addc-3cfb68d4c09f)





