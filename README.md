To submit as a single file in GitHub, save the following content into a file named `README.md`:

```markdown
# Log Analysis Tool

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Input Format](#input-format)
6. [Output](#output)
7. [Visualization](#visualization)
8. [Contributing](#contributing)
9. [License](#license)

---

## Introduction
The **Log Analysis Tool** is a Python-based application designed to process server log files, extract key insights, and generate actionable reports and visualizations. The tool detects suspicious activities, such as failed login attempts, timestamps and provides a summary of the traffic patterns and frequently accessed resources.

---

## Features
- Extracts IP addresses and endpoints (URLs or resource paths) from logs.
- Detects suspicious activities like repeated failed login attempts.
- Summarizes requests per IP address and identifies the most accessed endpoints.
- Provides visualizations for traffic patterns, top IPs, and suspicious activities.
- Outputs results to the terminal and saves them to a CSV file.

---

## Installation

### Prerequisites
- Python 3.8 or above
- Pip (Python Package Installer)
---
```
### Setup
1. Clone the repository:

   ```bash
   git clone https://github.com/GokulkrishnaL/log-analysis-tool.git
   cd log-analysis-tool
   ```


2. Install the required dependencies:
---

## Usage

### Running the Tool
1. Place your log file (e.g., `sample.log`) in the same directory as the script or specify its path.
2. Run the script:
   ```bash
   python log_analysis_tool.py
   ```

### Parameters
- `log_file_path`: Path to the log file to be analyzed (default: `sample.log`).
- `failed_login_threshold`: Threshold for detecting suspicious IPs based on failed login attempts (default: `10`).
- `output_csv`: Path to save the analysis results as a CSV file (default: `log_analysis_results.csv`).


---

## Input Format
The tool expects log files in the following format (Apache/Nginx-style logs):
```
127.0.0.1 - - [07/Dec/2023:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1234
192.168.0.2 - - [07/Dec/2023:13:45:12 +0000] "POST /login HTTP/1.1" 401 5678
```

Key assumptions:
- Log entries contain IP addresses, HTTP methods (GET/POST), resource paths, and timestamps.
- Failed login attempts are indicated by status codes (`401`) or relevant messages.

---

## Output

### Console Output
The tool displays summaries such as:
- **Requests per IP**
- **Most Frequently Accessed Endpoint**
- **Suspicious Activity Detected**
- **Summary of Unique IPs and Endpoints**

### CSV Output
The results are saved in a CSV file with the following sections:
1. Requests per IP
2. Most Accessed Endpoint
3. Suspicious Activity

---

## Visualization
The tool generates the following visualizations:
1. **Requests per Hour** (Line Chart): Displays traffic patterns by hour.
2. **Top 5 IPs by Request Count** (Pie Chart): Highlights the IPs contributing the most requests.
3. **Failed Login Attempts by Suspicious IPs** (Bar Chart): Shows suspicious IP activity.

---

### Key Functions
1. `extract_ip_addresses`: Extracts IPs from log lines.
2. `extract_endpoints`: Extracts accessed endpoints from log lines.
3. `detect_suspicious_activity`: Detects IPs exceeding failed login thresholds.
4. `extract_hourly_traffic`: Computes traffic distribution by hour.
5. `generate_visualizations`: Creates visualizations for insights.
6. `save_to_csv`: Saves results to a CSV file.

---

## Contributing
Contributions are welcome! If you'd like to contribute:
1. Fork the repository.
2. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature-name
   ```
3. Commit your changes and push the branch:
   ```bash
   git push origin feature-name
   ```
4. Open a pull request and describe your changes.

---
