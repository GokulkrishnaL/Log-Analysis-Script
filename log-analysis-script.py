import csv
import re
from collections import Counter, defaultdict
from datetime import datetime

import matplotlib.pyplot as plt

# Precompiled Regex Patterns
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
ENDPOINT_PATTERN = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS) ([^ ]+)')
FAILED_LOGIN_PATTERN = re.compile(r"401|Invalid credentials", re.IGNORECASE)
DATE_PATTERN = re.compile(
    r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}"
)  # for extracting date from log


def extract_ip_addresses(log_lines):
    """Extract IP addresses from log lines."""
    return [
        IP_PATTERN.search(line).group() for line in log_lines if IP_PATTERN.search(line)
    ]


def extract_endpoints(log_lines):
    """Extract endpoints (URLs or resource paths) from log lines."""
    return [
        ENDPOINT_PATTERN.search(line).group(1)
        for line in log_lines
        if ENDPOINT_PATTERN.search(line)
    ]


def detect_suspicious_activity(log_lines, failed_login_threshold=10):
    """
    Detect IPs with failed login attempts exceeding the threshold.
    """
    # Using Counter to streamline incrementing
    failed_login_attempts = Counter(
        IP_PATTERN.search(line).group()
        for line in log_lines
        if FAILED_LOGIN_PATTERN.search(line) and IP_PATTERN.search(line)
    )
    return {
        ip: count
        for ip, count in failed_login_attempts.items()
        if count > failed_login_threshold
    }


def extract_hourly_traffic(log_lines):
    """Extract hourly traffic from the logs."""
    hourly_traffic = defaultdict(int)
    for line in log_lines:
        date_match = DATE_PATTERN.search(line)
        if date_match:
            timestamp = datetime.strptime(date_match.group(), "%d/%b/%Y:%H:%M:%S")
            hour = timestamp.hour
            hourly_traffic[hour] += 1
    return hourly_traffic


def print_summary(title, data, headers=None):
    """
    Print a formatted table summary.
    """
    print(f"\n{'=' * 50}\n{title:^50}\n{'=' * 50}")
    if headers:
        print(f"{headers[0]:<20} {headers[1]:<15}")
        print("-" * 35)
    for row in data:
        print(" ".join(f"{str(item):<20}" for item in row))


def save_to_csv(output_csv, ip_count, endpoint_summary, suspicious_ips):
    """
    Save analysis results to a CSV file.
    """
    with open(output_csv, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)

        # Save Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(ip_count)
        writer.writerow([])

        # Save Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(endpoint_summary)
        writer.writerow([])

        # Save Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips.items())


def generate_visualizations(ip_count, hourly_traffic, sorted_ip_count, suspicious_ips):
    """
    Generate visualizations for:
    1. Requests per Hour
    2. Top 5 IPs by Request Count (Pie Chart)
    3. Failed Login Attempts by Suspicious IPs (Bar Chart)
    """
    # Visualization for Requests per Hour (Line Plot)
    fig, axes = plt.subplots(
        1, 3, figsize=(15, 5)
    )  # 1 row, 3 columns with reduced space

    # Plot Requests per Hour
    axes[0].plot(list(hourly_traffic.keys()), list(hourly_traffic.values()), marker="o")
    axes[0].set_title("Requests per Hour", fontsize=10)
    axes[0].set_xlabel("Hour", fontsize=8)
    axes[0].set_ylabel("Number of Requests", fontsize=8)
    axes[0].tick_params(axis="both", labelsize=8)
    axes[0].tick_params(axis="x", rotation=45)

    # *Pie Chart for Top 5 IPs*
    top_5_ips = sorted_ip_count[:5]
    top_5_ips_labels = [ip for ip, _ in top_5_ips]
    top_5_ips_values = [count for _, count in top_5_ips]
    axes[1].pie(
        top_5_ips_values, labels=top_5_ips_labels, autopct="%1.1f%%", startangle=90
    )
    axes[1].set_title("Top 5 IP Addresses by Request Count", fontsize=10)

    # *Bar Chart for Suspicious IPs*
    suspicious_ips_labels = list(suspicious_ips.keys())
    suspicious_ips_values = [count for count in suspicious_ips.values()]
    axes[2].bar(suspicious_ips_labels, suspicious_ips_values)
    axes[2].set_title("Failed Login Attempts by Suspicious IPs", fontsize=10)
    axes[2].set_xlabel("IP Address", fontsize=8)
    axes[2].set_ylabel("Failed Login Attempts", fontsize=8)
    axes[2].tick_params(axis="x", labelsize=8)
    axes[2].tick_params(axis="y", labelsize=8)
    axes[2].tick_params(axis="x", rotation=45)

    plt.tight_layout()
    plt.show()


def analyze_log_file(
    log_file_path, failed_login_threshold=10, output_csv="log_analysis_results.csv"
):
    """
    Analyze the log file for request counts, endpoints, and suspicious activity.
    """
    try:
        with open(log_file_path, "r", encoding="utf-8") as log_file:
            log_lines = log_file.readlines()

        # Analysis
        ip_addresses = extract_ip_addresses(log_lines)
        endpoints = extract_endpoints(log_lines)
        suspicious_ips = detect_suspicious_activity(log_lines, failed_login_threshold)
        hourly_traffic = extract_hourly_traffic(log_lines)

        ip_count = Counter(ip_addresses)
        endpoint_count = Counter(endpoints)
        sorted_ip_count = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
        most_frequent_endpoint, access_count = endpoint_count.most_common(1)[0]

        # Terminal Output
        print_summary(
            "Requests per IP", sorted_ip_count, headers=["IP Address", "Request Count"]
        )
        print_summary(
            "Most Frequently Accessed Endpoint",
            [(most_frequent_endpoint, access_count)],
            headers=["Endpoint", "Access Count"],
        )
        if suspicious_ips:
            print_summary(
                "Suspicious Activity Detected",
                suspicious_ips.items(),
                headers=["IP Address", "Failed Login Attempts"],
            )
        else:
            print("\nNo suspicious activity detected.")
        print_summary(
            "Summary",
            [
                ("Total Unique IPs", len(ip_count)),
                ("Total Unique Endpoints", len(endpoint_count)),
            ],
        )

        # Save to CSV
        save_to_csv(
            output_csv,
            sorted_ip_count,
            [(most_frequent_endpoint, access_count)],
            suspicious_ips,
        )
        print(f"\nResults saved to '{output_csv}'.")

        # Generate Visualizations
        generate_visualizations(
            ip_count, hourly_traffic, sorted_ip_count, suspicious_ips
        )

    except FileNotFoundError:
        print(f"Error: The file '{log_file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Run Analysis
log_file_path = "sample.log"
analyze_log_file(log_file_path)


