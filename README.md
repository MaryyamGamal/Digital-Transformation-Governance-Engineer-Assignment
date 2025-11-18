# Network Automation & Governance Engineering Assessment

This repository contains the solutions for the two technical tasks assigned for the Network Automation (DevNet) & Governance Engineer position. The projects demonstrate proficiency in Python, Flask, data analysis, network configuration parsing, and data visualization, aligning directly with the core requirements of the role.

---

## Task 1: Advanced Network Log Analyzer (Syslog + Trend Detection)

This project is a Python-based solution designed to parse network device syslog dumps, extract key event data, detect critical operational trends, and generate a comprehensive, data-driven report.

It demonstrates proficiency in Python programming, data manipulation (Pandas), network event analysis, and data visualization (Matplotlib).

### 🚀 Features

*   **Multi-File Parsing:** Reads and processes multiple `.log` files from a specified directory.
*   **Structured Data Extraction:** Extracts **Timestamp**, **Device Name**, **Event Type** (OSPF, CPU, Interface, etc.), and a **Key Detail** from each log line.
*   **Critical Trend Detection:**
    *   Identifies devices with repeated **OSPF Flaps** (more than 3 times within a 10-minute window).
    *   Identifies devices with sustained **High CPU Utilization** (above 80% more than 2 times in an hour).
*   **Risk-Based Reporting:** Generates a final CSV report with a calculated `Risk_Level` to prioritize critical events.
*   **Data Visualization:** Produces a bar chart showing the top 5 devices by event count.

### 🛠️ Requirements

This script requires Python 3 and the following libraries:

```bash
pip install pandas matplotlib
```

### 💻 Usage

1.  **Prepare Log Files:** Place all your network log files (e.g., `router1.log`, `switch_core.log`) into a directory named `logs/` in the same location as the script.
2.  **Run the Analyzer:** Execute the script from your terminal:
    ```bash
    python log_analyzer.py
    ```
3.  **Review Output:** The script will create an `output/` directory containing the following files:
    | File Name | Description |
    | :--- | :--- |
    | `network_events_report.csv` | The main report with columns: `Device`, `Event`, `Count`, `Last_Seen`, and `Risk_Level`. |
    | `top_devices_by_event.png` | Bar chart visualizing the top 5 noisiest devices. |

#### Sample Output
The final report provides actionable insights for network operations.

![Sample Log Analyzer Summary](Task%201/summary.png)

![Sample Log Analyzer Graph](Task%201/graph.png)

---

## Task 2: Multi-Service Flask Platform for Network Audit, Analytics & File Distribution

This project is a full-stack web application built with **Flask** that serves as a centralized platform for network configuration auditing and analytics. It directly addresses the job requirement to "Build & maintain Flask-based web apps" and demonstrates proficiency in backend development, data processing, and frontend visualization.

### 🚀 Features

The platform provides two main routes: `/upload` and `/dashboard`.

#### 1. Configuration Upload and Parsing (`/upload`)
*   **Multi-Vendor Support:** Accepts and processes configuration files from Cisco (`.cfg`), Huawei (`.cfg`), and Juniper (`.conf`) devices.
*   **Key Data Extraction:** Parses each configuration file to extract:
    *   Device Hostname
    *   Interface names and IP addresses
    *   Routing Protocols (OSPF, BGP)
    *   ACL/Security Rules

#### Sample Upload Interface
The user-friendly interface allows for quick and easy configuration file submission.

![Sample Upload Interface](Task%202/upload.png)

#### 2. Network Configuration Validation
The application performs critical network health checks on the parsed data:
*   **Loopback Check:** Ensures every device has a configured `Loopback0` interface.
*   **IP Overlap Check:** Verifies that IP subnets do not overlap across different devices.
*   **Routing Consistency:** Checks for consistency in OSPF/BGP area configurations.
*   **Data Storage:** Stores all parsed and validated results in a local database (e.g., SQLite) for persistence and retrieval.

#### 3. Analytics Dashboard (`/dashboard`)
*   **Validation Summary:** Displays a clear table summarizing the validation results (Pass/Fail) for each uploaded device.
*   **Routing Protocol Distribution:** A pie chart visualizing the number of devices running BGP versus OSPF.
*   **Interface Density:** A bar chart showing the total number of interfaces configured per device.
*   **Data Export:** Allows users to export the full validation and analytics data to **Excel** or **CSV** format.

#### Sample Dashboard View
The dashboard provides immediate visual feedback on validation and network statistics.

![Sample Dashboard Tables](Task%202/tables.png)

### 🛠️ Setup and Installation

#### 1. Installation

It is recommended to use a virtual environment:

```bash
# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install Flask pandas openpyxl
```

#### 2. Database Setup

The application uses a local SQLite database. The database file will be created automatically upon first run if it does not exist.

### 💻 Usage

1.  **Run the Application:** Start the Flask development server:
    ```bash
    python app.py
    ```
    The application will be accessible at `http://127.0.0.1:5000`.

2.  **Access Routes:**
    *   **Upload:** Navigate to `http://127.0.0.1:5000/upload` to use the HTML form to upload the sample configuration files.
    *   **Dashboard:** Navigate to `http://127.0.0.1:5000/dashboard` to view the validation results and analytics visualizations.

---
*Note: This README assumes the Task 1 script is named `log_analyzer.py` and the Task 2 script is named `app.py`.*
