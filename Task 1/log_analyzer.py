# Parsing network syslog files, detecting trends, producing CSV report and a matplotlib graph.
import re
from datetime import datetime, timedelta
import pandas as pd
import os
import matplotlib.pyplot as plt



# Use the script directory as the base so runs from different working directories behave the same
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
cwd_logs = [os.path.join(BASE_DIR, f) for f in os.listdir(BASE_DIR) if f.endswith('.log')]
log_paths = list(cwd_logs)
logs_dir = os.path.join(BASE_DIR, 'logs')
if os.path.isdir(logs_dir):
    logs_sub = [os.path.join(logs_dir, f) for f in os.listdir(logs_dir) if f.endswith('.log')]
    for p in logs_sub:
        if p not in log_paths:
            log_paths.append(p)

if not log_paths:
    print(f"No .log files found in {BASE_DIR} or '{logs_dir}' subdirectory. Exiting.")
    raise SystemExit(0)

# Pattern: "YYYY-MM-DD HH:MM:SS DEVICE LEVEL message..."
# Typical pattern: "YYYY-MM-DD HH:MM:SS DEVICE LEVEL message..."
# Allow some flexibility for extra spaces or missing level
line_re = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(?P<device>\S+)\s+(?P<level>\S+)?\s*(?P<msg>.+)$")

events = []

def classify_event(msg):
    """Return (event_type, key_detail)"""
    msg_lower = msg.lower()
    # CPU
    m = re.search(r"(cpu|cpu utilization|cpu%)[:\s\w-]*?(\d{1,3})%", msg_lower)
    if m:
        try:
            pct = int(m.group(2))
        except:
            pct = None
        return "CPU", f"CPU util {pct}%" if pct is not None else "CPU utilization"
    # Interface
    if msg_lower.startswith("interface") or "interface " in msg_lower:
        # try to extract interface name and state/value
        m = re.search(r"interface\s+([A-Za-z0-9/\.]+)\b(.*)", msg, re.IGNORECASE)
        if m:
            intf = m.group(1)
            rest = m.group(2).strip()
            rest = rest if rest else msg
            return "Interface", f"{intf} {rest}"
        return "Interface", msg
    # BGP
    if "bgp neighbor" in msg_lower or ("bgp" in msg_lower and "neighbor" in msg_lower):
        m = re.search(r"bgp neighbor\s+([0-9\.]+)\s+(established|went down|up|down)", msg_lower, re.IGNORECASE)
        if m:
            return "BGP", f"neighbor {m.group(1)} {m.group(2)}"
        return "BGP", msg
    # OSPF
    if "ospf" in msg_lower:
        # extract short detail if possible
        m = re.search(r"ospf.*?(neighbor|adj|adjacency|down|up|flap|change).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?", msg_lower)
        detail = msg
        if m:
            detail = m.group(0)
        return "OSPF", detail
    # SNMP
    if "snmp authentication failure" in msg_lower:
        m = re.search(r"from\s+([0-9\.]+)", msg_lower)
        ip = m.group(1) if m else ""
        return "SNMP", f"auth failure from {ip}"
    # Temperature
    if "temperature sensor" in msg_lower:
        m = re.search(r"temperature sensor\s*(\d+).*?(exceeded threshold|returned to normal)", msg_lower, re.IGNORECASE)
        if m:
            return "Temperature", f"sensor {m.group(1)} {m.group(2)}"
        return "Temperature", msg
    # Default: Other
    return "Other", msg

# Read files and parse
for p in log_paths:
    if not os.path.exists(p):
        continue
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = line_re.match(line)
            if not m:
                # skip unparsable
                continue
            ts = datetime.strptime(m.group("ts"), "%Y-%m-%d %H:%M:%S")
            device = m.group("device")
            level = m.group("level")
            msg = m.group("msg")
            event_type, detail = classify_event(msg)
            events.append({
                "timestamp": ts,
                "device": device,
                "level": level,
                "event_type": event_type,
                "detail": detail,
                "raw": msg
            })

# Create DataFrame
df = pd.DataFrame(events)
if df.empty:
    raise SystemExit("No events parsed from logs.")

# Sorting
df = df.sort_values("timestamp").reset_index(drop=True)

# Trend detection

# 1) OSPF flaps: >3 within 10 minutes per device
ospf_alerts = []
for device, g in df[df["event_type"]=="OSPF"].groupby("device"):
    times = list(g["timestamp"])
    # sliding window
    i = 0
    while i < len(times):
        j = i
        window = []
        while j < len(times) and (times[j] - times[i]) <= timedelta(minutes=10):
            window.append(times[j])
            j += 1
        if len(window) > 3:
            # Only record the first time this window is detected
            if not ospf_alerts or window[0] > ospf_alerts[-1]["last"]:
                ospf_alerts.append({
                    "device": device,
                    "count": len(window),
                    "first": window[0],
                    "last": window[-1],
                    "detail": f"OSPF flap detected: {len(window)} events between {window[0].strftime('%H:%M:%S')} and {window[-1].strftime('%H:%M:%S')}"
                })
        i += 1

# 2) CPU >80% more than 2 times in an hour per device
cpu_alerts = []
# find CPU events where detail contains a percentage >80
cpu_df = df[df["event_type"]=="CPU"].copy()
def extract_pct(detail):
    m = re.search(r"(\d{1,3})%", detail)
    if m:
        try:
            return int(m.group(1))
        except:
            return None
    return None

cpu_df["pct"] = cpu_df["detail"].apply(lambda d: extract_pct(d))
# filter >80
cpu_high = cpu_df[cpu_df["pct"].notnull() & (cpu_df["pct"]>80)].copy()

for device, g in cpu_high.groupby("device"):
    times = list(g["timestamp"])
    i = 0
    while i < len(times):
        j = i
        window = []
        while j < len(times) and (times[j] - times[i]) <= timedelta(hours=1):
            window.append(times[j])
            j += 1
        if len(window) > 2:
            # Only record the first time this window is detected
            if not cpu_alerts or window[0] > cpu_alerts[-1]["last"]:
                # Find the max CPU% in this window for detail
                max_pct = cpu_high[(cpu_high["device"] == device) & (cpu_high["timestamp"] >= window[0]) & (cpu_high["timestamp"] <= window[-1])]["pct"].max()
                cpu_alerts.append({
                    "device": device,
                    "count": len(window),
                    "first": window[0],
                    "last": window[-1],
                    "detail": f"High CPU detected: {len(window)} events (max {max_pct}%) between {window[0].strftime('%H:%M:%S')} and {window[-1].strftime('%H:%M:%S')}"
                })
        i += 1

# Build CSV report: Device, Event, Count, Last_Seen, Risk_Level
# We'll aggregate by device and event_type for counts
agg = df.groupby(["device","event_type"]).agg(
    Count=("event_type","count"),
    Last_Seen=("timestamp","max")
).reset_index()

def assess_risk(row):
    device = row["device"]
    et = row["event_type"]
    cnt = row["Count"]
    # High risk if in alerts
    if et == "OSPF":
        if any(a["device"] == device for a in ospf_alerts):
            return "Critical" # Changed to Critical for trend detection
    if et == "CPU":
        if any(a["device"] == device for a in cpu_alerts):
            return "Critical" # Changed to Critical for trend detection
    
    # High risk for high event count
    if cnt >= 50:
        return "High"
    # Medium risk for moderate event count
    if cnt >= 10:
        return "Medium"
    # Low risk otherwise
    return "Low"

agg["Risk_Level"] = agg.apply(assess_risk, axis=1)

# Reformat Last_Seen to ISO string
agg["Last_Seen"] = agg["Last_Seen"].dt.strftime("%Y-%m-%d %H:%M:%S")



# Prepare output paths (use timestamped filenames and an output directory)
out_dir = 'output'
os.makedirs(out_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
csv_path = os.path.join(out_dir, f"network_report_{timestamp}.csv")
img_path = os.path.join(out_dir, f"top_events_{timestamp}.png")

# Save CSV (handle permission errors e.g. file open in Excel)
agg.rename(columns={"event_type":"Event", "device":"Device", "Count":"Count"}, inplace=True)
try:
    agg.to_csv(csv_path, index=False)
except PermissionError:
    # Fallback: try a different filename with a random suffix
    alt_path = os.path.join(out_dir, f"network_report_{timestamp}_alt.csv")
    try:
        agg.to_csv(alt_path, index=False)
        print(f"Warning: could not write to '{csv_path}' (permission denied). Wrote to '{alt_path}' instead.")
        csv_path = alt_path
    except Exception as e:
        print(f"Error: failed to write CSV report to '{csv_path}' and fallback '{alt_path}': {e}")
        raise

# Display top rows to user
print("Network Events Summary")
print(agg.to_string(index=False))

# Visualization: top 5 devices by total event count (across event types)
device_counts = df.groupby("device").size().sort_values(ascending=False).head(5)
plt.figure(figsize=(8,5))
device_counts.plot(kind="bar")
plt.title("Top devices by event count")
plt.xlabel("Device")
plt.ylabel("Event Count")
plt.tight_layout()



plt.savefig(img_path)
plt.close()

# Also display the parsed raw events head for inspection
print("Parsed Raw Events (first 100 rows)")
print(df.head(100).to_string(index=False))

# Prepare summary to show below in notebook output
summary = {
    "total_events_parsed": len(df),
    "unique_devices": df["device"].nunique(),
    "ospf_alerts": ospf_alerts,
    "cpu_alerts": cpu_alerts,
    "csv_report": csv_path,
    "plot_image": img_path
}

summary

# Print trend detection results for clarity
print("\n--- Trend Detection Summary ---")
if ospf_alerts:
    print("\nOSPF Flap Alerts:")
    for a in ospf_alerts:
        print(f"  Device: {a['device']}, Detail: {a['detail']}")
else:
    print("No OSPF Flap Alerts detected.")
    
if cpu_alerts:
    print("\nHigh CPU Alerts:")
    for a in cpu_alerts:
        print(f"  Device: {a['device']}, Detail: {a['detail']}")
else:
    print("No High CPU Alerts detected.")
