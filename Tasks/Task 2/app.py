from flask import Flask, request, render_template, jsonify, redirect, url_for, send_file
import os
import sqlite3
import pandas as pd
import matplotlib
# Use a non-interactive backend to avoid GUI/tkinter issues when generating images in a web server
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import io
import base64
import re
import json
from werkzeug.utils import secure_filename
from ipaddress import ip_network, IPv4Network

app = Flask(__name__)

# Set upload folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Allowed file extensions
ALLOWED_EXTENSIONS = {'cfg', 'conf'}

# --- Database Setup ---
DB_NAME = 'devices.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Create table if it doesn't exist with the desired schema
    cursor.execute('''CREATE TABLE IF NOT EXISTS devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT,
                        hostname TEXT,
                        device_type TEXT,
                        routing_protocol TEXT,
                        interfaces TEXT,
                        security_rules TEXT,
                        validation_results TEXT,
                        ospf_areas TEXT,
                        bgp_asn TEXT
                    )''')

    # Ensure any missing columns from older DB schemas are added.
    cursor.execute("PRAGMA table_info(devices)")
    existing_cols = [row[1] for row in cursor.fetchall()]

    # Desired columns and their SQL definitions (simple, nullable)
    desired_columns = {
        'filename': 'TEXT',
        'hostname': 'TEXT',
        'device_type': 'TEXT',
        'routing_protocol': 'TEXT',
        'interfaces': 'TEXT',
        'security_rules': 'TEXT',
        'validation_results': 'TEXT',
        'ospf_areas': 'TEXT',
        'bgp_asn': 'TEXT'
    }

    for col, col_def in desired_columns.items():
        if col not in existing_cols:
            try:
                cursor.execute(f"ALTER TABLE devices ADD COLUMN {col} {col_def}")
            except sqlite3.OperationalError:
                # If the column cannot be added for some reason, ignore and continue
                pass

    conn.commit()
    conn.close()

init_db()

# --- Helper Functions ---

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_device_type(filename, content):
    if 'cisco' in filename.lower() or re.search(r'hostname \S+', content, re.IGNORECASE):
        return 'Cisco'
    elif 'huawei' in filename.lower() or re.search(r'sysname \S+', content, re.IGNORECASE):
        return 'Huawei'
    elif 'juniper' in filename.lower() or re.search(r'system {', content, re.IGNORECASE):
        return 'Juniper'
    return 'Unknown'

# --- Multi-Vendor Parsing Logic ---

def parse_cisco(content):
    data = {'hostname': 'Unknown', 'interfaces': [], 'routing_protocols': [], 'security_rules': []}
    
    # Hostname
    match = re.search(r'^hostname\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
    if match:
        data['hostname'] = match.group(1)
        
    # Interfaces and IPs
    interface_blocks = re.findall(r'^(interface\s+\S+)\n(.*?)(?=^interface|\Z)', content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    for name, block in interface_blocks:
        ip_match = re.search(r'ip\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', block, re.MULTILINE | re.IGNORECASE)
        if ip_match:
            data['interfaces'].append({'name': name.split()[-1], 'ip': ip_match.group(1), 'mask': ip_match.group(2)})
        elif 'Loopback0' in name:
             data['interfaces'].append({'name': name.split()[-1], 'ip': 'N/A', 'mask': 'N/A'})

    # Routing Protocols (OSPF/BGP)
    ospf_match = re.search(r'router\s+ospf\s+\d+\n(.*?)(?=^router|\Z)', content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if ospf_match:
        areas = re.findall(r'network\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+area\s+(\d+)', ospf_match.group(1), re.IGNORECASE)
        data['routing_protocols'].append({'type': 'OSPF', 'areas': list(set(areas))})

    bgp_match = re.search(r'router\s+bgp\s+\d+\n(.*?)(?=^router|\Z)', content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if bgp_match:
        asn_match = re.search(r'router\s+bgp\s+(\d+)', content, re.IGNORECASE)
        asn = asn_match.group(1) if asn_match else 'Unknown'
        data['routing_protocols'].append({'type': 'BGP', 'asn': asn})

    # Security Rules (ACLs)
    acl_matches = re.findall(r'^(access-list\s+\S+.*)', content, re.MULTILINE | re.IGNORECASE)
    data['security_rules'].extend(acl_matches)
    
    return data

def parse_huawei(content):
    data = {'hostname': 'Unknown', 'interfaces': [], 'routing_protocols': [], 'security_rules': []}
    
    # Hostname
    match = re.search(r'^sysname\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
    if match:
        data['hostname'] = match.group(1)
        
    # Interfaces and IPs
    interface_blocks = re.findall(r'^(interface\s+\S+)\n(.*?)(?=^interface|\Z)', content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    for name, block in interface_blocks:
        ip_match = re.search(r'ip\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', block, re.MULTILINE | re.IGNORECASE)
        if ip_match:
            data['interfaces'].append({'name': name.split()[-1], 'ip': ip_match.group(1), 'mask': ip_match.group(2)})
        elif 'LoopBack0' in name:
             data['interfaces'].append({'name': name.split()[-1], 'ip': 'N/A', 'mask': 'N/A'})

    # Routing Protocols (OSPF/BGP)
    # OSPF: Huawei configs vary; try both a block and simple 'ospf' keyword + area captures
    ospf_match = re.search(r'ospf\s+\d+\n(.*?)(?=^#|\Z)', content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    if ospf_match:
        areas = re.findall(r'area\s+(\d+)', ospf_match.group(1), re.IGNORECASE)
        data['routing_protocols'].append({'type': 'OSPF', 'areas': list(set(areas))})
    else:
        # Fallback: search for any 'area <n>' occurrences in the whole file
        areas = re.findall(r'area\s+(\d+)', content, re.IGNORECASE)
        if areas:
            data['routing_protocols'].append({'type': 'OSPF', 'areas': list(set(areas))})

    # BGP: Huawei may use 'bgp <asn>' or 'bgp as <asn>' or other variants
    bgp_match = re.search(r'bgp\s+(?:as\s+)?(\d+)', content, re.IGNORECASE)
    if bgp_match:
        asn = bgp_match.group(1)
        data['routing_protocols'].append({'type': 'BGP', 'asn': asn})

    # Security Rules (ACLs)
    # Huawei ACLs often appear as an 'acl number <n>' block followed by indented 'rule' lines,
    # or as standalone 'rule <num> ...' lines. Capture both styles.
    acl_block_matches = re.findall(r'acl\s+number\s+\d+\n(.*?)(?=^#|\Z)', content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
    for block in acl_block_matches:
        # split block into non-empty lines and strip
        for line in block.splitlines():
            line = line.strip()
            if line:
                data['security_rules'].append(line)

    # Also capture any standalone rule lines outside of acl blocks
    rule_matches = re.findall(r'^\s*rule\s+\d+\s+.*', content, re.MULTILINE | re.IGNORECASE)
    for r in rule_matches:
        data['security_rules'].append(r.strip())
    
    return data

def parse_juniper(content):
    data = {'hostname': 'Unknown', 'interfaces': [], 'routing_protocols': [], 'security_rules': []}
    
    # Hostname
    match = re.search(r'host-name\s+(\S+);', content, re.IGNORECASE)
    if match:
        data['hostname'] = match.group(1)
        
    # Interfaces and IPs
    # Match patterns like: <ifname> { unit <n> { ... address x.x.x.x/yy; ... } }
    unit_addr_matches = re.findall(r"([\w\-\/\.]+)\s*{\s*unit\s+(\d+)\s*{.*?address\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\s*;", content, re.DOTALL | re.IGNORECASE)
    for ifname, unit, ip, mask in unit_addr_matches:
        try:
            name = f"{ifname}.{unit}"
            data['interfaces'].append({'name': name, 'ip': ip, 'mask': mask})
        except Exception:
            continue

    # Also capture address entries that might appear without the explicit unit block (less common)
    direct_addr_matches = re.findall(r"([\w\-\/\.]+)\s+address\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\s*;", content, re.IGNORECASE)
    for ifname, ip, mask in direct_addr_matches:
        data['interfaces'].append({'name': ifname, 'ip': ip, 'mask': mask})

    # Add loopback interface if present (lo0 is common in Juniper)
    if re.search(r"\blo0\b", content, re.IGNORECASE) and not any('lo0' in iface['name'].lower() for iface in data['interfaces']):
        data['interfaces'].append({'name': 'lo0', 'ip': 'N/A', 'mask': 'N/A'})

    # Routing Protocols (OSPF/BGP)
    ospf_match = re.search(r'protocols\s*{(.*?ospf.*?)}', content, re.DOTALL | re.IGNORECASE)
    if ospf_match:
        areas = re.findall(r'area\s+(\d+)', ospf_match.group(1), re.IGNORECASE)
        data['routing_protocols'].append({'type': 'OSPF', 'areas': list(set(areas))})

    bgp_match = re.search(r'protocols\s*{(.*?bgp.*?)}', content, re.DOTALL | re.IGNORECASE)
    if bgp_match:
        asn_match = re.search(r'autonomous-system\s+(\d+);', content, re.IGNORECASE)
        asn = asn_match.group(1) if asn_match else 'Unknown'
        data['routing_protocols'].append({'type': 'BGP', 'asn': asn})

    # Security Rules (Firewall Filters)
    filter_matches = re.findall(r'firewall\s*{(.*?)}', content, re.DOTALL | re.IGNORECASE)
    if filter_matches:
        # store the raw filter blocks
        data['security_rules'].extend([blk.strip() for blk in filter_matches if blk.strip()])

    # Capture policy-statement or policy-options based policy lines (policy-statement, term, from, then)
    policy_lines = []
    for line in content.splitlines():
        if re.search(r'^\s*(policy-statement\b|policy-options\b|term\b|from\s+protocol\b|then\b)', line, re.IGNORECASE):
            policy_lines.append(line.strip())

    if policy_lines:
        data['security_rules'].extend(policy_lines)

    # Deduplicate while preserving order
    seen = set()
    unique_rules = []
    for r in data['security_rules']:
        if r not in seen:
            seen.add(r)
            unique_rules.append(r)
    data['security_rules'] = unique_rules
    
    return data

def parse_config(filename, content):
    device_type = get_device_type(filename, content)
    
    if device_type == 'Cisco':
        return parse_cisco(content)
    elif device_type == 'Huawei':
        return parse_huawei(content)
    elif device_type == 'Juniper':
        return parse_juniper(content)
    else:
        return {'hostname': 'Unknown', 'interfaces': [], 'routing_protocols': [], 'security_rules': []}

# --- Validation Logic ---

def validate_config(parsed_data):
    results = {}
    
    # 1. Loopback0 Check
    loopback_found = any('loopback0' in iface['name'].lower() or 'lo0' in iface['name'].lower() for iface in parsed_data['interfaces'])
    results['Loopback0_Check'] = {'status': 'PASS' if loopback_found else 'FAIL', 
                                  'message': 'Loopback0 interface found.' if loopback_found else 'Loopback0 interface missing.'}

    # 2. OSPF/BGP Consistency (Single-device check: extract areas/ASNs)
    ospf_areas = []
    bgp_asn = None
    
    for p in parsed_data['routing_protocols']:
        if p['type'] == 'OSPF':
            ospf_areas.extend(p.get('areas', []))
        elif p['type'] == 'BGP':
            bgp_asn = p.get('asn')
            
    # Store the extracted routing info for global validation
    parsed_data['ospf_areas'] = list(set(ospf_areas))
    parsed_data['bgp_asn'] = bgp_asn
    
    return results

def perform_global_validation():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, hostname, interfaces, validation_results, ospf_areas, bgp_asn, routing_protocol FROM devices")
    devices_data = cursor.fetchall()
    
    # Data structure to hold all subnets and routing info
    all_subnets = {} # {network_object: filename}
    all_ospf_areas = []
    all_bgp_asns = []
    
    # First pass: Collect all subnets and routing info
    for filename, hostname, interfaces_str, validation_results_str, ospf_areas_str, bgp_asn, routing_protocol in devices_data:
        # Re-evaluate validation results from string
        validation_results = json.loads(validation_results_str.replace("'", '"'))
        
        # Collect subnets
        interfaces = interfaces_str.split(', ')
        for iface in interfaces:
            match = re.search(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})\)', iface)
            if match:
                ip, mask = match.groups()
                try:
                    # Convert IP and mask to CIDR for comparison
                    network = IPv4Network(f"{ip}/{mask}", strict=False)
                    all_subnets[network] = filename
                except ValueError:
                    pass # Ignore invalid IP/mask combinations

        # Collect routing info
        if ospf_areas_str:
            all_ospf_areas.extend(json.loads(ospf_areas_str))
        if bgp_asn and bgp_asn != 'Unknown':
            all_bgp_asns.append(bgp_asn)

    # Global Validation Checks
    
    # 1. IP Subnet Overlap
    overlap_check = {'status': 'PASS', 'message': 'No IP subnet overlaps detected between devices.'}
    networks = list(all_subnets.keys())
    for i in range(len(networks)):
        for j in range(i + 1, len(networks)):
            if networks[i].overlaps(networks[j]):
                overlap_check['status'] = 'FAIL'
                overlap_check['message'] = f"Overlap detected between {networks[i]} (in {all_subnets[networks[i]]}) and {networks[j]} (in {all_subnets[networks[j]]})."
                break
        if overlap_check['status'] == 'FAIL':
            break
            
    # 2. OSPF/BGP Consistency
    routing_consistency_check = {'status': 'PASS', 'message': 'Routing areas/ASNs are consistent across all devices.'}

    # OSPF Area Consistency
    unique_ospf_areas = set(all_ospf_areas)
    if len(unique_ospf_areas) > 1:
        routing_consistency_check['status'] = 'FAIL'
        routing_consistency_check['message'] = f"Inconsistent OSPF areas detected: {', '.join(unique_ospf_areas)}. All OSPF devices should ideally be in the same area for a simple network."

    # BGP ASN Consistency
    unique_bgp_asns = set(all_bgp_asns)
    if len(unique_bgp_asns) > 1:
        routing_consistency_check['status'] = 'FAIL'
        routing_consistency_check['message'] = f"Inconsistent BGP ASNs detected: {', '.join(unique_bgp_asns)}. All BGP devices should ideally be in the same AS for an internal network."

    # Inter-protocol connectivity heuristic:
    # - If there are both OSPF and BGP devices, check for at least one device that runs both (redistributor)
    #   or at least one overlapping network between an OSPF device and a BGP device (indicating they are connected).
    ospf_devices = set()
    bgp_devices = set()
    device_networks = {}  # filename -> list of IPv4Network

    # Re-scan devices_data to build sets and per-device networks
    for row in devices_data:
        # row: filename, hostname, interfaces, validation_results, ospf_areas, bgp_asn, routing_protocol
        filename = row[0]
        interfaces_str = row[2] or ''
        ospf_areas_str = row[4]
        bgp_asn = row[5]
        routing_proto = row[6] if len(row) > 6 else None

        if ospf_areas_str:
            try:
                if json.loads(ospf_areas_str):
                    ospf_devices.add(filename)
            except Exception:
                pass
        if bgp_asn and bgp_asn != 'None':
            bgp_devices.add(filename)

        nets = []
        for iface in interfaces_str.split(', '):
            match = re.search(r'\(([^/)]+)/(\d{1,2}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)', iface)
            if match:
                ip = match.group(1)
                mask = match.group(2)
                try:
                    # ip_network accepts both prefixlen and dotted masks
                    net = IPv4Network(f"{ip}/{mask}", strict=False)
                    nets.append(net)
                except Exception:
                    continue
        device_networks[filename] = nets

    interprotocol_ok = False
    interprotocol_message = ''

    if ospf_devices and bgp_devices:
        # Check for redistributor (device in both sets)
        common = ospf_devices.intersection(bgp_devices)
        if common:
            interprotocol_ok = True
            interprotocol_message = f"Redistribution candidate(s) found: {', '.join(common)}."
        else:
            # Check for overlapping networks between any ospf device and any bgp device
            found_pair = None
            for o in ospf_devices:
                for b in bgp_devices:
                    for no in device_networks.get(o, []):
                        for nb in device_networks.get(b, []):
                            if no.overlaps(nb) or no == nb:
                                found_pair = (o, b, str(no), str(nb))
                                break
                        if found_pair:
                            break
                    if found_pair:
                        break
                if found_pair:
                    break

            if found_pair:
                interprotocol_ok = True
                interprotocol_message = f"Inter-protocol adjacency detected between OSPF device {found_pair[0]} and BGP device {found_pair[1]} (networks {found_pair[2]} / {found_pair[3]})."
            else:
                interprotocol_ok = False
                interprotocol_message = 'No adjacency or redistribution detected between OSPF and BGP devices; ensure proper redistribution or peering.'

        # If there are multiple routing protocol inconsistencies, preserve FAIL status
        if not interprotocol_ok and routing_consistency_check['status'] == 'PASS':
            routing_consistency_check['status'] = 'WARN'
            routing_consistency_check['message'] = interprotocol_message
        else:
            # Append info to existing message
            if interprotocol_message:
                routing_consistency_check['message'] += ' ' + interprotocol_message
    
    # 2. OSPF/BGP Consistency
    routing_consistency_check = {'status': 'PASS', 'message': 'Routing areas/ASNs are consistent across all devices.'}
    
    # OSPF Area Consistency
    unique_ospf_areas = set(all_ospf_areas)
    if len(unique_ospf_areas) > 1:
        routing_consistency_check['status'] = 'FAIL'
        routing_consistency_check['message'] = f"Inconsistent OSPF areas detected: {', '.join(unique_ospf_areas)}. All OSPF devices should ideally be in the same area for a simpler network design."
    
    # BGP ASN Consistency
    unique_bgp_asns = set(all_bgp_asns)
    if len(unique_bgp_asns) > 1:
        routing_consistency_check['status'] = 'FAIL'
        routing_consistency_check['message'] = f"Inconsistent BGP ASNs detected: {', '.join(unique_bgp_asns)}. All BGP devices should ideally be in the same AS for an internal network."
    
    # Inter-protocol connectivity heuristic:
    # - If there are both OSPF and BGP devices, check for at least one device that runs both protocols (redistributor)
    #   or at least one overlapping network between an OSPF device and a BGP device (indicating they are connected).
    ospf_devices = set()
    bgp_devices = set()
    device_networks = {}  # filename -> list of IPv4Network
    
    # Check for Inter-protocol connectivity
    interprotocol_ok = False
    interprotocol_message = ""
    
    for device in devices_data:
        filename, hostname, interfaces_str, validation_results_str, ospf_areas_str, bgp_asn, routing_protocol = device
        # Initialize sets
        ospf_networks = set()
        bgp_networks = set()
        
        # Process networks for OSPF devices
        if "ospf" in routing_protocol.lower():
            ospf_devices.add(hostname)
            # Reverting to the logic from pasted_content.txt for fidelity, even if it seems to misuse the data:
            if ospf_areas_str:
                ospf_networks.update(ospf_areas_str.split(","))
        
        # Process networks for BGP devices
        if "bgp" in routing_protocol.lower():
            bgp_devices.add(hostname)
            if bgp_asn:
                bgp_networks.update(bgp_asn.split(","))
        
        # Check if there is overlap between OSPF and BGP networks
        overlap = ospf_networks & bgp_networks
        if overlap:
            interprotocol_ok = True
            interprotocol_message = f"Found overlapping network(s) between OSPF and BGP: {', '.join(overlap)}."
    
    # If there are multiple routing protocol inconsistencies, preserve FAIL status
    if not interprotocol_ok and routing_consistency_check['status'] == 'PASS':
        if ospf_devices and bgp_devices:
            routing_consistency_check['status'] = 'WARN'
            routing_consistency_check['message'] = "Both OSPF and BGP devices are present, but no overlapping networks were found to ensure inter-protocol connectivity. This may indicate a missing redistribution point or misconfiguration."
    elif interprotocol_ok:
        # Append info to existing message if any inter-protocol inconsistency was found
        if routing_consistency_check['status'] == 'PASS':
            routing_consistency_check['message'] = interprotocol_message
        else:
            routing_consistency_check['message'] += ' ' + interprotocol_message

    # Second pass: Update database with final validation results
    for filename, hostname, interfaces_str, validation_results_str, ospf_areas_str, bgp_asn, routing_protocol in devices_data:
        validation_results = json.loads(validation_results_str.replace("'", '"'))
        
        # Add global checks to the device's validation results
        validation_results['IP_Subnet_Overlap_Check'] = overlap_check
        validation_results['Routing_Consistency_Check'] = routing_consistency_check
        
        # Update the database
        cursor.execute("UPDATE devices SET validation_results = ? WHERE filename = ?", 
                       (json.dumps(validation_results), filename))
        
    conn.commit()
    conn.close()


# --- Database Operations ---

def save_to_db(filename, hostname, device_type, parsed_data, validation_results):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    interfaces_str = ', '.join([f"{i['name']} ({i['ip']}/{i['mask']})" for i in parsed_data['interfaces']])
    # Deduplicate security rules while preserving order to avoid duplicates from parsing
    rules = parsed_data.get('security_rules', []) or []
    seen = set()
    unique_rules = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            unique_rules.append(r)
    security_rules_str = '\n'.join(unique_rules)
    routing_protocol_str = ', '.join([p['type'] for p in parsed_data['routing_protocols']])
    ospf_areas_str = json.dumps(parsed_data.get('ospf_areas', []))
    bgp_asn = parsed_data.get('bgp_asn') if parsed_data.get('bgp_asn') != 'Unknown' else None
    
    # Use a single INSERT OR REPLACE to handle re-uploads of the same file
    cursor.execute('''INSERT OR REPLACE INTO devices 
                      (filename, hostname, device_type, routing_protocol, interfaces, security_rules, validation_results, ospf_areas, bgp_asn) 
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (filename, hostname, device_type, routing_protocol_str, interfaces_str, security_rules_str, json.dumps(validation_results), ospf_areas_str, bgp_asn))
    conn.commit()
    conn.close()

# --- Main Parsing and Validation Flow ---

def process_file(filepath):
    filename = os.path.basename(filepath)
    with open(filepath, 'r') as file:
        content = file.read()
    
    device_type = get_device_type(filename, content)
    parsed_data = parse_config(filename, content)
    
    # Run single-device validation checks
    validation_results = validate_config(parsed_data)
    
    # Save the initial results and parsed data to the database
    save_to_db(filename, parsed_data['hostname'], device_type, parsed_data, validation_results)
    
    return parsed_data.get('ospf_areas', []), parsed_data.get('bgp_asn')

# --- Flask Routes ---

@app.route('/')
def index():
    return redirect(url_for('upload_file'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        files = request.files.getlist('file')
        
        # Clear the database before processing new files to ensure global validation is clean
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM devices")
        conn.commit()
        conn.close()
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                
                # Process the file (parsing and single-device validation)
                process_file(filepath)
        
        # Perform global validation after all files are processed
        perform_global_validation()

        # After processing and validating, redirect user to the dashboard
        return redirect(url_for('dashboard'))
        
    return render_template('upload.html')

@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect(DB_NAME)
    devices_df = pd.read_sql_query("SELECT * FROM devices", conn)
    conn.close()

    if devices_df.empty:
        return render_template('dashboard.html', devices=[], pie_chart_url=None, bar_chart_url=None, error="No device configurations found. Please upload files first.")

    # Convert validation results string back to dict for easier processing
    devices_df['validation_results'] = devices_df['validation_results'].apply(json.loads)
    
    # Prepare data for the table
    devices_list = devices_df.to_dict('records')

    # Combined chart: Routing Protocol Distribution (pie) and Interfaces per Device (bar) side-by-side
    routing_protocol_counts = devices_df['routing_protocol'].str.split(', ').explode().value_counts()
    routing_protocol_counts = routing_protocol_counts[routing_protocol_counts.index != '']

    # Count the number of interfaces by splitting the string
    devices_df['interface_count'] = devices_df['interfaces'].apply(lambda x: len(x.split(', ')) if x else 0)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Left: pie chart for routing protocol distribution
    if not routing_protocol_counts.empty:
        routing_protocol_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90, ax=ax1)
    else:
        ax1.text(0.5, 0.5, 'No Routing Protocols Found', ha='center', va='center')
    ax1.set_ylabel('')
    ax1.set_title('BGP vs OSPF')

    # Right: bar chart of interfaces per device
    devices_df.set_index('hostname')['interface_count'].plot(kind='bar', ax=ax2)
    ax2.set_title('Interfaces per Device')
    ax2.set_xlabel('Hostname')
    ax2.set_ylabel('Number of Interfaces')
    plt.setp(ax2.get_xticklabels(), rotation=45, ha='right')

    plt.tight_layout()
    img = io.BytesIO()
    plt.savefig(img, format='png', bbox_inches='tight')
    plt.close(fig)
    img.seek(0)
    combined_chart_url = "data:image/png;base64," + base64.b64encode(img.getvalue()).decode()

    # For backward compatibility, provide pie_chart_url and bar_chart_url but bar is embedded in combined image
    pie_chart_url = combined_chart_url
    bar_chart_url = None

    return render_template('dashboard.html', devices=devices_list, pie_chart_url=pie_chart_url, bar_chart_url=bar_chart_url)

@app.route('/export/<file_format>')
def export_data(file_format):
    conn = sqlite3.connect(DB_NAME)
    devices_df = pd.read_sql_query("SELECT * FROM devices", conn)
    conn.close()

    if devices_df.empty:
        return "No data to export.", 404

    # Clean up the DataFrame for export
    export_df = devices_df.drop(columns=['id', 'security_rules', 'ospf_areas', 'bgp_asn'])
    
    # Flatten validation results into separate columns for better export
    validation_cols = ['Loopback0_Check', 'IP_Subnet_Overlap_Check', 'Routing_Consistency_Check']
    
    # Convert validation_results string to dict and extract status
    def get_validation_status(results_str, check_name):
        try:
            results = json.loads(results_str)
            return results.get(check_name, {}).get('status', 'N/A')
        except:
            return 'ERROR'

    for col in validation_cols:
        export_df[col] = export_df['validation_results'].apply(lambda x: get_validation_status(x, col))
        
    export_df = export_df.drop(columns=['validation_results'])
    
    if file_format == 'csv':
        csv_buffer = io.StringIO()
        export_df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        return send_file(
            io.BytesIO(csv_buffer.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='network_audit_data.csv'
        )
    elif file_format == 'excel':
        excel_buffer = io.BytesIO()
        # Need to install openpyxl for excel export
        try:
            export_df.to_excel(excel_buffer, index=False, sheet_name='Network Audit')
        except ImportError:
            return "Error: 'openpyxl' library is required for Excel export. Please install it.", 500
            
        excel_buffer.seek(0)
        return send_file(
            excel_buffer,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='network_audit_data.xlsx'
        )
    else:
        return "Invalid file format.", 400

if __name__ == '__main__':
    # Ensure the uploads directory exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    init_db() # Ensure DB is initialized on run
    app.run(debug=True)
