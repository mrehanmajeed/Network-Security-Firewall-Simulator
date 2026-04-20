"""
Network Security Scanner & Firewall Visualizer — Assignment 3
Backend: Python Flask + python-nmap
"""
from flask import Flask, render_template, request, jsonify
import nmap
import socket
import json
import re
from datetime import datetime

app = Flask(__name__)

# ── Firewall rules store (in-memory) ─────────────────────────────────────────
firewall_rules = []
rule_id_counter = 1

# ── Common service names for quick display ────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

def validate_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9\-\.]+$'
    return bool(re.match(pattern, ip.strip()))

def get_service_name(port):
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'tcp_connect')
    port_range = data.get('port_range', '1-1024')

    if not target or not validate_ip(target):
        return jsonify({'error': 'Invalid target IP or hostname.'}), 400

    try:
        nm = nmap.PortScanner()
        results = []

        # Build nmap arguments based on scan type
        nmap_args = {
            'tcp_connect': f'-sT -p {port_range} --open -T4',
            'tcp_syn':     f'-sS -p {port_range} --open -T4',
            'udp':         f'-sU -p {port_range} --open -T4',
            'full':        f'-sV -p {port_range} -T4',
            'ping':        f'-sn',
        }.get(scan_type, f'-sT -p {port_range} --open -T4')

        nm.scan(hosts=target, arguments=nmap_args)

        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        host_info = {}

        for host in nm.all_hosts():
            host_info = {
                'ip': host,
                'hostname': nm[host].hostname() or host,
                'state': nm[host].state(),
            }
            # OS detection if available
            if 'osclass' in nm[host]:
                host_info['os'] = nm[host]['osclass'][0].get('osfamily','Unknown') if nm[host]['osclass'] else 'Unknown'

            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    port_data = nm[host][proto][port]
                    service = port_data.get('name', '') or get_service_name(port)
                    version = port_data.get('product', '') + ' ' + port_data.get('version', '')
                    result = {
                        'ip': host,
                        'port': port,
                        'protocol': proto.upper(),
                        'state': port_data['state'],
                        'service': service,
                        'version': version.strip() or '-',
                        'firewall_action': evaluate_firewall(host, port, proto)
                    }
                    results.append(result)

        return jsonify({
            'success': True,
            'target': target,
            'scan_type': scan_type,
            'scan_time': scan_time,
            'host_info': host_info,
            'results': results,
            'total_open': len([r for r in results if r['state'] == 'open'])
        })

    except nmap.PortScannerError as e:
        return jsonify({'error': f'Nmap error: {str(e)}. Make sure nmap is installed.'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/socket', methods=['POST'])
def socket_scan():
    """Fallback scanner using raw sockets — no nmap required."""
    data = request.json
    target = data.get('target', '').strip()
    port_range = data.get('port_range', '1-1024')

    if not target or not validate_ip(target):
        return jsonify({'error': 'Invalid target.'}), 400

    try:
        start, end = map(int, port_range.split('-'))
        start = max(1, min(start, 65535))
        end   = min(65535, max(end, start))
        results = []
        scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return jsonify({'error': 'Cannot resolve hostname.'}), 400

        for port in range(start, min(end + 1, start + 500)):   # cap at 500 ports
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result_code = sock.connect_ex((ip, port))
            sock.close()
            if result_code == 0:
                svc = get_service_name(port)
                results.append({
                    'ip': ip,
                    'port': port,
                    'protocol': 'TCP',
                    'state': 'open',
                    'service': svc,
                    'version': '-',
                    'firewall_action': evaluate_firewall(ip, port, 'tcp')
                })

        return jsonify({
            'success': True,
            'target': target,
            'scan_type': 'socket_scan',
            'scan_time': scan_time,
            'host_info': {'ip': ip, 'hostname': target, 'state': 'up'},
            'results': results,
            'total_open': len(results)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── Firewall API ──────────────────────────────────────────────────────────────

@app.route('/api/firewall/rules', methods=['GET'])
def get_rules():
    return jsonify(firewall_rules)

@app.route('/api/firewall/rules', methods=['POST'])
def add_rule():
    global rule_id_counter
    data = request.json
    rule = {
        'id':       rule_id_counter,
        'action':   data.get('action', 'DENY').upper(),
        'protocol': data.get('protocol', 'TCP').upper(),
        'src_ip':   data.get('src_ip', '*').strip() or '*',
        'dst_port': str(data.get('dst_port', '*')).strip() or '*',
        'priority': int(data.get('priority', rule_id_counter)),
        'comment':  data.get('comment', ''),
        'created':  datetime.now().strftime('%H:%M:%S')
    }
    firewall_rules.append(rule)
    firewall_rules.sort(key=lambda r: r['priority'])
    rule_id_counter += 1
    return jsonify({'success': True, 'rule': rule})

@app.route('/api/firewall/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    global firewall_rules
    firewall_rules = [r for r in firewall_rules if r['id'] != rule_id]
    return jsonify({'success': True})

@app.route('/api/firewall/simulate', methods=['POST'])
def simulate():
    data = request.json
    src_ip    = data.get('src_ip', '').strip()
    dst_port  = str(data.get('dst_port', '')).strip()
    protocol  = data.get('protocol', 'TCP').upper()

    if not src_ip or not dst_port:
        return jsonify({'error': 'Please provide source IP and destination port.'}), 400

    trace = []
    final_action = 'ALLOW'  # default if no rules match

    for rule in firewall_rules:
        ip_match   = (rule['src_ip'] == '*' or rule['src_ip'] == src_ip)
        port_match = (rule['dst_port'] == '*' or rule['dst_port'] == dst_port)
        proto_match= (rule['protocol'] == '*' or rule['protocol'] == protocol)
        matched    = ip_match and port_match and proto_match
        trace.append({
            'rule_id': rule['id'],
            'action': rule['action'],
            'matched': matched,
            'reason': f"IP={'✓' if ip_match else '✗'}  Port={'✓' if port_match else '✗'}  Proto={'✓' if proto_match else '✗'}"
        })
        if matched:
            final_action = rule['action']
            break

    return jsonify({
        'src_ip': src_ip,
        'dst_port': dst_port,
        'protocol': protocol,
        'final_action': final_action,
        'trace': trace
    })

# ── Helper: evaluate packet against current firewall rules ────────────────────
def evaluate_firewall(ip, port, proto):
    for rule in firewall_rules:
        ip_match   = (rule['src_ip'] == '*' or rule['src_ip'] == ip)
        port_match = (rule['dst_port'] == '*' or rule['dst_port'] == str(port))
        proto_match= (rule['protocol'] == '*' or rule['protocol'] == proto.upper())
        if ip_match and port_match and proto_match:
            return rule['action']
    return 'ALLOW'

if __name__ == '__main__':
    print("=" * 55)
    print("  Network Security Scanner & Firewall Visualizer")
    print("  Assignment 3 — Information Security")
    print("=" * 55)
    print("  Open http://127.0.0.1:5000 in your browser")
    print("  Press Ctrl+C to stop")
    print("=" * 55)
    app.run(debug=True, host='0.0.0.0', port=5000)
