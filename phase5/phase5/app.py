#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import subprocess
import os
import json
import datetime
import threading
import sys
import time
from pathlib import Path
import html # Added for HTML escaping

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ssl-tls-hacking-suite-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Base directories
BASE_DIR = '/opt/ssl-tls-suite'
TOOLS_DIR = f'{BASE_DIR}/phase4-tools' # Assuming Phase 4 tools are here
REPORTS_DIR = f'{BASE_DIR}/reports'
LOGS_DIR = f'{BASE_DIR}/logs'

# Ensure directories exist
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Define available tools and their parameters for the frontend
AVAILABLE_TOOLS = [
    # New Attack Tools from Phase 4
    {
        "id": "ssl_strip",
        "name": "SSL Stripping Attack",
        "description": "Intercepts and downgrades HTTPS to HTTP. Requires external ARP spoofing and iptables setup.",
        "parameters": [
            {"name": "target", "type": "text", "placeholder": "e.g., example.com (Target server hostname/IP)"},
            {"name": "port", "type": "number", "default": 8080, "placeholder": "Listen Port (default: 8080)"},
            {"name": "victim_ip", "type": "text", "placeholder": "e.g., 192.168.1.10 (Victim's IP for setup info)"},
            {"name": "attacker_ip", "type": "text", "placeholder": "e.g., 192.168.1.100 (Your IP for setup info)"},
            {"name": "test_mode", "type": "checkbox", "label": "Test Mode (Detection Only)"},
            {"name": "setup", "type": "checkbox", "label": "Show Setup Instructions"}
        ]
    },
    {
        "id": "ssl_downgrade",
        "name": "SSL/TLS Version Rollback",
        "description": "Attempts to force weaker SSL/TLS versions. Now handles automated MITM setup (requires sudo).",
        "parameters": [
            {"name": "target", "type": "text", "placeholder": "e.g., example.com (Target server hostname/IP)"},
            {"name": "port", "type": "number", "default": 443, "placeholder": "Target Port (default: 443)"},
            {"name": "proxy_port", "type": "number", "default": 8443, "placeholder": "Proxy Port (default: 8443)"},
            {"name": "victim_ip", "type": "text", "placeholder": "e.g., 192.168.1.10 (Victim's IP - REQUIRED for full attack)"},
            {"name": "iface", "type": "text", "placeholder": "e.g., eth0 (Network Interface - auto-detected if not specified)"},
            {"name": "gateway_ip", "type": "text", "placeholder": "e.g., 192.168.1.1 (Gateway IP - auto-detected if not specified)"},
            {"name": "test_mode", "type": "checkbox", "label": "Test Mode (Detection Only)"}
        ]
    },
    {
        "id": "cipher_downgrade",
        "name": "Cipher Downgrade Attack",
        "description": "Attempts to force weak cipher suites. Now handles automated MITM setup (requires sudo).",
        "parameters": [
            {"name": "target", "type": "text", "placeholder": "e.g., example.com (Target server hostname/IP)"},
            {"name": "port", "type": "number", "default": 443, "placeholder": "Target Port (default: 443)"},
            {"name": "proxy_port", "type": "number", "default": 8444, "placeholder": "Proxy Port (default: 8444)"},
            {"name": "victim_ip", "type": "text", "placeholder": "e.g., 192.168.1.10 (Victim's IP - REQUIRED for full attack)"},
            {"name": "iface", "type": "text", "placeholder": "e.g., eth0 (Network Interface - auto-detected if not specified)"},
            {"name": "gateway_ip", "type": "text", "placeholder": "e.g., 192.168.1.1 (Gateway IP - auto-detected if not specified)"},
            {"name": "test_mode", "type": "checkbox", "label": "Test Mode (Detection Only)"}
        ]
    },
    {
        "id": "heartbleed_exploit",
        "name": "Heartbleed Exploit",
        "description": "Exploits the Heartbleed vulnerability to extract memory.",
        "parameters": [
            {"name": "target", "type": "text", "placeholder": "e.g., example.com"},
            {"name": "port", "type": "number", "default": 443, "placeholder": "Target Port (default: 443)"},
            {"name": "test_mode", "type": "checkbox", "label": "Test Mode (Detection Only)"},
            {"name": "verbose", "type": "checkbox", "label": "Verbose Output"}
        ]
    },
    {
        "id": "ai_ssl_orchestrator",
        "name": "AI SSL Orchestrator",
        "description": "Uses AI to detect vulnerabilities and launch appropriate attacks.",
        "parameters": [
            {"name": "target", "type": "text", "placeholder": "e.g., example.com"},
            {"name": "port", "type": "number", "default": 443, "placeholder": "Target Port (default: 443)"},
            {"name": "auto_mode", "type": "checkbox", "label": "Auto Attack Mode"},
            {"name": "test_mode", "type": "checkbox", "label": "Test Mode (Detection Only)"}
        ]
    },
    {
        "id": "test_domain",
        "name": "Test Domain Security",
        "description": "Tests domain SSL/TLS security using a trained ML model.",
        "parameters": [
            {"name": "target", "type": "text", "placeholder": "e.g., example.com"}
        ]
    }
]


class SSLTLSTestSuite:
    def __init__(self):
        self.active_tests = {}
        self.test_results = {}
    
    def run_tool(self, tool_id, target, options=None):
        """Execute SSL/TLS testing and exploitation tools"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"{LOGS_DIR}/{tool_id}_{timestamp}.log"
        
        cmd = []
        python_executable = sys.executable # Use current Python interpreter

        if options is None:
            options = {}

        try:
            if tool_id == "ssl_strip":
                cmd = [python_executable, f"{TOOLS_DIR}/ssl_strip.py", target]
                if options.get('port'): cmd.extend(['-p', str(options['port'])])
                if options.get('test_mode'): cmd.append('--test')
                if options.get('setup'): cmd.append('--setup')
                if options.get('victim_ip'): cmd.extend(['--victim-ip', options['victim_ip']])
                if options.get('attacker_ip'): cmd.extend(['--attacker-ip', options['attacker_ip']])
            elif tool_id == "ssl_downgrade":
                cmd = [python_executable, f"{TOOLS_DIR}/ssl_downgrade.py", target]
                if options.get('port'): cmd.extend(['-p', str(options['port'])])
                if options.get('proxy_port'): cmd.extend(['--proxy-port', str(options['proxy_port'])])
                if options.get('victim_ip'): cmd.extend(['--victim-ip', options['victim_ip']])
                if options.get('iface'): cmd.extend(['--iface', options['iface']])
                if options.get('gateway_ip'): cmd.extend(['--gateway-ip', options['gateway_ip']])
                if options.get('test_mode'): cmd.append('--test')
            elif tool_id == "cipher_downgrade":
                cmd = [python_executable, f"{TOOLS_DIR}/cipher_downgrade.py", target]
                if options.get('port'): cmd.extend(['-p', str(options['port'])])
                if options.get('proxy_port'): cmd.extend(['--proxy-port', str(options['proxy_port'])])
                if options.get('victim_ip'): cmd.extend(['--victim-ip', options['victim_ip']])
                if options.get('iface'): cmd.extend(['--iface', options['iface']])
                if options.get('gateway_ip'): cmd.extend(['--gateway-ip', options['gateway_ip']])
                if options.get('test_mode'): cmd.append('--test')
            elif tool_id == "heartbleed_exploit":
                cmd = [python_executable, f"{TOOLS_DIR}/heartbleed_exploit.py", target]
                if options.get('port'): cmd.extend(['-p', str(options['port'])])
                if options.get('test_mode'): cmd.append('--test')
                if options.get('verbose'): cmd.append('--verbose')
            elif tool_id == "ai_ssl_orchestrator":
                cmd = [python_executable, f"{TOOLS_DIR}/ai_ssl_orchestrator.py", target]
                if options.get('port'): cmd.extend(['-p', str(options['port'])])
                if options.get('auto_mode'): cmd.append('--auto')
                if options.get('test_mode'): cmd.append('--test')
            elif tool_id == "test_domain":
                cmd = [python_executable, f"{TOOLS_DIR}/test_domain.py", target]
            else:
                return {"error": f"Unknown tool: {tool_id}"}
            
            print(f"Executing command: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                cwd=TOOLS_DIR
            )
            
            stdout_bytes, stderr_bytes = process.communicate(timeout=600)
            
            stdout = stdout_bytes.decode('utf-8', errors='replace')
            stderr = stderr_bytes.decode('utf-8', errors='replace')

            result = {
                "tool": tool_id,
                "target": target,
                "timestamp": timestamp,
                "exit_code": process.returncode,
                "stdout": html.escape(stdout),
                "stderr": html.escape(stderr),
                "log_file": log_file
            }
            
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"Tool: {tool_id}\n")
                f.write(f"Target: {target}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Exit Code: {process.returncode}\n")
                f.write(f"STDOUT:\n{stdout}\n")
                f.write(f"STDERR:\n{stderr}\n")
            
            print(f"--- Tool: {tool_id} ---")
            print(f"Target: {target}")
            print(f"Exit Code: {process.returncode}")
            print(f"STDOUT:\n{stdout}")
            print(f"STDERR:\n{stderr}")
            print(f"-----------------------\n")

            return result
            
        except subprocess.TimeoutExpired:
            process.kill()
            stdout_bytes, stderr_bytes = process.communicate()
            stdout = stdout_bytes.decode('utf-8', errors='replace')
            stderr = stderr_bytes.decode('utf-8', errors='replace')
            print(f"--- Tool: {tool_id} - TIMEOUT ---")
            print(f"STDOUT (on timeout):\n{stdout}")
            print(f"STDERR (on timeout):\n{stderr}")
            print(f"---------------------------\n")
            return {"error": f"Tool execution timed out. STDOUT: {html.escape(stdout)}, STDERR: {html.escape(stderr)}"}
        except FileNotFoundError:
            print(f"--- Tool: {tool_id} - SCRIPT NOT FOUND ---")
            print(f"Error: Tool script not found: {tool_id}. Please ensure it exists in {TOOLS_DIR}")
            print(f"-------------------------------------\n")
            return {"error": f"Tool script not found: {tool_id}. Please ensure it exists in {TOOLS_DIR}"}
        except Exception as e:
            print(f"--- Tool: {tool_id} - GENERAL EXCEPTION ---")
            print(f"Error: Execution failed for {tool_id}: {str(e)}")
            print(f"-------------------------------------\n")
            return {"error": f"Execution failed for {tool_id}: {html.escape(str(e))}"}

suite = SSLTLSTestSuite()

@app.route('/')
def index():
    """Renders the main web interface."""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Endpoint to initiate a security scan."""
    try:
        data = request.json
        target = data.get('target')
        tools = data.get('tools', [])
        options = data.get('options', {})

        if not target:
            return jsonify({"error": "Target is required"}), 400
        
        if not tools:
            return jsonify({"error": "At least one tool must be selected"}), 400

        results = {}
        for tool_id in tools:
            result = suite.run_tool(tool_id, target, options.get(tool_id, {}))
            results[tool_id] = result
            socketio.emit('scan_update', { 'tool': tool_id, 'target': target, 'result': result })
        
        report_id = generate_report(target, results)
        
        return jsonify({
            "status": "completed",
            "results": results,
            "report_id": report_id
        })
    except Exception as e:
        print(f"Unhandled error in /api/scan: {e}")
        return jsonify({"error": f"An unexpected server error occurred: {html.escape(str(e))}"}), 500

@app.route('/api/tools')
def get_tools():
    """Returns the list of available tools with their their parameters."""
    return jsonify(AVAILABLE_TOOLS)

@app.route('/api/reports')
def get_reports():
    """Returns a list of available reports."""
    reports_list = []
    for filename in os.listdir(REPORTS_DIR):
        if filename.endswith(".json"):
            report_id = filename.replace(".json", "")
            try:
                with open(os.path.join(REPORTS_DIR, filename), 'r') as f:
                    report_data = json.load(f)
                    reports_list.append({
                        "id": report_id,
                        "target": report_data.get('target', 'N/A'),
                        "timestamp": report_data.get('timestamp', 'N/A'),
                        "summary": report_data.get('summary', {})
                    })
            except json.JSONDecodeError:
                print(f"Error decoding JSON for report: {filename}")
                continue
    reports_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify(reports_list)

@app.route('/reports/<path:filename>')
def download_report(filename):
    """Serves generated reports."""
    return send_from_directory(REPORTS_DIR, filename)

def generate_report(target, results):
    """Generates a comprehensive security audit report."""
    report_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    summary = generate_summary(results)
    recommendations = generate_recommendations(results)

    report = {
        "id": report_id,
        "target": target,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "results": results,
        "recommendations": recommendations
    }
    
    json_report_path = os.path.join(REPORTS_DIR, f"{report_id}.json")
    with open(json_report_path, 'w') as f:
        json.dump(report, f, indent=2)

    generate_html_report(report)
    
    return report_id

def generate_summary(results):
    """Generates a summary of the scan results."""
    summary = {
        "total_tests": len(results),
        "vulnerabilities_found": 0,
        "critical_issues": 0,
        "warnings": 0,
        "successful_tests": 0,
        "failed_tests": 0,
        "error_tests": 0
    }
    for tool, result in results.items():
        if result.get('error'):
            summary['error_tests'] += 1
            continue

        if result.get('exit_code') == 0:
            summary['successful_tests'] += 1
            output = result.get('stdout', '').upper()
            if 'VULNERABLE' in output or 'CRITICAL' in output:
                summary['vulnerabilities_found'] += 1
                summary['critical_issues'] += 1
            elif 'WARNING' in output or 'WEAK' in output or 'INSECURE' in output:
                summary['vulnerabilities_found'] += 1
                summary['warnings'] += 1
        else:
            summary['failed_tests'] += 1
            output = result.get('stdout', '').upper() + result.get('stderr', '').upper()
            if 'VULNERABLE' in output or 'CRITICAL' in output:
                summary['vulnerabilities_found'] += 1
                summary['critical_issues'] += 1
            elif 'ERROR' in output or 'FAILED' in output:
                summary['error_tests'] += 1
            elif 'WARNING' in output or 'WEAK' in output or 'INSECURE' in output:
                summary['vulnerabilities_found'] += 1
                summary['warnings'] += 1
                
    return summary

def generate_recommendations(results):
    """Generates security recommendations based on scan results."""
    recommendations = set()
    for tool, result in results.items():
        raw_output = (result.get('stdout', '') + result.get('stderr', '')).upper()
        
        if 'VULNERABLE' in raw_output or 'CRITICAL' in raw_output or 'EXPLOITED' in raw_output:
            if 'HEARTBLEED' in tool.upper() or 'HEARTBLEED' in raw_output:
                recommendations.add("Patch OpenSSL to a version not vulnerable to Heartbleed (e.g., 1.0.1g or later).")
            if 'SSL STRIPPING' in tool.upper() or 'STRIPPING' in raw_output:
                recommendations.add("Implement HSTS (HTTP Strict Transport Security) to prevent SSL stripping attacks.")
            if 'DOWNGRA' in raw_output or 'WEAK CIPHERS' in raw_output:
                recommendations.add("Disable weak cipher suites (e.g., RC4, DES, 3DES) and enforce strong, modern cipher suites (e.g., AES-256 with GCM).")
                recommendations.add("Ensure only TLS 1.2 and TLS 1.3 are enabled. Disable all older SSL/TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1).")
            if 'EXPIRED' in raw_output or 'SELF-SIGNED' in raw_output or 'INVALID CERTIFICATE' in raw_output:
                recommendations.add("Replace expired, self-signed, or invalid SSL/TLS certificates with valid, trusted certificates from a reputable CA.")
            if 'AI_SSL_ORCHESTRATOR' in tool.upper() and ('VULNERABLE' in raw_output or 'ATTACK RECOMMENDED' in raw_output):
                recommendations.add("Review the AI Orchestrator's specific recommendations for detected vulnerabilities and execute manual validation.")
        
        if "OLD PROTOCOL" in raw_output or "TLSV1" in raw_output or "SSLV2" in raw_output or "SSLV3" in raw_output:
            recommendations.add("Ensure only TLS 1.2 and TLS 1.3 are enabled. Disable all older SSL/TLS protocols.")
        
    return sorted(list(recommendations))

def generate_html_report(report):
    """Generates an HTML report from the scan results."""
    html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSL/TLS Security Audit Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        h1 {{ border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        h2 {{ border-bottom: 1px solid #e1e8ed; padding-bottom: 5px; margin-top: 30px; }}
        .section {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 8px; background-color: #f9f9f9; }}
        .summary-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .summary-table th, .summary-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        .summary-table th {{ background-color: #e9ecef; }}
        .result-item {{ margin-bottom: 15px; padding: 10px; border-left: 5px solid; }}
        .result-item.success {{ border-color: #28a745; background-color: #e6ffe6; }}
        .result-item.warning {{ border-color: #ffc107; background-color: #fffacd; }}
        .result-item.critical {{ border-color: #dc3545; background-color: #ffe6e6; }}
        .result-item.error {{ border-color: #6c757d; background-color: #f0f0f0; }}
        pre {{ background-color: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }}
        .recommendations ul {{ list-style-type: disc; margin-left: 20px; }}
        .recommendations li {{ margin-bottom: 5px; }}
        .footer {{ margin-top: 50px; font-size: 0.9em; text-align: center; color: #777; }}
    </style>
</head>
<body>
    <h1>SSL/TLS Security Audit Report</h1>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Scan Date:</strong> {timestamp}</p>

    <h2>1. Executive Summary</h2>
    <div class="section">
        <table class="summary-table">
            <tr>
                <th>Total Tests Run</th>
                <td>{total_tests}</td>
            </tr>
            <tr>
                <th>Successful Tests</th>
                <td style="color: #28a745;">{successful_tests}</td>
            </tr>
            <tr>
                <th>Failed Tests</th>
                <td style="color: #dc3545;">{failed_tests}</td>
            </tr>
            <tr>
                <th>Tests with Errors</th>
                <td style="color: #6c757d;">{error_tests}</td>
            </tr>
            <tr>
                <th>Vulnerabilities Detected</th>
                <td style="color: #dc3545; font-weight: bold;">{vulnerabilities_found}</td>
            </tr>
            <tr>
                <th>Critical Issues</th>
                <td style="color: #dc3545;">{critical_issues}</td>
            </tr>
            <tr>
                <th>Warnings</th>
                <td style="color: #ffc107;">{warnings}</td>
            </tr>
        </table>
    </div>

    <h2>2. Detailed Scan Results</h2>
    <div class="section">
        {tool_results}
    </div>

    <h2>3. Recommendations</h2>
    <div class="section recommendations">
        <ul>
            {recommendations}
        </ul>
    </div>

    <div class="footer">
        <p>Report generated by SSL/TLS Hacking Suite - Phase 5 Integration.</p>
        <p>&copy; {current_year}</p>
    </div>
</body>
</html>
    """

    tool_results_html = ""
    for tool_id, result in report['results'].items():
        tool_name_display = tool_id.replace('_', ' ').title()
        
        status_class = "result-item error"
        status_icon = "?"

        if result.get('error'):
            status_class = "result-item error"
            status_icon = "X"
        elif result.get('exit_code') == 0:
            status_class = "result-item success"
            status_icon = "✓"
            output_upper = result.get('stdout', '').upper()
            if 'VULNERABLE' in output_upper or 'CRITICAL' in output_upper or 'EXPLOITED' in output_upper:
                status_class = "result-item critical" 
                status_icon = "!"
            elif 'WARNING' in output_upper or 'WEAK' in output_upper or 'INSECURE' in output_upper:
                status_class = "result-item warning"
                status_icon = "!"
        else: # Non-zero exit code
            status_class = "result-item error"
            status_icon = "X"
            output_upper = result.get('stdout', '').upper() + result.get('stderr', '').upper()
            if 'VULNERABLE' in output_upper or 'CRITICAL' in output_upper or 'EXPLOITED' in output_upper:
                status_class = "result-item critical" 
                status_icon = "!"
            elif 'WARNING' in output_upper or 'WEAK' in output_upper or 'INSECURE' in output_upper:
                status_class = "result-item warning"
                status_icon = "!"

        escaped_stdout = result.get('stdout', 'No output.')
        escaped_stderr = result.get('stderr', '')
        escaped_error = result.get('error', '')

        error_html_block = ""
        if result.get('error'):
            error_html_block = '<p class="error-output"><strong>Execution Error:</strong> {}</p>'.format(escaped_error)

        stderr_html_block = ""
        if result.get('stderr'):
            stderr_html_block = '<h4>Standard Error:</h4><pre>{}</pre>'.format(escaped_stderr)

        tool_results_html += """
        <div class="{status_class}">
            <h3>{status_icon} {tool_name_display}</h3>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Status:</strong> {status_text}</p>
            <p><strong>Log File:</strong> <a href="{log_file}" target="_blank">{log_file_basename}</a></p>
            <h4>Standard Output:</h4>
            <pre>{stdout}</pre>
            {stderr_html_block}
            {error_html_block}
        </div>
        """.format(
            status_class=status_class,
            status_icon=status_icon,
            tool_name_display=tool_name_display,
            target=result.get('target', 'N/A'),
            status_text=('Error' if result.get('error') else ('Completed Successfully' if result.get('exit_code') == 0 else 'Failed')),
            log_file=result.get('log_file', 'N/A'),
            log_file_basename=Path(result.get('log_file', 'N/A')).name,
            stdout=escaped_stdout,
            stderr_html_block=stderr_html_block,
            error_html_block=error_html_block
        )
    
    recommendations_html = ""
    for rec in report['recommendations']:
        recommendations_html += f"<li>{rec}</li>"
    
    html_content = html_template.format(
        target=report['target'],
        timestamp=report['timestamp'],
        total_tests=report['summary']['total_tests'],
        successful_tests=report['summary']['successful_tests'],
        failed_tests=report['summary']['failed_tests'],
        error_tests=report['summary']['error_tests'],
        vulnerabilities_found=report['summary']['vulnerabilities_found'],
        critical_issues=report['summary']['critical_issues'],
        warnings=report['summary']['warnings'],
        tool_results=tool_results_html,
        recommendations=recommendations_html,
        current_year=datetime.datetime.now().year
    )
    
    html_report_path = os.path.join(REPORTS_DIR, f"{report['id']}.html")
    with open(html_report_path, 'w') as f:
        f.write(html_content)

# Run the Flask app with Socket.IO
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
