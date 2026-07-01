#!/usr/bin/env python3
"""
ai_ssl_orchestrator.py - AI-Powered SSL/TLS Attack Orchestrator

This script uses the trained ML model from Phase 3 to automatically
detect SSL/TLS vulnerabilities and launch appropriate attacks.
"""

import pickle
import subprocess
import pandas as pd
import argparse
import time
import os
import sys
import re
from datetime import datetime

class AISSLOrchestrator:
    def __init__(self):
        self.model = None
        self.features_list = None
        self.vulnerability_map = {
            'ssl_downgrade': ['sslv2_supported', 'sslv3_supported', 'tlsv1_0_supported'],
            'cipher_downgrade': ['weak_ciphers', 'rc4_ciphers', 'des_ciphers'],
            'ssl_strip': ['secure_renegotiation', 'tlsv1_2_supported'],
        }
        
    def load_ai_model(self):
        """Load the trained SSL security model"""
        try:
            print("[INFO] Loading AI security model...")
            # Assuming model files are in the same directory as the script
            # Adjust path if model files are in a common location like /opt/ssl-tls-suite/models/
            model_path = os.path.join(os.path.dirname(__file__), 'ssl_security_model.pkl')
            features_path = os.path.join(os.path.dirname(__file__), 'model_features.pkl')

            if not os.path.exists(model_path) or not os.path.exists(features_path):
                # Fallback to common location if not found in script's directory
                common_model_dir = '/opt/ssl-tls-suite/models'
                model_path = os.path.join(common_model_dir, 'ssl_security_model.pkl')
                features_path = os.path.join(common_model_dir, 'model_features.pkl')
                if not os.path.exists(model_path) or not os.path.exists(features_path):
                    print(f"[ERROR] AI model files not found. Looked in {os.path.dirname(__file__)} and {common_model_dir}. Ensure 'ssl_security_model.pkl' and 'model_features.pkl' are available.")
                    return False

            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            with open(features_path, 'rb') as f:
                self.features_list = pickle.load(f)
            print("[SUCCESS] AI model loaded successfully")
            return True
        except FileNotFoundError:
            print("[ERROR] AI model files not found. Ensure 'ssl_security_model.pkl' and 'model_features.pkl' are in the script's directory or /opt/ssl-tls-suite/models/.")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to load AI model: {e}")
            return False
    
    def run_sslscan(self, domain):
        """Run sslscan on the target domain"""
        print(f"[INFO] Scanning {domain} with sslscan...")
        try:
            result = subprocess.run(
                ['sslscan', '--no-colour', domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=60
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] sslscan failed with exit code {e.returncode}: {e.stderr}")
            return None
        except subprocess.TimeoutExpired:
            print("[ERROR] sslscan timeout")
            return None
        except FileNotFoundError:
            print("[ERROR] sslscan not found. Please ensure it is installed and in your system's PATH.")
            return None
    
    def extract_vulnerability_features(self, scan_output):
        """Extract vulnerability features from sslscan output"""
        features = {
            'sslv2_supported': False,
            'sslv3_supported': False,
            'tlsv1_0_supported': False,
            'tlsv1_1_supported': False,
            'tlsv1_2_supported': False,
            'tlsv1_3_supported': False,
            'heartbleed_vulnerable': False,
            'poodle_vulnerable': False,
            'secure_renegotiation': True,
            'weak_ciphers': False,
            'rc4_ciphers': False,
            'des_ciphers': False,
            'cert_expiry_days': 90, # Default value
            'cert_bits': 2048 # Default value
        }
        
        if not scan_output:
            return features
        
        # Protocol detection
        if re.search(r'SSLv2\s+enabled', scan_output, re.IGNORECASE):
            features['sslv2_supported'] = True
        
        if re.search(r'SSLv3\s+enabled', scan_output, re.IGNORECASE):
            features['sslv3_supported'] = True
        
        if re.search(r'TLSv1\.0\s+enabled', scan_output, re.IGNORECASE):
            features['tlsv1_0_supported'] = True
        
        if re.search(r'TLSv1\.1\s+enabled', scan_output, re.IGNORECASE):
            features['tlsv1_1_supported'] = True
        
        if re.search(r'TLSv1\.2\s+enabled', scan_output, re.IGNORECASE):
            features['tlsv1_2_supported'] = True
        
        if re.search(r'TLSv1\.3\s+enabled', scan_output, re.IGNORECASE):
            features['tlsv1_3_supported'] = True
        
        # Vulnerability detection
        if re.search(r'heartbleed.*vulnerable', scan_output, re.IGNORECASE):
            features['heartbleed_vulnerable'] = True
        
        if re.search(r'poodle.*vulnerable', scan_output, re.IGNORECASE):
            features['poodle_vulnerable'] = True
        
        if re.search(r'secure renegotiation.*not supported', scan_output, re.IGNORECASE):
            features['secure_renegotiation'] = False
        
        # Cipher analysis
        if re.search(r'weak\s+cipher|64\s+bits', scan_output, re.IGNORECASE):
            features['weak_ciphers'] = True
        
        if re.search(r'RC4', scan_output, re.IGNORECASE):
            features['rc4_ciphers'] = True
        
        if re.search(r'DES|3DES', scan_output, re.IGNORECASE):
            features['des_ciphers'] = True
        
        # Certificate analysis
        expiry_match = re.search(r'Not valid after:\s+(.+)', scan_output)
        if expiry_match:
            try:
                # Attempt to parse common date formats
                expiry_date_str = expiry_match.group(1).strip()
                parsed = False
                for fmt in ('%b %d %H:%M:%S %Y GMT', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
                    try:
                        expiry = datetime.strptime(expiry_date_str, fmt)
                        days_remaining = (expiry - datetime.now()).days
                        features['cert_expiry_days'] = max(0, days_remaining)
                        parsed = True
                        break
                    except ValueError:
                        continue
                if not parsed:
                    print(f"[WARNING] Could not parse certificate expiry date: {expiry_date_str}")
            except Exception as e:
                print(f"[WARNING] Error processing certificate expiry: {e}")
        
        bits_match = re.search(r'RSA (\d+) bits|ECC (\d+) bits', scan_output)
        if bits_match:
            features['cert_bits'] = int(bits_match.group(1) or bits_match.group(2))
        
        return features
    
    def analyze_vulnerabilities(self, features):
        """Use AI model to analyze vulnerabilities and recommend attacks"""
        if not self.model or not self.features_list:
            print("[ERROR] AI model not loaded. Cannot analyze vulnerabilities.")
            return []
        
        # Prepare features for prediction
        features_df = pd.DataFrame([features])
        
        # Ensure all expected features are present, fill missing with 0 or False
        for feature_name in self.features_list:
            if feature_name not in features_df.columns:
                features_df[feature_name] = False # Use False for boolean features, 0 for numeric

        # Align columns with the model's expected feature order
        features_df = features_df[self.features_list]
        
        # Get AI prediction
        is_secure = self.model.predict(features_df)[0]
        confidence = self.model.predict_proba(features_df)[0].max()
        
        print(f"\n[AI ANALYSIS] Security Status: {'SECURE' if is_secure else 'VULNERABLE'}")
        print(f"[AI ANALYSIS] Confidence: {confidence:.2f}")
        
        if is_secure:
            print("[AI RECOMMENDATION] Target appears SECURE - limited attack surface.")
            return []
        
        # Determine specific vulnerabilities and recommend attacks
        recommended_attacks = []
        
        # Check for SSL/TLS version vulnerabilities
        if features['sslv2_supported'] or features['sslv3_supported'] or features['tlsv1_0_supported']:
            recommended_attacks.append({
                'attack': 'ssl_downgrade',
                'reason': 'Old SSL/TLS versions supported (SSLv2, SSLv3, TLSv1.0).',
                'severity': 'HIGH',
                'script': 'ssl_downgrade.py'
            })
        
        # Check for weak cipher vulnerabilities
        if features['weak_ciphers'] or features['rc4_ciphers'] or features['des_ciphers']:
            recommended_attacks.append({
                'attack': 'cipher_downgrade',
                'reason': 'Weak cipher suites supported (RC4, DES, 3DES).',
                'severity': 'HIGH',
                'script': 'cipher_downgrade.py'
            })
        
        # Check for SSL stripping vulnerabilities (inferred from insecure renegotiation or older highest TLS version)
        if not features['secure_renegotiation'] or not features['tlsv1_2_supported']: # Assuming TLS 1.2 is baseline for good config
            recommended_attacks.append({
                'attack': 'ssl_strip',
                'reason': 'Insecure renegotiation or older TLS version might allow SSL stripping (requires external setup).',
                'severity': 'MEDIUM',
                'script': 'ssl_strip.py'
            })
        
        # Check for critical vulnerabilities directly detected by sslscan
        if features['heartbleed_vulnerable']:
            recommended_attacks.append({
                'attack': 'heartbleed_exploit',
                'reason': 'Heartbleed vulnerability detected (CVE-2014-0160).',
                'severity': 'CRITICAL',
                'script': 'heartbleed_exploit.py'
            })
        
        if features['poodle_vulnerable']:
            recommended_attacks.append({
                'attack': 'poodle_exploit', # POODLE is often part of SSLv3 downgrade, but an explicit exploit check is good.
                'reason': 'POODLE vulnerability detected (CVE-2014-3566).',
                'severity': 'HIGH',
                'script': 'ssl_downgrade.py' # Often handled by SSL downgrade tools
            })
        
        # Certificate-related recommendations (not directly leading to attack scripts, but important)
        if features['cert_bits'] < 2048:
            print("[AI RECOMMENDATION] WARNING: Certificate key strength is weak (less than 2048 bits).")
        if features['cert_expiry_days'] < 30:
            print("[AI RECOMMENDATION] WARNING: Certificate is expiring soon (less than 30 days).")

        return recommended_attacks
    
    def display_recommendations(self, attacks):
        """Display attack recommendations"""
        if not attacks:
            print("\n[AI RECOMMENDATION] No specific attacks recommended.")
            return
        
        print(f"\n{'='*60}")
        print("AI-POWERED ATTACK RECOMMENDATIONS")
        print(f"{'='*60}")
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        attacks.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        for i, attack in enumerate(attacks, 1):
            print(f"\n{i}. {attack['attack'].upper()} ATTACK")
            print(f"   Severity: {attack['severity']}")
            print(f"   Reason: {attack['reason']}")
            print(f"   Script: {attack['script']}")
    
    def execute_attack(self, attack_info, target, port=443, test_mode=False):
        """Execute the recommended attack script"""
        script_name = attack_info['script']
        
        # Construct the full path to the script, assuming they are in the same directory
        # This assumes the app.py runs tools from TOOLS_DIR
        script_path = os.path.join(os.path.dirname(__file__), script_name)

        if not os.path.exists(script_path):
            print(f"[ERROR] Attack script {script_path} not found.")
            return False
        
        print(f"\n[ATTACK] Executing {attack_info['attack']} against {target}")
        print(f"[ATTACK] Reason: {attack_info['reason']}")
        
        try:
            cmd = [sys.executable, script_path, target, '-p', str(port)]
            
            # Pass test_mode to the individual attack scripts
            if test_mode:
                cmd.append('--test')
            
            # Special handling for ssl_strip if in test mode (show setup instructions)
            if attack_info['attack'] == 'ssl_strip' and test_mode:
                cmd.append('--setup') 

            print(f"[INFO] Running command: {' '.join(cmd)}")
            
            # Execute attack script
            # Use PIPE for stdout/stderr to capture all output
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=300) # 5-minute timeout for individual attacks

            print(f"[ATTACK_OUTPUT_STDOUT]\n{stdout}")
            if stderr:
                print(f"[ATTACK_OUTPUT_STDERR]\n{stderr}")

            if process.returncode == 0:
                print(f"[SUCCESS] Attack {attack_info['attack']} completed successfully.")
                return True
            else:
                print(f"[ERROR] Attack {attack_info['attack']} failed with exit code {process.returncode}.")
                return False
                
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            print(f"[ERROR] Attack {attack_info['attack']} timed out.")
            print(f"[ATTACK_OUTPUT_STDOUT_TIMEOUT]\n{stdout}")
            if stderr:
                print(f"[ATTACK_OUTPUT_STDERR_TIMEOUT]\n{stderr}")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to execute attack {attack_info['attack']}: {e}")
            return False
    
    def check_attack_scripts(self):
        """Check if all required attack scripts are present"""
        required_scripts = [
            'ssl_downgrade.py',
            'cipher_downgrade.py', 
            'ssl_strip.py',
            'heartbleed_exploit.py'
        ]
        
        missing_scripts = []
        script_dir = os.path.dirname(__file__) # Get directory of current script
        for script in required_scripts:
            if not os.path.exists(os.path.join(script_dir, script)):
                missing_scripts.append(script)
        
        if missing_scripts:
            print("[WARNING] The following attack scripts are missing from the tools directory:")
            for script in missing_scripts:
                print(f"  - {script}")
            print("[INFO] Please ensure these scripts are in the same directory as ai_ssl_orchestrator.py or in the configured TOOLS_DIR.")
            return False
        
        return True

def run_orchestrator(target, port=443, auto_mode=False, test_mode=False, verbose=False):
    """
    Main function to orchestrate SSL/TLS vulnerability scanning and attacks.
    Designed to be called by app.py.
    """
    print(f"\n{'='*70}")
    print("AI-POWERED SSL/TLS ATTACK ORCHESTRATOR")
    print(f"{'='*70}")
    print(f"Target: {target}:{port}")
    print(f"Mode: {'Auto' if auto_mode else 'Manual'} / {'Test' if test_mode else 'Exploit'}")
    print(f"{'='*70}\n")
    
    orchestrator = AISSLOrchestrator()
    
    # Check if attack scripts are available
    if not orchestrator.check_attack_scripts():
        print("[ERROR] Missing attack scripts. Orchestrator cannot proceed.")
        return False
    
    # Load AI model
    if not orchestrator.load_ai_model():
        print("[ERROR] Failed to load AI security model. Orchestrator cannot proceed.")
        return False
    
    executed_attacks = []
    
    # Main processing logic
    # In this context, we run the scan once and make recommendations/execute.
    # The app.py then captures the stdout and handles reporting.
    
    # Run SSL scan
    scan_output = orchestrator.run_sslscan(target)
    if not scan_output:
        print("[ERROR] Failed to scan target with sslscan. Orchestrator cannot proceed.")
        return False
    
    # Extract vulnerability features
    features = orchestrator.extract_vulnerability_features(scan_output)
    
    # Print verbose output if requested
    if verbose:
        print("\n[VERBOSE] Extracted features:")
        for feature, value in features.items():
            print(f"  - {feature}: {value}")
    
    # Analyze vulnerabilities and get attack recommendations
    recommended_attacks = orchestrator.analyze_vulnerabilities(features)
    
    # Display attack recommendations
    orchestrator.display_recommendations(recommended_attacks)
    
    if not recommended_attacks:
        print("\n[INFO] No significant vulnerabilities detected that can be exploited. Target appears secure.")
        return True # Indicate success even if no attacks are needed
    
    # Handle attack execution based on mode
    if auto_mode:
        print("\n[AUTO MODE] Executing recommended attacks...")
        for attack in recommended_attacks:
            if orchestrator.execute_attack(attack, target, port, test_mode):
                executed_attacks.append(attack)
        print("\n[COMPLETE] Automated attack execution finished.")
    else:
        # In non-auto mode, just display recommendations.
        # The app.py frontend will allow the user to trigger individual tools if needed.
        print("\n[INFO] Manual mode: Recommendations displayed. No automated attacks executed.")
    
    # Final message for app.py to capture
    print("\n[ORCHESTRATOR_COMPLETE] AI orchestration assessment finished.")
    # The actual report generation is handled by app.py based on captured output.
    
    return True # Indicate success

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='AI-Powered SSL/TLS Attack Orchestrator')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('-p', '--port', type=int, default=443, help='Target port (default: 443)')
    parser.add_argument('-a', '--auto', action='store_true', dest='auto_mode', help='Automatically execute recommended attacks')
    parser.add_argument('-t', '--test', action='store_true', dest='test_mode', help='Test mode (do not execute actual attacks)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    
    try:
        success = run_orchestrator(
            target=args.target,
            port=args.port,
            auto_mode=args.auto_mode, # Use the dest name
            test_mode=args.test_mode, # Use the dest name
            verbose=args.verbose
        )
        if not success:
            sys.exit(1) # Exit with error code if orchestration failed
    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")
        sys.exit(1)
