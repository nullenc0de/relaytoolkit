# NTLM Relay Toolkit

A modern Python-based NTLM relay toolkit that combines multiple attack vectors for network penetration testing. This toolkit automates various relay attacks, coercion techniques, and credential capture methods.

## Overview

The NTLM Relay Toolkit automates several attack vectors:
- LLMNR/NBT-NS/mDNS poisoning
- SMB Relay
- LDAP(S) Relay
- HTTP(S) Relay
- WebDAV Coercion
- ADCS ESC8 Attacks
- Shadow Credentials
- IPv6 DNS Poisoning
- Resource-Based Constrained Delegation

## Quick Start

```bash
# Install
sudo python3 install.py

# Basic usage
sudo ./relay.py --auto -d domain.local

# Advanced usage with specific attacks
sudo ./relay.py -i eth0 --adcs --shadow-credentials --webdav -d domain.local
```

## Prerequisites

- Linux-based OS (tested on Kali Linux)
- Python 3.8+
- Root privileges
- Git
- Python3-pip

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ntlm-relay-toolkit.git
cd ntlm-relay-toolkit
```

2. Run the installer:
```bash
sudo python3 install.py
```

The installer will:
- Create necessary directories
- Install Python dependencies
- Set up required tools
- Configure file permissions
- Verify installations

## Directory Structure

```
ntlm-relay-toolkit/
├── relay.py                  # Main script
├── install.py               # Installation script
├── web/                     # Web server root
│   ├── payloads/           # PowerShell payloads
│   └── templates/          # Attack templates
├── logs/                    # Log files
├── certs/                   # ADCS certificates
└── tools/                   # External tools
```

## Usage

### Basic Command Options

```bash
usage: relay.py [-h] [-i INTERFACE] [-t TARGET_FILE] [-d DOMAIN] [-c COMMAND] [-p PORT]
                [--no-mitm6] [--no-http] [--no-smb] [--adcs] [--shadow-credentials]
                [--webdav] [--delegate-access] [--auto] [--analyze]

arguments:
  -h, --help            show help message
  -i INTERFACE          network interface to use
  -t TARGET_FILE        file containing relay targets
  -d DOMAIN            domain for mitm6 attack
  -c COMMAND           command to execute on successful relay
  -p PORT              HTTP server port (default: 8080)

attack vectors:
  --no-mitm6           disable mitm6 DNS poisoning
  --no-http            disable HTTP relay
  --no-smb             disable SMB relay
  --adcs               enable ADCS ESC8 attack
  --shadow-credentials enable shadow credentials attack
  --webdav             enable WebDAV coercion
  --delegate-access    configure delegation access

modes:
  --auto               enable automated attack sequence
  --analyze            run Responder in analyze mode
```

### Attack Scenarios

1. Automated Attack:
```bash
sudo ./relay.py --auto -d domain.local
```

2. ADCS ESC8 Attack:
```bash
sudo ./relay.py --adcs -d domain.local -t targets.txt
```

3. Shadow Credentials Attack:
```bash
sudo ./relay.py --shadow-credentials -d domain.local -t targets.txt
```

4. WebDAV Coercion:
```bash
sudo ./relay.py --webdav -d domain.local -t targets.txt
```

5. Analysis Mode:
```bash
sudo ./relay.py --analyze -i eth0
```

## Attack Vectors Explained

### 1. LLMNR/NBT-NS/mDNS Poisoning
- Exploits name resolution fallback
- Captures NetNTLMv2 hashes
- Uses Responder for poisoning

### 2. SMB Relay
- Relays captured SMB authentication
- Requires targets with SMB signing disabled
- Can execute commands on successful relay

### 3. LDAP(S) Relay
- Relays authentication to domain controllers
- Can modify AD objects
- Supports delegation attacks

### 4. ADCS ESC8
- Exploits certificate templates
- Supports domain escalation
- Certificate request attacks

### 5. Shadow Credentials
- Modifies msDS-KeyCredentialLink
- Alternative to RBCD attacks
- Requires AD CS infrastructure

### 6. WebDAV Coercion
- Forces WebDAV authentication
- Works with SMB disabled targets
- Supports cross-protocol attacks

## Logging and Output

Logs are stored in the `logs/` directory:
- `relay.log`: Main relay operations
- `responder.log`: Responder capture logs
- `ntlmrelay.log`: NTLM relay events
- `mitm6.log`: IPv6 poisoning logs

## Defense Detection

This tool may trigger:
- Windows Event ID 4624 (Successful Logon)
- Windows Event ID 4625 (Failed Logon)
- Windows Event ID 4768 (Kerberos TGT Request)
- Windows Event ID 4769 (Kerberos Service Ticket Request)
- Network IDS alerts for LLMNR/NBT-NS traffic
- Unusual IPv6 DNS traffic

## Mitigations

Organizations should:
- Disable LLMNR/NBT-NS/mDNS
- Enable SMB Signing
- Implement LDAP Signing
- Configure ADCS security
- Monitor for abnormal authentication
- Use network segmentation
- Disable WebDAV when unnecessary
- Monitor AD object modifications

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## References

- [Responder](https://github.com/lgandx/Responder)
- [Impacket](https://github.com/fortra/impacket)
- [mitm6](https://github.com/dirkjanm/mitm6)
- [NetExec](https://github.com/Pennyw0rth/NetExec)

## Disclaimer

This tool is for educational and authorized testing only. Use responsibly and only against systems you own or have explicit permission to test.

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Dirk-jan Mollema
- Laurent Gaffié
- Benjamin Delpy
- And all other security researchers who developed the original tools and techniques
