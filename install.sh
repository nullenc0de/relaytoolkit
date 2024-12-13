#!/bin/bash

RED='\033[1;31m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'
NC='\033[0m'

echo -e "${BLUE}Installing NTLM Toolkit dependencies...${NC}"

# Install required packages
pip install -r requirements.txt

# Install core tools if not already installed via pipx
command -v netexec >/dev/null 2>&1 || pipx install git+https://github.com/Pennyw0rth/NetExec.git
command -v impacket-ntlmrelayx >/dev/null 2>&1 || pipx install git+https://github.com/fortra/impacket.git
command -v responder >/dev/null 2>&1 || pipx install git+https://github.com/lgandx/Responder.git
command -v mitm6 >/dev/null 2>&1 || pipx install mitm6
command -v certipy >/dev/null 2>&1 || pipx install git+https://github.com/ly4k/Certipy.git

# Create requirements.txt
cat << EOF > requirements.txt
termcolor>=2.3.0
netifaces>=0.11.0
EOF

echo -e "${GREEN}Installation complete!${NC}"
