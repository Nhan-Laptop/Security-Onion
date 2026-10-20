#!/usr/bin/env bash
# ==============================================================================
# Script: endpoint_simulation.sh
# Purpose: Simulate Suspicious Endpoint Behaviors on Linux (T1059.004, T1082)
# Target: Linux Endpoint (Ubuntu/Debian) with Elastic Agent
# ==============================================================================

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${CYAN}==========================================================${NC}"
echo -e "${YELLOW} [!] BAT DAU MO PHONG HANH VI LINUX ENDPOINT (SCENARIO 4)${NC}"
echo -e " MITRE ATT&CK: T1059.004 (Unix Shell), T1082 (Discovery)"
echo -e " Thoi gian: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}==========================================================${NC}"

# 1. Benign Execution Marker
echo -e "\n${YELLOW}[*] Buoc 1: Chay tien trinh voi Marker kiem thu...${NC}"
bash -c "echo 'SO-LAB-LINUX-ENDPOINT-MARKER-2026'"

# 2. System and Account Discovery (T1082, T1087)
echo -e "${YELLOW}[*] Buoc 2: Mo phong do quet thong tin he thong va user...${NC}"
whoami
uname -a
id
cat /etc/passwd | cut -d: -f1,3,7 | head -n 10

# 3. Base64 Encoded Command Execution (T1059.004)
echo -e "${YELLOW}[*] Buoc 3: Mo phong thuc thi lenh ma hoa Base64...${NC}"
CMD="echo 'SO-LAB-LINUX-ENCODED-EXECUTION'"
B64_CMD=$(echo -n "$CMD" | base64)
echo "    Payload Base64: $B64_CMD"
echo "$B64_CMD" | base64 -d | bash

# 4. Outbound network call
echo -e "${YELLOW}[*] Buoc 4: Mo phong ket noi mang tu tien trinh...${NC}"
curl -s -m 3 "http://192.168.182.10/endpoint-linux-test" >/dev/null 2>&1 || true

echo -e "\n${CYAN}==========================================================${NC}"
echo -e "${GREEN} [V] HOAN TAT MO PHONG LINUX ENDPOINT!${NC}"
echo -e " Bay gio hay vao Security Onion SOC -> Hunt:"
echo -e " - Query: process.command_line:*SO-LAB-LINUX-* OR message:*SO-LAB-LINUX-*"
echo -e "${CYAN}==========================================================${NC}"
