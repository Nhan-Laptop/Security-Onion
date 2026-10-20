# Scenario 2 — Authentication Attack Simulation (SSH Brute Force) trên VMware

Tài liệu hướng dẫn chi tiết kịch bản mô phỏng tấn công xác thực (**SSH Brute Force / Password Guessing**), thiết lập cấu hình mạng trên môi trường ảo hóa **VMware** (VMware Workstation / ESXi / Player) cho 3 máy: **Security Onion**, **Metasploitable 2**, và **Attacker (Linux / Kali)**. Đồng thời hướng dẫn quy trình điều tra tương quan đa tầng (**Network Telemetry + Host Telemetry**) trên Security Onion SOC.

- **Kỹ thuật MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) (Sub-technique: [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001/)).
- **Câu hỏi cốt lõi của SOC Analyst:**
  1. *IP nào đang cố gắng dò thông tin đăng nhập từ mạng?*
  2. *Dịch vụ và cổng mục tiêu là gì (SSH - Port 22)?*
  3. *Tài khoản (username) nào đang bị nhắm tới?*
  4. *Kết quả đăng nhập là thành công hay thất bại?*
  5. *Network Sensor thấy gì và Endpoint log thấy gì khác biệt?*

---

## 1. Kiến trúc luồng giám sát & Giá trị Two-Layer Visibility

Trong tấn công xác thực vào giao thức SSH, toàn bộ payload (bao gồm username và mật khẩu gửi lên) đều bị mã hóa bằng TLS/SSH handshake. Một mình **Network Sensor (Zeek / Suricata)** sẽ **không thể đọc nội dung gói tin** để biết attacker đang thử mật khẩu gì hay đăng nhập thành công hay không.

Sự kết hợp giữa **Network Telemetry** và **Host Telemetry** (Defense-in-Depth) là điểm mấu chốt để phân tích toàn diện cuộc tấn công:

```text
Attacker Linux (192.168.100.50)
       │
       │ SSH Failed Logins (Port 22)
       ▼
Metasploitable 2 Target (192.168.100.188)
 ├── Host View: /var/log/auth.log (hoặc Syslog forward sang SO)
 └── Network View: Traffic trên VMnet2 ──► VMware Promiscuous vSwitch ──► Sniffing NIC ──► Zeek / Suricata
                                                                                │
                                                                                ▼
                                                                         Security Onion SOC
                                                                (Correlate Network + Host Telemetry)
```

### Bảng đối chiếu năng lực giám sát

| Tầng giám sát | Thành phần | Dữ liệu thu thập | Ý nghĩa trong điều tra |
|---|---|---|---|
| **Network Visibility** | Zeek (`zeek.conn`, `zeek.ssh`), Suricata | IP nguồn/đích, Port 22, số lượng session, thời gian, handshake, banner | Biết có IP lạ kết nối dồn dập vào SSH server, nhưng **không biết** password đúng/sai hay user nào vì payload đã bị mã hóa. |
| **Host Visibility** | `/var/log/auth.log` (Syslog / Elastic Agent) | Username (`labuser`), tiến trình `sshd`, kết quả `Failed password`, PAM status, IP nguồn | Biết chính xác **ai** (username) bị dò, **kết quả** thất bại, số lần thử và PID tiến trình `sshd`. |
| **PCAP Evidence** | Suricata Full Packet Capture | Gói tin TCP/IP nguyên bản | Bằng chứng điều tra pháp lý số, phân tích quá trình bắt tay SSH Key Exchange (KEX) và chứng minh payload bị mã hóa. |

---

## 2. Sơ đồ phân bổ Mạng & Interface trên VMware

Trong môi trường VMware, ta phân chia 2 mạng ảo độc lập thông qua **Virtual Network Editor**:
- **`VMnet8` (NAT) hoặc `VMnet0` (Bridged):** Dải mạng quản trị (Management). Nối card quản trị của Security Onion để truy cập giao diện Web SOC từ máy thật, cập nhật rule và đồng bộ hệ thống.
- **`VMnet2` (Custom / Host-Only / Isolated Lab):** Dải mạng cô lập `192.168.100.0/24`. Là nơi chứa card Sniffing của Security Onion, card mạng của Metasploitable 2 và card mạng của Attacker Linux.

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         VMware Hypervisor (Workstation / ESXi)                   │
│                                                                                  │
│   VMnet8 (NAT / Bridged): 192.168.182.0/24 (Mạng quản trị & Internet)            │
│   VMnet2 (Custom / Host-Only): 192.168.100.0/24 (Mạng Isolated Lab)               │
└───────────────┬──────────────────────────────────────────┬───────────────────────┘
                │                                          │
          [VMnet8 / NAT]                             [VMnet2 / Promisc]
                │                                          │
┌───────────────▼──────────────────────────────────────────▼───────────────────────┐
│                           Security Onion (VM Dual NIC)                           │
│   • Management NIC : ens33 (Có IP: 192.168.182.10/24, GW: 192.168.182.2)         │
│   • Sniffing NIC   : ens34 (KHÔNG IP, Promiscuous Mode, hứng traffic VMnet2)     │
└─────────────────────────────────────▲────────────────────────────────────────────┘
                                      │
                                      │ VMware vSwitch Promiscuous Traffic
                                      │
        ┌─────────────────────────────┴─────────────────────────────┐
        │                                                           │
┌───────▼─────────────────────────────┐             ┌───────────────▼───────────────┐
│        Metasploitable 2             │             │        Attacker Linux         │
│  Target SSH Server (Ubuntu 8.04)    │             │       (Kali / Ubuntu)         │
│  Adapter: VMnet2 (e1000 / pcnet32)  │ ◄────────── │  Adapter: VMnet2              │
│  IP : 192.168.100.188/24            │   SSH:22    │  IP : 192.168.100.50/24       │
└─────────────────────────────────────┘             └───────────────────────────────┘
```

### Bảng thông số phân bổ tài nguyên Lab

| Máy ảo | Vai trò trong Lab | Network Adapter VMware | Interface trong OS | Địa chỉ IP đề xuất | Ghi chú cấu hình |
|---|---|---|---|---|---|
| **Security Onion** | Sensor NIDS & SIEM SOC | **Adapter 1:** VMnet8 (NAT)<br>**Adapter 2:** VMnet2 (Custom) | `ens33` (Mgmt)<br>`ens34` (Sniff) | `192.168.182.10/24`<br>**Không có IP (Unnumbered)** | Dual NIC. `ens34` bật Promiscuous để hứng toàn bộ traffic trên VMnet2. Host máy thật truy cập SOC qua `192.168.182.1`. |
| **Metasploitable 2** | Mục tiêu (SSH Server) | **Adapter 1:** VMnet2 (Custom) | `eth0` | `192.168.100.188/24` | Adapter type: `e1000` hoặc mặc định. Port 22 mở sẵn. |
| **Attacker Linux** | Máy tấn công (Kali/Ubuntu) | **Adapter 1:** VMnet2 (Custom) | `eth0` / `ens33` | `192.168.100.50/24` | Chạy Hydra / Python / Script mô phỏng dò mật khẩu. |

---

## 3. Hướng dẫn thiết lập Interface và Phần cứng trên VMware

### 3.1. Thiết lập Virtual Switch (VMnet2) và Chế độ Promiscuous trên VMware

Để card Sniffing của Security Onion có thể nhận được toàn bộ các gói tin Unicast trao đổi giữa Metasploitable 2 và Attacker Linux, switch ảo của VMware cần cho phép chế độ **Promiscuous Mode**:

#### A. Đối với VMware Workstation / Player trên Windows / Linux Host:
1. Mở **VMware Workstation** ➔ Menu **Edit** ➔ **Virtual Network Editor**.
2. Nhấp chọn **Change Settings** (yêu cầu quyền Admin).
3. Chọn mạng **VMnet2** (hoặc tạo mới dạng Host-only):
   - Đặt Subnet IP: `192.168.100.0`, Subnet mask: `255.255.255.0`.
   - **Bỏ tick** `Use local DHCP service to distribute IP address to VMs` (để tránh xung đột IP, các máy gán IP tĩnh).
4. **Quyền Promiscuous trên Linux Host (nếu dùng Host Linux):**
   ```bash
   # Cấp quyền đọc/ghi cho vmnet để hỗ trợ promiscuous sniffing
   sudo chmod a+rw /dev/vmnet*
   ```
   *(Trên Windows Host, VMware Workstation tự động hỗ trợ promiscuous khi card mạng trong máy khách bật chế độ này)*.

#### B. Đối với VMware ESXi (vSphere):
1. Vào **Networking** ➔ Chọn **Virtual Switches** (hoặc Port Groups) liên kết với mạng Lab.
2. Nhấp **Edit settings** ➔ Mục **Security**:
   - **Promiscuous mode:** Chọn **Accept**.
   - **MAC address changes:** Chọn **Accept**.
   - **Forged transmits:** Chọn **Accept**.

---

### 3.2. Máy 1: Security Onion (Cấu hình Dual NIC)

Security Onion **bắt buộc** phải có 2 card mạng độc lập:

1. **Gán Card mạng trong Cài đặt Máy ảo VMware (VM Settings):**
   - **Network Adapter 1:** Chọn `NAT` (hoặc `VMnet8`).
   - **Network Adapter 2:** Chọn `Custom (VMnet2)`.

2. **Xác định tên card mạng trong Security Onion:**
   ```bash
   ip -br link
   # Ví dụ: ens33 (Management) và ens34 (Sniffing)
   ```

3. **Cấu hình Card 1 — Management (`ens33`):**
   ```bash
   # Thiết lập IP tĩnh cho card quản lý (thuộc dải VMnet8: 192.168.182.0/24)
   sudo nmcli con mod "ens33" ipv4.addresses "192.168.182.10/24"
   sudo nmcli con mod "ens33" ipv4.gateway "192.168.182.2"
   sudo nmcli con mod "ens33" ipv4.dns "8.8.8.8 192.168.182.2"
   sudo nmcli con mod "ens33" ipv4.method manual
   sudo nmcli con up "ens33"

   # Kiểm tra lại IP
   ip -br addr show ens33
   ```

4. **Cấu hình Card 2 — Sniffing (`ens34`):**
   - **NGUYÊN TẮC:** Card này **TUYỆT ĐỐI KHÔNG CÓ IP**. Nếu gán IP vào card sniffing, máy sensor có thể bị quét, bị tấn công trực tiếp hoặc làm đảo lộn routing table.
   ```bash
   # Xóa toàn bộ IP nếu lỡ gán
   sudo ip addr flush dev ens34

   # Bật card và kích hoạt chế độ Promiscuous (hứng mọi packet trên VMnet2)
   sudo ip link set ens34 up
   sudo ip link set ens34 promisc on

   # Kiểm tra: Thấy trạng thái UP, cờ PROMISC và KHÔNG CÓ IP
   ip -br addr show ens34
   ```

5. **Cấu hình Host Firewall bằng `so-firewall` (Security Onion 3.3):**
   > [!IMPORTANT]
   > Trên **Security Onion 3.3**, công cụ quản lý tường lửa tích hợp là **`so-firewall`** (thay thế cho lệnh `so-allow` của các phiên bản cũ).
   > Mặc định, Security Onion chặn hoàn toàn cổng HTTPS (port 443). Nếu máy Host chưa được cấp phép, Nmap quét sẽ báo `443/tcp filtered` và trình duyệt sẽ bị connection timeout.

   Chạy lệnh sau trên terminal của Security Onion:
   ```bash
   # Mở quyền truy cập Web SOC (port 443) cho máy Host Analyst (hoặc toàn dải VMnet8 192.168.182.0/24)
   sudo so-firewall includehost analyst 192.168.182.0/24 --apply
   ```

---

### 3.3. Máy 2: Metasploitable 2 (Mục tiêu - SSH Target)

Metasploitable 2 là máy chủ Linux dựng sẵn để thực hành pentest và phân tích log.

1. **Gán Card mạng trong Cài đặt Máy ảo (VM Settings):**
   - **Network Adapter:** Chọn `Custom: Specific virtual network` ➔ Chọn **`VMnet2`**.

2. **Cấu hình IP tĩnh trong Metasploitable 2:**
   - Đăng nhập vào Metasploitable 2 với tài khoản: `msfadmin` / `msfadmin`.
   - Chỉnh sửa cấu hình mạng:
     ```bash
     sudo nano /etc/network/interfaces
     ```
   - Điền thông tin IP tĩnh cho `eth0`:
     ```text
     auto lo
     iface lo inet loopback

     auto eth0
     iface eth0 inet static
         address 192.168.100.188
         netmask 255.255.255.0
         gateway 192.168.100.1
     ```
   - Khởi động lại card mạng:
     ```bash
     sudo /etc/init.d/networking restart
     ifconfig eth0
     # Đảm bảo eth0 đã nhận IP: 192.168.100.188
     ```

3. **Kiểm tra dịch vụ SSH và tạo User thử nghiệm:**
   - Metasploitable 2 đã bật sẵn SSH service (OpenSSH). Kiểm tra:
     ```bash
     sudo netstat -tlpn | grep :22
     # Phải thấy 0.0.0.0:22 LISTEN
     ```
   - Tạo tài khoản người dùng `labuser` để phục vụ kịch bản dò mật khẩu:
     ```bash
     sudo useradd -m -s /bin/bash labuser
     echo "labuser:Lab@123456" | sudo chpasswd
     ```

4. **Giải pháp thu thập Log từ Metasploitable 2 (Host Visibility):**
   > [!NOTE]
   > Metasploitable 2 chạy hệ điều hành Ubuntu 8.04 LTS (32-bit, Linux kernel 2.6.24) nên không thể cài đặt Elastic Agent 8.x hiện đại (yêu cầu 64-bit và systemd).  
   > Để có cái nhìn toàn diện trong bài lab, ta áp dụng 1 trong 2 cách sau:
   - **Cách 1 (Chuẩn Lab):** Mở cửa sổ terminal trên Metasploitable 2 theo dõi trực tiếp log xác thực thời gian thực bằng lệnh:
     ```bash
     sudo tail -f /var/log/auth.log
     ```
     Sau đó đối chiếu timestamp và IP với dữ liệu `zeek.conn` trên giao diện Security Onion SOC Hunt.
   - **Cách 2 (Đẩy Syslog về Security Onion):** Cấu hình `syslogd` trên Metasploitable 2 đẩy log `/var/log/auth.log` về Logstash / Syslog receiver của Security Onion:
     ```bash
     # Thêm dòng đẩy syslog vào cuối file /etc/syslog.conf
     auth,authpriv.* @192.168.100.10
     sudo /etc/init.d/sysklogd restart
     ```

---

### 3.4. Máy 3: Attacker Linux (Kali / Ubuntu)

1. **Gán Card mạng trong Cài đặt Máy ảo (VM Settings):**
   - **Network Adapter:** Chọn `Custom: Specific virtual network` ➔ Chọn **`VMnet2`**.

2. **Cấu hình IP trong Attacker Linux:**
   - Đặt IP tĩnh cùng dải `192.168.100.0/24` (ví dụ `192.168.100.50`):
     ```bash
     sudo nmcli con add type ethernet con-name "lab-net" ifname eth0 ip4 192.168.100.50/24
     sudo nmcli con up "lab-net"
     ```
   - Hoặc gán nhanh bằng lệnh `ip`:
     ```bash
     sudo ip addr add 192.168.100.50/24 dev eth0
     sudo ip link set eth0 up
     ```

3. **Kiểm tra thông mạng tới máy mục tiêu:**
   ```bash
   ping -c 3 192.168.100.188
   nc -zv 192.168.100.188 22
   # Kết quả: Connection to 192.168.100.188 22 port [tcp/ssh] succeeded!
   ```

---

## 4. Checklist kiểm tra sẵn sàng trước khi chạy kịch bản (Pre-flight Checklist)

| STT | Bước kiểm tra | Máy thực hiện | Lệnh kiểm tra | Kết quả mong đợi |
|:---:|---|---|---|---|
| 1 | **Management SOC** | Máy thật / Host | Mở trình duyệt: `https://192.168.182.10` (hoặc `nmap 192.168.182.10 -p 443 -Pn`) | Đăng nhập SOC bình thường (Port 443 mở; nếu bị `filtered`/timeout thì cấu hình `sudo so-firewall includehost analyst ...`) |
| 2 | **Sniffing Promisc** | Security Onion | `ip -br link show ens34` | Thấy trạng thái `UP`, cờ `PROMISC`, **không có IP** |
| 3 | **SSH Target Port** | Metasploitable 2 | `sudo netstat -tlpn \| grep :22` | Port 22 ở trạng thái `LISTEN` |
| 4 | **Target User** | Metasploitable 2 | `id labuser` | Tài khoản `labuser` tồn tại |
| 5 | **Attacker Connectivity** | Attacker Linux | `ping -c 2 192.168.100.188` | Phản hồi ICMP `0% packet loss` |
| 6 | **Sniffer Traffic Check** | Security Onion | `sudo timeout 15 tcpdump -nn -i ens34 'port 22'` | Khi Attacker kết nối tới port 22, tcpdump phải hiện gói tin |

---

## 5. Các bước thực thi kịch bản (Execution Steps)

### Bước 1 — Lắng nghe packet trên Security Onion (Pre-attack Capture)

Trên máy Security Onion, mở terminal và kiểm tra xem card sniffing có nhìn thấy traffic port 22 hay không:
```bash
sudo timeout 60 tcpdump -nn -i ens34 'host 192.168.100.188 and port 22'
```
*(Thay `ens34` bằng đúng tên card sniffing của máy bạn. Đảm bảo thấy dòng `listening on ens34` trước khi sang Bước 2)*.

---

### Bước 2 — Thực hiện tấn công mô phỏng từ Attacker Linux

Từ máy Attacker Linux (`192.168.100.50`), bạn có thể chọn 1 trong 3 phương pháp kiểm thử:

#### Phương pháp 1: Sử dụng Script mô phỏng tự động (`auth_attack_simulation.sh`)
Script được chuẩn bị sẵn, tự động thử 6 mật khẩu thông dụng, ghi log timestamp và xử lý lỗi:
```bash
chmod +x src/scenarios/s2/auth_attack_simulation.sh

# Chạy với tham số Target IP và Target User
./src/scenarios/s2/auth_attack_simulation.sh 192.168.100.188 labuser
```
Kết quả các lần thử sẽ được in ra màn hình và lưu vào file `scenario2-auth-attack.log`.

#### Phương pháp 2: Sử dụng Hydra (Công cụ pentest tiêu chuẩn)
Chạy Hydra với wordlist ngắn và giới hạn 2 luồng (`-t 2`):
```bash
# Tạo danh sách mật khẩu thử nghiệm
cat << 'EOF' > passlist.txt
123456
admin123
password
toor2024
letmein
wrongpass1
EOF

# Chạy Hydra brute force SSH
hydra -l labuser -P passlist.txt ssh://192.168.100.188 -t 2 -V -o scenario2-hydra-results.txt
```

#### Phương pháp 3: Vòng lặp SSH / Bash thủ công
```bash
TARGET_IP="192.168.100.188"
USER="labuser"
PASSWORDS=("123456" "admin123" "password" "toor2024" "letmein" "wrongpass1")

for pass in "${PASSWORDS[@]}"; do
    echo "[*] Thu dang nhap user '$USER' voi password '$pass'..."
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o NumberOfPasswordPrompts=1 "$USER@$TARGET_IP" 2>&1
    sleep 1
done | tee scenario2-auth-attack.log
```

---

### Bước 3 — Điều tra & Tương quan trên Security Onion SOC (Threat Hunting)

#### 3.1. Phân tích Network Telemetry (Zeek Logs)
1. Đăng nhập giao diện Web SOC: `https://192.168.182.10` ➔ Vào mục **Hunt**.
2. Chọn mốc thời gian bao phủ đợt kiểm thử (ví dụ: `Last 15 minutes`).
3. Chạy truy vấn tìm các kết nối SSH tới máy mục tiêu:
   ```text
   event.dataset:"zeek.conn" AND destination.port:22 AND destination.ip:"192.168.100.188"
   ```
4. Kiểm tra metadata chi tiết của giao thức SSH:
   ```text
   event.dataset:"zeek.ssh" AND destination.ip:"192.168.100.188"
   ```
5. **Quan sát & Nhận định:**
   - Thấy nhiều phiên kết nối liên tiếp từ `source.ip: 192.168.100.50` tới `destination.ip: 192.168.100.188` trên port 22 trong thời gian rất ngắn.
   - Trường `zeek.ssh.client` hiển thị banner client (ví dụ `SSH-2.0-OpenSSH_...`).
   - **Hạn chế của Network View:** Network metadata ghi nhận lưu lượng SSH đột biến, nhưng **không hiển thị** được username nào đang bị dò và **không biết** mật khẩu đúng hay sai do payload đã bị mã hóa.

#### 3.2. Phân tích Host Telemetry (Log Xác thực)
1. **Trên máy Metasploitable 2:**
   - Mở file log xác thực:
     ```bash
     sudo cat /var/log/auth.log | grep sshd
     ```
   - **Kết quả thực tế ghi nhận:**
     ```text
     sshd[...]: Failed password for labuser from 192.168.100.50 port ... ssh2
     sshd[...]: Failed password for labuser from 192.168.100.50 port ... ssh2
     ```
2. **Nếu đã cấu hình Syslog đẩy về Security Onion:**
   - Trong giao diện **Hunt**, truy vấn:
     ```text
     message:"Failed password" AND source.ip:"192.168.100.50"
     ```
3. **Giá trị Tương quan (Correlation):**
   - Khớp nối chính xác mốc thời gian giữa các phiên kết nối `zeek.conn` với các bản ghi `Failed password for labuser` trong auth log.
   - Khẳng định cuộc tấn công nhắm trực diện vào tài khoản `labuser` với nguồn phát từ `192.168.100.50`.

---

### Bước 4 — Kiểm tra Alerts và Bằng chứng PCAP

1. **Kiểm tra Suricata Alerts:**
   - Vào tab **Alerts** trên SOC.
   - Tìm kiếm alert liên quan đến SSH scan / brute force (ví dụ: `ET SCAN Potential SSH Scan` hoặc cảnh báo policy SSH).
2. **Phân tích Bằng chứng PCAP:**
   - Từ một event `zeek.conn` trong Hunt, nhấp vào biểu tượng **PCAP** (hoặc chọn **Pivot to PCAP**).
   - SOC sẽ hiển thị luồng TCP stream:
     * 3 bước bắt tay TCP (SYN, SYN-ACK, ACK).
     * Bắt tay phiên bản SSH (SSH Version Exchange).
     * Gói tin khởi tạo thuật toán mã hóa (KEXINIT) và Diffie-Hellman Key Exchange.
     * Toàn bộ phần dữ liệu sau đó đều được đánh nhãn `Encrypted packet` ➔ Minh chứng giá trị pháp lý số: payload được bảo mật, chứng minh tính cần thiết của Host Telemetry.

---

### Bước 5 — Đóng Case điều tra (Case Management)

Tạo một Case mới trong tab **Cases** của Security Onion SOC:

- **Case Title:** `LAB Scenario 2 — SSH Authentication Brute Force Attempt (VMware)`
- **Severity:** `Medium`
- **Status:** `Closed / Resolved`
- **ATT&CK Technique:** `T1110.001 - Brute Force: Password Guessing`
- **Observables:**
  - `source.ip: 192.168.100.50` (Attacker Linux)
  - `destination.ip: 192.168.100.188` (Metasploitable 2)
  - `destination.port: 22`
  - `target.user: labuser`
  - `event.outcome: failure` (6 lần thử không thành công)
- **Disposition:** `Authorized Lab Activity`
- **Case Summary:**
  > "Phát hiện chuỗi kết nối SSH dồn dập từ 192.168.100.50 tới 192.168.100.188 trên port 22. Đối chiếu giữa Zeek connection metadata và auth log từ máy mục tiêu xác nhận đối tượng đã thực hiện 6 lần thử mật khẩu không chính xác nhắm vào tài khoản 'labuser'. Payload lưu lượng trên mạng bị mã hóa. Hoạt động được phân loại là diễn tập an ninh kiểm thử có kiểm soát."
- **Đính kèm bằng chứng:**
  - File log tấn công: `scenario2-auth-attack.log` hoặc `scenario2-hydra-results.txt`.
  - Ảnh chụp màn hình Zeek `zeek.conn` / `zeek.ssh` trên SOC Hunt.
  - Ảnh chụp `/var/log/auth.log` trên Metasploitable 2.
  - File trích xuất PCAP của phiên SSH.

---

## 6. Dọn dẹp sau bài Lab (Cleanup)

- Trên máy Metasploitable 2: Xóa tài khoản `labuser` nếu không còn sử dụng:
  ```bash
  sudo userdel -r labuser
  ```
- Dừng tiến trình bắt gói tin `tcpdump` trên Security Onion nếu còn chạy ngầm.
