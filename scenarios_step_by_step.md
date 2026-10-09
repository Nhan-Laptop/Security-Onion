# Security Onion — Scenario guide và handoff

## 1. Các thành phần có ý nghĩa gì?

| Thành phần | Dùng để làm gì? |
|---|---|
| **Suricata** | Phát hiện traffic khớp signature/rule và tạo alert. |
| **Zeek** | Biến traffic thành metadata như connection, DNS, HTTP, file. |
| **PCAP** | Lưu packet để chứng minh chính xác chuyện gì xảy ra. |
| **Elastic Agent** | Gửi log/process/authentication từ endpoint vào Security Onion. |
| **Hunt** | Tìm và tương quan dữ liệu; không phải mọi event trong Hunt đều là alert. |
| **Cases** | Lưu kết luận, thời gian và bằng chứng của investigation. |

Mỗi scenario nên đi theo chuỗi:

```text
Tạo hành vi vô hại trong lab
→ sensor nhận traffic/log
→ Hunt tìm metadata
→ Alerts kiểm tra detection
→ PCAP kiểm tra packet
→ Case ghi kết luận
```

**Quan trọng:** Có `zeek.conn` không đồng nghĩa đã có Suricata alert. Có packet trong `tcpdump` cũng chưa đồng nghĩa SOC đã lưu PCAP.

---

## 2. Topology lab hiện tại

```text
Kali/host: 192.168.100.1
       │
       │ lab-net / virbr1
       ▼
Metasploitable: 192.168.100.188
       │  tap vnet5
       │ mirror
       ▼
Security Onion sniffing: vnet1 → enp7s0

Security Onion management: 192.168.122.10
```

| Thành phần | Giá trị hiện tại |
|---|---|
| Security Onion VM | `rocky9` |
| Management tap | `vnet0`, mạng `default` |
| Sniffing tap | `vnet1`, mạng `lab-net` |
| Sniffing NIC trong SO | `enp7s0`, không có IP |
| Metasploitable VM | `linux2024` |
| Metasploitable tap | `vnet5`, model `e1000` |
| Metasploitable IP | `192.168.100.188` |
| Host IP trên lab-net | `192.168.100.1` |

Tap có thể đổi sau reboot. Luôn kiểm tra lại:

```bash
sudo virsh domiflist linux2024
sudo virsh domiflist rocky9
```

---

# Scenario 1 — Network Scanning

## 1.1. Scenario này nói về gì?

Một máy quét thử nhiều cổng của máy mục tiêu để tìm dịch vụ đang mở.

- Kỹ thuật ATT&CK: **T1046 — Network Service Scanning**.
- Câu hỏi cần trả lời: *Ai quét? Quét máy nào? Quét cổng nào? Khi nào? Có bằng chứng packet không?*
- Không cần khai thác lỗ hổng; chỉ cần quan sát reconnaissance.

## 1.2. Vì sao cần target riêng?

Scan thẳng IP quản lý Security Onion chỉ kiểm tra chính máy sensor. Dùng Metasploitable làm target giúp mô hình đúng hơn:

```text
Kali/host → Metasploitable
                 ↓
          Security Onion sensor
```

Security Onion không tự nhìn thấy traffic unicast chỉ vì NIC sniffing cùng `lab-net`; cần SPAN/TAP hoặc mirror. Trong KVM lab này, dùng `tc mirred` để copy traffic từ tap của target sang tap sniffing.

## 1.3. Các bước đã thực hiện

### Bước 1 — Tạo target

1. Tạo VM từ `metasploitable2.qcow2`.
2. Metasploitable 2 cũ không boot được khi disk dùng VirtIO; VM rơi vào `(initramfs)` và chỉ thấy `lo`.
3. Đổi disk bus sang **SATA/IDE**.
4. Đổi NIC sang **e1000**.
5. Nối NIC duy nhất vào **`lab-net`**, không nối `default`/bridged.

### Bước 2 — Lấy IP target

Trên host:

```bash
sudo virsh net-dhcp-leases lab-net
```

Kết quả thực tế:

```text
MAC 52:54:00:ef:1e:15
IP  192.168.100.188/24
```

Kiểm tra target sống:

```bash
ping -c 3 192.168.100.188
```

### Bước 3 — Xác định tap

Kết quả thực tế:

```text
linux2024: vnet5 → lab-net → 52:54:00:ef:1e:15
rocky9:     vnet1 → lab-net → Security Onion sniffing NIC
```

### Bước 4 — Kiểm tra mirror

Trước khi sửa, lệnh sau không trả output:

```bash
sudo tc -s filter show dev vnet5 ingress
sudo tc -s filter show dev vnet5 egress
```

Điều đó giải thích vì sao scan thành công nhưng Hunt không có `zeek.conn`: packet chưa được copy tới sensor.

### Bước 5 — Tạo mirror

Trên host, chạy từng dòng:

```bash
sudo tc qdisc show dev vnet5
```

Nếu chưa có `clsact`:

```bash
sudo tc qdisc add dev vnet5 clsact
```

Tạo mirror hai chiều:

```bash
sudo tc filter add dev vnet5 ingress pref 49151 matchall action mirred egress mirror dev vnet1
sudo tc filter add dev vnet5 egress pref 49151 matchall action mirred egress mirror dev vnet1
```

Kiểm tra:

```bash
sudo tc -s filter show dev vnet5 ingress
sudo tc -s filter show dev vnet5 egress
```

`ingress` và `egress` đều cần thiết vì muốn thấy cả chiều scan và chiều phản hồi.

### Bước 6 — Bắt packet trước khi scan

Trong Security Onion chạy trước:

```bash
sudo timeout 60 tcpdump -nn -i enp7s0 'host 192.168.100.188 and tcp'
```

Phải thấy dòng `listening on enp7s0` trước khi chạy Nmap.

### Bước 7 — Chạy Nmap

Lệnh bị lỗi trước đó vì IP bị xuống dòng thành command riêng:

```text
192.168.100.188: command not found
```

Lệnh đúng phải nằm trên **một dòng**:

```bash
sudo nmap -sS -Pn -p 1-1000 -T3 --reason 192.168.100.188 -oN scenario1-metasploitable-scan.txt
```

Ý nghĩa:

| Tùy chọn | Ý nghĩa |
|---|---|
| `-sS` | TCP SYN scan |
| `-Pn` | Không bỏ qua target vì host discovery |
| `-p 1-1000` | Chỉ quét 1000 cổng đầu |
| `-T3` | Timing vừa phải cho lab |
| `--reason` | Hiển thị vì sao Nmap quyết định open/closed |
| `-oN` | Lưu bằng chứng dạng text |

Kết quả thực tế có 12 cổng mở, gồm FTP, SSH, Telnet, HTTP, SMB và các dịch vụ khác; 988 cổng còn lại bị đóng.

### Bước 8 — Tìm trong Hunt

SOC → **Hunt**:

1. Chọn khoảng thời gian chứa lần scan.
2. Không dùng query mặc định chỉ hiển thị Elastic Agent logs.
3. Dùng:

```text
event.dataset:"zeek.conn" AND destination.ip:"192.168.100.188"
```

Kết quả thực tế đã xác minh:

- `Total Found: 1,000`.
- `event.dataset: zeek.conn`.
- `source.ip: 192.168.100.1`.
- `destination.ip: 192.168.100.188`.
- Nhiều `destination.port`, ví dụ `665` và `277`.
- Timestamp hiển thị khoảng `2026-10-08 22:03:17 +07:00`.

Đây là bằng chứng Zeek nhận được nhiều kết nối tới nhiều cổng trong thời gian ngắn.

### Bước 9 — Kiểm tra Alert, PCAP và Case

1. SOC → **Alerts**: tìm theo thời gian/source/target.
2. Nếu không có alert, chỉ kết luận “Zeek ghi nhận scan”; không ghi “Suricata phát hiện”.
3. Từ event/alert chọn **PCAP/Pivot to PCAP** nếu có.
4. Xác minh TCP SYN tới nhiều cổng.
5. Tạo Case:

```text
Title: LAB Scenario 1 — Network Service Scanning
Technique: T1046
Source: 192.168.100.1
Target: 192.168.100.188
Disposition: Authorized lab activity
```

Đính kèm:

- `scenario1-metasploitable-scan.txt`.
- Ảnh tcpdump.
- Ảnh Hunt có `zeek.conn`.
- Suricata alert nếu thực sự có.
- PCAP nếu thực sự truy xuất được.

### Bước 10 — Cleanup

Sau demo, xóa đúng hai filter lab:

```bash
sudo tc filter del dev vnet5 ingress pref 49151
sudo tc filter del dev vnet5 egress pref 49151
```

Không xóa toàn bộ qdisc hoặc filter không thuộc bài lab.

---

# Scenario 2 — Authentication Attack Simulation

## 2.1. Scenario này nói về gì?

Mô phỏng nhiều lần đăng nhập thất bại vào SSH/Windows để kiểm tra cả:

- **Network visibility:** kết nối từ Kali tới SSH/RDP.
- **Host visibility:** auth log cho biết user, source IP và lý do thất bại.

ATT&CK: **T1110 — Brute Force**. Chỉ dùng vài lần thất bại có chủ ý trong lab, không chạy password spray lớn.

## 2.2. Các bước

1. Dùng Ubuntu target và bật SSH:

```bash
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
```

2. Tạo user lab:

```bash
sudo adduser labuser
```

3. Cài Elastic Agent từ SOC → **Downloads/Fleet**.
4. Bật System integration để thu `/var/log/auth.log`/`system.auth`.
5. Từ Kali thử SSH khoảng 5 lần và nhập password sai:

```bash
ssh labuser@UBUNTU_IP
```

6. Hunt:

```text
event.dataset:"system.auth" AND source.ip:"KALI_IP" AND event.outcome:"failure"
```

Nếu field khác:

```text
message:"Failed password" AND source.ip:"KALI_IP"
```

7. Xác minh user, source IP, host và timestamp.
8. Nếu cần alert, tạo Sigma threshold cho nhiều thất bại trong một khoảng thời gian.
9. Tạo Case và ghi rõ đây là authorized lab test.

## 2.3. Vì sao cần Elastic Agent?

Zeek chỉ thấy connection; nó không biết password sai hay user nào. Auth log từ endpoint mới cung cấp context đó.

---

# Scenario 3 — Suspicious Web Activity

## 3.1. Scenario này nói về gì?

Kiểm tra một HTTP request đáng chú ý nhưng không khai thác thật. Analyst cần nối:

```text
HTTP request → Zeek HTTP metadata → Suricata/custom detection → PCAP → Case
```

## 3.2. Các bước

1. Dùng Apache trên Ubuntu/Metasploitable:

```bash
sudo apt install -y apache2
sudo systemctl enable --now apache2
```

2. Kiểm tra web:

```bash
curl -I http://TARGET_IP/
```

3. Gửi request vô hại:

```bash
curl -i "http://TARGET_IP/does-not-exist?lab=SO-SCENARIO3"
curl -i -A "SO-LAB-TEST" "http://TARGET_IP/"
```

4. Mirror target traffic tới sensor.
5. Hunt:

```text
event.dataset:"zeek.http" AND destination.ip:"TARGET_IP"
```

6. Kiểm tra method, URI, status code, User-Agent và source IP.
7. Nếu cần alert chắc chắn, tạo custom rule chỉ tìm marker `SO-LAB-TEST`, deploy rồi gửi lại request.
8. Pivot PCAP để xem request/response.
9. Tạo Case.

## 3.3. Vì sao không dùng SQLi/XSS thật?

Mục tiêu scenario là chứng minh visibility và workflow, không phải khai thác. Marker vô hại đủ để kiểm tra pipeline.

---

# Scenario 4 — Endpoint Detection

## 4.1. Scenario này nói về gì?

Kiểm tra Security Onion có thấy hành vi trên endpoint hay không, kể cả khi packet network không đủ context.

ATT&CK: **T1059.001 — PowerShell**.

## 4.2. Các bước

1. Dùng Windows endpoint trong lab.
2. Cài Elastic Agent từ SOC.
3. Cài Sysmon với config được phê duyệt.
4. Xác nhận process creation/Event ID 1 được ingest.
5. Chạy lệnh vô hại:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SO-LAB-POWERSHELL'"
```

6. Hunt:

```text
process.name:"powershell.exe" AND process.command_line:*SO-LAB-POWERSHELL*
```

7. Xác minh host, user, parent process, command line và timestamp.
8. Tạo Sigma detection cho marker, deploy và chạy lại một lần.
9. Kiểm tra Alerts rồi tạo Case.
10. Disable rule lab sau demo.

## 4.3. Vì sao cần endpoint telemetry?

Network sensor có thể thấy kết nối, nhưng không biết process nào chạy trên Windows. Elastic Agent/Sysmon bổ sung process, user và parent process.

---

# Scenario 5 — File Transfer + PCAP Investigation

## 5.1. Scenario này nói về gì?

Chứng minh analyst có thể nhận ra file được truyền, kiểm tra hash và xem packet stream.

## 5.2. Các bước

1. Chuẩn bị Host A và Host B trong lab.
2. Tạo file vô hại:

```bash
printf 'SO-LAB-FILE-TRANSFER\n' > lab-test.txt
sha256sum lab-test.txt
```

3. Host A chạy HTTP server:

```bash
python3 -m http.server 8000 --directory .
```

4. Host B tải file:

```bash
curl -O http://HOST_A_IP:8000/lab-test.txt
sha256sum lab-test.txt
```

5. Mirror traffic và bắt packet trước khi transfer.
6. Hunt:

```text
event.dataset:"zeek.http" AND (source.ip:"HOST_A_IP" OR destination.ip:"HOST_A_IP")
```

7. Tìm `zeek.files` nếu deployment có file metadata.
8. Kiểm tra filename, size, MIME/hash nếu có.
9. Pivot PCAP và kiểm tra HTTP stream.
10. Tạo Case với hash nguồn/đích, Zeek event và PCAP.

## 5.3. Vì sao dùng file vô hại?

Mục tiêu là kiểm tra evidence chain, không phải exfiltration thật. Hash chứng minh file nhận được giống file gửi.

---

# Scenario 6 — Honeypot

## 6.1. Scenario này nói về gì?

OpenCanary giả lập các service dễ bị chú ý. Bất kỳ kết nối nào tới service đó đều đáng điều tra vì không có lý do hợp lệ trong lab.

## 6.2. Các bước

1. Tạo OpenCanary VM chỉ trên `lab-net`.
2. Không nối Internet hoặc bridged network.
3. Cài OpenCanary theo tài liệu đúng phiên bản OS.
4. Bật một số service giả như SSH/HTTP/FTP.
5. Cấu hình gửi log về Security Onion qua syslog/integration.
6. Kiểm tra service:

```bash
ss -lnt
```

7. Từ Kali tạo một kết nối đơn giản:

```bash
nc -vz CANARY_IP 22
```

8. Hunt/Alerts theo `CANARY_IP`, source IP, port và thời gian.
9. Nếu không có event, kiểm tra remote logging và sensor trước khi test lại.
10. Tạo Case với source IP, service, timestamp và alert/log.

## 6.3. Vì sao honeypot hữu ích?

Honeypot giảm nhiễu: một connection tới service giả thường có độ nghi ngờ cao hơn traffic tới server production.

---

# 7. Checklist bằng chứng

Mỗi scenario cần lưu:

- [ ] Topology và IP.
- [ ] Timestamp/timezone.
- [ ] Lệnh hoặc request test.
- [ ] Tcpdump hoặc endpoint telemetry.
- [ ] Zeek/Hunt event.
- [ ] Suricata/Sigma alert nếu thực sự có.
- [ ] PCAP nếu thực sự truy xuất được.
- [ ] Case ID.
- [ ] Cleanup sau test.

## Cleanup mirror hiện tại

Nếu tap vẫn là `vnet5` và `vnet1`:

```bash
sudo tc filter del dev vnet5 ingress pref 49151
sudo tc filter del dev vnet5 egress pref 49151
```

Nếu tap đã đổi, kiểm tra lại bằng:

```bash
sudo virsh domiflist linux2024
sudo virsh domiflist rocky9
```
