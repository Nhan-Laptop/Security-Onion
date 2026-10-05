# Báo cáo và handoff các scenarios — Security Onion

## 1. Phạm vi và trạng thái

Tài liệu đi kèm `Readme.md`, dùng để ghi nhận kết quả thực nghiệm và hướng dẫn người tiếp nhận tiếp tục triển khai.

**Chỉ thực hiện kiểm thử trên các máy và mạng lab thuộc quyền quản lý.** Không quét mạng bên ngoài hoặc chạy script khai thác.

| Scenario | Nội dung | Trạng thái thực tế |
|---|---|---|
| 1 | Network Scanning | Đã xác minh traffic scan đến sensor và có Zeek connection logs; chưa xác minh Suricata alert, PCAP qua SOC và Case |
| 2 | Authentication Attack Simulation | Chưa thực hiện trong phiên này |
| 3 | Suspicious Web Activity | Chưa thực hiện trong phiên này |
| 4 | Endpoint Detection | Chưa thực hiện trong phiên này |
| 5 | File Transfer + PCAP Investigation | Chưa thực hiện trong phiên này |
| 6 | Honeypot | Chưa thực hiện trong phiên này |

Các mục hướng dẫn bên dưới không đồng nghĩa với việc đã thực hiện thành công. Chỉ đánh dấu hoàn thành khi có bằng chứng tương ứng.

---

## 2. Scenario 1 — Network Scanning

### 2.1. Mục tiêu

Chứng minh analyst có thể nhận diện hành vi quét dịch vụ mạng và điều tra theo chuỗi:

```text
Nmap scan → Suricata alert → Zeek connection metadata → PCAP → Case
```

**MITRE ATT&CK:** T1046 — Network Service Scanning.

Trong phiên thực nghiệm này, đã chứng minh được:

```text
Nmap scan → traffic được mirror tới sensor → Zeek connection logs
```

Các phần Suricata alert, PCAP trong SOC và Case còn cần hoàn thiện.

### 2.2. Mô hình thực nghiệm thực tế

Để giảm số lượng VM, dùng Kali trên máy host làm máy quét và chính IP quản lý Security Onion làm mục tiêu.

```text
Kali host: 192.168.122.1
         │ Nmap TCP scan
         ▼
Security Onion management: 192.168.122.10
         │
         │ Host KVM mirror traffic hai chiều
         ▼
Security Onion sniffing NIC: enp7s0 → bond0 → Suricata / Zeek
```

> Đây là mô hình demo tối giản: sensor đồng thời là mục tiêu. Không phải mô hình doanh nghiệp trong `Readme.md`, vốn dùng mục tiêu riêng và SPAN/TAP. Khi báo cáo phải ghi rõ khác biệt này.

| Thành phần | Giá trị trong phiên thực nghiệm |
|---|---|
| Hypervisor | QEMU/KVM, virt-manager |
| Tên domain libvirt | `rocky9` — tên VM, không dùng tên này để suy luận hệ điều hành |
| Phiên bản trong Setup | Security Onion 3.3.0 |
| Kiểu triển khai | Standalone |
| Máy quét | Kali host |
| IP nguồn thấy trong tcpdump/Zeek | `192.168.122.1` |
| Management NIC trong VM | `enp1s0`, IP `192.168.122.10/24` |
| MAC management | `52:54:00:6a:e7:91` |
| Sniffing NIC trong VM | `enp7s0`, không có IP; nằm trong capture bond |
| MAC sniffing | `52:54:00:48:04:63` |
| Mạng management | `default`, NAT, bridge `virbr0`, gateway `192.168.122.1` |
| Mạng sniffing | `lab-net`, isolated, `192.168.100.0/24`, bridge `virbr1` |
| Management tap trên host tại thời điểm thực hiện | `vnet14` |
| Sniffing tap trên host tại thời điểm thực hiện | `vnet15` |

**Quan trọng:** `vnet14` và `vnet15` có thể thay đổi sau khi VM khởi động lại. Luôn xác định lại bằng MAC trước khi dùng lệnh mirror.

## 3. Hướng dẫn tái hiện Scenario 1 từng bước

### Bước 1 — Kiểm tra dịch vụ và mạng

**Trong VM Security Onion:**

```bash
ip -br addr
sudo so-status
```

Điều kiện để tiếp tục:
- `enp1s0` có `192.168.122.10/24`.
- NIC sniffing `enp7s0` không có IP.
- Suricata và Zeek hoạt động; SOC truy cập được qua `https://192.168.122.10`.

**Trên host Kali:**

```bash
sudo virsh domiflist rocky9
```

Đối chiếu theo MAC, không đoán theo thứ tự dòng:

```text
52:54:00:6a:e7:91 → management tap
52:54:00:48:04:63 → sniffing tap
```

Các lệnh dưới giả định kết quả vẫn là management `vnet14`, sniffing `vnet15`. Nếu khác, thay đúng tên trong mọi lệnh.

### Bước 2 — Mirror traffic trên host

Chỉ nối NIC sniffing vào một mạng ảo không tự làm nó nhìn thấy toàn bộ unicast traffic. Bài này copy traffic trên management tap tới sniffing tap.

**Kiểm tra hiện trạng trước:**

```bash
sudo tc qdisc show dev vnet14
sudo tc -s filter show dev vnet14 ingress
sudo tc -s filter show dev vnet14 egress
```

Nếu chưa có `clsact`, tạo:

```bash
sudo tc qdisc add dev vnet14 clsact
```

Nếu báo `File exists`, kiểm tra có đúng `clsact` không; không xóa qdisc hoặc filter khác để ép lệnh chạy.

Nếu chưa có hai filter của bài lab, tạo từng lệnh trên một dòng:

```bash
sudo tc filter add dev vnet14 ingress pref 49150 matchall action mirred egress mirror dev vnet15
sudo tc filter add dev vnet14 egress pref 49150 matchall action mirred egress mirror dev vnet15
```

Nếu priority `49150` đã được dùng bởi cấu hình khác, dừng và chọn priority trống; không ghi đè filter của người khác.

Kiểm tra lại:

```bash
sudo tc -s filter show dev vnet14 ingress
sudo tc -s filter show dev vnet14 egress
```

Mong đợi: thấy `matchall`, action mirror tới `vnet15`; sau khi có traffic, bộ đếm packet/byte tăng.

**Giới hạn:** mirror này copy cả traffic quản lý, đăng nhập SOC và TLS. Chỉ bật tạm trong lab, bảo vệ PCAP như dữ liệu nhạy cảm. Filter không được đảm bảo tồn tại sau reboot hoặc tái tạo tap.

### Bước 3 — Xác nhận sensor thấy scan

**Trong VM Security Onion, chạy trước:**

```bash
sudo timeout 60 tcpdump -nn -i enp7s0 'host 192.168.122.10 and tcp and portrange 1-100'
```

Chờ dòng `listening on enp7s0`, rồi chạy bước 4 trên host trong khoảng 60 giây đó.

Mong đợi:
- Nguồn `192.168.122.1`.
- Đích `192.168.122.10`.
- Nhiều cổng đích từ 1 tới 100.
- `Flags [S]` tương ứng TCP SYN.

Chỉ nhìn thấy traffic HTTPS của SOC không đủ xác minh scan. `tcpdump` thấy packet cũng chưa chứng minh pipeline Zeek, alert hay full packet capture hoạt động; cần kiểm tra riêng các bước sau.

### Bước 4 — Chạy scan có giới hạn

**Trên host Kali, trong thư mục lưu bằng chứng:**

```bash
date -Is
sudo nmap -sS -Pn -p 1-100 -T3 --reason 192.168.122.10 -oN scenario1-scan.txt
```

| Tùy chọn | Ý nghĩa |
|---|---|
| `sudo`, `-sS` | TCP SYN scan, cần quyền raw packet |
| `-Pn` | Không dùng host discovery thông thường để quyết định bỏ qua mục tiêu; vẫn có thể có ARP trên LAN |
| `-p 1-100` | Chỉ quét 100 cổng đầu |
| `-T3` | Timing mức mặc định/normal |
| `--reason` | Hiển thị lý do phân loại cổng |
| `-oN` | Lưu kết quả text vào thư mục hiện tại trên host |

Không có script khai thác hoặc đăng nhập thử trong lệnh này.

Xem kết quả:

```bash
cat scenario1-scan.txt
```

File Nmap không được gửi vào Security Onion. Sensor phân tích traffic được mirror.

### Bước 5 — Hunt dữ liệu Zeek

1. Đăng nhập SOC, mở **Hunt**.
2. Chọn thời gian bao phủ lần scan. Nếu xem lại dữ liệu cũ, dùng khoảng thời gian tuyệt đối thay vì `Last 15 minutes`.
3. Thay query hiện tại bằng:

```text
event.dataset:"zeek.conn" AND source.ip:192.168.122.1 AND destination.ip:192.168.122.10 AND destination.port:[1 TO 100]
```

4. Nhấn Enter; chờ pipeline ingest nếu vừa scan, sau đó refresh.
5. Hiển thị các cột timestamp, dataset, source IP/port, destination IP/port, transport.
6. Mở một event bằng dấu `>` và ghi lại chi tiết.

Mong đợi: nhiều kết nối TCP tới nhiều cổng trong khoảng thời gian rất ngắn.

Nếu trường có mặt, kiểm tra `zeek.conn.conn_state`. `S0` thường là thấy kết nối khởi đầu nhưng không thấy phản hồi; không tự kết luận cổng đóng. Mất packet hoặc mirror thiếu một chiều cũng có thể ảnh hưởng trạng thái.

**Lưu ý:** biểu tượng tam giác xanh trong Hunt không phải bằng chứng đã có alert Suricata.

---
