# Network Scanning 

Một máy quét thử nhiều cổng của máy mục tiêu để tìm dịch vụ đang mở.

- Kỹ thuật ATT&CK: **T1046 — Network Service Scanning**.
- Câu hỏi cần trả lời: *Ai quét? Quét máy nào? Quét cổng nào? Khi nào? Có bằng chứng packet không?*
- Không cần khai thác lỗ hổng; chỉ cần quan sát reconnaissance.


Scan thẳng IP quản lý Security Onion chỉ kiểm tra chính máy sensor. Dùng Metasploitable làm target giúp mô hình đúng hơn:

```text
Kali/host → Metasploitable
                 ↓
          Security Onion sensor
```

Security Onion không tự nhìn thấy traffic unicast chỉ vì NIC sniffing cùng `lab-net`; cần SPAN/TAP hoặc mirror. Trong KVM lab này, dùng `tc mirred` để copy traffic từ tap của target sang tap sniffing.



###  Bắt packet trước khi scan

Trong Security Onion chạy trước:

```bash
sudo timeout 60 tcpdump -nn -i enp7s0 'host 192.168.100.188 and tcp'
```

Phải thấy dòng `listening on enp7s0` trước khi chạy Nmap.

###  Chạy Nmap

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

###  Tìm trong Hunt

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

###  Kiểm tra Alert, PCAP và Case

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

###  Cleanup

Sau demo, xóa đúng hai filter lab:

```bash
sudo tc filter del dev vnet2 ingress pref 49151
sudo tc filter del dev vnet2 egress pref 49151
```

Không xóa toàn bộ qdisc hoặc filter không thuộc bài lab.
