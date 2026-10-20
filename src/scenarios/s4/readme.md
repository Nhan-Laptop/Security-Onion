# Kịch bản 4 — Endpoint Detection & Host Telemetry (Elastic Agent + Sysmon)

> **Môn học:** Chuyên đề An toàn Thông tin / Đồ án Giám sát An ninh Mạng  
> **Giải pháp nghiên cứu:** Security Onion (SIEM / XDR / NSM Platform)  
> **Thành viên thực hiện:** Nhan_laptop, Lvy-H, Supershy  
> **Kỹ thuật ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/), [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082/)

---

## 1. Giới thiệu Kịch bản & Mục tiêu Đồ án

### 1.1. Tại sao Network Security Monitoring (NSM) là chưa đủ?
Trong các kịch bản trước (Scenario 1 & Scenario 2), Security Onion đóng vai trò là một Network Sensor (Suricata, Zeek, PCAP). Tuy nhiên, nếu chỉ dựa vào lưu lượng mạng:
1. **Lưu lượng bị mã hóa:** Giao thức HTTPS hoặc SSH che giấu hoàn toàn payload, NIDS không thể biết tiến trình nào đang chạy và nội dung thực thi là gì.
2. **Khai thác nội bộ / Không sinh lưu lượng mạng:** Hacker thực thi mã độc bằng PowerShell, leo thang đặc quyền, dump password LSASS hoặc trích xuất dữ liệu nội bộ trên máy trạm mà không gửi gói tin ra mạng ngoài.
3. **Thiếu ngữ cảnh tiến trình (Process Context):** Mạng chỉ thấy `IP nguồn:Port nguồn ➔ IP đích:Port đích`, nhưng **không thể biết** tiến trình nào (`powershell.exe`, `cmd.exe`, `malware.exe`), thuộc user nào, có PID là gì đã tạo ra kết nối đó.

### 1.2. Giải pháp của Security Onion: Elastic Agent & Sysmon
Để hoàn thiện mô hình **XDR (Extended Detection and Response)** và giám sát toàn diện (**Defense in Depth**), Security Onion tích hợp sẵn **Elastic Fleet Server** để quản lý tập trung các **Elastic Agent** triển khai trên Endpoint (Windows/Linux/macOS):
* **Sysmon (System Monitor - Microsoft):** Driver cấp kernel theo dõi chi tiết hoạt động Windows:
  * **Event ID 1:** Process Creation (Tạo tiến trình kèm toàn bộ Command Line, Parent Process, Hash file thực thi).
  * **Event ID 3:** Network Connection (Liên kết chính xác PID của tiến trình với IP/Port mạng).
  * **Event ID 11:** File Create (Theo dõi file bị tạo/ghi đè).
* **Elastic Agent:** Thu thập toàn bộ log Sysmon, Security Event Log và gửi về Security Onion Fleet Server qua kênh mã hóa an toàn.

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SO SÁNH GÓC NHÌN ĐIỀU TRA                             │
├────────────────────────────────┬────────────────────────────────────────────────┤
│   Network View (Zeek / Suricata) │   Host View (Elastic Agent / Sysmon)           │
├────────────────────────────────┼────────────────────────────────────────────────┤
│ Thấy kết nối HTTP/DNS ra ngoài │ Thấy chính xác tiến trình powershell.exe       │
│ Thấy IP máy trạm gửi gói tin   │ Thấy Username, Command line, Parent PID, Hash  │
│ KHÔNG THẤY script bên trong    │ THẤY RÕ toàn bộ chuỗi lệnh Base64 / tham số   │
└────────────────────────────────┴────────────────────────────────────────────────┘
```

---

## 2. Sơ đồ Kiến trúc & Phân bổ IP trên VMware

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                         VMware Hypervisor (Workstation)                          │
│                                                                                  │
│   VMnet8 (NAT): 192.168.182.0/24 (Mạng Quản trị & Endpoint Communication)        │
└───────────────┬──────────────────────────────────────────┬───────────────────────┘
                │                                          │
                │ Port 8220 / 9200 (Fleet Ingest)          │
                │                                          │
┌───────────────▼─────────────────────────────┐  ┌─────────▼───────────────────────────┐
│     Security Onion (Fleet Server)           │  │   Windows Endpoint (hoặc Linux)     │
│   • Management IP : 192.168.182.10/24       │  │   • IP : 192.168.182.20/24 (hoặc DHCP) │
│   • Fleet Server  : https://192.168.182.10  │  │   • OS : Windows 10/11 (hoặc Ubuntu)│
│   • Fleet Port    : 8220                    │  │   • Components :                    │
│   • Elasticsearch : Port 9200               │  │     - Sysmon (SwiftOnSecurity)      │
│                                             │  │     - Elastic Agent (Enrolled)      │
└─────────────────────────────────────────────┘  └─────────────────────────────────────┘
```

### Bảng thông số tài nguyên Lab

| Máy ảo | Vai trò | Mạng VMware | IP đề xuất | Phần mềm & Dịch vụ |
|---|---|---|---|---|
| **Security Onion** | Fleet Server & SOC Console | VMnet8 (NAT) | `192.168.182.10/24` | Fleet Server (Port 8220), Elasticsearch, SOC Hunt |
| **Windows Endpoint** | Máy trạm mục tiêu theo dõi | VMnet8 (NAT) | `192.168.182.20/24` (hoặc DHCP) | Windows 10/11, Sysmon v15+, Elastic Agent |
| *(Tùy chọn)* **Linux Endpoint** | Máy trạm Linux mục tiêu | VMnet8 (NAT) | `192.168.182.21/24` | Ubuntu Server 24.04, Elastic Agent |

---

## 3. Hướng dẫn Cài đặt & Kết nối Endpoint vào Security Onion

### 3.1. Lấy lệnh cài đặt Elastic Agent từ Security Onion SOC
1. Mở trình duyệt trên máy thật, truy cập Web SOC: `https://192.168.182.10`.
2. Đăng nhập bằng tài khoản quản trị đã tạo lúc setup.
3. Ở menu thanh bên trái, chọn **Administration** ➔ Chọn mục **Elastic Fleet** (hoặc **Fleet**).
4. Vào tab **Agent policies** ➔ Chọn chính sách mặc định (ví dụ `Security Onion Endpoint Policy` hoặc `Default`).
5. Bấm nút **Add agent**:
   * Hệ thống sẽ hiển thị sẵn câu lệnh cài đặt dành riêng cho Windows (PowerShell) hoặc Linux kèm theo **Enrollment Token**.

```powershell
# Ví dụ lệnh cài đặt sinh ra từ Fleet (chú ý cờ --insecure do dùng SSL tự ký trong lab):
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://192.168.182.10:8220/downloads/bundles/elastic-agent/elastic-agent-windows-x86_64.zip" -OutFile "elastic-agent.zip" -SkipCertificateCheck
Expand-Archive .\elastic-agent.zip -DestinationPath .
cd elastic-agent-*
.\elastic-agent.exe install --url=https://192.168.182.10:8220 --enrollment-token=<TOKEN_CUA_BAN> --insecure
```

> [!IMPORTANT]
> Do trong môi trường Lab, Security Onion sử dụng chứng chỉ SSL tự ký (Self-signed certificate), khi cài đặt Elastic Agent bắt buộc phải có tham số **`--insecure`** để agent chấp nhận kết nối với Fleet Server.

---

### 3.2. Cài đặt Sysmon trên Windows Endpoint
Để thu thập log tiến trình (Event ID 1) chuẩn xác nhất, cài đặt **Sysmon** với file cấu hình chuẩn:

1. Tải **Sysmon** từ Microsoft Sysinternals: [Sysmon Download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Tải cấu hình phát hiện nổi tiếng **SwiftOnSecurity**:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"
   ```
3. Cài đặt Sysmon ở quyền Administrator:
   ```cmd
   sysmon64.exe -i sysmonconfig.xml -accepteula
   ```
4. Kiểm tra dịch vụ Sysmon:
   ```powershell
   Get-Service Sysmon64
   # Trạng thái phải là Running
   ```

---

## 4. Thực thi Kịch bản Mô phỏng Tấn công (Execution)

### Cách 1: Chạy Script tự động (`endpoint_simulation.ps1`)
Trên máy Windows Endpoint, mở PowerShell (Run as Administrator) và chạy script mô phỏng được chuẩn bị sẵn trong thư mục `src/scenarios/s4/`:

```powershell
# Chạy script mô phỏng
.\src\scenarios\s4\endpoint_simulation.ps1
```

Script sẽ lần lượt thực hiện 4 hành vi kỹ thuật kinh điển của kẻ tấn công:
1. **Marker Execution:** Chạy tiến trình vô hại mang cờ nhận diện đặc trưng `SO-LAB-POWERSHELL-MARKER-2026`.
2. **Discovery (T1082 / T1057):** Dò quét cấu hình hệ thống bằng `whoami`, `hostname`, `net user`, `systeminfo`.
3. **Obfuscated / Base64 Execution (T1059.001):** Thực thi lệnh PowerShell mã hóa Base64 qua tham số `-EncodedCommand` (kỹ thuật malware hay dùng để né AV cơ bản).
4. **Outbound Connection (T1071.001):** Tạo kết nối HTTP từ PowerShell ra ngoài để kích hoạt Sysmon Event ID 3.

---

### Cách 2: Chạy các lệnh thủ công từng bước

#### Bước 1: Kích hoạt Process Creation với Marker
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SO-LAB-POWERSHELL-TEST'"
```

#### Bước 2: Kích hoạt mã hóa Base64
```powershell
# Mã hóa chuỗi "Write-Output 'PWNED-BY-LAB'" sang Base64
$cmd = "Write-Output 'PWNED-BY-LAB'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$b64 = [Convert]::ToBase64String($bytes)

# Thực thi lệnh mã hóa
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $b64
```

---

## 5. Quy trình Điều tra trên Security Onion SOC (Threat Hunting)

Sau khi chạy lệnh trên máy trạm, mở giao diện **SOC ➔ Hunt** trên trình duyệt máy thật (`https://192.168.182.10`) để điều tra:

### 5.1. Truy vấn Process Creation (Sysmon Event ID 1)
Đặt mốc thời gian: **Last 15 minutes**.

* **Truy vấn 1: Tìm đúng Marker đã chạy trong lab:**
  ```text
  event.code:1 AND process.command_line:*SO-LAB-POWERSHELL*
  ```

* **Truy vấn 2: Phát hiện các lệnh PowerShell sử dụng tham số `-EncodedCommand`:**
  ```text
  process.name:"powershell.exe" AND process.command_line:*-EncodedCommand*
  ```

* **Truy vấn 3: Phát hiện hành vi trinh sát hệ thống (Discovery):**
  ```text
  process.name:("whoami.exe" OR "net.exe" OR "systeminfo.exe")
  ```

---

### 5.2. Các trường bằng chứng quan trọng cần phân tích (Evidence Fields)

Khi mở chi tiết một Event ID 1 trong Hunt, hãy quan sát các trường sau để chứng minh sự vượt trội của Host Visibility:

| Trường dữ liệu | Giá trị quan sát thực tế | Ý nghĩa điều tra |
|---|---|---|
| **`host.hostname`** | `WIN-LAB-PC` | Tên máy trạm phát sinh hành vi |
| **`user.name`** | `Administrator` hoặc `labuser` | Danh tính tài khoản thực thi mã |
| **`process.name`** | `powershell.exe` | Tên tiến trình thực thi |
| **`process.command_line`** | `powershell.exe -NoProfile -EncodedCommand ...` | **Bằng chứng đanh thép:** Thấy nguyên văn câu lệnh kể cả khi đã bị ẩn |
| **`process.parent.name`** | `cmd.exe` hoặc `explorer.exe` | Tiến trình cha đã sinh ra PowerShell (Parent-Child relation) |
| **`process.hash.sha256`** | Hash SHA256 của file `powershell.exe` | Đối chiếu tính toàn vẹn (loại trừ masquerading malware) |

---

### 5.3. Tương quan Host Telemetry và Network Telemetry

* Tại sao điều này biến Security Onion thành SIEM/XDR mạnh mẽ?
  * Zeek / Suricata ghi nhận: `192.168.182.20` kết nối tới cổng 80 của `192.168.182.10`.
  * Sysmon Event ID 3 ghi nhận: Kết nối đó **chính xác được tạo ra bởi PID 4820 (`powershell.exe`)**, chứ không phải do trình duyệt `chrome.exe` của người dùng.
  * Sự kết hợp này giúp phân biệt ngay lập tức giữa hoạt động duyệt web bình thường của nhân viên và hành vi Call-back C2 bí mật của mã độc PowerShell.

---

## 6. Tạo Detection Alert & Đóng Case

### 6.1. Tạo Detection Rule trên SOC
1. Trong giao diện SOC, vào mục **Detections** ➔ **Rules**.
2. Thêm rule Sigma hoặc Elastic Security Rule:
   * **Title:** `Suspicious Encoded PowerShell Execution (Lab S4)`
   * **Query:** `process.name:"powershell.exe" AND process.command_line:*-EncodedCommand*`
   * **Severity:** Medium / High
   * **MITRE ATT&CK:** `T1059.001`
3. Chạy lại script mô phỏng, hệ thống sẽ sinh ra **Alert** trong tab **Alerts**.

### 6.2. Tạo và Đóng Case điều tra
1. Từ Alert hoặc Hunt event, chọn **Escalate to Case** (hoặc tạo Case mới trong tab **Cases**).
2. Điền thông tin Case:
   * **Title:** `LAB Scenario 4 — Suspicious PowerShell Execution on Windows Endpoint`
   * **Category:** Unauthorized Execution / Reconnaissance
   * **Severity:** Medium
   * **Description:** Phát hiện tiến trình PowerShell thực thi tham số `-EncodedCommand` và các lệnh dò quét (`whoami`, `net user`) trên máy trạm `WIN-LAB-PC`.
   * **Artifacts đính kèm:** Snapshot log Sysmon Event ID 1, Parent Process ID, Command line giải mã.
   * **Status:** Closed - `Authorized Penetration Testing / Lab Demonstration`.

---

## 7. Bảng câu hỏi bảo vệ & Thuyết trình đồ án (Q&A)

* **Q1: Nếu hacker xóa log Windows Event Log (`wevtutil cl System`) thì Elastic Agent có bị mất log không?**
  * *Trả lời:* Elastic Agent hoạt động theo cơ chế Stream/Shipper gần như theo thời gian thực (Real-time). Khi log vừa được ghi vào kernel/Event Viewer, Agent đã lập tức chuyển về Elasticsearch trước khi kẻ tấn công kịp thực hiện thao tác xóa log. Ngoài ra, chính hành vi xóa log cũng kích hoạt Event ID 1102 (The audit log was cleared).

* **Q2: Vì sao Zeek không thể phát hiện được câu lệnh bên trong PowerShell script?**
  * *Trả lời:* Zeek là network analyzer chỉ phân tích dữ liệu truyền trên dây mạng. Nếu PowerShell chạy local (offline) hoặc kết nối qua kênh mã hóa HTTPS/TLS, payload bị che khuất. Phải cần Endpoint Visibility (Sysmon/Elastic Agent) để nhìn trực tiếp vào bộ nhớ và tiến trình của hệ điều hành.

* **Q3: Làm sao phát hiện nếu hacker đổi tên `powershell.exe` thành `svchost.exe` để ngụy trang?**
  * *Trả lời:* Sysmon ghi lại trường `process.pe.original_file_name` và mã băm `process.hash.sha256`. Dù đổi tên file thực thi, `OriginalFileName` vẫn là `PowerShell.EXE`, cho phép SOC dễ dàng viết rule phát hiện Masquerading (T1036).
