# **Threat Intelligence Report: Stuxbot**

The report underlines the menace posed by the organized cybercrime collective called Stuxbot, which the primary motivation is espionage.
The attack sequence for the initially compromised device can be laid out as follows:

![](Image/Pasted%20image%2020250413202709.png)
### Initial Breach
The phishing email is rudimentary, with the malware posing as an invoice file.
This is the link leading to OneNote file.

![](Image/Pasted%20image%2020250413210108.png)

The OneNote file masquerades as an invoice featuring a button that triggers an embedded batch file fetching PowerShell script in turn.

### RAT Characteristics
The RAT is modular, it can be augment with an infinite range of capabilities.
The report notes the use of tools that capture screen dumps ->  [Mimikatz](https://attack.mitre.org/software/S0002/), provide an interactive shell on compromised machine.

### Persistence
All persistence mechanisms utilized to the date involved EXE file deposited on the disk.
### Lateral Movement
- Leveraging the original, Microsoft-signed PsExec
- Using WinRM
### Indicators of Compromise (IOCs)
**OneNote File**:
- https://transfer.sh/get/kNxU7/invoice.one
- https://mega.io/dl9o1Dz/invoice.one

**Staging Entity (PowerShell Script)**:
- https://pastebin.com/raw/AvHtdKb2
- https://pastebin.com/raw/gj58DKz

**Command and Control (C&C) Nodes**:
- 91.90.213.14:443
- 103.248.70.64:443
- 141.98.6.59:443

**Cryptographic Hashes of Involved Files (SHA256)**:
- 226A723FFB4A91D9950A8B266167C5B354AB0DB1DC225578494917FE53867EF2
- C346077DAD0342592DB753FE2AB36D2F9F1C76E55CF8556FE5CDA92897E99C7E
- 018D37CBD3878258C29DB3BC3F2988B6AE688843801B9ABC28E6151141AB66D4

---
## **Hunting For Stuxbot With The Elastic Stack**
#### The Available Data
- `Windows audit logs` 
- `System Monitor (Sysmon) logs` [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- `PowerShell logs`  [here](https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html)
- `Zeek logs`, [a network security monitoring tool](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-zeek.html) 
#### The Hunt
The report indicates that initial compromises all took place via **"invoice.one"** files.
- **`event.code:15 AND file.name:*invoice.one`** 
	-  [Sysmon Event ID 15](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015)(FileCreateStreamHash), which represents a browser file download event.
	- **MSEdge** was the application (`process.name` or `process.executable`) used to download the file, which was stored in the Downloads folder of an employee named Bob.
	- The timestamp to note is: `March 26, 2023 @ 22:05:47`

![](Image/Pasted%20image%2020250413220630.png)

- **`event.code:11 AND file.name:invoice.one*`**
	- [Sysmon Event ID 11](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011) (File create) and the "invoice.one" file name.
	- **Zone Identifier** indicates that the file originated from the internet.
	- "invoice.one" file has the hostname WS001.

![](Image/Pasted%20image%2020250414095651.png)

- `event.code:3 AND host.hostname:WS001`
	- IP address of 192.168.28.130 can be confirmed by checking any network connection event (Sysmon Event ID 3) from this machine in **source.ip** field.
	- When inspecting network connections leveraging [Sysmon Event ID 3](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003) around the time this file was downloaded -> find that Sysmon has no entries because of an overwhelming volume of logs.
- `source.ip:192.168.28.130 AND dns.question.name:*`
	- `Zeek query` will search for a source IP matching 192.168.28.130, querying about DNS queries.
	- Note that this will return a lot of common noise.

 **Observe the following activities:**

![](Image/Pasted%20image%2020250414151143.png)
 ![](Image/Pasted%20image%2020250414152105.png)
 
- The user accessed Google Mail, followed by interaction with **"file.io"**, a known hosting provider. Subsequently, **Microsoft Defender SmartScreen** initiated a file scan, typically triggered when a file is downloaded via Microsoft Edge.
- Expanding the log entry for **file.io** reveals the returned IP addresses: `34.197.10.85`, `3.213.216.16`.

![](Image/Pasted%20image%2020250414152752.png)

=> Bob, successfully downloaded the file "invoice.one" from the hosting provider "file.io".

- **Vào thời điểm này, ta phải:**
	1. So sánh chéo với dữ liệu Threat Intel Report, để xác các thông tin trùng lặp theo báo cáo.
	2. Thực hiện cuộc điều tra để theo dõi trình tự các event sau khi OneNote được tải về.

---
#### **Post Investigation**
- Nếu "invoice.one" được access, nó sẽ mở phần mềm **OneNote**.
```
event.code:1 AND process.command_line:*invoice.one*
```

![](Image/Pasted%20image%2020250414154301.png)

- Khi mở **OneNote.exe**, nó có thể chứa browser hoặc malicious file.
- Vì vậy ta kiểm tra xem process mà **OneNote.exe** là parent process.

```
event.code:1 AND process.parent.name:"ONENOTE.EXE"
```

![](Image/Pasted%20image%2020250414154855.png)

- **Result:**
	- The middle entry documents a new process - **OneNoteM.exe**, which is a component of OneNote and assists in launching files.
	- The top entry reveals **"cmd.exe"** in operation, executing a file named **"invoice.bat"**.

![](Image/Pasted%20image%2020250414155220.png)

- Nhận ra sự kết nối giữa **ONENOTE.EXE**, **invoice.one** và thực thi **cmd.exe** khởi chạy **invoice.bat**.
- Giờ ta phải check xem **batch script** (.bat) sinh thêm các child process:

```
event.code:1 AND process.parent.command_line:*invoice.bat*
```

![](Image/Pasted%20image%2020250414161853.png)

- Note that we have added `process.name`, `process.args`, and `process.pid`.
- A command to download and execute content from **Pastebin**, an open text hosting provider.
- This is referred to in the Threat Intelligence report, stating that a **PowerShell Script from Pastebin** was downloaded.
- Để biết được PowerShell làm gì, ta phải dựa vào PID.

```
process.pid:"9944" and process.name:"powershell.exe"
```

![](Image/Pasted%20image%2020250414162624.png)

- Chỉ rõ việc tạo tệp, kết nối mạng, phân giải DNS với **Sysmon Event ID 22** (DNSEvent).

Add thêm thông tin với field: `file.path`, `dns.question.name`, and `destination.ip`.

![](Image/Pasted%20image%2020250414163237.png)

- Ngrok is C2, after DNS resolution, we see connection to ip address with port 443, traffic got encrypt.
- The dropped EXE is likely intended for persistence.
- The final actions that this process points to are a DNS query for DC1 and connections to it.

##### **C&C server**
-  Review Zeek data for information on the destination IP address `18.158.249.75` that we just discovered.
- Add `source.ip`, `destination.ip`, and `destination.port` field.

![](Image/Pasted%20image%2020250414164751.png)

- Hoạt động kết nối mở rộng sang ngày hôm sau, rồi bị terminate -> Đổi C2 IP hoặc dừng cuộc tấn công.
- DNS query với **"ngrok.io"** -> ip trả về của **dns.answer.data** bị thay đổi.

![](Image/Pasted%20image%2020250414170904.png)

- Indicates that connections continued consistently over the following days.

![](Image/Pasted%20image%2020250414171424.png)

- Xác nhận rằng C2 đã được truy cập liên tục. 

##### **EXE file - Persistence**
- Phân tích **default.exe** -> xác minh liệu nó đã thực thi hay chưa.
- Add `process.name`, `process.args`, `event.code`, `file.path`, `destination.ip`, and `dns.question.name` fields.

```
process.name:"default.exe"
```

![](Image/Pasted%20image%2020250414171811.png)

- **default.exe** đã được thực thi - khởi tạo kết nối với C2 server (Event Code 3),  tạo tệp **"svchost.exe"** and **"SharpHound.exe"** (Event Code 11).
- If we scroll up there's further activity from this executable, including the uploading of **"payload.exe"**, **a VBS file**, and repeated uploads of **"svchost.exe"**.
- **SharpHound.exe** 
	- Diagramming Active Directory (Lập sơ đồ Active Directory).
	- Identifying Attack Paths for Escalation (Xác định các con đường tấn công để leo thang).
- **svchost.exe** - mimic the legitimate svchost file, part of OS.

```
process.name:"SharpHound.exe"
```

![](Image/Pasted%20image%2020250414203347.png)

- Tool được thực thi 2 lần, cách nhau 2 phút.
##### Lateral Movement
- **"default.exe"** với file hash (`process.hash.sha256` field) nằm đúng trên report.
- Giờ ta xác minh liệu file exe có được phát hiện trong các thiết bị khác không.
- Add **host.hostname** field.

```
process.hash.sha256:018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4
```

![](Image/Pasted%20image%2020250414204259.png)

- The hash value have been found on **WS001** and **PKI**, indicating that the attacker has also breached the PKI server.
- A backdoor file has been placed under the profile of user **"svc-sql1"** -> this user's account is compromised.
- Expanding **"default.exe"** execution on PKI, we notice that the parent process was **"PSEXESVC"**.
- **PSEXESVC** là một thành phần của **PSExec**, một công cụ Sysinternals dùng để thực thi lệnh, điều khiển từ xa các máy tính khác qua terminal.
	- Các máy khác được cài **PSEXESVC** service trước đó để được truy cập từ xa, tận dụng điều này truyền **SharpHound.exe** qua máy khác.
	- Lạm dụng để thực hiện **Lateral Movement** trong AD, giúp họ lây nhiễm nhiều máy, thu thập thông tin qua **SharpHound.exe** (tạo bởi default.exe).

![](Image/Pasted%20image%2020250414210750.png)

- Notice **"svc-sql1"** in the `user.name` field, thereby confirming the compromise of this user.
- Lý do mà bị lộ mật khẩu user **"svc-sql1"** vì **PSEXESVC** cần password để kết nối -> **Powershell script** trước đó (payload.exe, VBS, svchost.exe) được thiết kể để **Password Bruteforcing.**
- Check for any successful or failed password attempts from that machine, excluding those for Bob, the user of that machine.

```
(event.code:4624 OR event.code:4625) AND winlog.event_data.LogonType:3 AND source.ip:192.168.28.130
```

![](Image/Pasted%20image%2020250414212440.png)

- Two failed attempts for the administrator account, roughly around the time when the initial suspicious activity was detected. 
- Subsequently, there were numerous successful logon attempts for **"svc-sql1"**.

---
### **Answer**

![](Image/Pasted%20image%2020250414220723.png)

![](Image/Pasted%20image%2020250414221050.png)

![](Image/Pasted%20image%2020250414230139.png)

- `event.module:powershell AND event.code:4104 AND (message:"Invoke-ShareFinder" OR message:"Find-DomainShare")`
- `Invoke-ShareFinder -ExcludeStandard -ExcludeIPC`