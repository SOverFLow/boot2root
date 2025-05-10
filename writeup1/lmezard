The home directory of user lmezard contains two files: README and fun.
File: README

Complete this little challenge and use the result as password for user 'laurie' to login in ssh

Step-by-step Instructions

    Inspect the fun File
    Using the file command, we discovered that the fun file is a tar archive:

file fun
# Output: fun: POSIX tar archive (GNU)

Extract the Archive
After extracting it using:

tar -xf fun

a directory named ft_fun is created, which contains multiple files with random names ending in .pcap.

Analyze the Contents
Each .pcap file contains a fragment of C source code. A special comment line in each file marks the order of the fragments, in the format:

// fileXX

Reconstruct the Original C Program
A Python script was used to read all files, identify their sequence from the comment, sort them, and combine the contents into a single file:

import os
import re

folder_path = "ft_fun"
output_file = "merged.c"
file_parts = []

for filename in os.listdir(folder_path):
    file_path = os.path.join(folder_path, filename)
    if os.path.isfile(file_path):
        with open(file_path, 'r') as f:
            content = f.read()
            match = re.search(r'//\s*file\s*(\d+)', content, re.IGNORECASE)
            if match:
                file_number = int(match.group(1))
                file_parts.append((file_number, content))
            else:
                print("Skipping file without index")

file_parts.sort(key=lambda x: x[0])

with open(os.path.join(folder_path, output_file), 'w') as out_file:
    for _, content in file_parts:
        out_file.write(content + '\n')

print("C source file created as 'merged.c'")

Compile and Run
Compile the assembled C program:

gcc merged.c -o merged
./merged

The program outputs a string.

Hash the Output
Take the output and apply SHA-256 hashing:

echo -n "output_string" | sha256sum

Replace "output_string" with the actual string printed by the compiled program.

Final Password
The final password obtained after hashing is:

    330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4

Use this password to log in as user laurie via SSH.