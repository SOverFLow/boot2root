# Challenge Instructions for User `laurie`

The home directory of user `lmezard` contains two important files: `README` and `fun`.

## 🎯 Objective

Complete this little challenge and use the result as the password for user `laurie` to log in via SSH.

## 📁 Step-by-Step Instructions

## 1. Inspect the `fun` File

Run the `file` command to determine the file type:

bash
file fun
# Output: fun: POSIX tar archive (GNU)
## 2. Extract the Archive
Extract the tar archive using:


tar -xf fun
This creates a directory named ft_fun containing multiple files with random names ending in .pcap.

## 3. Analyze the Contents
Each .pcap file contains a fragment of a C source code. A special comment in each file indicates the sequence:

fileXX
Where XX is a number that determines the order of the code fragment.

## 4. Reconstruct the Original C Program
Use the following Python script to:

Read all .pcap files.

Identify the order from the comment.

Sort and merge them into one C file.

<pre>
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
</pre>


## 5. Compile and Run the Program
Compile the reconstructed C program:

<pre>
gcc merged.c -o merged
./merged
</pre>
The program will output a string.

## 6. Hash the Output
Take the output string and hash it using SHA-256:

<pre>
 echo -n "output_string" | sha256sum 
</pre>

✅ Final Password
Use the resulting hash as the password:

<pre>
330b845f32185747e4f8ca15d40ca59796035c89ea809fb5d30f4da83ecf45a4
</pre>
🔐 Login via SSH
Now, log in as user laurie using the obtained password:

<pre>
ssh laurie@host
</pre>
Replace `<host>` with the actual hostname or IP address.
