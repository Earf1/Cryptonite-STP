# Challenge: chall 1 (xor challenge)
- Category: Cryptography

## Description
I was given a chall.py file and a file called ct

```
from itertools import cycle

flag = b"flaggg{????????????????????????????????????????}"
# len(flag) = 48
key  = b'djpakoda'
# len(key) = 8
ct = bytes(x ^ y for x, y in zip(flag, cycle(key)))

with open("ct", "wb") as ct_file:
    ct_file.write(ct)
```

## Flag: 
`flaggg{w0w_g0od_j0b_V3ry_gr34t_amazing_AW35OMEE}`

## Solution
Upon analyzing the provided Python code, I noticed this is a classic XOR encryption challenge where the 8 byte repeating key is `b'djpakoda'`

The encryption uses `itertools.cycle()` to repeat the key across the 48-byte flag, XORing each byte. 
we know that xor cipher is symmetric, applying the same operation with the key to the ciphertext will decrypt it back to the original flag.

I wrote a small decryption script for this

```
from itertools import cycle
key = b'djpakoda'
with open("ct", "rb") as ct_file:
    ct = ct_file.read()
flag = bytes(x ^ y for x, y in zip(ct, cycle(key)))
print(flag.decode())
```

This script gave me the flag by simply XORing each byte of the ciphertext with the corresponding byte of the repeating key pattern. 
