# Challenge: chall 2 (base3 xor)
- Category: Cryptography

## Description
I was given two files: `chal.py` and `out.py`

The challenge code in `chal.py`:
```
from out import enc, R
from math import prod

flag = ''
a = [0]
for i in range(355):
    b = [_+1 for _ in a]
    c = [_+1 for _ in b]
    a += b + c

    if i%5 == 0:
        flag += chr(enc[i//5] ^ prod([a[_] for _ in R[i//5]]))
        print(flag)
```

The `out.py` file contains encrypted values in `enc` (71 elements) and indices in `R` (71 arrays with 3 indices each).

## Flag: 
`CSCTF{2441d2f22fa1d5b9fc0a850dcfbbccf608cafbc22a1beaae0ac328ff6d218781}`

## Solution

Upon analyzing the provided code, i found that the sequence construction creates an exponentially growing array where at each iteration, the array triples in size following the pattern `a = [a, a+1, a+2]`.

The array grows as 3^n, meaning after 355 iterations it would contain approximately 10^169 elements, making it physically impossible to store in memory. Running the code directly results in a MemoryError.

Reading up about how to do xor fast and how to recognise the pattern in how values are distributed across the array. 

Using the factt that the array grows as 3^n each time, i thought of using base 3 to represent the values in the array
Basically, in base 3, each position represents a power of 3:​

- ones place (3^0 = 1)
- threes place (3^1 = 3)
- nines place (3^2 = 9)
- twentysevens place (3^3 = 27)

taking an example from the R array, 573 can be represented as 
- 573 ÷ 3 = 191 remainder 0
- 191 ÷ 3 = 63 remainder 2
- 63 ÷ 3 = 21 remainder 0
- 21 ÷ 3 = 7 remainder 0
- 7 ÷ 3 = 2 remainder 1
- 2 ÷ 3 = 0 remainder 2
Sum of remainders: 2+1+0+0+1+2 = 6, so index 573 is basically value 6

Based on this, I wrote a script to get to the flag.

```
from out import enc, R
from math import prod
import numpy as np

def calculate_value(n):
    base3 = np.base_repr(n, base=3)
    total = 0
    for digit in base3:
        total = total + int(digit)
    return total

answer = ''

for iteration in range(355):
    if iteration % 5 == 0:
        position = iteration // 5
        
        values_list = []
        for index in R[position]:
            values_list.append(calculate_value(index))
        
        product_result = prod(values_list)
        character = chr(enc[position] ^ product_result)
        answer = answer + character

print(answer)
```

This script computes each required array value mathematically using base-3 representation, avoiding memory allocation entirely while successfully decrypting the flag through XOR operations with the products of specific sequence values.

## Resources
- https://www.expii.com/t/base-ternary-numbers-9194
- https://blag.nullteilerfrei.de/2018/11/28/fast-xor-in-python/
