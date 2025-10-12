# Challenge:

- Category: Cryptography

## Description

We’re given a Python scirpt that outputs two modular equations (`remain[0]` and `remain[1]`) involving powers of 13 and 37 modulo a large prime `p`.

```python
from Crypto.Util.number import *

def generator(m:int) -> int:
    p = 396430433566694153228963024068183195900644000015629930982017434859080008533624204265038366113052353086248115602503012179807206251960510130759852727353283868788493357310003786807
    return (pow(13, m, p) + pow(37, m, p)) % p

flag = b"REDACTED"
secret = bytes_to_long(flag)
flag_obscured = generator(secret)
outputs = []

for i in range(secret):
    outputs.append(generator(i))

outputs.append(flag_obscured)

remain = outputs[-2:]
print(remain)

#[88952575866827947965983024351948428571644045481852955585307229868427303211803239917835211249629755846575548754617810635567272526061976590304647326424871380247801316189016325247, 67077340815509559968966395605991498895734870241569147039932716484176494534953008553337442440573747593113271897771706973941604973691227887232994456813209749283078720189994152242]
```

The comments in the challenge hinted that these values were generated from a small linear system involving the terms
`13^(secret - 1)` and `37^(secret - 1)`.

## Solution

### Step 1 — Understanding the Equations

Let:

```
x = 13^(secret - 1)  mod p  
y = 37^(secret - 1)  mod p
```

We are given two linear combinations:

```
remain[0] = x + 24y  (mod p)
remain[1] = 13x + 37y  (mod p)
```

That’s a simple 2×2 system of equations:

```
r0 = x + 24y
r1 = 13x + 37y
```

So i solved for `x` and `y` using modular arithmetic.

### Step 2 — Solving the System

Subtract `13 * r0` from `r1`:

```
r1 - 13*r0 = (13x + 37y) - 13(x + 24y)
r1 - 13*r0 = (37 - 312)y = -275y
```

That gave me:

```
y = (r1 - 13*r0) * inverse(-275, p) mod p
```

Since `-275 ≡ 24 mod p` (they’re congruent modulo p), we can simply compute:

```
y = (r1 - 13*r0) * inverse(24, p) mod p
x = (r0 - y) mod p
```

This gives us the actual values of `13^(secret-1)` and `37^(secret-1)` modulo `p`.

### Step 3 — Recovering the Secret

Now that I had `x = 13^(secret-1)`, I used a discrete log to recover the exponent `secret - 1`:

```
k = discrete_log(p, x, 13)
secret = k + 1
```

Finally, I had the complete script to get the flag

## Flag:
`idek{charles_and_the_chocolate_factory!!!}`

## Key Takeaways

-  This challenge combines linear algebra in modular arithmetic with a discrete loga problem
-  The `sympy.ntheory.discrete_log` function is extremely handy for small-to-medium primes but may become slow for large ones.

## Resources

- https://docs.sympy.org/latest/modules/ntheory.html#sympy.ntheory.residue_ntheory.discrete_log
- https://docs.python.org/3/library/functions.html#pow
- https://crypto.stanford.edu/pbc/notes/numbertheory/linear.html
